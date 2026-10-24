"""The release gates: tag/version matching and the contents of the built distributions."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from tests.conftest import PYTHON_DIR


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, PYTHON_DIR / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_version = load("check_version")
verify_dist = load("verify_dist")


@pytest.mark.parametrize(
    ("tag", "version"),
    [("v0.2.0", "0.2.0"), ("v0.2.0-rc.1", "0.2.0rc1"), ("v1.10.3-beta.12", "1.10.3b12"), ("v0.2.0-alpha.3", "0.2.0a3")],
)
def test_tags_become_pep_440_versions(tag: str, version: str) -> None:
    assert check_version.pep440(tag) == version
    packaging = pytest.importorskip("packaging.version")
    assert str(packaging.Version(version)) == version  # and PEP 440 agrees that it is normalised


@pytest.mark.parametrize(
    "tag", ["0.2.0", "v0.2", "v0.2.0-rc1", "v0.2.0-rc.1.2", "v0.2.0+local", "latest", "v0.2.0-dev.1"]
)
def test_other_tags_are_refused(tag: str) -> None:
    with pytest.raises(ValueError, match="not a release tag"):
        check_version.pep440(tag)


def test_the_gate_compares_pyproject_and_the_package(tmp_path: Path) -> None:
    (tmp_path / "src" / "steplight").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "steplight-sdk"\nversion = "0.2.0rc1"\n', encoding="utf-8"
    )
    (tmp_path / "src" / "steplight" / "__init__.py").write_text('__version__ = "0.2.0rc1"\n', encoding="utf-8")
    assert check_version.check("v0.2.0-rc.1", tmp_path) == []
    assert any(
        "pyproject.toml says '0.2.0rc1' but tag v0.2.0 means '0.2.0'" in p
        for p in check_version.check("v0.2.0", tmp_path)
    )
    (tmp_path / "src" / "steplight" / "__init__.py").write_text('__version__ = "0.2.0"\n', encoding="utf-8")
    assert [p.split(" says")[0] for p in check_version.check("v0.2.0-rc.1", tmp_path)] == ["steplight/__init__.py"]
    assert check_version.check("main", tmp_path)[0].startswith("'main' is not a release tag")


def make_dist(folder: Path, extra: str | None = None, requires: str | None = None) -> Path:
    """A minimal valid wheel + sdist pair, optionally with one stray file or one required dependency."""
    folder.mkdir(parents=True, exist_ok=True)
    metadata = "Name: steplight-sdk\nVersion: 0.2.0\nRequires-Python: >=3.10\nLicense-Expression: Apache-2.0\n"
    if requires:
        metadata += f"Requires-Dist: {requires}\n"
    package = dict.fromkeys(verify_dist.REQUIRED_PACKAGE_FILES, "x")
    with zipfile.ZipFile(folder / "steplight-0.2.0-py3-none-any.whl", "w") as wheel:
        for name, text in package.items():
            wheel.writestr(name, text)
        wheel.writestr("steplight-0.2.0.dist-info/METADATA", metadata)
        wheel.writestr("steplight-0.2.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        wheel.writestr("steplight-0.2.0.dist-info/RECORD", "")
        wheel.writestr("steplight-0.2.0.dist-info/licenses/LICENSE", "Apache")
        if extra:
            wheel.writestr(extra, "stray")
    source = folder / "src_tree"
    for name, text in {
        **{f"src/{n}": t for n, t in package.items()},
        "PKG-INFO": metadata,
        "pyproject.toml": "",
        "README.md": "",
        "LICENSE": "",
    }.items():
        (source / "steplight-0.2.0" / name).parent.mkdir(parents=True, exist_ok=True)
        (source / "steplight-0.2.0" / name).write_text(text, encoding="utf-8")
    if extra:
        (source / "steplight-0.2.0" / extra).parent.mkdir(parents=True, exist_ok=True)
        (source / "steplight-0.2.0" / extra).write_text("stray", encoding="utf-8")
    with tarfile.open(folder / "steplight-0.2.0.tar.gz", "w:gz") as sdist:
        sdist.add(source / "steplight-0.2.0", arcname="steplight-0.2.0")
    shutil.rmtree(source)
    return folder


def test_a_clean_distribution_passes(tmp_path: Path) -> None:
    assert verify_dist.check(make_dist(tmp_path / "ok")) == []


@pytest.mark.parametrize(
    "stray",
    [
        "tests/test_x.py",
        "uv.lock",
        ".github/workflows/x.yml",
        "steplight/secrets.env",
        "spec/page-scan.js",
        "steplight/_data/notes.txt",
    ],
)
def test_anything_else_fails_the_release(tmp_path: Path, stray: str) -> None:
    problems = verify_dist.check(make_dist(tmp_path / "bad", extra=stray))
    assert any(f"unexpected file {stray}" in p or f"unexpected file src/{stray}" in p for p in problems), problems


def test_a_required_dependency_fails_the_release(tmp_path: Path) -> None:
    assert any(
        "required dependency requests>=2" in p
        for p in verify_dist.check(make_dist(tmp_path / "dep", requires="requests>=2"))
    )
    assert verify_dist.check(make_dist(tmp_path / "extra", requires='playwright>=1.40; extra == "playwright"')) == []


def test_the_real_build_passes_the_gate(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not installed")
    out = tmp_path / "dist"
    done = subprocess.run(
        [uv, "build", "--out-dir", str(out), str(PYTHON_DIR)], capture_output=True, text=True, check=False, timeout=240
    )
    assert done.returncode == 0, done.stderr
    assert verify_dist.check(out) == []
    with zipfile.ZipFile(next(out.glob("*.whl"))) as wheel:
        names = set(wheel.namelist())
    assert {"steplight/py.typed", "steplight/_data/page-scan.js"} <= names
    assert not any(n.startswith(("tests", "spec", "scripts")) for n in names)
