"""Shared fixtures: the repository's fixtures site, the built Node CLI, and helpers to read what was written."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest

PYTHON_DIR = Path(__file__).resolve().parent.parent
REPO = PYTHON_DIR.parent
SPEC = REPO / "spec"
CLI = REPO / "packages" / "cli" / "dist" / "bin.js"

sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]


def node_available() -> bool:
    try:
        return subprocess.run(["node", "--version"], capture_output=True, check=False).returncode == 0
    except OSError:
        return False


needs_cli = pytest.mark.skipif(
    not (CLI.exists() and node_available()), reason="the Node CLI is not built (pnpm -r build)"
)


def run_cli(*args: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run the built ``steplight`` CLI."""
    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        ["node", str(CLI), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=merged,
        cwd=cwd,
        check=False,
        timeout=180,
    )


@pytest.fixture(scope="session")
def schema() -> dict[str, Any]:
    return json.loads((SPEC / "run-format.schema.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.fixture(scope="session")
def validate(schema: dict[str, Any]):  # type: ignore[no-untyped-def]
    """``validate("step", obj)`` raises when obj does not match the shared run-format schema."""

    def check(definition: str, instance: Any) -> None:
        validator = jsonschema.Draft202012Validator({"$ref": f"#/$defs/{definition}", "$defs": schema["$defs"]})
        errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
        if errors:
            raise AssertionError("; ".join(f"{'/'.join(map(str, e.path))}: {e.message}" for e in errors[:5]))

    return check


@pytest.fixture(scope="session")
def validate_run_dir(validate):  # type: ignore[no-untyped-def]
    """Validate every file of a plain (unencrypted) run folder against the schema; returns (run, steps)."""

    def check(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        validate("runJson", run)
        steps = [
            json.loads(line) for line in (run_dir / "steps.jsonl").read_text(encoding="utf-8").splitlines() if line
        ]
        for step in steps:
            validate("step", step)
            if "snapshotRef" in step:
                assert (run_dir / step["snapshotRef"]).is_file()
        analysis = run_dir / "analysis-input.jsonl"
        if analysis.exists():
            for line in analysis.read_text(encoding="utf-8").splitlines():
                if line:
                    validate("analysisInput", json.loads(line))
        return run, steps

    return check


@pytest.fixture(scope="session")
def fixtures_site() -> Iterator[dict[str, str]]:
    """The repository's fixtures site (flights, checkout, clean pages) plus a collector origin, on free ports."""
    if not node_available():
        pytest.skip("node is needed for the fixtures site")
    proc = subprocess.Popen(
        ["node", str(PYTHON_DIR / "tests" / "fixtures_server.mjs")],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    info: dict[str, str] = json.loads(proc.stdout.readline())
    yield info
    proc.kill()
    proc.wait()


@pytest.fixture
def runs_dir(tmp_path: Path) -> Path:
    return tmp_path / "runs"


def all_text(folder: Path) -> str:
    """Every file under a folder concatenated, to prove a secret reached the disk (or did not)."""
    out = []
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            out.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(out)
