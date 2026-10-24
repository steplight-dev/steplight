"""Release gate: the built sdist and wheel may contain only what belongs in them.

    python scripts/verify_dist.py dist/

Allowed in the wheel: ``steplight/*.py``, ``steplight/integrations/*.py``, ``steplight/py.typed``,
``steplight/_data/{page-scan.js,never-capture.json}`` and the ``.dist-info`` metadata (METADATA, WHEEL, RECORD and the
license). Allowed in the sdist: the same package under ``src/``, plus PKG-INFO, pyproject.toml, README.md and LICENSE.
Anything else (tests, caches, lock files, scripts, workflows, the rest of the monorepo) fails the release, and so does
a required file that is missing or a required runtime dependency. Standard library only.
"""

from __future__ import annotations

import re
import sys
import tarfile
import zipfile
from pathlib import Path

PACKAGE_FILE = re.compile(
    r"steplight/(?:[a-z_]+\.py|integrations/[a-z_]+\.py|py\.typed|_data/(?:page-scan\.js|never-capture\.json))"
)
REQUIRED_PACKAGE_FILES = {
    "steplight/__init__.py",
    "steplight/py.typed",
    "steplight/_data/page-scan.js",
    "steplight/_data/never-capture.json",
    "steplight/redact.py",
    "steplight/integrations/browser_use.py",
}


def wheel_problems(path: Path) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(path) as wheel:
        names = [n for n in wheel.namelist() if not n.endswith("/")]
        dist_info = {n.split("/")[0] for n in names if n.split("/")[0].endswith(".dist-info")}
        if len(dist_info) != 1:
            return [f"{path.name}: expected exactly one .dist-info folder, found {sorted(dist_info)}"]
        info = next(iter(dist_info))
        allowed_meta = {f"{info}/METADATA", f"{info}/WHEEL", f"{info}/RECORD", f"{info}/licenses/LICENSE"}
        for name in names:
            if name in allowed_meta or PACKAGE_FILE.fullmatch(name):
                continue
            problems.append(f"{path.name}: unexpected file {name}")
        present = set(names)
        problems += [f"{path.name}: missing {r}" for r in sorted(REQUIRED_PACKAGE_FILES - present)]
        problems += [
            f"{path.name}: missing {m}" for m in sorted({f"{info}/METADATA", f"{info}/licenses/LICENSE"} - present)
        ]
        if f"{info}/METADATA" in present:
            problems += metadata_problems(path.name, wheel.read(f"{info}/METADATA").decode("utf-8"))
    return problems


def sdist_problems(path: Path) -> list[str]:
    problems: list[str] = []
    with tarfile.open(path) as sdist:
        members = [m for m in sdist.getmembers() if m.isfile()]
        roots = {m.name.split("/")[0] for m in members}
        if len(roots) != 1:
            return [f"{path.name}: expected one top-level folder, found {sorted(roots)}"]
        root = next(iter(roots))
        names = {m.name[len(root) + 1 :] for m in members}
        top_level = {"PKG-INFO", "pyproject.toml", "README.md", "LICENSE"}
        for name in sorted(names):
            if name in top_level or name == ".gitignore":  # hatchling copies the ignore rules; they are not code
                continue
            if name.startswith("src/") and PACKAGE_FILE.fullmatch(name[4:]):
                continue
            problems.append(f"{path.name}: unexpected file {name}")
        problems += [f"{path.name}: missing {m}" for m in sorted(top_level - names)]
        problems += [
            f"{path.name}: missing src/{r}"
            for r in sorted(REQUIRED_PACKAGE_FILES - {n[4:] for n in names if n.startswith("src/")})
        ]
        pkg_info = sdist.extractfile(f"{root}/PKG-INFO")
        if pkg_info is not None:
            problems += metadata_problems(path.name, pkg_info.read().decode("utf-8"))
    return problems


def metadata_problems(name: str, metadata: str) -> list[str]:
    """No required runtime dependency: every Requires-Dist must belong to an extra."""
    problems = []
    for line in metadata.splitlines():
        if line.startswith("Requires-Dist:") and "extra ==" not in line:
            problems.append(
                f"{name}: required dependency {line.removeprefix('Requires-Dist:').strip()} (the package has none)"
            )
    if not re.search(r"^Name: steplight-sdk\s*$", metadata, re.MULTILINE):
        problems.append(f"{name}: metadata Name is not steplight-sdk")
    if not re.search(r"^Requires-Python: >=3\.10\s*$", metadata, re.MULTILINE):
        problems.append(f"{name}: metadata Requires-Python is not >=3.10")
    if not re.search(r"^License-Expression: Apache-2\.0\s*$", metadata, re.MULTILINE):
        problems.append(f"{name}: metadata License-Expression is not Apache-2.0")
    return problems


def check(dist: Path) -> list[str]:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    problems: list[str] = []
    if len(wheels) != 1 or len(sdists) != 1:
        return [f"expected exactly one wheel and one sdist in {dist}, found {[p.name for p in wheels + sdists]}"]
    problems += wheel_problems(wheels[0])
    problems += sdist_problems(sdists[0])
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_dist.py <dist-dir>", file=sys.stderr)
        return 2
    problems = check(Path(argv[1]))
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        print("dist OK: only the package, py.typed, page-scan.js, LICENSE, README and metadata")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
