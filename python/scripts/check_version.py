"""Release gate: a git tag must match the version of the Python package (PEP 440 form).

    python scripts/check_version.py v0.2.0-rc.1     # needs python/pyproject.toml to say 0.2.0rc1

Tag form (the one the npm packages use) -> PEP 440: ``v0.2.0`` -> ``0.2.0``, ``v0.2.0-rc.1`` -> ``0.2.0rc1``,
``-beta.N`` -> ``bN``, ``-alpha.N`` -> ``aN``. Anything else is refused. The version in
``src/steplight/__init__.py`` must say the same. Standard library only (runs on any Python 3.9+).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TAG = re.compile(r"v(?P<base>\d+\.\d+\.\d+)(?:-(?P<kind>alpha|beta|rc)\.(?P<n>\d+))?")
SHORT = {"alpha": "a", "beta": "b", "rc": "rc"}
ROOT = Path(__file__).resolve().parent.parent


def pep440(tag: str) -> str:
    """The PEP 440 version for a release tag; raises ``ValueError`` for a tag that is not a release."""
    match = TAG.fullmatch(tag)
    if match is None:
        raise ValueError(f"{tag!r} is not a release tag like v0.2.0 or v0.2.0-rc.1")
    pre = f"{SHORT[match['kind']]}{match['n']}" if match["kind"] else ""
    return f"{match['base']}{pre}"


def declared_versions(root: Path = ROOT) -> dict[str, str]:
    """The version written in pyproject.toml and in the package."""
    pyproject = re.search(
        r'^version\s*=\s*"([^"]+)"', (root / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE
    )
    package = re.search(
        r'^__version__\s*=\s*"([^"]+)"',
        (root / "src" / "steplight" / "__init__.py").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    return {
        "pyproject.toml": pyproject.group(1) if pyproject else "",
        "steplight/__init__.py": package.group(1) if package else "",
    }


def check(tag: str, root: Path = ROOT) -> list[str]:
    """Problems found (empty when the tag matches)."""
    try:
        expected = pep440(tag)
    except ValueError as err:
        return [str(err)]
    return [
        f"{where} says {found!r} but tag {tag} means {expected!r}"
        for where, found in declared_versions(root).items()
        if found != expected
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_version.py <tag>", file=sys.stderr)
        return 2
    problems = check(argv[1])
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        print(f"python version OK: {argv[1]} == {pep440(argv[1])}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
