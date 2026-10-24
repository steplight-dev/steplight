"""Organisation policy for the SDK (port of ``policy.ts`` and ``storage/policyFiles.ts``).

A policy can only make Steplight MORE restrictive. It comes from an organisation policy file
(``$STEPLIGHT_POLICY_FILE``), a ``steplight.config.json`` and ``STEPLIGHT_*`` environment variables, merged so
the result is never looser than any of them. An unreadable policy file is an error, never "no restrictions".
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .custom_patterns import validate_pattern
from .settings import CAPTURE_LEVELS, normalize_domain_list

POLICY_KEYS = (
    "maxCaptureLevel",
    "forceRedactionPatterns",
    "siteAllowlist",
    "siteDenylist",
    "retentionDays",
    "disableExport",
    "disableCliConnection",
    "disableDeepCapture",
    "requireEncryption",
)
_BOOLEAN_KEYS = ("disableExport", "disableCliConnection", "disableDeepCapture", "requireEncryption")


@dataclass(frozen=True)
class Policy:
    """Restrictions an administrator enforces; every field is optional."""

    max_capture_level: str | None = None
    force_redaction_patterns: tuple[str, ...] = ()
    site_allowlist: tuple[str, ...] = ()
    site_denylist: tuple[str, ...] = ()
    retention_days: int | None = None
    disable_export: bool = False
    disable_cli_connection: bool = False
    disable_deep_capture: bool = False
    require_encryption: bool = False

    def is_empty(self) -> bool:
        """True when no restriction is in force."""
        return self == Policy()


@dataclass
class PolicyProblem:
    """What :func:`normalize_policy` could not accept."""

    key: str
    reason: str


@dataclass
class LoadedPolicy:
    """A policy plus where it came from."""

    policy: Policy
    sources: list[str] = field(default_factory=list)
    problems: list[PolicyProblem] = field(default_factory=list)


def _snake(key: str) -> str:
    return re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), key)


def normalize_policy(raw: object, problems: list[PolicyProblem] | None = None) -> Policy:
    """Turn untrusted policy data into a valid :class:`Policy`. Never raises."""
    problems = problems if problems is not None else []
    if not isinstance(raw, dict):
        return Policy()
    fields: dict[str, Any] = {}

    def bad(key: str, reason: str) -> None:
        problems.append(PolicyProblem(key, reason))

    for key in raw:
        if key not in POLICY_KEYS:
            bad(str(key), "unknown policy key")
    level = raw.get("maxCaptureLevel")
    if level is not None:
        if level in CAPTURE_LEVELS:
            fields["max_capture_level"] = str(level)
        else:
            bad("maxCaptureLevel", "must be minimal, standard or full")
    for key, attr in (("siteAllowlist", "site_allowlist"), ("siteDenylist", "site_denylist")):
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, list):
            bad(key, "must be a list of domains")
            continue
        clean = normalize_domain_list(value)
        if len(clean) < len(value):
            bad(key, "some entries were not valid domains and were ignored")
        if clean:
            fields[attr] = tuple(clean)
    patterns = raw.get("forceRedactionPatterns")
    if patterns is not None:
        if not isinstance(patterns, list):
            bad("forceRedactionPatterns", "must be a list of regular expressions")
        else:
            ok: list[str] = []
            for p in patterns:
                check = validate_pattern(p)
                if check.ok:
                    ok.append(str(p))
                else:
                    bad("forceRedactionPatterns", f"{str(p)[:40]}: {check.reason}")
            if ok:
                fields["force_redaction_patterns"] = tuple(ok)
    days = raw.get("retentionDays")
    if days is not None:
        if isinstance(days, (int, float)) and not isinstance(days, bool) and 1 <= days <= 3650:
            fields["retention_days"] = round(days)
        else:
            bad("retentionDays", "must be a number of days between 1 and 3650")
    for key in _BOOLEAN_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(value, bool):
            if value:
                fields[_snake(key)] = True
        else:
            bad(key, "must be true or false")
    return Policy(**fields)


def merge_policies(*policies: Policy) -> Policy:
    """Combine policies so the result is at least as strict as each of them.

    Lowest capture level and retention, union of deny lists and patterns, intersection of allow lists, and any
    ``disable`` / ``require`` wins.
    """
    level: str | None = None
    days: int | None = None
    patterns: list[str] = []
    deny: list[str] = []
    allow: list[str] | None = None
    flags: dict[str, bool] = {}
    for p in policies:
        if p.max_capture_level is not None and (
            level is None or CAPTURE_LEVELS.index(p.max_capture_level) < CAPTURE_LEVELS.index(level)
        ):
            level = p.max_capture_level
        if p.retention_days is not None:
            days = p.retention_days if days is None else min(days, p.retention_days)
        patterns = list(dict.fromkeys([*patterns, *p.force_redaction_patterns]))
        deny = list(dict.fromkeys([*deny, *p.site_denylist]))
        if p.site_allowlist:
            allow = list(p.site_allowlist) if allow is None else [d for d in allow if d in p.site_allowlist]
        for key in _BOOLEAN_KEYS:
            if getattr(p, _snake(key)):
                flags[_snake(key)] = True
    return Policy(
        max_capture_level=level,
        force_redaction_patterns=tuple(patterns),
        site_allowlist=tuple(allow or ()),
        site_denylist=tuple(deny),
        retention_days=days,
        **flags,
    )


def policy_from_env(env: Mapping[str, str | None], problems: list[PolicyProblem] | None = None) -> Policy:
    """Policy from ``STEPLIGHT_*`` variables, e.g. ``STEPLIGHT_MAX_CAPTURE_LEVEL=standard`` or ``STEPLIGHT_SITE_DENYLIST=a.com,b.com``."""

    def truthy(v: str | None) -> bool | None:
        return None if not v else re.fullmatch(r"(1|true|yes|on)", v, re.IGNORECASE) is not None

    def items(v: str | None, sep: str) -> list[str] | None:
        return [s.strip() for s in re.split(sep, v) if s.strip()] if v else None

    raw: dict[str, object] = {
        "maxCaptureLevel": env.get("STEPLIGHT_MAX_CAPTURE_LEVEL") or None,
        "forceRedactionPatterns": items(env.get("STEPLIGHT_FORCE_REDACTION_PATTERNS"), r"\r?\n"),
        "siteAllowlist": items(env.get("STEPLIGHT_SITE_ALLOWLIST"), r"[,\s]+"),
        "siteDenylist": items(env.get("STEPLIGHT_SITE_DENYLIST"), r"[,\s]+"),
        "disableExport": truthy(env.get("STEPLIGHT_DISABLE_EXPORT")),
        "disableCliConnection": truthy(env.get("STEPLIGHT_DISABLE_CLI_CONNECTION")),
        "disableDeepCapture": truthy(env.get("STEPLIGHT_DISABLE_DEEP_CAPTURE")),
        "requireEncryption": truthy(env.get("STEPLIGHT_REQUIRE_ENCRYPTION")),
    }
    days = env.get("STEPLIGHT_RETENTION_DAYS")
    if days:
        try:
            raw["retentionDays"] = float(days)
        except ValueError:
            raw["retentionDays"] = days  # rejected by normalize_policy, and reported
    return normalize_policy({k: v for k, v in raw.items() if v is not None}, problems)


def _read_policy_file(file: Path, label: str, problems: list[PolicyProblem]) -> Policy:
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        # A policy that cannot be read must not silently mean "no restrictions".
        raise RuntimeError(f"Cannot read {label} {file}: {err}") from err
    return normalize_policy(raw, problems)


def load_policy(
    *,
    policy_file: str | os.PathLike[str] | None = None,
    config_file: str | os.PathLike[str] | None = None,
    env: Mapping[str, str | None] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> LoadedPolicy:
    """The effective policy: organisation file, ``steplight.config.json`` and ``STEPLIGHT_*`` variables, merged.

    Raises ``RuntimeError`` when a policy file that was asked for cannot be read.
    """
    environ: Mapping[str, str | None] = env if env is not None else os.environ
    base = Path(cwd) if cwd is not None else Path(".")
    problems: list[PolicyProblem] = []
    parts: list[Policy] = []
    sources: list[str] = []
    org = policy_file if policy_file is not None else environ.get("STEPLIGHT_POLICY_FILE")
    if org:
        parts.append(_read_policy_file((base / org).resolve(), "organisation policy", problems))
        sources.append(f"org policy {org}")
    explicit = config_file if config_file is not None else environ.get("STEPLIGHT_CONFIG")
    config = Path(explicit) if explicit else base / "steplight.config.json"
    if explicit or config.exists():
        parts.append(_read_policy_file((base / config).resolve(), "config file", problems))
        sources.append(f"config {config}")
    from_env = policy_from_env(environ, problems)
    if not from_env.is_empty():
        parts.append(from_env)
        sources.append("environment")
    return LoadedPolicy(merge_policies(*parts), sources, problems)
