"""Capture levels and site rules (port of the relevant parts of ``settings.ts``)."""

from __future__ import annotations

import re
from typing import Literal, get_args
from urllib.parse import urlsplit

CaptureLevel = Literal["minimal", "standard", "full"]
"""How much to write to disk. ``minimal``: URLs without query strings, step kinds and flags only.
``standard`` (default): also redacted page text and request metadata, no request bodies.
``full``: also redacted request body previews."""

CAPTURE_LEVELS: tuple[CaptureLevel, ...] = get_args(CaptureLevel)

_DOMAIN = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*")
_MAX_LIST = 200


def normalize_domain_list(raw: object) -> list[str]:
    """Clean a list of domain entries: lowercase, trim, drop invalid and duplicate entries."""
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        d = re.sub(r"[/:?#].*$", "", re.sub(r"^https?://", "", item.strip().lower()))
        if not d or len(d) > 253 or not _DOMAIN.fullmatch(d) or d in out:
            continue
        out.append(d)
        if len(out) >= _MAX_LIST:
            break
    return out


def domain_matches(entry: str, host: str) -> bool:
    """Does a domain entry (``example.com`` or ``*.example.com``) cover this host?"""
    h = host.lower()
    if entry.startswith("*."):
        base = entry[2:]
        return h == base or h.endswith(f".{base}")
    return h == entry or h.endswith(f".{entry}")


def recording_blocked_reason(
    url: str | None, allowlist: tuple[str, ...] | list[str], denylist: tuple[str, ...] | list[str]
) -> str | None:
    """Why a URL may not be recorded, or None when recording is allowed."""
    try:
        parts = urlsplit(url or "")
        if parts.scheme not in ("http", "https"):
            return None
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    if any(domain_matches(e, host) for e in denylist):
        return "Recording paused on this site (deny list)"
    if allowlist and not any(domain_matches(e, host) for e in allowlist):
        return "Recording paused on this site (not on your allow list)"
    return None
