"""Response-header allow-list (port of the relevant part of ``network.ts``)."""

from __future__ import annotations

import re
from collections.abc import Mapping

ALLOWED_HEADERS: tuple[str, ...] = ("content-type", "content-length")
"""The only response headers Steplight ever keeps. Everything else is dropped unseen."""

# Never kept, even if someone adds them to the allow-list by mistake.
_NEVER_KEEP = re.compile(
    r"authori[sz]ation|cookie|token|auth|key|secret|session|password|credential|signature|bearer", re.IGNORECASE
)


def pick_headers(headers: Mapping[str, str] | None) -> dict[str, str | int]:
    """Keep only ``content-type`` and ``content-length``.

    Authorization, Cookie, Set-Cookie, X-API-Key and anything whose name contains token / auth / key / secret /
    session is never returned, whatever the input.
    """
    out: dict[str, str | int] = {}
    for raw_name, value in (headers or {}).items():
        name = raw_name.lower()
        if _NEVER_KEEP.search(name) or name not in ALLOWED_HEADERS or value is None:
            continue
        if name == "content-type":
            out["contentType"] = value.split(";")[0].strip()[:100].lower()
        else:
            try:
                n = float(value)
            except ValueError:
                continue
            if 0 <= n < float("inf"):
                out["contentLength"] = int(n)
    return out
