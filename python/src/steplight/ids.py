"""Run and step ids (port of ``ids.ts``)."""

from __future__ import annotations

import re
import secrets
import time

_SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")


def new_run_id(now: float | None = None) -> str:
    """A sortable, filesystem-safe run id such as ``20261008-101500-a1b2c3`` (local time)."""
    t = time.localtime(now if now is not None else time.time())
    return f"{time.strftime('%Y%m%d-%H%M%S', t)}-{secrets.token_hex(3)}"


def new_step_id(index: int) -> str:
    """A step id unique within a run, such as ``s0007-9f3a``."""
    return f"s{index:04d}-{secrets.token_hex(2)}"


def is_safe_id(value: str) -> bool:
    """True when the id is safe to use as a folder name (letters, digits, ``-`` and ``_``)."""
    return _SAFE_ID.fullmatch(value) is not None
