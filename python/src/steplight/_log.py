"""Logging for a library that must never disturb the program it watches: one line on stderr, nothing raised."""

from __future__ import annotations

import sys


def log_error(where: str, err: object) -> None:
    """Write ``[steplight] <where>: <message>`` to stderr. Never raises."""
    try:
        message = str(err) if not isinstance(err, BaseException) else (str(err) or type(err).__name__)
        sys.stderr.write(f"[steplight] {where}: {message}\n")
    except Exception:
        pass
