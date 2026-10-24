"""Steplight: record and replay what an AI browser agent does.

Records Playwright (async and sync) and Browser Use runs in the Steplight run format, so the ``steplight`` CLI
(``view``, ``check``, ``diff``, ``report``, ``analyze``) and the GitHub Action work on them unchanged. Everything is
redacted before it is written; nothing leaves the machine.

>>> run = await steplight.record(page, task="Book the cheapest flight")  # doctest: +SKIP
>>> run.note("model chose Premium")  # doctest: +SKIP
>>> await run.end("success")  # doctest: +SKIP
"""

from __future__ import annotations

__version__ = "0.2.0"

from .analyze import analyze
from .crypto import EncryptedRunError, EncryptionOptions
from .handles import Run, SyncRun, record, record_sync, recording, recording_sync
from .redact import redact_text
from .settings import CaptureLevel
from .store import read_run, read_snapshot

__all__ = [
    "CaptureLevel",
    "EncryptedRunError",
    "EncryptionOptions",
    "Run",
    "SyncRun",
    "__version__",
    "analyze",
    "read_run",
    "read_snapshot",
    "record",
    "record_sync",
    "recording",
    "recording_sync",
    "redact_text",
]
