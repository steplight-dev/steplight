"""The same API for ``playwright.sync_api``: ``from steplight.sync_api import record, recording``."""

from __future__ import annotations

from .handles import SyncRun
from .handles import record_sync as record
from .handles import recording_sync as recording

__all__ = ["SyncRun", "record", "recording"]
