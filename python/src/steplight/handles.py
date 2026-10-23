"""The objects :func:`steplight.record` returns, and the entry points for Playwright's async and sync APIs."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Literal

from ._attach import Attachment, ContextAttachment
from ._log import log_error
from .recorder import RecorderCore, RecordOptions, prepare
from .settings import CaptureLevel

Status = Literal["success", "failed"]


class _Handle:
    """What both run handles share. Nothing here ever raises into the agent."""

    def __init__(
        self, core: RecorderCore | None, attachment: Attachment | ContextAttachment | None, otel: bool, root: str
    ) -> None:
        self._core = core
        self._attachment = attachment
        self._otel = otel
        self._root = root
        self._result: dict[str, Any] | None = None

    @property
    def id(self) -> str:
        """The run id (also the folder name); empty when nothing is being recorded."""
        return self._core.run_id if self._core else ""

    @property
    def dir(self) -> str:
        """The run folder (or the runs folder when nothing is being recorded)."""
        return str(self._core.writer.dir) if self._core else self._root

    @property
    def recording(self) -> bool:
        """False when policy or an error means nothing is being recorded (the agent is not affected)."""
        return self._core is not None

    @property
    def core(self) -> RecorderCore | None:
        """The engine-independent recorder (used by integrations)."""
        return self._core

    def note(self, text: str) -> str | None:
        """Record a note about the agent's reasoning (an ``agent_note`` step). Returns the step id."""
        try:
            return self._core.note(text) if self._core else None
        except Exception as err:
            log_error("note", err)
            return None

    def report_error(self, error: BaseException | str, selector: str | None = None) -> None:
        """Record a failure the recorder could not see itself (for example from a Locator action) as an ``error`` step."""
        try:
            if self._core:
                self._core.report_error(error, selector)
        except Exception as err:
            log_error("report_error", err)

    def _finish(self, status: str) -> dict[str, Any]:
        if self._result is not None:
            return self._result
        empty: dict[str, Any] = {"id": "", "task": "", "startedAt": 0, "status": "failed", "steps": [], "meta": {}}
        if self._core is None:
            self._result = empty
            return empty
        if self._attachment:
            self._attachment.detach()
        try:
            run = self._core.finish(status)
        except Exception as err:
            log_error("finish", err)
            run = empty
        if self._otel:
            from .otel import export_run_otlp

            export_run_otlp(run)
        self._result = run
        return run


class Run(_Handle):
    """Handle for an in-progress recording of an async Playwright page. ``note`` is plain; ``end`` is awaited."""

    async def end(self, status: Status = "success") -> dict[str, Any]:
        """Finish the run, flush everything to disk and optionally export OpenTelemetry spans. Returns the run as a dict."""
        return await asyncio.get_running_loop().run_in_executor(None, self._finish, status)

    async def __aenter__(self) -> Run:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.end("failed" if exc_type else "success")


class SyncRun(_Handle):
    """Handle for an in-progress recording of a sync Playwright page."""

    def end(self, status: Status = "success") -> dict[str, Any]:
        """Finish the run, flush everything to disk and optionally export OpenTelemetry spans. Returns the run as a dict."""
        return self._finish(status)

    def __enter__(self) -> SyncRun:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.end("failed" if exc_type else "success")


def _options(task: str, dir: str | os.PathLike[str] | None, capture_level: CaptureLevel, **rest: Any) -> RecordOptions:
    return RecordOptions(task=task, dir=dir, capture_level=capture_level, **rest)


def _root(options: RecordOptions) -> str:
    return (
        str(options.dir)
        if options.dir is not None
        else os.environ.get("STEPLIGHT_DIR") or os.path.join(".steplight", "runs")
    )


async def record(
    page: Any,
    task: str,
    *,
    dir: str | os.PathLike[str] | None = None,
    capture_level: CaptureLevel = "standard",
    meta: dict[str, str] | None = None,
    otel: bool | None = None,
    encrypt: bool = False,
    encryption_key: bytes | str | None = None,
    passphrase: str | None = None,
) -> Run:
    """Start recording an async Playwright page (``playwright.async_api``).

    Hooks navigation, requests, clicks, field changes and form submits, snapshots every page load and writes the
    run to ``dir`` (default ``$STEPLIGHT_DIR`` or ``.steplight/runs``). Recording never raises into the agent:
    internal errors go to stderr, and if policy or an error means nothing may be recorded you get a handle that
    does nothing (``run.recording`` is False).

    Args:
        page: the Playwright page.
        task: what the agent is trying to do.
        capture_level: ``"minimal"``, ``"standard"`` (default) or ``"full"``; see :data:`steplight.CaptureLevel`.
        encrypt: require encryption at rest (key from ``encryption_key``, ``passphrase`` or the environment).
        otel: send the run to ``OTEL_EXPORTER_OTLP_ENDPOINT`` on ``end()`` (default: only if that variable is set).

    Example:
        >>> run = await steplight.record(page, task="Book the cheapest flight")  # doctest: +SKIP
        >>> run.note("model chose Premium")  # doctest: +SKIP
        >>> await run.end("success")  # doctest: +SKIP
    """
    options = _options(
        task,
        dir,
        capture_level,
        meta=meta,
        otel=otel,
        encrypt=encrypt,
        encryption_key=encryption_key,
        passphrase=passphrase,
    )
    try:
        setup = await asyncio.get_running_loop().run_in_executor(None, prepare, options)
        if setup is None:
            return Run(None, None, False, _root(options))
        core = RecorderCore(setup.writer, options, setup.level, setup.policy, lambda: _page_url(page))
        attachment = Attachment(page, core)
        await attachment.attach_async()
        return Run(core, attachment, setup.otel, _root(options))
    except Exception as err:
        log_error("record", err)
        return Run(None, None, False, _root(options))


def record_sync(
    page: Any,
    task: str,
    *,
    dir: str | os.PathLike[str] | None = None,
    capture_level: CaptureLevel = "standard",
    meta: dict[str, str] | None = None,
    otel: bool | None = None,
    encrypt: bool = False,
    encryption_key: bytes | str | None = None,
    passphrase: str | None = None,
) -> SyncRun:
    """Start recording a sync Playwright page (``playwright.sync_api``). Same arguments as :func:`record`."""
    options = _options(
        task,
        dir,
        capture_level,
        meta=meta,
        otel=otel,
        encrypt=encrypt,
        encryption_key=encryption_key,
        passphrase=passphrase,
    )
    try:
        setup = prepare(options)
        if setup is None:
            return SyncRun(None, None, False, _root(options))
        core = RecorderCore(setup.writer, options, setup.level, setup.policy, lambda: _page_url(page))
        attachment = Attachment(page, core)
        attachment.attach_sync()
        return SyncRun(core, attachment, setup.otel, _root(options))
    except Exception as err:
        log_error("record", err)
        return SyncRun(None, None, False, _root(options))


def _page_url(page: Any) -> str:
    try:
        return str(page.url)
    except Exception:
        return ""


@asynccontextmanager
async def recording(page: Any, task: str, **kwargs: Any) -> AsyncIterator[Run]:
    """``async with steplight.recording(page, task=...) as run:`` ends the run as ``success``, or ``failed`` if the block raises."""
    run = await record(page, task, **kwargs)
    try:
        yield run
    except BaseException:
        await run.end("failed")
        raise
    else:
        await run.end("success")


@contextmanager
def recording_sync(page: Any, task: str, **kwargs: Any) -> Iterator[SyncRun]:
    """``with steplight.recording_sync(page, task=...) as run:`` ends the run as ``success``, or ``failed`` if the block raises."""
    run = record_sync(page, task, **kwargs)
    try:
        yield run
    except BaseException:
        run.end("failed")
        raise
    else:
        run.end("success")
