"""Record a Browser Use agent: the browser steps *and* what the model decided.

Browser Use drives Chrome directly over the Chrome DevTools Protocol (it has no Playwright page since 0.6), so
this adapter does two things, both through public hooks:

1. **Browser side.** Once Browser Use has started its browser, Steplight connects Playwright to the *same*
   browser with ``connect_over_cdp`` and records every tab from there, exactly as it records a Playwright page.
2. **Agent side.** Through Browser Use's ``register_new_step_callback`` (called after the model has answered and
   before its actions run) every step becomes an ``agent_note`` step: the model's next goal and chosen actions,
   plus its reasoning when it gave any. Browser steps that follow carry ``decidedBy``, the id of that note: the
   first piece of a decision trace.

Supported: ``browser-use >= 0.7, < 0.14`` (the test-suite passes on 0.7.12, 0.9.7, 0.12.x and 0.13.11; 0.6 and older do not work). The adapter touches only ``agent.browser_session
.cdp_url``, ``agent.register_new_step_callback`` / ``register_done_callback`` and the callback's arguments. If a
future version changes those, it warns on stderr and records whatever it still can; it never raises into the agent.

Typed text is never copied into a note: string parameters of actions (what the model types) are replaced by their
length, except for URLs and search queries.

Example:
    >>> agent = Agent(task="Book the cheapest flight", llm=llm)  # doctest: +SKIP
    >>> async with steplight.integrations.browser_use.recording(agent) as run:  # doctest: +SKIP
    ...     await agent.run()
"""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from .._attach import ContextAttachment
from .._log import log_error
from ..handles import Run, Status
from ..recorder import RecorderCore, RecordOptions, prepare
from ..settings import CaptureLevel

SUPPORTED_RANGE = ">=0.7,<0.14"

_SAFE_STRING_PARAMS = frozenset({"url", "query", "direction", "tab_id", "file_name", "path", "title", "goal"})
_NOTE_LIMIT = 280


def _warn(what: str) -> None:
    log_error(
        "browser-use", f"{what}; Steplight keeps recording what it can (supported: browser-use {SUPPORTED_RANGE})"
    )


def describe_action(action: Any) -> str:
    """``click(index=3)``-style text for one Browser Use action; strings the model typed are replaced by their length."""
    try:
        data = (
            action.model_dump(exclude_unset=True, exclude_none=True) if hasattr(action, "model_dump") else dict(action)
        )
    except Exception:
        return "action"
    parts = []
    for name, params in data.items():
        if isinstance(params, dict):
            shown = []
            for key, value in params.items():
                if isinstance(value, str) and key not in _SAFE_STRING_PARAMS:
                    shown.append(f"{key}=<{len(value)} chars>")
                elif isinstance(value, (str, int, float, bool)):
                    shown.append(f"{key}={value}")
            parts.append(f"{name}({', '.join(shown)})")
        else:
            parts.append(str(name))
    return "; ".join(parts) or "action"


def _text(value: Any) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


class BrowserUseRun(Run):
    """The run handle for a Browser Use agent. ``note`` and ``report_error`` work as for a Playwright page."""

    def __init__(self, core: RecorderCore | None, attachment: ContextAttachment | None, otel: bool, root: str) -> None:
        super().__init__(core, attachment, otel, root)
        self._context_attachment = attachment
        self._playwright: Any = None
        self._browser: Any = None
        self._connect_lock = asyncio.Lock()
        self._connect_failed = False
        self.agent: Any = None

    async def connect(self, cdp_url: str) -> bool:
        """Connect Playwright to the agent's browser (once). Returns True when pages are being recorded."""
        if self._core is None or self._context_attachment is None:
            return False
        async with self._connect_lock:
            if self._browser is not None:
                return True
            if self._connect_failed:
                return False
            try:
                from playwright.async_api import async_playwright

                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.connect_over_cdp(cdp_url)
                if not self._browser.contexts:
                    raise RuntimeError("the browser has no default context")
                await self._context_attachment.attach_to(self._browser.contexts[0], self._core)
                return True
            except Exception as err:
                self._connect_failed = True
                _warn(f"could not attach to the browser at {cdp_url}: {err}")
                await self._disconnect()
                return False

    async def _disconnect(self) -> None:
        browser, playwright = self._browser, self._playwright
        self._browser = self._playwright = None
        try:
            if browser is not None:
                await browser.close()  # a CDP connection: this disconnects, it does not close Chrome
        except Exception:
            pass
        try:
            if playwright is not None:
                await playwright.stop()
        except Exception:
            pass

    async def end(self, status: Status = "success") -> dict[str, Any]:
        result = await super().end(status)
        await self._disconnect()
        return result


def _cdp_url(agent: Any) -> str | None:
    session = getattr(agent, "browser_session", None)
    url = getattr(session, "cdp_url", None)
    return url if isinstance(url, str) and url else None


def _final_status(history: Any) -> Status:
    try:
        return "success" if history.is_successful() is not False else "failed"
    except Exception:
        return "success"


async def record(
    agent: Any,
    task: str | None = None,
    *,
    dir: str | os.PathLike[str] | None = None,
    capture_level: CaptureLevel = "standard",
    meta: dict[str, str] | None = None,
    otel: bool | None = None,
    encrypt: bool = False,
    encryption_key: bytes | str | None = None,
    passphrase: str | None = None,
    auto_end: bool = True,
) -> BrowserUseRun:
    """Start recording a Browser Use ``Agent`` before ``agent.run()``.

    Args:
        agent: the ``browser_use.Agent``.
        task: the run title (default: the agent's own task).
        auto_end: end the run when the agent finishes (its done callback); you can still call ``await run.end()``.
        Other arguments: as for :func:`steplight.record`.

    Never raises: when nothing can be recorded the agent still runs and you get a handle that does nothing.
    """
    title = task if task is not None else str(getattr(agent, "task", "Browser Use agent"))
    run_meta = {**(meta or {}), "agent": "browser-use"}
    options = RecordOptions(
        task=title,
        dir=dir,
        capture_level=capture_level,
        meta=run_meta,
        otel=otel,
        encrypt=encrypt,
        encryption_key=encryption_key,
        passphrase=passphrase,
    )
    root = str(dir) if dir is not None else os.environ.get("STEPLIGHT_DIR") or os.path.join(".steplight", "runs")
    try:
        setup = await asyncio.get_running_loop().run_in_executor(None, prepare, options)
        if setup is None:
            return BrowserUseRun(None, None, False, root)
        attachment = ContextAttachment(None)
        core = RecorderCore(setup.writer, options, setup.level, setup.policy, attachment.url)
        run = BrowserUseRun(core, attachment, setup.otel, root)
        run.agent = agent
        _hook_agent(agent, run, core, auto_end)
        url = _cdp_url(agent)
        if url:  # the browser is already running
            await run.connect(url)
        return run
    except Exception as err:
        log_error("record", err)
        return BrowserUseRun(None, None, False, root)


def _hook_agent(agent: Any, run: BrowserUseRun, core: RecorderCore, auto_end: bool) -> None:
    previous_step = getattr(agent, "register_new_step_callback", None)
    previous_done = getattr(agent, "register_done_callback", None)
    if not hasattr(agent, "register_new_step_callback"):
        _warn("this Agent has no register_new_step_callback, so the model's decisions cannot be recorded")

    async def call_previous(fn: Any, *args: Any) -> None:
        if fn is None:
            return
        result = fn(*args)
        if inspect.isawaitable(result):
            await result

    async def on_step(state: Any, output: Any, step_number: int) -> None:
        try:
            if not run._connect_failed and run._browser is None:
                url = _cdp_url(agent)
                if url:
                    await run.connect(url)
                else:
                    _warn("the agent's browser has no cdp_url yet")
            _record_decision(core, agent, output, step_number)
        except Exception as err:
            log_error("browser-use step", err)
        await call_previous(previous_step, state, output, step_number)

    async def on_done(history: Any) -> None:
        try:
            core.set_decision(None)
            final = getattr(history, "final_result", None)
            text = _text(final()) if callable(final) else ""
            run.note(f"Agent finished: {text}" if text else "Agent finished")
            if auto_end:
                await run.end(_final_status(history))
        except Exception as err:
            log_error("browser-use done", err)
        await call_previous(previous_done, history)

    try:
        agent.register_new_step_callback = on_step
        agent.register_done_callback = on_done
    except Exception as err:
        _warn(f"could not install the step callbacks ({err})")


def _record_decision(core: RecorderCore, agent: Any, output: Any, step_number: int) -> None:
    """One ``agent_note`` for the model's goal and actions (plus one for its reasoning); later browser steps point back at it."""
    core.set_decision(None)
    _record_previous_errors(core, agent)
    goal = _text(getattr(output, "next_goal", None))
    actions = "; ".join(describe_action(a) for a in (getattr(output, "action", None) or []))
    note = f"Step {step_number}: {goal} -> {actions}" if goal else f"Step {step_number}: {actions}"
    note_id = core.note(note[:_NOTE_LIMIT])
    thinking = _text(getattr(output, "thinking", None)) or _text(getattr(output, "evaluation_previous_goal", None))
    if thinking:
        core.note(f"Reasoning (step {step_number}): {thinking}"[:_NOTE_LIMIT])
    core.set_decision(note_id)


def _record_previous_errors(core: RecorderCore, agent: Any) -> None:
    try:
        results = getattr(getattr(agent, "state", None), "last_result", None) or []
        for result in results:
            error = getattr(result, "error", None)
            if error:
                core.report_error(_text(str(error))[:300] or "action failed")
    except Exception as err:
        log_error("browser-use errors", err)


@asynccontextmanager
async def recording(agent: Any, task: str | None = None, **kwargs: Any) -> AsyncIterator[BrowserUseRun]:
    """``async with recording(agent) as run: await agent.run()`` - ends the run (``failed`` if the block raises)."""
    run = await record(agent, task, **kwargs)
    try:
        yield run
    except BaseException:
        await run.end("failed")
        raise
    else:
        await run.end("success")
