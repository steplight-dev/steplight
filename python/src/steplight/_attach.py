"""Hooks a Playwright page (sync or async API) up to a :class:`RecorderCore`.

The same handlers serve both APIs: they are plain callables that capture data and return at once, wrapped so
that an error is logged and never raised into the agent. Only the setup calls differ (``await`` or not).
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from importlib import resources
from typing import Any
from weakref import WeakKeyDictionary

from ._log import log_error
from .recorder import BINDING_NAME, RecorderCore

_script_cache: str | None = None


def page_script() -> str:
    """The shared page script (``spec/page-scan.js``), bundled as package data."""
    global _script_cache
    if _script_cache is None:
        _script_cache = resources.files("steplight").joinpath("_data/page-scan.js").read_text(encoding="utf-8")
    return _script_cache


class _Dispatcher:
    """The one binding a page can have: a page can be recorded again after a run ended, but a binding cannot be exposed twice."""

    def __init__(self) -> None:
        self.current: Attachment | None = None

    def __call__(self, source: Any, event: Any) -> None:
        target = self.current
        if target is not None:
            target.binding(source, event)


_dispatchers: WeakKeyDictionary[Any, _Dispatcher] = WeakKeyDictionary()


def _safe(where: str, fn: Callable[..., None]) -> Callable[..., None]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
        except Exception as err:
            log_error(where, err)

    return wrapper


class Attachment:
    """The listeners installed on one page, so they can be removed again."""

    def __init__(self, page: Any, core: RecorderCore) -> None:
        self.page = page
        self.core = core
        self.listeners: list[tuple[str, Callable[..., None]]] = []
        self.requests: dict[int, Any] = {}

    # -- handlers (all fail open) ------------------------------------------------------------

    def binding(self, source: Any, event: Any) -> None:
        try:
            frame = source["frame"] if not hasattr(source, "frame") else source.frame
            if frame is not self.page.main_frame or not isinstance(event, dict):
                return
            if event.get("type") == "scan":
                self.core.scan(event)
            else:
                self.core.page_event(event, self.page.url)
        except Exception as err:
            log_error("event", err)

    def _on_framenavigated(self, frame: Any) -> None:
        if frame is self.page.main_frame:
            self.core.navigate(frame.url)

    def _on_request(self, request: Any) -> None:
        body: bytes | None
        try:
            body = request.post_data_buffer
        except Exception:
            body = None
        self.core.request_started(request, request.method, request.url, request.resource_type, body)

    def _on_response(self, response: Any) -> None:
        self.core.request_finished(response.request, response.status, response.headers)

    def _on_request_failed(self, request: Any) -> None:
        self.core.request_finished(request, None, None, str(request.failure or "request failed"))

    def _on_websocket(self, ws: Any) -> None:
        on_frame = self.core.websocket(ws.url)
        ws.on("framesent", _safe("websocket", on_frame))

    def _on_download(self, download: Any) -> None:
        self.core.download(download.url, download.suggested_filename)

    def _on_crash(self, *_: Any) -> None:
        self.core.crashed()

    def _listen(self) -> None:
        for event, handler in (
            ("framenavigated", self._on_framenavigated),
            ("request", self._on_request),
            ("response", self._on_response),
            ("requestfailed", self._on_request_failed),
            ("websocket", self._on_websocket),
            ("download", self._on_download),
            ("crash", self._on_crash),
        ):
            safe = _safe(event, handler)
            self.listeners.append((event, safe))
            self.page.on(event, safe)

    def _initial_page(self) -> bool:
        url = self.page.url
        if url and url != "about:blank":
            self.core.navigate(url)
            return True
        return False

    # -- setup -------------------------------------------------------------------------------

    def _dispatcher(self) -> tuple[_Dispatcher, bool]:
        existing = _dispatchers.get(self.page)
        if existing is not None:
            return existing, False
        fresh = _Dispatcher()
        _dispatchers[self.page] = fresh
        return fresh, True

    async def attach_async(self) -> None:
        dispatcher, first = self._dispatcher()
        if first:
            await self.page.expose_binding(BINDING_NAME, dispatcher)
            await self.page.add_init_script(script=page_script())
        dispatcher.current = self
        self._listen()
        if self._initial_page():
            try:
                await self.page.evaluate(page_script())
            except Exception as err:
                log_error("initial scan", err)

    def attach_sync(self) -> None:
        dispatcher, first = self._dispatcher()
        if first:
            self.page.expose_binding(BINDING_NAME, dispatcher)
            self.page.add_init_script(script=page_script())
        dispatcher.current = self
        self._listen()
        if self._initial_page():
            try:
                self.page.evaluate(page_script())
            except Exception as err:
                log_error("initial scan", err)

    def detach(self) -> None:
        dispatcher = _dispatchers.get(self.page)
        if dispatcher is not None and dispatcher.current is self:
            dispatcher.current = None
        for event, handler in self.listeners:
            try:
                self.page.remove_listener(event, handler)
            except Exception:
                pass
        self.listeners.clear()
