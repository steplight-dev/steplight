"""The recorder: turns browser events into steps in the Steplight run format.

``RecorderCore`` knows nothing about Playwright. Event handlers (called on the agent's thread or event loop)
only capture plain data and put a job on a queue; one worker thread does the redaction and the file writing, so
the agent is never slowed by it. Every handler is wrapped: an error is logged to stderr and never reaches the
agent. Privacy fails closed (a redaction error drops the data), the agent fails open.

The detectors do not run here. The recorder leaves ``analysis-input.jsonl`` (redacted page scans and request
bodies) next to the run and marks it ``meta.analyzed = false``; ``steplight analyze`` (or any command that reads
the run) turns that into flags. See ``spec/run-format.schema.json``.
"""

from __future__ import annotations

import atexit
import math
import os
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from ._log import log_error
from .crypto import EncryptionOptions, effective_encryption
from .domain import is_cross_site, site_of
from .ids import new_run_id, new_step_id
from .network import pick_headers
from .policy import Policy, load_policy
from .redact import (
    MAX_BODY_PREVIEW,
    MAX_SNAPSHOT_TEXT,
    _prefix_utf16,
    configure_redaction,
    redact_text,
    sanitize_body,
    sanitize_snapshot,
    truncate,
)
from .settings import CAPTURE_LEVELS, CaptureLevel, recording_blocked_reason
from .store import DEFAULT_RUNS_DIR, RunWriter, Step, apply_capture_level, purge_runs

BINDING_NAME = "__steplightEmit"
MAX_NODES = 1500
MAX_NODE_TEXT = 20_000
MAX_NETWORK_STEPS = 500
MAX_WEBSOCKET_FRAMES = 200
FLUSH_TIMEOUT_S = 30.0

_NODE_STRINGS = ("display", "visibility", "color", "backgroundColor")
_NODE_NUMBERS = ("opacity", "fontSizePx")


@dataclass
class RecordOptions:
    """Everything :func:`steplight.record` accepts, after defaults."""

    task: str
    dir: str | os.PathLike[str] | None = None
    capture_level: CaptureLevel = "standard"
    meta: dict[str, str] | None = None
    otel: bool | None = None
    encrypt: bool = False
    encryption_key: bytes | str | None = None
    passphrase: str | None = None
    sdk: str = "python"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def _clip(text: Any, units: int) -> str:
    return _prefix_utf16(str(text), units)


def sanitize_scan(scan: Any) -> dict[str, Any] | None:
    """Validate and redact a page scan from the page script. The page is hostile, so only known fields of the right type survive."""
    if not isinstance(scan, dict):
        return None
    dom = scan.get("dom")
    nodes_in = dom.get("nodes") if isinstance(dom, dict) else None
    if not isinstance(nodes_in, list) or not isinstance(scan.get("text"), str) or not isinstance(scan.get("url"), str):
        return None
    url = redact_text(_clip(scan["url"], 4096))
    nodes: list[dict[str, Any]] = []
    for raw in nodes_in[:MAX_NODES]:
        if not isinstance(raw, dict) or not isinstance(raw.get("text"), str):
            continue
        node: dict[str, Any] = {"text": redact_text(truncate(raw["text"], MAX_NODE_TEXT))}
        for key in _NODE_STRINGS:
            if isinstance(raw.get(key), str):
                node[key] = raw[key][:200]
        for key in _NODE_NUMBERS:
            number = _finite(raw.get(key))
            if number is not None:
                node[key] = number
        for key in ("ariaHidden", "hiddenAttr"):
            if isinstance(raw.get(key), bool):
                node[key] = raw[key]
        if raw.get("source") in ("text", "comment", "attribute"):
            node["source"] = raw["source"]
        if raw.get("landmark") in ("nav", "footer", "aside", "cookie", "ads"):
            node["landmark"] = raw["landmark"]
        rect = raw.get("rect")
        if isinstance(rect, dict):
            parts = [_finite(rect.get(k)) for k in ("x", "y", "width", "height")]
            if all(p is not None for p in parts):
                node["rect"] = dict(zip(("x", "y", "width", "height"), parts, strict=True))
        nodes.append(node)
    title = redact_text(_clip(scan.get("title") if isinstance(scan.get("title"), str) else "", 1000))
    return {
        "url": url,
        "title": title,
        "text": sanitize_snapshot(scan["text"]),
        "dom": {"url": url, "nodes": nodes},
    }


class _Worker:
    """One daemon thread that runs jobs in order. A failing job is logged and skipped."""

    def __init__(self) -> None:
        self._queue: queue.SimpleQueue[Callable[[], None] | None] = queue.SimpleQueue()
        self._idle = threading.Event()
        self._idle.set()
        self._pending = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="steplight-writer", daemon=True)
        self._thread.start()

    def submit(self, where: str, job: Callable[[], None]) -> None:
        def guarded() -> None:
            try:
                job()
            except Exception as err:
                log_error(where, err)

        with self._lock:
            self._pending += 1
            self._idle.clear()
        self._queue.put(guarded)

    def _run(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            try:
                job()
            finally:
                with self._lock:
                    self._pending -= 1
                    if self._pending == 0:
                        self._idle.set()

    def flush(self, timeout: float = FLUSH_TIMEOUT_S) -> bool:
        return self._idle.wait(timeout)

    def stop(self) -> None:
        self._queue.put(None)


class RecorderCore:
    """Engine-independent recorder state. Safe to call from any thread."""

    def __init__(
        self,
        writer: RunWriter,
        options: RecordOptions,
        level: CaptureLevel,
        policy: Policy,
        get_url: Callable[[], str],
    ) -> None:
        self.writer = writer
        self.options = options
        self.level = level
        self.policy = policy
        self.get_url = get_url
        self.run_id: str = writer.run["id"]
        self.started_at: int = writer.run["startedAt"]
        self.steps: list[Step] = []
        self.ended = False
        self._worker = _Worker()
        self._lock = threading.Lock()
        self._seq = 0
        self._decision: str | None = None
        self._last_nav: str | None = None
        self._pending_requests: dict[Any, dict[str, Any]] = {}
        self._network_steps = 0
        self._bucket = 200.0
        self._bucket_at = time.monotonic()
        atexit.register(self._at_exit)

    # ------------------------------------------------------------------ helpers

    def _at_exit(self) -> None:
        # A recording the program forgot to end keeps what it has (status stays "running").
        if not self.ended:
            self._worker.flush(5.0)

    def _allow_event(self) -> bool:
        """A hostile page can forge events through the binding: at most ~100 per second (burst 200)."""
        with self._lock:
            now = time.monotonic()
            self._bucket = min(200.0, self._bucket + (now - self._bucket_at) * 100.0)
            self._bucket_at = now
            if self._bucket < 1.0:
                return False
            self._bucket -= 1.0
            return True

    def _next_id(self) -> str:
        with self._lock:
            self._seq += 1
            return new_step_id(self._seq - 1)

    def set_decision(self, note_id: str | None) -> None:
        """Steps recorded from now on say they were decided in this ``agent_note`` step (decision trace)."""
        self._decision = note_id

    def _submit_step(
        self,
        where: str,
        kind: str,
        ts: int,
        fields: Step,
        snapshot: str | None = None,
        analysis: dict[str, Any] | None = None,
    ) -> str:
        step_id = self._next_id()
        decided_by = self._decision if kind not in ("agent_note", "page_read", "error") else None
        self._worker.submit(where, lambda: self._write_step(step_id, kind, ts, fields, snapshot, analysis, decided_by))
        return step_id

    def _write_step(
        self,
        step_id: str,
        kind: str,
        ts: int,
        fields: Step,
        snapshot: str | None,
        analysis: dict[str, Any] | None,
        decided_by: str | None,
    ) -> None:
        rules = (self.policy.site_allowlist, self.policy.site_denylist)
        url = fields.get("url")
        request_url = (fields.get("request") or {}).get("url")
        if recording_blocked_reason(url, *rules) or recording_blocked_reason(
            request_url, (), self.policy.site_denylist
        ):
            return  # organisation policy: sites that must not be recorded leave no trace at all
        index = len(self.steps)
        step: Step = {
            "id": step_id,
            "runId": self.run_id,
            "index": index,
            "kind": kind,
            "timestamp": ts,
            "flags": [],
            **fields,
        }
        if decided_by:
            step["decidedBy"] = decided_by
        shaped, snap = apply_capture_level(step, snapshot, self.level)
        self.writer.add_step(shaped, snap, analysis)
        stored = dict(shaped)
        if snap is not None:
            stored["snapshotRef"] = f"snapshots/{step_id}.txt"
        self.steps.append(stored)

    # ------------------------------------------------------------------ events from the browser

    def navigate(self, url: str) -> None:
        if self.ended or not url or url in ("about:blank", self._last_nav):
            return
        self._last_nav = url
        self._submit_step("navigate", "navigate", _now_ms(), {"url": url})

    def scan(self, event: dict[str, Any]) -> None:
        """A page scan reported by the page script (``load``, ``rescan`` or ``spa``)."""
        if self.ended or not self._allow_event():
            return
        ts = _now_ms()
        reason = event.get("reason")
        scan = sanitize_scan(event.get("scan"))
        if scan is None:
            return
        title = scan["title"]
        if reason == "rescan":
            title = f"{title} (content changed after load)"
        elif reason == "spa":
            title = f"{title} (client-side route change)"
        analysis: dict[str, Any] = {"scan": scan}
        if reason in ("rescan", "spa"):
            analysis["rescan"] = True
        # The stored snapshot is redacted again by the writer; the scan above is already redacted.
        self._submit_step(
            "page_read", "page_read", ts, {"url": scan["url"], "targetText": title}, scan["text"], analysis
        )

    def page_event(self, event: dict[str, Any], url: str) -> None:
        """A click, field change or form submit reported by the page script."""
        if self.ended or not self._allow_event():
            return
        ts = _now_ms()
        kind = event.get("type")
        selector = _clip(event.get("selector") or "", 500)
        text = _clip(event.get("text") or "", 300)
        if kind == "click":
            self._submit_step("click", "click", ts, {"url": url, "targetSelector": selector, "targetText": text})
        elif kind == "change":
            self._submit_step(
                "type",
                "type",
                ts,
                {"url": url, "targetSelector": selector, "targetText": f"{text} (value not recorded)"},
            )
        elif kind == "submit":
            action = event.get("action") if isinstance(event.get("action"), str) else None
            method = str(event.get("method") or "GET").upper()[:10]
            request: Step = {"method": method, "url": _clip(action or url, 4096)}
            analysis: dict[str, Any] | None = None
            body = event.get("body")
            if isinstance(body, str) and body:
                request["bodyPreview"] = truncate(body, MAX_BODY_PREVIEW)
                analysis = {"body": sanitize_body(body)}
            target = "form → other domain" if is_cross_site(url, action) else text
            self._submit_step(
                "submit",
                "form_submit",
                ts,
                {"url": url, "targetSelector": selector, "targetText": target, "request": request},
                None,
                analysis,
            )

    def request_started(self, token: Any, method: str, url: str, resource_type: str, body: bytes | str | None) -> None:
        """A request the browser is about to send. Recorded when its response (or failure) arrives."""
        if self.ended:
            return
        page_url = self.get_url()
        if resource_type in ("fetch", "xhr"):
            kind = "xmlhttprequest"
        elif resource_type == "image" and site_of(url) != site_of(page_url):
            kind = "image"  # tracking pixels
        elif resource_type == "ping":
            kind = "ping"  # navigator.sendBeacon
        else:
            return  # navigations and forms are recorded as navigate / form_submit
        if len(self._pending_requests) > 2000:
            return
        raw = body.encode("utf-8", "replace") if isinstance(body, str) else (body or b"")
        self._pending_requests[token] = {
            "ts": _now_ms(),
            "from": page_url,
            "method": method,
            "url": url,
            "type": kind,
            "body": raw,
        }

    def request_finished(
        self, token: Any, status: int | None, headers: dict[str, str] | None, error: str | None = None
    ) -> None:
        info = self._pending_requests.pop(token, None)
        if info is None or self.ended:
            return
        self._submit_request(info, status, headers, error)

    def _submit_request(
        self, info: dict[str, Any], status: int | None, headers: dict[str, str] | None, error: str | None
    ) -> None:
        if self._network_steps >= MAX_NETWORK_STEPS:
            return
        self._network_steps += 1
        request: Step = {"method": info["method"], "url": info["url"], "resourceType": info["type"]}
        if status is not None:
            request["status"] = int(status)
        request.update(pick_headers(headers))
        if error:
            request["error"] = _clip(error, 200)
        analysis: dict[str, Any] | None = None
        body: bytes = info["body"]
        if body:
            text = body.decode("utf-8", "replace")
            request["bodyBytes"] = len(body)
            request["bodyPreview"] = truncate(text, MAX_BODY_PREVIEW)
            analysis = {"body": sanitize_body(text)}
        self._submit_step(
            "request", "network_request", info["ts"], {"url": info["from"], "request": request}, None, analysis
        )

    def websocket(self, url: str) -> Callable[[str | bytes], None]:
        """A WebSocket connection; returns the callback for the frames the page sends over it."""
        page_url = self.get_url()
        if not self.ended:
            self._submit_step(
                "websocket",
                "network_request",
                _now_ms(),
                {"url": page_url, "request": {"method": "GET", "url": url, "resourceType": "websocket"}},
            )
        sent = 0

        def on_frame(payload: str | bytes) -> None:
            nonlocal sent
            if self.ended or sent >= MAX_WEBSOCKET_FRAMES:
                return
            sent += 1
            text = payload if isinstance(payload, str) else payload.decode("utf-8", "replace")
            request: Step = {
                "method": "SEND",
                "url": url,
                "resourceType": "websocket",
                "bodyPreview": truncate(text, MAX_BODY_PREVIEW),
                "bodyBytes": len(text.encode("utf-8")),
            }
            self._submit_step(
                "websocket",
                "network_request",
                _now_ms(),
                {"url": page_url, "request": request},
                None,
                {"body": sanitize_body(text)},
            )

        return on_frame

    def download(self, url: str, filename: str) -> None:
        if not self.ended:
            self._submit_step("download", "download", _now_ms(), {"url": url, "targetText": filename})

    def crashed(self) -> None:
        if not self.ended:
            self._submit_step("crash", "error", _now_ms(), {"url": self.get_url(), "targetText": "page crashed"})

    # ------------------------------------------------------------------ from the agent

    def note(self, text: str) -> str | None:
        """Record a note about the agent's reasoning (an ``agent_note`` step). Returns the step id."""
        if self.ended:
            return None
        return self._submit_step("note", "agent_note", _now_ms(), {"url": self.get_url(), "targetText": str(text)})

    def report_error(self, error: BaseException | str, selector: str | None = None) -> None:
        """Record a failure the recorder could not see itself as an ``error`` step."""
        if self.ended:
            return
        message = str(error) or (type(error).__name__ if isinstance(error, BaseException) else "error")
        fields: Step = {"url": self.get_url(), "targetText": message.split("\n", 1)[0][:200], "error": message}
        if selector:
            fields["targetSelector"] = selector
        self._submit_step("error", "error", _now_ms(), fields)

    # ------------------------------------------------------------------ end

    def finish(self, status: str) -> dict[str, Any]:
        """Stop accepting events, flush everything to disk and write the final ``run.json``. Idempotent."""
        if not self.ended:
            self.ended = True
            for info in list(self._pending_requests.values()):
                self._submit_request(info, None, None, "unfinished when the run ended")
            self._pending_requests.clear()
            ended_at = _now_ms()

            def close() -> None:
                self.writer.finish(status, ended_at)

            self._worker.submit("finish", close)
            if not self._worker.flush():
                log_error("finish", "timed out waiting for the writer; some steps may be missing")
            self._worker.stop()
            self.writer.run = {**self.writer.run, "status": status, "endedAt": ended_at}
        return {**self.writer.run, "steps": list(self.steps)}


@dataclass
class Setup:
    """What :func:`prepare` decided: where and how to record."""

    writer: RunWriter
    level: CaptureLevel
    policy: Policy
    otel: bool


def prepare(options: RecordOptions) -> Setup | None:
    """Apply organisation policy and create the run folder; None when nothing may be recorded.

    Fail open for the agent, closed for privacy: every reason not to record is logged to stderr and the
    agent simply runs without a recorder.
    """
    root = Path(options.dir if options.dir is not None else os.environ.get("STEPLIGHT_DIR") or DEFAULT_RUNS_DIR)
    try:
        policy = load_policy().policy
    except RuntimeError as err:
        log_error("policy", f"{err} - NOT recording")
        return None
    explicit = EncryptionOptions(key=options.encryption_key, passphrase=options.passphrase)
    encryption = effective_encryption(explicit)
    if options.encrypt and encryption is None:
        log_error(
            "encryption",
            "encrypt=True but no key: pass encryption_key / passphrase or set STEPLIGHT_ENCRYPTION_KEY - NOT recording",
        )
        return None
    if policy.require_encryption and encryption is None:
        log_error(
            "policy",
            "organisation policy requires encryption but no key is configured (set STEPLIGHT_ENCRYPTION_KEY) - NOT recording",
        )
        return None
    level: CaptureLevel = options.capture_level if options.capture_level in CAPTURE_LEVELS else "standard"
    for cap in CAPTURE_LEVELS:
        if cap == policy.max_capture_level and CAPTURE_LEVELS.index(level) > CAPTURE_LEVELS.index(cap):
            level = cap
    configure_redaction(list(policy.force_redaction_patterns))
    if policy.retention_days is not None:
        try:
            purge_runs(root, policy.retention_days)
        except Exception as err:
            log_error("retention", err)
    run_id = new_run_id()
    meta: dict[str, Any] = {
        **(options.meta or {}),
        "sdk": options.sdk,
        "sdkVersion": __version__,
        "captureLevel": level,
        "analyzed": False,
    }
    run = {"id": run_id, "task": options.task, "startedAt": _now_ms(), "status": "running", "meta": meta}
    try:
        writer = RunWriter.create(root, run, encryption)
    except Exception as err:
        log_error("start", f"{err} - NOT recording")
        return None
    use_otel = options.otel if options.otel is not None else bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))
    return Setup(writer, level, policy, use_otel)


__all__ = ["BINDING_NAME", "MAX_SNAPSHOT_TEXT", "RecordOptions", "RecorderCore", "Setup", "prepare", "sanitize_scan"]
