"""Writing runs to disk in the Steplight run format (port of ``storage/runStore.ts``, ``sanitize.ts``, ``captureLevel.ts``).

Everything is redacted *before* it is written. Files are created 0600 and folders 0700 on POSIX. When a key is
configured, every file is an AES-256-GCM envelope (see :mod:`steplight.crypto`).
"""

from __future__ import annotations

import json
import math
import os
import shutil
import time
from pathlib import Path
from typing import Any

from .crypto import (
    EncryptedRunError,
    EncryptionOptions,
    decrypt_file,
    encrypt_file,
    is_encrypted_text,
    resolve_key,
    write_private,
)
from .domain import strip_query
from .ids import is_safe_id
from .redact import _prefix_utf16, redact_text, sanitize_body, sanitize_snapshot
from .settings import CaptureLevel

FORMAT_VERSION = 1
DEFAULT_RUNS_DIR = os.path.join(".steplight", "runs")
ANALYSIS_INPUT_FILE = "analysis-input.jsonl"

Step = dict[str, Any]


def _clip(text: str, units: int) -> str:
    return _prefix_utf16(text, units)


def json_safe(value: Any) -> Any:
    """Drop non-finite numbers (``NaN`` is not JSON) and keep everything else as it is."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items() if not (isinstance(v, float) and not math.isfinite(v))}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value


def dumps(value: Any, indent: int | None = None) -> str:
    """``JSON.stringify``-compatible output: compact separators unless indented, non-ASCII kept as it is."""
    separators = None if indent else (",", ":")
    return json.dumps(json_safe(value), ensure_ascii=False, indent=indent, separators=separators, allow_nan=False)


def apply_capture_level(step: Step, snapshot: str | None, level: CaptureLevel) -> tuple[Step, str | None]:
    """Shape a step (and its page text) for storage according to the capture level; returns copies.

    ``minimal``: URLs lose their query strings; no page text, target text, error text, diagnosis or request
    details beyond method + URL. ``standard``: redacted page text and request metadata, no request bodies.
    ``full``: also a redacted request body preview.
    """
    out: Step = dict(step)
    if level == "minimal":
        if out.get("url"):
            out["url"] = strip_query(out["url"])
        for key in ("targetText", "diagnosis", "error", "snapshotRef"):
            out.pop(key, None)
        request = out.get("request")
        if request:
            out["request"] = {"method": request["method"], "url": strip_query(request["url"])}
        return out, None
    request = out.get("request")
    if request:
        request = dict(request)
        if level == "full" and request.get("bodyPreview") is not None:
            request["bodyPreview"] = sanitize_body(request["bodyPreview"])
        else:
            request.pop("bodyPreview", None)  # standard: the body is not kept
        out["request"] = request
    return out, (sanitize_snapshot(snapshot) if snapshot is not None else None)


def sanitize_step(step: Step) -> Step:
    """A copy of the step that is safe to write: bodies redacted and truncated, free-text fields redacted."""
    copy: Step = {**step, "flags": [dict(f) for f in step.get("flags", [])]}
    request = copy.get("request")
    if request:
        request = dict(request)
        request["url"] = redact_text(request["url"])
        if request.get("bodyPreview") is not None:
            request["bodyPreview"] = sanitize_body(request["bodyPreview"])
        copy["request"] = request
    if copy.get("targetText") is not None:
        copy["targetText"] = _clip(redact_text(copy["targetText"]), 300)
    if copy.get("targetSelector") is not None:
        copy["targetSelector"] = _clip(redact_text(copy["targetSelector"]), 500)
    if copy.get("url") is not None:
        copy["url"] = redact_text(copy["url"])
    if copy.get("error") is not None:
        copy["error"] = _clip(redact_text(copy["error"]), 1000)
    for flag in copy["flags"]:
        flag["evidence"] = redact_text(flag["evidence"])
        flag["message"] = redact_text(flag["message"])
    return copy


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)


class RunWriter:
    """Incrementally writes one run to ``<root>/<runId>/``. Not thread-safe: use it from one thread."""

    def __init__(self, root: str | os.PathLike[str], run: dict[str, Any], key: bytes | None) -> None:
        if not is_safe_id(run["id"]):
            raise ValueError(f"Unsafe run id: {run['id']}")
        self.root = Path(root)
        self.dir = self.root / run["id"]
        self.run = run
        self._key = key

    @classmethod
    def create(
        cls, root: str | os.PathLike[str], run: dict[str, Any], encryption: EncryptionOptions | None = None
    ) -> RunWriter:
        """Create the run folder and write the initial ``run.json`` and an empty ``steps.jsonl``."""
        key = resolve_key(root, encryption, create=True)
        writer = cls(root, run, key)
        _mkdir_private(writer.root)
        _mkdir_private(writer.dir)
        _mkdir_private(writer.dir / "snapshots")
        write_private(writer.dir / "steps.jsonl", "")
        writer._write_meta()
        return writer

    def _seal(self, text: str, file: str) -> str:
        return encrypt_file(text, self._key, f"{self.run['id']}/{file}") if self._key else text

    def _write_meta(self) -> None:
        meta = {"formatVersion": FORMAT_VERSION, **{k: v for k, v in self.run.items() if k != "steps"}}
        meta["task"] = redact_text(str(meta["task"]))
        meta["meta"] = {k: (v if isinstance(v, bool) else redact_text(str(v))) for k, v in meta["meta"].items()}
        target = self.dir / "run.json"
        tmp = self.dir / "run.json.tmp"
        write_private(tmp, self._seal(dumps(meta, indent=2), "run.json"))
        os.replace(tmp, target)

    def add_step(self, step: Step, snapshot_text: str | None = None, analysis: dict[str, Any] | None = None) -> None:
        """Append a step (and its snapshot). ``analysis`` is the step's line of ``analysis-input.jsonl`` (already redacted)."""
        to_write: Step = dict(step)
        if snapshot_text is not None:
            ref = f"snapshots/{step['id']}.txt"
            to_write["snapshotRef"] = ref
            write_private(self.dir / ref, self._seal(sanitize_snapshot(snapshot_text), ref))
        self._append("steps.jsonl", dumps(sanitize_step(to_write)))
        if analysis is not None:
            self._append(ANALYSIS_INPUT_FILE, dumps({"stepId": step["id"], **analysis}))

    def _append(self, file: str, line: str) -> None:
        path = self.dir / file
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="") as handle:
            handle.write(self._seal(line, file) + "\n")
        if os.name != "nt":
            os.chmod(path, 0o600)

    def finish(self, status: str, ended_at: int) -> None:
        """Update the run status and end time and rewrite ``run.json``."""
        self.run = {**self.run, "status": status, "endedAt": ended_at}
        self._write_meta()


def read_run(root: str | os.PathLike[str], run_id: str, encryption: EncryptionOptions | None = None) -> dict[str, Any]:
    """Read a stored run (``run.json`` plus ``steps.jsonl``) as a dict with ``steps``. Handy in tests and notebooks."""
    if not is_safe_id(run_id):
        raise ValueError(f"Unsafe run id: {run_id}")
    base = Path(root) / run_id
    meta_text = (base / "run.json").read_text(encoding="utf-8")
    key = resolve_key(root, encryption) if is_encrypted_text(meta_text) else None
    run: dict[str, Any] = json.loads(decrypt_file(meta_text, key, f"{run_id}/run.json"))
    steps: list[Step] = []
    try:
        raw = (base / "steps.jsonl").read_text(encoding="utf-8")
    except OSError:
        raw = ""
    for line in raw.split("\n"):
        if not line.strip():
            continue
        try:
            steps.append(json.loads(decrypt_file(line, key, f"{run_id}/steps.jsonl")))
        except EncryptedRunError:
            raise
        except ValueError:
            continue  # a partially written line
    steps.sort(key=lambda s: s["index"])
    run["steps"] = steps
    return run


def read_snapshot(
    root: str | os.PathLike[str], run_id: str, step: Step, encryption: EncryptionOptions | None = None
) -> str | None:
    """The stored page text of a step, or None."""
    ref = step.get("snapshotRef")
    if not ref:
        return None
    base = (Path(root) / run_id).resolve()
    file = (base / ref).resolve()
    if base not in file.parents:
        return None
    try:
        text = file.read_text(encoding="utf-8")
    except OSError:
        return None
    key = resolve_key(root, encryption) if is_encrypted_text(text) else None
    return decrypt_file(text, key, f"{run_id}/{ref}")


def purge_runs(root: str | os.PathLike[str], older_than_days: float) -> list[str]:
    """Delete run folders that started more than N days ago (retention). Only valid run folders inside ``root`` are touched."""
    cutoff = (time.time() - older_than_days * 86400) * 1000
    base = Path(root)
    deleted: list[str] = []
    if not base.is_dir():
        return deleted
    for entry in base.iterdir():
        run_json = entry / "run.json"
        if not entry.is_dir() or not is_safe_id(entry.name) or not run_json.is_file():
            continue
        started = run_json.stat().st_mtime * 1000  # an encrypted run we cannot read falls back to the file time
        try:
            text = run_json.read_text(encoding="utf-8")
            if not is_encrypted_text(text):
                started = float(json.loads(text)["startedAt"])
        except (OSError, ValueError, KeyError):
            pass
        if started < cutoff:
            shutil.rmtree(entry, ignore_errors=True)
            deleted.append(entry.name)
    return deleted
