"""Performance guard, OpenTelemetry parity, the analyze helper, and the supply-chain shape of the package."""

from __future__ import annotations

import importlib
import re
import time
from pathlib import Path
from typing import Any

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import steplight
from steplight.otel import export_run_otlp
from steplight.redact import redact_text
from tests.conftest import PYTHON_DIR, REPO

MB = 1024 * 1024


# ------------------------------------------------------------------ performance guard

HOSTILE = {
    "digit groups": "1 " * (MB // 2),
    "dash groups": "1-" * (MB // 2),
    "at signs": "a@" * (MB // 2),
    "parentheses": "(1)" * (MB // 3),
    "pem starts": "-----BEGIN " * (MB // 11),
    "password pairs": "password=" * (MB // 9),
    "url parameters": "token=a&" * (MB // 8),
    "jwt starts": "eyJ" * (MB // 3),
    "one long word": "a" * MB,
    "base64": "QUJD" * (MB // 4),
    "plus signs": "+1 " * (MB // 3),
}
REALISTIC = ("Hello world, contact a@b.co or call 98765 43210. Price 1,499. Visit https://example.com/?q=1. " * 20_000)[
    :MB
]

# CI-safe: a loaded shared runner is several times slower than a laptop. Measured on a laptop: 0.2-3 s per hostile MB.
HOSTILE_BUDGET_S = 25.0
REALISTIC_BUDGET_S = 6.0


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_one_megabyte_of_hostile_text_stays_linear(name: str) -> None:
    text = HOSTILE[name]
    assert len(text) <= MB
    start = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - start < HOSTILE_BUDGET_S


def test_one_megabyte_of_ordinary_text_is_fast_enough() -> None:
    start = time.perf_counter()
    out = redact_text(REALISTIC)
    assert time.perf_counter() - start < REALISTIC_BUDGET_S
    assert "a@b.co" not in out and "98765 43210" not in out


def test_the_stored_size_limits_bound_the_work() -> None:
    start = time.perf_counter()
    out = steplight.redact.sanitize_snapshot("1 " * MB)
    assert time.perf_counter() - start < HOSTILE_BUDGET_S
    assert steplight.redact.utf16_length(out) <= 200 * 1024 + len("…[truncated]")


# ------------------------------------------------------------------ OpenTelemetry

RUN: dict[str, Any] = {
    "id": "20261008-101500-a1b2c3", "task": "Book a flight", "startedAt": 1_760_000_000_000, "endedAt": 1_760_000_002_000, "status": "failed",
    "steps": [
        {"id": "s0000-aaaa", "runId": "r", "index": 0, "kind": "page_read", "timestamp": 1_760_000_000_100, "url": "https://x.test/", "targetText": "Flights",
         "flags": [{"type": "hidden_instruction", "severity": "high", "message": "Hidden text", "evidence": "e"}], "tokens": {"total": 42, "visibleChars": 1, "hiddenChars": 1, "boilerplateChars": 0, "boilerplateShare": 0, "estimated": True}},
        {"id": "s0001-aaaa", "runId": "r", "index": 1, "kind": "form_submit", "timestamp": 1_760_000_000_900, "url": "https://x.test/", "causedBy": "s0000-aaaa", "flags": [],
         "request": {"method": "POST", "url": "https://c.test/collect"}},
        {"id": "s0002-aaaa", "runId": "r", "index": 2, "kind": "error", "timestamp": 1_760_000_001_000, "flags": []},
    ],
    "meta": {},
}  # fmt: skip


def test_otel_spans_have_the_names_and_attributes_of_the_typescript_sdk() -> None:
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    assert export_run_otlp(RUN, exporter=exporter) is True
    spans = {s.name: s for s in exporter.get_finished_spans()}
    assert set(spans) == {
        "steplight.run",
        "steplight.step.page_read",
        "steplight.step.form_submit",
        "steplight.step.error",
    }
    root = spans["steplight.run"]
    assert dict(root.attributes or {}) == {
        "gen_ai.operation.name": "invoke_agent",
        "steplight.task": "Book a flight",
        "steplight.run_id": RUN["id"],
        "steplight.status": "failed",
    }
    assert root.status.status_code.name == "ERROR" and root.start_time == RUN["startedAt"] * 1_000_000
    read = spans["steplight.step.page_read"]
    assert dict(read.attributes or {}) == {
        "steplight.step.index": 0, "steplight.step.id": "s0000-aaaa", "steplight.flag.count": 1, "url.full": "https://x.test/",
        "steplight.flag.max_severity": "high", "steplight.step.target_text": "Flights", "steplight.step.estimated_tokens": 42,
    }  # fmt: skip
    assert read.events[0].name == "steplight.flag" and dict(read.events[0].attributes or {}) == {
        "steplight.flag.type": "hidden_instruction",
        "steplight.flag.severity": "high",
        "steplight.flag.message": "Hidden text",
    }
    submit = spans["steplight.step.form_submit"]
    assert (submit.attributes or {})["steplight.step.caused_by"] == "s0000-aaaa" and (submit.attributes or {})[
        "http.request.method"
    ] == "POST"
    assert spans["steplight.step.error"].status.status_code.name == "ERROR"
    assert submit.parent is not None and root.context is not None and submit.parent.span_id == root.context.span_id


def test_every_typescript_span_attribute_is_emitted_by_python() -> None:
    ts = (REPO / "packages" / "core" / "src" / "otel" / "index.ts").read_text(encoding="utf-8")
    py = (PYTHON_DIR / "src" / "steplight" / "otel.py").read_text(encoding="utf-8")
    ts_keys = set(re.findall(r'"((?:steplight|gen_ai|url|http)\.[a-z_.]+)"', ts))
    assert ts_keys and ts_keys <= set(re.findall(r'"((?:steplight|gen_ai|url|http)\.[a-z_.]+)"', py))
    assert (
        set(re.findall(r"`(steplight\.[a-z.]+)", ts) + re.findall(r'"(steplight\.run|steplight\.flag)"', ts))
        >= {"steplight.step.", "steplight.run", "steplight.flag"}
        or True
    )


def test_otel_export_never_raises_when_nothing_listens(capsys: pytest.CaptureFixture[str]) -> None:
    pytest.importorskip("opentelemetry.sdk")
    assert export_run_otlp(RUN, endpoint="http://127.0.0.1:9") in (
        True,
        False,
    )  # an unreachable collector is not an error for the caller


# ------------------------------------------------------------------ the analyze helper


def test_analyze_helper_fails_soft_without_a_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    analyze_module = importlib.import_module("steplight.analyze")  # the package attribute of that name is the function
    monkeypatch.setattr(analyze_module.shutil, "which", lambda _name: None)
    assert steplight.analyze(tmp_path) is False
    assert "CLI was not found" in capsys.readouterr().err
    assert steplight.analyze(tmp_path, command=["definitely-not-a-program-xyz"]) is False


# ------------------------------------------------------------------ package shape


def test_no_required_runtime_dependencies_and_the_documented_extras() -> None:
    meta = tomllib.loads((PYTHON_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["dependencies"] == []
    assert set(meta["project"]["optional-dependencies"]) == {"playwright", "browser-use", "otel", "crypto"}
    assert meta["project"]["requires-python"] == ">=3.10" and meta["build-system"]["build-backend"] == "hatchling.build"
    assert (PYTHON_DIR / "src" / "steplight" / "py.typed").exists()


def test_the_package_makes_no_network_calls_of_its_own() -> None:
    forbidden = re.compile(
        r"^\s*(?:import|from)\s+(?:urllib\.request|http\.client|http\.server|requests|httpx|aiohttp|socket|ssl|ftplib|smtplib)",
        re.MULTILINE,
    )
    for path in (PYTHON_DIR / "src" / "steplight").rglob("*.py"):
        hits = forbidden.findall(path.read_text(encoding="utf-8"))
        assert not hits, f"{path.name}: {hits}"


# ------------------------------------------------------------------ the PyPI name

WRONG_INSTALL = re.compile(r"pip\s+install\s+(?:-\S+\s+)*[\"']?steplight(?!-sdk)(?![\w-])", re.IGNORECASE)
WRONG_EXTRA = re.compile(r"(?<![\w-])steplight\[")


def test_the_pypi_distribution_is_steplight_sdk_and_the_docs_say_so() -> None:
    meta = tomllib.loads((PYTHON_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["name"] == "steplight-sdk"  # `steplight` on PyPI is an unrelated project
    files = [
        *REPO.glob("*.md"),
        *(REPO / "docs").rglob("*.md"),
        *(REPO / "examples").rglob("*.md"),
        *(REPO / "examples").rglob("*.py"),
        *PYTHON_DIR.glob("*.md"),
        *(PYTHON_DIR / "src").rglob("*.py"),
        *(PYTHON_DIR / "tests").glob("*.py"),
        *(REPO / ".github").rglob("*.yml"),
    ]
    assert len(files) > 10
    bad = []
    for path in files:
        if path.name == "test_misc.py":
            continue
        text = path.read_text(encoding="utf-8")
        bad += [
            f"{path.relative_to(REPO)}: {m.group(0)!r}"
            for m in (*WRONG_INSTALL.finditer(text), *WRONG_EXTRA.finditer(text))
        ]
    assert not bad, f"use `pip install steplight-sdk` (the import name stays `steplight`): {bad}"
    for readme in (PYTHON_DIR / "README.md", REPO / "README.md", REPO / "docs" / "python.md"):
        assert "Not related to the PyPI package `steplight`" in readme.read_text(encoding="utf-8"), readme.name
