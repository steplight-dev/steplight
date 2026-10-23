"""Optional OpenTelemetry export of a run, with the same span names and attributes as the TypeScript SDK.

A root ``steplight.run`` span, one child ``steplight.step.<kind>`` span per step and one ``steplight.flag`` event per
flag. Needs ``pip install steplight[otel]``. The only network traffic is to the OTLP endpoint the user configures
(``OTEL_EXPORTER_OTLP_ENDPOINT`` or ``endpoint=``). Flags exist only once the run has been analyzed; spans exported
at ``end()`` carry ``steplight.flag.count = 0`` (export again after ``steplight analyze`` with
``steplight export <runId> --otlp``).
"""

from __future__ import annotations

import os
from typing import Any

from ._log import log_error

DEFAULT_OTLP_ENDPOINT = "http://localhost:4318"
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_severity(flags: list[dict[str, Any]]) -> str | None:
    worst = None
    for f in flags:
        if worst is None or _SEVERITY_RANK.get(f["severity"], 0) > _SEVERITY_RANK[worst]:
            worst = f["severity"]
    return worst


def emit_run_spans(run: dict[str, Any], tracer: Any) -> None:
    """Emit a run as spans on the given OpenTelemetry tracer."""
    from opentelemetry import context, trace
    from opentelemetry.trace import StatusCode

    steps: list[dict[str, Any]] = run.get("steps", [])
    end = run.get("endedAt") or (steps[-1]["timestamp"] if steps else run["startedAt"])
    ns = 1_000_000
    root = tracer.start_span(
        "steplight.run",
        context=context.get_current(),
        start_time=int(run["startedAt"]) * ns,
        attributes={
            "gen_ai.operation.name": "invoke_agent",
            "steplight.task": run["task"],
            "steplight.run_id": run["id"],
            "steplight.status": run["status"],
        },
    )
    parent = trace.set_span_in_context(root)
    for step in steps:
        flags = step.get("flags", [])
        attributes: dict[str, Any] = {
            "steplight.step.index": step["index"],
            "steplight.step.id": step["id"],
            "steplight.flag.count": len(flags),
        }
        if step.get("url"):
            attributes["url.full"] = step["url"]
        worst = _max_severity(flags)
        if worst:
            attributes["steplight.flag.max_severity"] = worst
        if step.get("targetText"):
            attributes["steplight.step.target_text"] = step["targetText"]
        if step.get("causedBy"):
            attributes["steplight.step.caused_by"] = step["causedBy"]
        if step.get("tokens"):
            attributes["steplight.step.estimated_tokens"] = step["tokens"]["total"]
        if step.get("request"):
            attributes["http.request.method"] = step["request"]["method"]
        start = int(step["timestamp"]) * ns
        span = tracer.start_span(
            f"steplight.step.{step['kind']}", context=parent, start_time=start, attributes=attributes
        )
        for flag in flags:
            span.add_event(
                "steplight.flag",
                {
                    "steplight.flag.type": flag["type"],
                    "steplight.flag.severity": flag["severity"],
                    "steplight.flag.message": flag["message"],
                },
                timestamp=start,
            )
        if step["kind"] == "error":
            span.set_status(StatusCode.ERROR)
        span.end(end_time=start + int(step.get("durationMs") or 0) * ns)
    if run["status"] == "failed":
        root.set_status(StatusCode.ERROR)
    root.end(end_time=max(int(end), int(run["startedAt"])) * ns)


def export_run_otlp(run: dict[str, Any], endpoint: str | None = None, exporter: Any = None) -> bool:
    """Send a run to an OTLP/HTTP endpoint (or a custom span exporter). Never raises; returns False on failure."""
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        if exporter is None:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            base = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or DEFAULT_OTLP_ENDPOINT
            exporter = OTLPSpanExporter(endpoint=f"{base.rstrip('/')}/v1/traces", timeout=3)
        provider = TracerProvider(resource=Resource.create({"service.name": "steplight"}))
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        emit_run_spans(run, provider.get_tracer("steplight"))
        provider.force_flush()
        provider.shutdown()
        return True
    except Exception as err:
        log_error("otel", err)
        return False
