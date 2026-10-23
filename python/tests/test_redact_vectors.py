"""The Python redaction engine must give exactly the output of the TypeScript engine on every shared vector."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from steplight import redact
from tests.conftest import SPEC

VECTORS = json.loads((SPEC / "redaction-vectors.json").read_text(encoding="utf-8"))


def expand(value: Any) -> str:
    """A vector text is a string, {join: [parts]} (provider-key-shaped text is never stored literally) or {repeat: ...}."""
    if isinstance(value, str):
        return value
    if "join" in value:
        return "".join(value["join"])
    return value.get("prefix", "") + value["repeat"][0] * value["repeat"][1] + value.get("suffix", "")


def test_there_are_300_plus_vectors_covering_every_group() -> None:
    assert len(VECTORS["cases"]) + len(VECTORS["sanitize"]) >= 300
    groups = {c["group"] for c in VECTORS["cases"]}
    assert {
        "email",
        "card",
        "api_key",
        "jwt",
        "private_key",
        "bearer",
        "password",
        "url_param",
        "iban",
        "ssn",
        "aadhaar",
        "pan",
        "phone",
        "encoded",
        "hostile",
        "idempotent",
    } <= groups


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_redact_matches_the_reference_engine(case: dict[str, Any]) -> None:
    text = expand(case["input"])
    out = redact.redact_text(text)
    assert out == expand(case["redact"])
    assert (redact.redact_text(out) == out) == case["idempotent"]
    assert [m.kind for m in redact.find_sensitive(text)] == case["find"]
    assert [m.kind for m in redact.find_sensitive(text, credentials=True)] == case["findCredentials"]


@pytest.mark.parametrize("case", VECTORS["sanitize"], ids=lambda c: c["id"])
def test_sanitize_matches_the_reference_engine(case: dict[str, Any]) -> None:
    text = expand(case["input"])
    out = redact.sanitize_body(text) if case["kind"] == "body" else redact.sanitize_snapshot(text)
    if "output" in case:
        assert out == expand(case["output"])
    else:
        digest = case["outputDigest"]
        assert len(out.encode("utf-16-le")) // 2 == digest["length"]
        assert hashlib.sha256(out.encode("utf-8")).hexdigest() == digest["sha256"]


def test_redacting_twice_changes_nothing_for_every_non_hostile_vector() -> None:
    for case in VECTORS["cases"]:
        if case["group"] != "hostile":
            assert case["idempotent"], case["id"]


def test_redaction_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any) -> Any:
        raise RuntimeError("scanner broke")

    monkeypatch.setattr(redact, "_collect", boom)
    assert redact.redact_text("jane@example.com") == "[REDACTED:error]"
    assert redact.sanitize_body("jane@example.com") == "[REDACTED:error]"


def test_custom_patterns_are_validated_and_applied() -> None:
    try:
        redact.configure_redaction(["EMP-[0-9]{6}", "(a+)+$", "x" * 300, "("])
        assert redact.redact_text("badge EMP-123456 here") == "badge [REDACTED:custom] here"
        assert redact.redact_text("aaaa!") == "aaaa!"  # the catastrophic pattern was rejected, not used
    finally:
        redact.configure_redaction([])
