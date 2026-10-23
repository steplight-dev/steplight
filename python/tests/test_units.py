"""Unit tests: never-capture rules, headers, capture levels, policy, encryption, ids, domains, step sanitising."""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from steplight import crypto, domain, ids, network, policy, settings, store
from steplight.never_capture import is_never_capture_field, is_payment_frame_url
from steplight.redact import utf16_length
from tests.conftest import REPO, SPEC

# ------------------------------------------------------------------ never-capture rules

NEVER = json.loads((SPEC / "never-capture.json").read_text(encoding="utf-8"))

_ARGS = {
    "tag": "tag", "type": "type", "name": "name", "id": "id", "autocomplete": "autocomplete", "ariaLabel": "aria_label",
    "placeholder": "placeholder", "label": "label", "contentEditable": "content_editable", "inPaymentFrame": "in_payment_frame",
}  # fmt: skip


@pytest.mark.parametrize("case", NEVER["fieldCases"], ids=lambda c: json.dumps(c["descriptor"], sort_keys=True))
def test_never_capture_field_rules_match_the_shared_cases(case: dict[str, Any]) -> None:
    kwargs = {_ARGS[k]: v for k, v in case["descriptor"].items()}
    assert is_never_capture_field(**kwargs) is case["neverCapture"]


@pytest.mark.parametrize("case", NEVER["urlCases"], ids=lambda c: c["url"] or "empty")
def test_payment_frame_hosts_match_the_shared_cases(case: dict[str, Any]) -> None:
    assert is_payment_frame_url(case["url"]) is case["paymentFrame"]


def test_the_bundled_data_files_are_the_spec_files() -> None:
    data = Path(__file__).resolve().parent.parent / "src" / "steplight" / "_data"
    assert (data / "page-scan.js").read_bytes().replace(b"\r\n", b"\n") == (SPEC / "page-scan.js").read_bytes().replace(
        b"\r\n", b"\n"
    )
    assert (data / "never-capture.json").read_bytes().replace(b"\r\n", b"\n") == (
        SPEC / "never-capture.json"
    ).read_bytes().replace(b"\r\n", b"\n")


def test_the_page_script_carries_the_never_capture_rules_and_makes_no_network_calls() -> None:
    script = (SPEC / "page-scan.js").read_text(encoding="utf-8")
    assert NEVER["namePattern"]["source"] in script
    assert NEVER["autocompletePattern"]["source"] in script
    assert not re.search(r"\bfetch\(|XMLHttpRequest|sendBeacon|\bimport\s|require\(", script)


def test_the_version_matches_pyproject() -> None:
    import steplight

    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{steplight.__version__}"' in pyproject


# ------------------------------------------------------------------ headers


def test_only_content_type_and_length_are_ever_kept() -> None:
    picked = network.pick_headers(
        {
            "Set-Cookie": "a=b",
            "Authorization": "Bearer x",
            "X-API-Key": "k",
            "Content-Type": "Text/HTML; charset=utf-8",
            "Content-Length": "123",
            "X-Session-Id": "s",
            "Server": "nginx",
        }
    )
    assert picked == {"contentType": "text/html", "contentLength": 123}
    assert network.pick_headers({"content-length": "-5"}) == {}
    assert network.pick_headers({"content-length": "abc"}) == {}
    assert network.pick_headers(None) == {}


def test_the_header_allow_list_matches_the_typescript_one() -> None:
    source = (REPO / "packages" / "core" / "src" / "network.ts").read_text(encoding="utf-8")
    match = re.search(r"ALLOWED_HEADERS: readonly string\[\] = \[(.*?)\]", source)
    assert match is not None
    assert tuple(re.findall(r'"([^"]+)"', match.group(1))) == network.ALLOWED_HEADERS


# ------------------------------------------------------------------ capture levels and step sanitising

STEP: dict[str, Any] = {
    "id": "s0001-aaaa", "runId": "r", "index": 1, "kind": "form_submit", "timestamp": 1, "flags": [],
    "url": "https://shop.test/checkout?token=abc123&x=1", "targetText": "Pay now", "error": "boom",
    "request": {"method": "POST", "url": "https://c.test/collect?session=zzz", "bodyPreview": "email=a@b.co&note=hi", "resourceType": "xmlhttprequest", "status": 200, "bodyBytes": 20},
}  # fmt: skip


def test_minimal_keeps_only_kinds_and_urls_without_query_strings() -> None:
    step, snap = store.apply_capture_level(STEP, "page text", "minimal")
    assert snap is None
    assert step["url"] == "https://shop.test/checkout"
    assert "targetText" not in step and "error" not in step
    assert step["request"] == {"method": "POST", "url": "https://c.test/collect"}


def test_standard_keeps_metadata_and_page_text_but_no_bodies() -> None:
    step, snap = store.apply_capture_level(STEP, "mail a@b.co", "standard")
    assert snap == "mail [REDACTED:email]"
    assert "bodyPreview" not in step["request"]
    assert step["request"]["status"] == 200 and step["request"]["bodyBytes"] == 20
    assert step["targetText"] == "Pay now"


def test_full_keeps_a_redacted_body_preview() -> None:
    step, _ = store.apply_capture_level(STEP, None, "full")
    assert step["request"]["bodyPreview"] == "email=[REDACTED:email]&note=hi"


def test_sanitize_step_redacts_and_truncates_every_free_text_field() -> None:
    step = store.sanitize_step(
        {
            **STEP,
            "targetText": "mail jane@example.com " + "x" * 400,
            "error": "key sk-" + "a" * 30,
            "flags": [{"type": "hidden_instruction", "severity": "high", "message": "to a@b.co", "evidence": "a@b.co"}],
        }
    )
    assert "jane@example.com" not in step["targetText"] and utf16_length(step["targetText"]) <= 300
    assert "[REDACTED:api_key]" in step["error"]
    assert step["flags"][0]["evidence"] == "[REDACTED:email]" and step["flags"][0]["message"] == "to [REDACTED:email]"
    assert "token=abc123" not in step["url"]
    assert STEP["targetText"] == "Pay now"  # the input is not modified


def test_json_output_is_compact_and_has_no_nan() -> None:
    assert (
        store.dumps({"a": 1, "b": [float("nan"), 2.5], "c": float("inf"), "d": "é"}) == '{"a":1,"b":[null,2.5],"d":"é"}'
    )


# ------------------------------------------------------------------ ids, domains


def test_ids_have_the_typescript_shape() -> None:
    assert re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", ids.new_run_id())
    assert re.fullmatch(r"s0007-[0-9a-f]{4}", ids.new_step_id(7))
    assert ids.is_safe_id("20261008-101500-a1b2c3") and not ids.is_safe_id("../x") and not ids.is_safe_id("")


def test_registrable_domains() -> None:
    assert domain.registrable_domain("https://a.b.example.com/x") == "example.com"
    assert domain.registrable_domain("https://shop.example.co.uk/") == "example.co.uk"
    assert domain.registrable_domain("http://127.0.0.1:4001/") == "127.0.0.1:4001"
    assert domain.registrable_domain("ftp://example.com") is None
    assert domain.is_cross_site("http://127.0.0.1:1/", "http://127.0.0.1:2/")
    assert not domain.is_cross_site("https://a.example.com", "https://b.example.com")
    assert domain.strip_query("https://u:p@h.test:8443/a/b?x=1#f") == "https://h.test:8443/a/b"


# ------------------------------------------------------------------ site rules and policy


def test_site_rules() -> None:
    assert settings.recording_blocked_reason("https://bank.example.com/x", (), ("example.com",))
    assert settings.recording_blocked_reason("https://other.org/", ("example.com",), ())
    assert settings.recording_blocked_reason("https://sub.example.com/", ("*.example.com",), ()) is None
    assert settings.recording_blocked_reason("about:blank", (), ("example.com",)) is None


def test_policy_from_the_environment_only_tightens() -> None:
    env = {
        "STEPLIGHT_MAX_CAPTURE_LEVEL": "minimal",
        "STEPLIGHT_SITE_DENYLIST": "a.com, b.com",
        "STEPLIGHT_RETENTION_DAYS": "3",
        "STEPLIGHT_REQUIRE_ENCRYPTION": "1",
    }
    p = policy.policy_from_env(env)
    assert (p.max_capture_level, p.site_denylist, p.retention_days, p.require_encryption) == (
        "minimal",
        ("a.com", "b.com"),
        3,
        True,
    )
    merged = policy.merge_policies(
        p, policy.Policy(max_capture_level="full", retention_days=30, site_denylist=("c.com",))
    )
    assert (
        merged.max_capture_level == "minimal"
        and merged.retention_days == 3
        and merged.site_denylist == ("a.com", "b.com", "c.com")
    )
    allow = policy.merge_policies(
        policy.Policy(site_allowlist=("a.com", "b.com")), policy.Policy(site_allowlist=("b.com", "c.com"))
    )
    assert allow.site_allowlist == ("b.com",)


def test_policy_rejects_bad_values_and_dangerous_patterns() -> None:
    problems: list[policy.PolicyProblem] = []
    p = policy.normalize_policy(
        {
            "maxCaptureLevel": "huge",
            "retentionDays": 0,
            "forceRedactionPatterns": ["(a+)+$", "EMP-[0-9]+"],
            "bogus": 1,
            "requireEncryption": "yes",
        },
        problems,
    )
    assert p.force_redaction_patterns == ("EMP-[0-9]+",) and p.max_capture_level is None and p.retention_days is None
    assert {pr.key for pr in problems} == {
        "maxCaptureLevel",
        "retentionDays",
        "forceRedactionPatterns",
        "bogus",
        "requireEncryption",
    }


def test_an_unreadable_policy_file_is_an_error_not_no_policy(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="Cannot read organisation policy"):
        policy.load_policy(policy_file=tmp_path / "missing.json", env={})
    good = tmp_path / "policy.json"
    good.write_text(json.dumps({"maxCaptureLevel": "standard"}), encoding="utf-8")
    (tmp_path / "steplight.config.json").write_text(json.dumps({"siteDenylist": ["x.com"]}), encoding="utf-8")
    loaded = policy.load_policy(policy_file=good, env={"STEPLIGHT_MAX_CAPTURE_LEVEL": "minimal"}, cwd=tmp_path)
    assert loaded.policy.max_capture_level == "minimal" and loaded.policy.site_denylist == ("x.com",)
    assert len(loaded.sources) == 3


# ------------------------------------------------------------------ encryption

KEY = bytes(range(32))


def test_encrypt_roundtrip_envelope_shape_and_aad() -> None:
    env = crypto.encrypt_file("héllo", KEY, "run1/steps.jsonl")
    assert env.startswith(crypto.ENC_MARKER) and "\n" not in env
    data = json.loads(env)
    assert (
        list(data) == ["steplight", "iv", "tag", "ct"]
        and len(base64.b64decode(data["iv"])) == 12
        and len(base64.b64decode(data["tag"])) == 16
    )
    assert crypto.decrypt_file(env, KEY, "run1/steps.jsonl") == "héllo"
    with pytest.raises(crypto.EncryptedRunError):
        crypto.decrypt_file(env, KEY, "run2/steps.jsonl")  # moved to another run
    with pytest.raises(crypto.EncryptedRunError):
        crypto.decrypt_file(env, bytes(32), "run1/steps.jsonl")
    with pytest.raises(crypto.EncryptedRunError):
        crypto.decrypt_file(env, None, "run1/steps.jsonl")
    assert crypto.decrypt_file("plain text", None, "x") == "plain text"
    assert crypto.encrypt_file("a", KEY, "x") != crypto.encrypt_file("a", KEY, "x")  # a fresh IV every time


def test_keys_accept_hex_and_base64_and_must_be_32_bytes() -> None:
    assert crypto.parse_key(KEY.hex()) == KEY
    assert crypto.parse_key(base64.b64encode(KEY).decode()) == KEY
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.parse_key("abcd")


def test_passphrase_creates_a_salt_file_and_detects_a_wrong_passphrase(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    key = crypto.resolve_key(root, crypto.EncryptionOptions(passphrase="correct horse"), create=True)
    assert key is not None and len(key) == 32
    salt = json.loads((root / crypto.SALT_FILE).read_text(encoding="utf-8"))
    assert (salt["v"], salt["kdf"], salt["N"], salt["r"], salt["p"]) == (1, "scrypt", 32768, 8, 1) and len(
        base64.b64decode(salt["salt"])
    ) == 16
    crypto._derived.clear()
    assert crypto.resolve_key(root, crypto.EncryptionOptions(passphrase="correct horse")) == key
    crypto._derived.clear()
    with pytest.raises(crypto.EncryptedRunError, match="Wrong passphrase"):
        crypto.resolve_key(root, crypto.EncryptionOptions(passphrase="battery staple"))


def test_environment_selects_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STEPLIGHT_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("STEPLIGHT_PASSPHRASE", raising=False)
    assert crypto.effective_encryption() is None
    monkeypatch.setenv("STEPLIGHT_PASSPHRASE", "pw")
    assert crypto.effective_encryption() == crypto.EncryptionOptions(passphrase="pw")
    monkeypatch.setenv("STEPLIGHT_ENCRYPTION_KEY", KEY.hex())
    assert crypto.effective_encryption() == crypto.EncryptionOptions(key=KEY.hex())


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_files_are_private_on_posix(tmp_path: Path) -> None:
    writer = store.RunWriter.create(
        tmp_path / "runs", {"id": "r1", "task": "t", "startedAt": 1, "status": "running", "meta": {}}
    )
    writer.add_step(
        {
            "id": "s1",
            "runId": "r1",
            "index": 0,
            "kind": "navigate",
            "timestamp": 1,
            "flags": [],
            "url": "https://x.test/",
        },
        "text",
        {"scan": None},
    )
    for path in [
        writer.dir,
        writer.dir / "snapshots",
        writer.dir / "run.json",
        writer.dir / "steps.jsonl",
        writer.dir / "snapshots" / "s1.txt",
        writer.dir / "analysis-input.jsonl",
    ]:
        assert (path.stat().st_mode & 0o077) == 0, path
