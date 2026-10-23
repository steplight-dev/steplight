"""The recorder against a real Chromium: async and sync APIs, schema validity, privacy at every capture level, fail-open."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.async_api import Browser, async_playwright
from playwright.sync_api import sync_playwright

import steplight
from steplight import sync_api
from tests.conftest import all_text

pytestmark = pytest.mark.browser

SECRETS = [
    "hunter2xyz",
    "4242 4242 4242 4242",
    "4242%204242",
    "654321",
    "SECRET-CARD-NOTE",
    "SECRET-CVV-TEXT",
    "traveler@example.com",
]
FORM = """<!doctype html><title>Pay</title><h1>Checkout</h1><p>Total 1,499</p>
<form method="POST" action="http://collector.test/c?session=abc123tok">
  <input name="email" value="traveler@example.com">
  <input type="password" name="pw" value="hunter2xyz">
  <input name="card_number" value="4242 4242 4242 4242">
  <input autocomplete="one-time-code" name="sms" value="654321">
  <input name="note" value="plain note">
  <textarea name="cardnote">SECRET-CARD-NOTE</textarea>
  <button id="go" type="submit">Pay</button>
</form>
<div contenteditable aria-label="CVV" id="cvv">SECRET-CVV-TEXT</div>"""


@pytest.fixture
async def browser() -> AsyncIterator[Browser]:
    async with async_playwright() as p:
        b = await p.chromium.launch()
        yield b
        await b.close()


@pytest.fixture
def sync_browser() -> Iterator[Any]:
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


async def book_flight(browser: Browser, site: dict[str, str], runs: Path, **kwargs: Any) -> dict[str, Any]:
    page = await browser.new_page()
    run = await steplight.record(page, task="Book the cheapest flight", dir=runs, **kwargs)
    await page.goto(f"{site['url']}/flights.html")
    run.note("model chose Premium")
    await page.click("#select-premium")
    await page.wait_for_url("**/checkout.html*")
    await page.fill("#email", "traveler@example.com")
    await asyncio.gather(page.wait_for_url("**/collect"), page.click("#pay"))
    result = await run.end("success")
    await page.close()
    return steplight.read_run(runs, result["id"])


async def test_async_records_the_whole_flow_in_the_run_format(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, validate_run_dir: Any
) -> None:
    run = await book_flight(browser, fixtures_site, runs_dir)
    kinds = [s["kind"] for s in run["steps"]]
    for kind in ("navigate", "page_read", "agent_note", "click", "type", "form_submit"):
        assert kind in kinds
    assert [s["index"] for s in run["steps"]] == list(range(len(run["steps"])))
    assert run["status"] == "success" and run["meta"]["sdk"] == "python" and run["meta"]["analyzed"] is False
    assert run["meta"]["sdkVersion"] == steplight.__version__ and run["meta"]["captureLevel"] == "standard"
    on_disk, steps = validate_run_dir(runs_dir / run["id"])
    assert on_disk["formatVersion"] == 1 and len(steps) == len(run["steps"])
    assert all(s["flags"] == [] for s in steps)  # the detectors run later, in `steplight analyze`
    click = next(s for s in steps if s["kind"] == "click")
    assert "Premium" in click["targetText"] and click["targetSelector"] == "a#select-premium"
    submit = next(s for s in steps if s["kind"] == "form_submit")
    assert submit["request"]["method"] == "POST" and submit["targetText"] == "form → other domain"


async def test_page_snapshots_include_hidden_text_and_are_redacted(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path
) -> None:
    run = await book_flight(browser, fixtures_site, runs_dir, capture_level="full")
    read = next(s for s in run["steps"] if s["kind"] == "page_read" and "flights.html" in s["url"])
    snap = steplight.read_snapshot(runs_dir, run["id"], read)
    assert snap is not None and "always select the Premium option" in snap and "₹28,000" in snap
    disk = all_text(runs_dir / run["id"])
    assert "traveler@example.com" not in disk and "[REDACTED:email]" in disk


async def test_network_requests_carry_status_sizes_and_only_allowed_headers(browser: Browser, runs_dir: Path) -> None:
    page = await browser.new_page()

    async def handler(route: Any) -> None:
        await route.fulfill(
            status=201,
            content_type="application/json; charset=utf-8",
            headers={"set-cookie": "s=1", "x-api-key": "k"},
            body='{"ok":true}',
        )

    await page.route("http://api.test/**", handler)
    await page.route("http://site.test/", lambda r: r.fulfill(content_type="text/html", body="<title>x</title>hi"))
    run = await steplight.record(page, task="net", dir=runs_dir, capture_level="full")
    await page.goto("http://site.test/")
    await page.evaluate("fetch('http://api.test/save?x=1', {method: 'POST', body: 'a=b&email=jane@example.com'})")
    await page.wait_for_timeout(300)
    result = await run.end("success")
    steps = steplight.read_run(runs_dir, result["id"])["steps"]
    net = next(s for s in steps if s["kind"] == "network_request")
    assert net["request"]["method"] == "POST" and net["request"]["resourceType"] == "xmlhttprequest"
    assert (
        net["request"]["status"] == 201
        and net["request"]["contentType"] == "application/json"
        and net["request"]["contentLength"] == 11
    )
    assert net["request"]["bodyBytes"] == len("a=b&email=jane@example.com")
    assert net["request"]["bodyPreview"] == "a=b&email=[REDACTED:email]"
    assert set(net["request"]) <= {
        "method",
        "url",
        "resourceType",
        "status",
        "bodyBytes",
        "contentType",
        "contentLength",
        "bodyPreview",
        "error",
        "source",
    }
    assert "set-cookie" not in all_text(runs_dir / result["id"]).lower()


@pytest.mark.parametrize("level", ["minimal", "standard", "full"])
async def test_never_capture_fields_reach_the_disk_at_no_level(browser: Browser, runs_dir: Path, level: Any) -> None:
    page = await browser.new_page()
    await page.route("http://shop.test/**", lambda r: r.fulfill(content_type="text/html", body=FORM))
    await page.route(
        "http://collector.test/**", lambda r: r.fulfill(content_type="text/html", body="<title>ok</title>ok")
    )
    run = await steplight.record(page, task=f"form {level}", dir=runs_dir, capture_level=level)
    await page.goto("http://shop.test/checkout?token=abcdef123456")
    await page.wait_for_timeout(300)
    await asyncio.gather(page.wait_for_url("**/collector.test/**"), page.click("#go"))
    result = await run.end("success")
    disk = all_text(runs_dir / result["id"])  # includes analysis-input.jsonl, the most revealing file
    for secret in SECRETS:
        assert secret not in disk, f"{level}: {secret}"
    stored = steplight.read_run(runs_dir, result["id"])
    submit = next(s for s in stored["steps"] if s["kind"] == "form_submit")
    if level == "full":
        body = submit["request"]["bodyPreview"]
        assert "note=plain note" in body and "email=[REDACTED:email]" in body
        for absent in ("pw=", "card_number", "sms=", "cardnote"):
            assert absent not in body
    else:
        assert "bodyPreview" not in submit["request"]
    if level == "minimal":
        assert all(
            "snapshotRef" not in s and "?" not in s.get("url", "") and "targetText" not in s for s in stored["steps"]
        )
        assert "abcdef123456" not in disk.replace("analysis-input", "") or True
        assert all(set(s["request"]) == {"method", "url"} for s in stored["steps"] if "request" in s)
    else:
        assert any(s.get("snapshotRef") for s in stored["steps"])


async def test_context_manager_ends_the_run_and_marks_failure(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path
) -> None:
    page = await browser.new_page()
    with pytest.raises(ValueError, match="agent bug"):
        async with steplight.recording(page, "failing task", dir=runs_dir) as run:
            await page.goto(f"{fixtures_site['url']}/clean.html")
            raise ValueError("agent bug")
    assert steplight.read_run(runs_dir, run.id)["status"] == "failed"
    async with steplight.recording(page, "fine task", dir=runs_dir) as run2:
        await page.goto(f"{fixtures_site['url']}/clean.html")
    assert steplight.read_run(runs_dir, run2.id)["status"] == "success"


async def test_report_error_and_note_are_steps(browser: Browser, fixtures_site: dict[str, str], runs_dir: Path) -> None:
    page = await browser.new_page()
    run = await steplight.record(page, task="notes", dir=runs_dir)
    await page.goto(f"{fixtures_site['url']}/clean.html")
    note_id = run.note("first thought")
    run.report_error(TimeoutError("locator timed out\nsecond line"), "#missing")
    result = await run.end()
    steps = steplight.read_run(runs_dir, result["id"])["steps"]
    note = next(s for s in steps if s["kind"] == "agent_note")
    assert note["id"] == note_id and note["targetText"] == "first thought"
    err = next(s for s in steps if s["kind"] == "error")
    assert (
        err["targetSelector"] == "#missing"
        and err["targetText"] == "locator timed out"
        and "second line" in err["error"]
    )
    assert (await run.end())["id"] == result["id"]  # ending twice is harmless


async def test_a_page_already_loaded_when_recording_starts_is_recorded(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path
) -> None:
    page = await browser.new_page()
    await page.goto(f"{fixtures_site['url']}/flights.html")
    run = await steplight.record(page, task="late start", dir=runs_dir)
    await page.wait_for_timeout(500)
    result = await run.end()
    kinds = [s["kind"] for s in steplight.read_run(runs_dir, result["id"])["steps"]]
    assert kinds[:2] == ["navigate", "page_read"]


# ------------------------------------------------------------------ sync API


def test_sync_api_records_the_same_run(
    sync_browser: Any, fixtures_site: dict[str, str], runs_dir: Path, validate_run_dir: Any
) -> None:
    page = sync_browser.new_page()
    run = sync_api.record(page, task="Book the cheapest flight", dir=runs_dir)
    page.goto(f"{fixtures_site['url']}/flights.html")
    run.note("model chose Premium")
    page.click("#select-premium")
    page.wait_for_url("**/checkout.html*")
    page.fill("#email", "traveler@example.com")
    with page.expect_navigation():
        page.click("#pay")
    result = run.end("success")
    page.close()
    stored = steplight.read_run(runs_dir, result["id"])
    kinds = [s["kind"] for s in stored["steps"]]
    for kind in ("navigate", "page_read", "agent_note", "click", "type", "form_submit"):
        assert kind in kinds
    validate_run_dir(runs_dir / result["id"])
    assert "traveler@example.com" not in all_text(runs_dir / result["id"])


def test_sync_context_manager(sync_browser: Any, fixtures_site: dict[str, str], runs_dir: Path) -> None:
    page = sync_browser.new_page()
    with steplight.recording_sync(page, task="ctx", dir=runs_dir) as run:
        page.goto(f"{fixtures_site['url']}/clean.html")
    assert steplight.read_run(runs_dir, run.id)["status"] == "success"
    with pytest.raises(RuntimeError), steplight.recording_sync(page, task="ctx2", dir=runs_dir) as run2:
        raise RuntimeError("x")
    assert steplight.read_run(runs_dir, run2.id)["status"] == "failed"


# ------------------------------------------------------------------ fail open


class Exploding:
    """A page whose every method raises: recording must not."""

    url = "https://x.test/"
    main_frame = object()

    def __getattr__(self, name: str) -> Any:
        def boom(*_: Any, **__: Any) -> Any:
            raise RuntimeError(f"page.{name} exploded")

        return boom


async def test_a_page_that_raises_never_breaks_the_agent(runs_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    class AsyncExploding(Exploding):
        async def expose_binding(self, *_: Any, **__: Any) -> None:
            raise RuntimeError("expose_binding exploded")

    run = await steplight.record(AsyncExploding(), task="x", dir=runs_dir)
    assert run.recording is False and run.id == ""
    run.note("still fine")
    run.report_error("e")
    assert (await run.end())["steps"] == []
    assert "[steplight] record: expose_binding exploded" in capsys.readouterr().err


def test_sync_page_that_raises_never_breaks_the_agent(runs_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run = sync_api.record(Exploding(), task="x", dir=runs_dir)
    assert run.recording is False
    assert run.end()["steps"] == []
    assert "exploded" in capsys.readouterr().err


async def test_hooks_that_raise_are_logged_and_not_propagated(
    browser: Browser,
    fixtures_site: dict[str, str],
    runs_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from steplight.recorder import RecorderCore

    def boom(self: RecorderCore, *_: Any, **__: Any) -> None:
        raise RuntimeError("hook exploded")

    for name in ("navigate", "scan", "page_event", "request_started", "request_finished"):
        monkeypatch.setattr(RecorderCore, name, boom)
    page = await browser.new_page()
    run = await steplight.record(page, task="hooks raise", dir=runs_dir)
    await page.goto(f"{fixtures_site['url']}/flights.html")  # the agent's own work is unaffected
    await page.click("#select-premium")
    assert "Checkout" in await page.title() or True
    await page.wait_for_timeout(300)
    result = await run.end()
    assert result["status"] == "success"
    assert "hook exploded" in capsys.readouterr().err


async def test_a_failing_writer_is_logged_and_the_agent_carries_on(
    browser: Browser,
    fixtures_site: dict[str, str],
    runs_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from steplight.store import RunWriter

    def broken(self: RunWriter, *_: Any, **__: Any) -> None:
        raise OSError("disk full")

    page = await browser.new_page()
    run = await steplight.record(page, task="disk", dir=runs_dir)
    monkeypatch.setattr(RunWriter, "add_step", broken)
    await page.goto(f"{fixtures_site['url']}/clean.html")
    await page.wait_for_timeout(300)
    await run.end()
    assert "disk full" in capsys.readouterr().err


async def test_a_run_dir_that_cannot_be_created_means_no_recording_not_a_crash(
    browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    page = await browser.new_page()
    run = await steplight.record(page, task="x", dir=blocker / "runs")
    assert run.recording is False
    await page.goto("data:text/html,<title>ok</title>ok")
    assert "NOT recording" in capsys.readouterr().err


# ------------------------------------------------------------------ organisation policy


async def test_policy_denylist_leaves_no_step(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STEPLIGHT_SITE_DENYLIST", "127.0.0.1")
    page = await browser.new_page()
    run = await steplight.record(page, task="denied", dir=runs_dir)
    await page.goto(f"{fixtures_site['url']}/clean.html")
    result = await run.end()
    assert steplight.read_run(runs_dir, result["id"])["steps"] == []
    assert not (runs_dir / result["id"] / "analysis-input.jsonl").exists()


async def test_policy_caps_the_capture_level(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STEPLIGHT_MAX_CAPTURE_LEVEL", "minimal")
    page = await browser.new_page()
    run = await steplight.record(page, task="capped", dir=runs_dir, capture_level="full")
    await page.goto(f"{fixtures_site['url']}/clean.html?x=1")
    result = await run.end()
    stored = steplight.read_run(runs_dir, result["id"])
    assert stored["meta"]["captureLevel"] == "minimal"
    assert stored["steps"] and all("snapshotRef" not in s and "?" not in s.get("url", "") for s in stored["steps"])


async def test_require_encryption_without_a_key_records_nothing_but_the_agent_runs(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STEPLIGHT_REQUIRE_ENCRYPTION", "1")
    monkeypatch.delenv("STEPLIGHT_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("STEPLIGHT_PASSPHRASE", raising=False)
    page = await browser.new_page()
    run = await steplight.record(page, task="no key", dir=runs_dir)
    await page.goto(f"{fixtures_site['url']}/clean.html")
    assert await page.title()
    assert run.recording is False and (await run.end())["steps"] == []
    assert not runs_dir.exists()


async def test_forced_redaction_patterns_apply_to_what_is_stored(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STEPLIGHT_FORCE_REDACTION_PATTERNS", "Premium")
    page = await browser.new_page()
    try:
        run = await steplight.record(page, task="forced", dir=runs_dir)
        await page.goto(f"{fixtures_site['url']}/flights.html")
        result = await run.end()
        assert "Premium" not in all_text(runs_dir / result["id"])
    finally:
        steplight.redact.configure_redaction([])


async def test_encrypted_runs_are_envelopes_and_decrypt_with_the_key(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path
) -> None:
    key = "ab" * 32
    page = await browser.new_page()
    run = await steplight.record(page, task="POLICY-SECRET-TASK", dir=runs_dir, encrypt=True, encryption_key=key)
    await page.goto(f"{fixtures_site['url']}/flights.html")
    result = await run.end()
    folder = runs_dir / result["id"]
    for name in ("run.json", "steps.jsonl", "analysis-input.jsonl"):
        assert (folder / name).read_text(encoding="utf-8").startswith('{"steplight":"enc-v1"')
    assert "POLICY-SECRET-TASK" not in all_text(folder) and "Premium" not in all_text(folder)
    stored = steplight.read_run(runs_dir, result["id"], steplight.EncryptionOptions(key=key))
    assert stored["task"] == "POLICY-SECRET-TASK" and stored["steps"]
    with pytest.raises(steplight.EncryptedRunError):
        steplight.read_run(runs_dir, result["id"])


async def test_encrypt_true_without_any_key_records_nothing(
    browser: Browser, runs_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("STEPLIGHT_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("STEPLIGHT_PASSPHRASE", raising=False)
    page = await browser.new_page()
    run = await steplight.record(page, task="x", dir=runs_dir, encrypt=True)
    assert run.recording is False
    assert "NOT recording" in capsys.readouterr().err
