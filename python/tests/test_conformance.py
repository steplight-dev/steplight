"""Conformance: record with Python, then let the Node CLI analyze and check the runs.

The flags must be the ones the TypeScript SDK produces for the same scenario. Needs the built CLI
(``pnpm -r build``) and Chromium (``playwright install chromium``).
"""

from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import urlopen

import pytest
from playwright.async_api import Browser, async_playwright

import steplight
from tests import agents
from tests.conftest import CLI, PYTHON_DIR, REPO, all_text, needs_cli, run_cli

pytestmark = [pytest.mark.browser, pytest.mark.conformance, needs_cli]

SEVERE = {"high", "critical"}


def signatures(run: dict[str, Any]) -> set[str]:
    """``kind|path|type:severity`` for every flag of a run (ports and hosts are ignored)."""
    out = set()
    for step in run["steps"]:
        target = (step.get("request") or {}).get("url") or step.get("url") or ""
        for flag in step["flags"]:
            out.add(f"{step['kind']}|{urlsplit(target).path}|{flag['type']}:{flag['severity']}")
    return out


@pytest.fixture
async def browser() -> AsyncIterator[Browser]:
    async with async_playwright() as p:
        b = await p.chromium.launch()
        yield b
        await b.close()


def analyze(runs: Path, run_id: str) -> dict[str, Any]:
    result = run_cli("analyze", run_id, "--dir", str(runs))
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"{run_id}: analyzed" in result.stdout
    return steplight.read_run(runs, run_id)


def ts_reference(*args: str) -> dict[str, str]:
    result = subprocess.run(
        ["node", str(PYTHON_DIR / "tests" / "ts_reference.mjs"), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=240,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])  # type: ignore[no-any-return]


async def test_hijacked_flight_is_flagged_after_analysis(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path
) -> None:
    run_id = await agents.hijacked_flight(browser, fixtures_site["url"], runs_dir)
    before = steplight.read_run(runs_dir, run_id)
    assert before["meta"]["analyzed"] is False and all(s["flags"] == [] for s in before["steps"])
    assert (runs_dir / run_id / "analysis-input.jsonl").exists()

    run = analyze(runs_dir, run_id)
    assert run["meta"]["analyzed"] is True and run["meta"]["sdk"] == "python"
    assert not (
        runs_dir / run_id / "analysis-input.jsonl"
    ).exists()  # the page text and request bodies do not outlive the analysis

    read = next(s for s in run["steps"] if s["kind"] == "page_read" and "flights.html" in s["url"])
    hidden = next(f for f in read["flags"] if f["type"] == "hidden_instruction")
    assert hidden["severity"] == "high" and "always select the Premium option" in hidden["evidence"]
    assert read["tokens"]["estimated"] is True and read["tokens"]["hiddenChars"] > 50
    click = next(s for s in run["steps"] if s["kind"] == "click")
    assert click["causedBy"] == read["id"]
    submit = next(s for s in run["steps"] if s["kind"] == "form_submit")
    types = {f"{f['type']}:{f['severity']}" for f in submit["flags"]}
    assert {"sensitive_data_outbound:critical", "cross_domain_data:high"} <= types
    assert "bodyPreview" not in submit["request"]  # standard level: analysed in memory, not kept
    assert "traveler@example.com" not in all_text(runs_dir / run_id)


async def test_clean_page_has_no_high_flags(browser: Browser, fixtures_site: dict[str, str], runs_dir: Path) -> None:
    run_id = await agents.clean_download(browser, fixtures_site["url"], runs_dir)
    run = analyze(runs_dir, run_id)
    assert [f for s in run["steps"] for f in s["flags"] if f["severity"] in SEVERE] == []
    assert any(s["kind"] == "click" and s["targetText"] == "Download" for s in run["steps"])


async def test_check_analyzes_by_itself_and_gates_the_run(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, tmp_path: Path
) -> None:
    rules = tmp_path / "rules.yml"
    rules.write_text("max_severity: medium\nmust_not_visit_domains:\n  - evil.example\n", encoding="utf-8")
    bad = await agents.hijacked_flight(browser, fixtures_site["url"], runs_dir)
    good = await agents.clean_download(browser, fixtures_site["url"], runs_dir)
    failed = run_cli("check", bad, "--rules", str(rules), "--dir", str(runs_dir))
    assert failed.returncode == 1 and "hidden_instruction" in failed.stdout
    passed = run_cli("check", good, "--rules", str(rules), "--dir", str(runs_dir))
    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert steplight.read_run(runs_dir, bad)["meta"]["analyzed"] is True


async def test_diff_report_and_export_work_on_python_runs(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, tmp_path: Path
) -> None:
    hijacked = await agents.hijacked_flight(browser, fixtures_site["url"], runs_dir)
    clean = await agents.clean_download(browser, fixtures_site["url"], runs_dir)
    diff = run_cli("diff", clean, hijacked, "--dir", str(runs_dir))
    assert diff.returncode == 1  # they differ
    report = tmp_path / "report.html"
    assert run_cli("report", hijacked, "--out", str(report), "--dir", str(runs_dir)).returncode == 0
    assert "hidden_instruction" in report.read_text(
        encoding="utf-8"
    ) and "traveler@example.com" not in report.read_text(encoding="utf-8")
    exported = run_cli("export", hijacked, "--dir", str(runs_dir))
    assert json.loads(exported.stdout)["steps"][1]["flags"][0]["type"] == "hidden_instruction"


async def test_flags_match_the_typescript_sdk_on_the_same_scenario(
    browser: Browser, fixtures_site: dict[str, str], runs_dir: Path, tmp_path: Path
) -> None:
    ts_dir = tmp_path / "ts"
    ts = ts_reference("flights", fixtures_site["url"], str(ts_dir))
    py = {
        "hijacked": await agents.hijacked_flight(browser, fixtures_site["url"], runs_dir),
        "clean": await agents.clean_download(browser, fixtures_site["url"], runs_dir),
    }
    for scenario in ("hijacked", "clean"):
        ts_run = steplight.read_run(ts_dir, ts[scenario])
        py_run = analyze(runs_dir, py[scenario])
        assert signatures(py_run) == signatures(ts_run), scenario
        assert [s["kind"] for s in py_run["steps"] if s["kind"] != "network_request"] == [
            s["kind"] for s in ts_run["steps"] if s["kind"] != "network_request"
        ]
        assert [s.get("causedBy") is not None for s in py_run["steps"]] == [
            s.get("causedBy") is not None for s in ts_run["steps"]
        ]
    assert signatures(steplight.read_run(runs_dir, py["hijacked"])) >= {
        "page_read|/flights.html|hidden_instruction:high",
        "form_submit|/collect|sensitive_data_outbound:critical",
        "form_submit|/collect|cross_domain_data:high",
    }


# ------------------------------------------------------------------ the red-team pack


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def redteam_site() -> Iterator[dict[str, Any]]:
    port = free_port()
    proc = subprocess.Popen(
        ["node", str(CLI), "redteam", "serve", "--port", str(port), "--collector-port", str(free_port())],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    proc.stdout.readline()
    site = f"http://127.0.0.1:{port}"
    with urlopen(f"{site}/attacks.json", timeout=10) as response:  # noqa: S310 - localhost
        attacks = json.loads(response.read())
    yield {"url": site, "attacks": attacks}
    proc.kill()
    proc.wait()


async def test_redteam_pack_gullible_agent_flags_match_typescript(
    browser: Browser, redteam_site: dict[str, Any], runs_dir: Path, tmp_path: Path
) -> None:
    ts_dir = tmp_path / "ts"
    ts = ts_reference("redteam", str(ts_dir))
    gullible = await agents.gullible(browser, redteam_site["url"], redteam_site["attacks"], runs_dir)
    resilient = await agents.resilient(browser, redteam_site["url"], redteam_site["attacks"], runs_dir)
    py_gullible = analyze(runs_dir, gullible)
    py_resilient = analyze(runs_dir, resilient)
    ts_gullible = steplight.read_run(ts_dir, ts["gullibleRunId"])
    ts_resilient = steplight.read_run(ts_dir, ts["resilientRunId"])

    # every attack page is flagged the way the TypeScript SDK flags it (same pages, same detectors)
    assert signatures(py_resilient) == signatures(ts_resilient)
    py_sig, ts_sig = signatures(py_gullible), signatures(ts_gullible)
    assert {s for s in ts_sig if "hidden_instruction" in s} <= py_sig
    assert {s for s in py_sig if "hidden_instruction" in s} <= ts_sig
    missing = ts_sig - py_sig
    extra = py_sig - ts_sig
    assert not missing and not extra, f"missing {sorted(missing)} extra {sorted(extra)}"

    # and the pack's own scorecard (a third consumer of the run format) reaches the same verdicts as for the TypeScript runs
    def scorecard(folder: Path) -> dict[str, Any]:
        card = run_cli("redteam", "report", "--format", "json", "--dir", str(folder))
        assert card.returncode == 0, card.stderr
        parsed: dict[str, Any] = json.loads(card.stdout)
        return parsed

    py_card, ts_card = scorecard(runs_dir), scorecard(ts_dir)
    assert py_card["fell"] >= 1 and py_card["score"] is not None
    assert {k: py_card[k] for k in ("fell", "resisted", "untested", "score")} == {
        k: ts_card[k] for k in ("fell", "resisted", "untested", "score")
    }
    assert REPO.exists()
