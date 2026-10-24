# steplight-sdk (Python)

> Not related to the PyPI package `steplight`; if you have it installed, both use the `steplight` import name.

A flight recorder for AI agents that drive a browser. This package records **Playwright** (async and sync) and **Browser Use** runs into the Steplight run format, so the `steplight` CLI (view, replay, diff, check, report) and the GitHub Action work on them unchanged. Everything is redacted before it is written and nothing leaves your machine: no telemetry, no accounts, no network calls of its own.

- **No required dependencies.** The recorder, the redaction engine and the run writer use the standard library. Extras: `playwright`, `browser-use`, `otel`, `crypto`.
- **Python 3.10 – 3.13**, Linux, macOS and Windows. Typed (`py.typed`).
- **Fails open for your agent:** a recorder error goes to stderr and the agent keeps running. **Fails closed for privacy:** if redaction fails, the data is dropped.

```bash
pip install "steplight-sdk[playwright]"        # or steplight-sdk[browser-use], steplight-sdk[otel], steplight-sdk[crypto]
npm i -D steplight                         # the CLI that flags, views and checks the runs
```

Python records; the Node CLI analyzes. A run is written with the redacted material the detectors need, and `steplight analyze` (run automatically by `view`, `check`, `diff`, `report` and `export`, or call `steplight.analyze(...)`) produces the flags with the same detectors as the TypeScript SDK.

## 1. Playwright, async

```python
import asyncio
import steplight
from playwright.async_api import async_playwright


async def main() -> None:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page()
        async with await steplight.record(page, task="Book the cheapest flight") as run:
            await page.goto("https://airline.example/flights")
            run.note("Comparing fares")  # optional: your agent's reasoning
            await page.click("text=Select Economy")
        await browser.close()


asyncio.run(main())
```

## 2. Playwright, sync

```python
import steplight
from playwright.sync_api import sync_playwright

with sync_playwright() as pw:
    page = pw.chromium.launch().new_page()
    with steplight.recording_sync(page, task="Book the cheapest flight") as run:
        page.goto("https://airline.example/flights")
        page.click("text=Select Economy")
```

The run ends as `success`, or as `failed` if the block raises (the exception is re-raised untouched).

## 3. Browser Use

```python
import asyncio
from browser_use import Agent, ChatOpenAI
from steplight.integrations import browser_use as steplight_bu


async def main() -> None:
    agent = Agent(task="Find the cheapest flight to Lisbon", llm=ChatOpenAI(model="gpt-4.1"))
    async with steplight_bu.recording(agent) as run:
        await agent.run()


asyncio.run(main())
```

Every model step is recorded as an `agent_note` (the model's goal, chosen actions and reasoning), and the browser steps it chose are linked back to that note (`decidedBy`), so the viewer shows *why* the agent did each thing. Typed text is never stored (only `<N chars>`). Tested with Browser Use 0.7 – 0.13 (Python 3.11+); older versions are not supported.

## Then use the CLI

```bash
npx steplight view                                          # timeline, replay, hidden text highlighted
npx steplight check --latest --rules steplight.rules.yml    # CI: exit 1 when the rules are broken
npx steplight diff <runA> <runB>                            # first point of divergence
```

## Options

`record(page, task, *, dir, capture_level, meta, otel, encrypt, encryption_key, passphrase)`

| Option | Meaning |
|---|---|
| `dir` | Runs folder (default `$STEPLIGHT_DIR` or `.steplight/runs`). Created `0700`, files `0600` on POSIX. |
| `capture_level` | `"minimal"`, `"standard"` (default) or `"full"`: what is written to disk. Detectors always see everything first. |
| `encrypt`, `encryption_key`, `passphrase` | AES-256-GCM at rest (needs `steplight-sdk[crypto]`). Byte-compatible with the Node CLI, which reads these runs given the same key or passphrase (`STEPLIGHT_ENCRYPTION_KEY` / `STEPLIGHT_PASSPHRASE`). |
| `otel` | Export OpenTelemetry spans on `end()` (needs `steplight-sdk[otel]`); on by default only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. |
| `meta` | Extra string metadata stored on the run. |

Organisation policy (`STEPLIGHT_POLICY_FILE`, `steplight.config.json`, `STEPLIGHT_*` variables: capture-level cap, site deny/allow lists, required encryption…) works as in the Node SDK and can only tighten settings; if a policy cannot be honoured nothing is recorded and the agent keeps running (`run.recording` is `False`).

For failures the recorder cannot see (for example `locator.click()`), call `run.report_error(err, "#selector")`.

Full guide, CI usage, privacy notes and known gaps: [docs/python.md](https://github.com/steplight-dev/steplight/blob/main/docs/python.md). License: Apache-2.0.
