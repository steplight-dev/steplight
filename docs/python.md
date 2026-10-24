# Steplight for Python

The `steplight-sdk` Python package (import name `steplight`) records Playwright (async and sync) and [Browser Use](https://github.com/browser-use/browser-use) runs into the same run format as the TypeScript SDK and the Chrome extension. Everything downstream is unchanged: `steplight view`, `diff`, `check`, `report`, `export` and the GitHub Action read the Python runs like any other.

Package README with the three examples: [python/README.md](../python/README.md). Runnable demo: [examples/python-demo/](../examples/python-demo/README.md).

## How it fits together

```
 your Python agent ── steplight.record(page) ──▶ .steplight/runs/<runId>/   ──▶ steplight analyze ──▶ flags
 (Playwright / Browser Use)   redacted at source    run.json, steps.jsonl,         (Node CLI, same          view · diff · check ·
                                                    snapshots/                      detectors as the TS SDK) report · GitHub Action
```

- The **Python package** has no required dependencies and makes no network calls. It captures, redacts, applies policy, optionally encrypts and writes the run folder.
- The **detectors** (hidden instructions, data leaving the page, loops) run in the Node CLI so there is one implementation. The Python recorder writes the run with `meta.analyzed = false` and the redacted material the detectors need; `steplight analyze <runId>` (or `--all`) adds the flags and removes that material. `view`, `check`, `diff`, `report`, `export`, `tokens` and the GitHub Action run it automatically, so you rarely call it yourself. From Python: `steplight.analyze(".steplight/runs", run_id)`.
- The run format is a versioned contract in [spec/](../spec): a JSON Schema, 562 redaction test vectors generated from the TypeScript engine (the Python port passes all of them), the never-capture rules, and the single in-page scan script both SDKs inject.

> Not related to the PyPI package `steplight`; if you have it installed, both use the `steplight` import name.

Install the CLI next to your Python project: `npm i -D steplight` (needs Node 20+). Without it the recording still works; you just cannot analyze, view or check.

## Playwright

```python
import steplight

run = await steplight.record(page, task="Book the cheapest flight")   # async API
run = steplight.record_sync(page, task="...")                         # sync API
...
await run.end("success")                                             # sync: run.end("success")
```

Context managers end the run for you (`success`, or `failed` if the block raises): `async with await steplight.record(...)` and `with steplight.recording_sync(page, task=...)`. It records navigation, clicks, field changes (never the values), form submits, fetch/XHR/beacons/image/WebSocket requests and downloads, scans each page inside the browser at load time and about a second later, and wraps `page.click/fill/type/check/select_option/press/goto` so failed actions become `error` steps with a diagnosis hint before the original exception is re-raised. `run.note(text)` adds an `agent_note`; `run.report_error(err, selector)` records failures of `Locator` actions.

A run is bound to the page (and its browser context for new tabs). Recording the same page again later starts a new run.

## Browser Use

```python
from steplight.integrations import browser_use as steplight_bu

async with steplight_bu.recording(agent) as run:
    await agent.run()
```

- **Supported versions:** `browser-use>=0.7,<0.14`, Python 3.11+ (what Browser Use itself needs). Tested against 0.7.12, 0.9.7, 0.12.x and 0.13.11 with a scripted fake LLM. 0.6 and older are not supported; 0.14+ is untested and excluded by the extra until it has been checked.
- **How it attaches:** Browser Use 0.13 drives Chrome over CDP, not Playwright. Steplight connects Playwright to the same browser with `connect_over_cdp` (lazily, once the agent has started the browser) and records through the context-level hooks. If the connection cannot be made, the agent continues unrecorded and a warning goes to stderr.
- **Decision trace:** `register_new_step_callback` records one `agent_note` per model step (goal, actions, reasoning). The browser steps that follow carry `decidedBy`, pointing at that note; the viewer and HTML report show "decided by" links. The model's output is redacted like everything else; typed text parameters are replaced by `<N chars>`.
- **Fails open:** every hook is wrapped; an adapter error cannot stop or slow the agent. Without a done callback the run is ended by `recording()` / `await run.end()`.

## Options

See the table in [python/README.md](../python/README.md#options). Capture levels, encryption, OpenTelemetry and policy behave as in the [Node SDK](../README.md#sdk-playwright) and [enterprise guide](enterprise.md). Specifics:

- **Encryption** needs `pip install "steplight-sdk[crypto]"`. The envelope format is identical to the Node CLI's (AES-256-GCM, AAD `<runId>/<file>`, scrypt N=32768 r=8 p=1 for passphrases, salt in `.steplight-enc.json`), tested in both directions. The CLI reads Python runs with `STEPLIGHT_ENCRYPTION_KEY` or `STEPLIGHT_PASSPHRASE`.
- **OpenTelemetry** needs `steplight-sdk[otel]`. Spans use the same names and attributes as the TypeScript SDK (`steplight.run`, `steplight.step.<kind>`, `steplight.flag`…). Because the flags come from the CLI, the spans Python exports at `end()` carry no flags; to export spans with flags, analyze first and export with the CLI: `steplight export <runId> --otlp`.
- **Files:** the runs folder is created `0700` and files `0600` on POSIX. On Windows they inherit the folder ACL.

## CI: fail the build when a Python agent misbehaves

```yaml
# .github/workflows/agent-check.yml
name: agent-check
on: [pull_request]
permissions:
  contents: read
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>          # pin every action by SHA
      - uses: actions/setup-python@<full-commit-sha>
        with: { python-version: "3.12" }
      - uses: actions/setup-node@<full-commit-sha>
        with: { node-version: "22" }
      - run: pip install "steplight-sdk[playwright]" && playwright install --with-deps chromium
      - run: npm i -D steplight
      - run: python run_agent.py                           # your agent, recording with steplight.record(...)
      - run: npx steplight check --latest --rules steplight.rules.yml --format sarif --out steplight.sarif
```

`steplight check` analyzes the run itself, so no extra step is needed. The [Steplight Agent Check](github-actions.md) Action reads the same runs (`fail-on: high`), and the rules file (`max_steps`, `max_severity`, `must_visit`, `must_not_visit_domains`, `no_stuck_loops`) is documented in the [GitHub Actions guide](github-actions.md#3-write-the-rules). The Action analyzes unanalyzed runs the same way.

## Privacy and security

- Redaction happens in Python before anything is queued for disk, then again when the file is written. It is a faithful port of the TypeScript engine (UTF-16 lengths, JavaScript `\s`, ASCII `\b`, linear-time card detection) and fails closed.
- Password, card, one-time-code and payment-frame fields are never read; typed values are never recorded; request headers are never captured. The rules are data in [spec/never-capture.json](../spec/never-capture.json), shared with TypeScript.
- A hostile page cannot flood the recorder: page-supplied data is size-capped and network/WebSocket steps are capped per run. A page that tampers with the in-page hook can stop its own capture but cannot write into the run.
- The package imports no network modules (a test enforces it). The only connections are the browser's, and (if you configure it) your OTLP collector.
- See the [threat model](THREAT_MODEL.md) for the Python trust boundary.

## Supply chain and releases

The package is published to PyPI from GitHub Actions with **Trusted Publishing (OIDC)** and attestations; no PyPI token exists. Pre-release tags (`v0.2.0-rc.1`) go to TestPyPI. A release is refused unless the tag matches the npm versions and the Python version (PEP 440), and the sdist and wheel contain only the package, `py.typed`, `page-scan.js`, license and metadata. CI runs ruff, `mypy --strict`, pytest on Python 3.10–3.13 × Ubuntu/Windows, `pip-audit`, a Python CycloneDX SBOM, and Dependabot (`uv`, with the same cooldown as npm). Steps for maintainers: [releasing.md](releasing.md).

## Known gaps

- Python does **not** run the detectors itself; analysis needs the Node CLI (`npm i -D steplight`). Runs are only viewable after analysis.
- No failure diagnosis on Python errors yet (`report_error` records an error step without the "covered / disabled / off-screen" hint).
- Browser Use: CDP only; multi-tab network capture follows the recorded browser context; 0.14+ is untested.
- `pip-audit` reports known vulnerabilities in packages pinned by Browser Use 0.13 itself; the CI leg for that extra warns instead of failing. The core package and the other extras must be clean.
- Redaction is pattern-based; names and addresses are not detected. Use `capture_level="minimal"` for sensitive sites.
