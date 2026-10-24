# Progress

## 0.2.0 (Python SDK): in progress

Task list (updated as parts finish):

- [x] A. Shared contract: `spec/run-format.schema.json`, `redaction-vectors.json` (562 cases), `never-capture.json`, `page-scan.js` (TS SDK uses the same file); `pnpm spec` regenerates, tests detect drift
- [x] B. `steplight analyze` + auto-analysis in view/check/diff/report/export/tokens/check-action (hand-made unanalyzed fixture tests in core, cli, check-action)
- [x] C. Python package (`python/`): recorder, redaction port (562/562 vectors), encryption (both directions with Node), policy, OTel; ruff + mypy --strict clean
- [x] D. Browser Use integration (CDP attach + decision trace via decidedBy; browser-use 0.7-0.13 tested with a scripted LLM)
- [~] E. 703 pytest tests incl. conformance (Python flags == TS flags, red-team scorecard identical), cross-language encryption, perf guard; Browser Use tests follow Part D
- [x] F. Tooling (uv, ruff, mypy --strict), CI matrix 3.10-3.13 x ubuntu/windows, pip-audit, Dependabot (uv), Python SBOM
- [x] G. Release pipeline (PyPI / TestPyPI trusted publishing, content + version gates; environments created; NOT tagged)
- [ ] H. Docs

## npm: 0.1.0 (final)

- Five packages: `steplight` (new, unscoped: SDK + `steplight` command), `@steplight/core`, `sdk`, `cli`, `redteam`. `0.1.0-rc.3` validated the unscoped package and its Trusted Publisher in CI: all five on `next` with provenance, `latest` untouched; fresh-install smoke test (`npm i -D steplight@next playwright`, `--version`, `--help`, record a local page, `check --latest`) and `npm audit signatures` (npm 11: 22 signatures, 20 attestations verified) passed.
- 0.1.0 is tagged `v0.1.0` and published by the same workflow as `latest`; see CHANGELOG.md and docs/releasing.md, docs/github-actions.md.

## npm: 0.1.0-rc.2 published through GitHub OIDC trusted publishing

- `@steplight/core`, `sdk`, `cli`, `redteam` @ `0.1.0-rc.2` are on npm under the `next` dist-tag (`latest` still `0.0.1`), published by the Release workflow from tag `v0.1.0-rc.2` (commit 981da07) with signed provenance (SLSA v1, repository `steplight-dev/steplight`, workflow `release.yml`). No npm token exists anywhere; the trusted publishers are validated by this publish.
- `v0.1.0-rc.1` failed before publishing anything (npm read `tarballs/x.tgz` as a git spec; fixed with `./`). Process: [docs/releasing.md](docs/releasing.md); decisions 150-152.
- Next: soak `rc.2`, fix what shows up, then tag `v0.1.0` (publishes as `latest`).

## GitHub Action (Marketplace): built, published to its own repository, proven on GitHub

- Source: `packages/check-action` (private). Public repo: https://github.com/steplight-dev/steplight-check-action, tags `v1.0.0` and `v1` on the same commit, release v1.0.0. Contains only `action.yml`, `dist/index.js`, `dist/licenses.txt`, `README.md`, `LICENSE`, `SECURITY.md` (verified from a fresh clone).
- 52 tests in the package (rules, formats, inputs, traversal, summary escaping, workflow-command injection, the built bundle run as a subprocess with runner-style env vars, assemble allow-list, action.yml/README consistency). Whole repo: 726 tests passing, lint clean.
- Proven on GitHub in `Thirumalaiboobathi/steplight-action-test`: clean run passes, hijacked run fails (annotation, outputs), `fail-on`, SARIF and JUnit files, path traversal rejected. All 5 jobs green: https://github.com/Thirumalaiboobathi/steplight-action-test/actions/runs/37781448258
- Not done: the Marketplace listing itself (web UI only; steps in `docs/releasing-action.md`), and the main repository is still private, so the README's link to it will not resolve for others.
- Release process: `docs/releasing-action.md`.

## Round 3 status: complete

Network capture plus security and privacy hardening. Verified from a fresh `git clone`: `pnpm install --frozen-lockfile && pnpm -r build && pnpm -r test && pnpm demo` (after the one-time `pnpm --filter @steplight/extension exec playwright install chromium`); `pnpm audit --audit-level=high` reports nothing; ESLint is clean.

| Part | Status |
|---|---|
| A. Existing attack surfaces | ✅ text-only rendering proven with XSS payloads in viewer and report; CSP on viewer (header), extension pages (manifest) and report (hash-pinned, no network); CLI session token + pairing, Host/Origin checks, 5 MB / 8 MB limits, rate limit, zod ingest schema, id validation; extension sender + message validation |
| B. Network capture + SPA | ✅ `webRequest` capture (recorded tab, header allowlist, body analysed in memory), `networkExfil` detector, opt-in MAIN-world Deep capture, SPA navigation + debounced re-scan, 5 new red-team pages (18 total), SDK parity, real-Chromium e2e for each page + analytics control + <5 ms perf test |
| C. Privacy controls | ✅ capture levels (extension + SDK), always-on never-capture fields, site allow/deny + first-run suggestions, redaction engine rewrite (20+ kinds, encodings, custom patterns with ReDoS checks, fast-check fuzzing), redaction at the source, retention + `steplight purge`, delete-all, REC badge + page pill, settings page |
| D. Encryption at rest | ✅ extension AES-256-GCM (non-extractable key, IV per record), CLI/SDK file encryption (key / scrypt passphrase, 0600), password-protected JSON + HTML exports, pre-export dialog with strip options, `steplight decrypt` |
| E. Enterprise controls | ✅ `managed_schema.json` + `chrome.storage.managed` (9 keys, only tightens), `--policy` / `steplight.config.json` / `STEPLIGHT_*`, hash-chained audit log, `docs/enterprise.md` |
| F. Supply chain | ✅ SECURITY.md, THREAT_MODEL.md, six SHA-pinned least-privilege workflows (CI, audit, CodeQL, dependency review, SBOM, provenance release), Dependabot, audit findings fixed (vitest 4, vite 6), unused deps removed; guarded by tests |
| G. Honest docs | ✅ README "Security & Privacy" and feature table, PRIVACY.md rewritten, store listing and permission justifications updated (`webRequest`, `webNavigation`), CONTRIBUTING security notes |

### Tests: 670 passing

| Package | Tests |
|---|---|
| core | 453 (detectors, redaction incl. property tests, encryption, exports, policy, audit log, storage, perf guard) |
| cli | 100 (server security, XSS e2e, export e2e, encryption, policy, purge, supply-chain guards, plus all earlier) |
| extension | 75 (validation, network collector + <5 ms perf, real-Chromium e2e for every network page, privacy controls, encryption, policy UI, audit) |
| redteam | 19 |
| sdk | 14 |
| viewer | 7 |
| demo-agent | 2 |

About 330 of these are security or privacy tests (negative cases included): `core/security`, `redact`, `redact.fuzz`, `privacy`, `encryption`, `exportPackage`, `enterprise`, `storage/*`, `network`, `perf`; `cli/security`, `xss.e2e`, `export.e2e`, `encryption`, `policy`, `purge`, `supplychain`; `extension/validate`, `manifest`, privacy / encryption / policy e2e; `sdk` privacy and policy tests.

### Known gaps (honest)

- Redaction is pattern-based: names, addresses and free text are not recognised. Detectors are heuristic and English-only; no images, canvas, PDFs, shadow DOM or iframe internals.
- Extension encryption protects data at rest, not from malware running as the user (key and data share a profile). Windows has no POSIX file modes. Deleting files does not overwrite disk blocks.
- Deep capture shares a JS world with the page: a hostile page can notice or disable it (it cannot inject events).
- Network capture follows one tab; page events follow the agent across tabs. Multi-tab runs are not done.
- `chrome.storage.managed` cannot be provisioned in tests, so the policy logic is unit-tested and the UIs are tested with a published policy; verify a real policy at `chrome://policy` (see docs/enterprise.md).
- The audit log is tamper-evident, not tamper-proof. Policy files are ordinary files.
- The GitHub workflows could only be checked structurally (and the SBOM generator and `pnpm pack` locally), not run on GitHub; the first CI run may need small fixes. npm packages are not yet published and the Chrome Web Store has no screenshots yet.
- Python SDK, MCP tracing and live streaming (earlier next steps) are still open.

### Next 5 tasks

1. Run the new workflows on GitHub, fix whatever the first run shows, then publish `0.1.x` with provenance.
2. Multi-tab runs and network capture across tabs; shadow DOM and iframe scanning.
3. Real-policy end-to-end test (Chrome with a managed-policy file in CI) and a Web Store submission with screenshots.
4. Detector corpus: measure false positives of `networkExfil` on real sites; multilingual hidden-instruction patterns.
5. Python SDK / Browser Use integration emitting the same run format (and policy).

Round 1 (MVP) and Round 2 (store readiness, polish, developer features) are complete and committed. The acceptance command was verified from a fresh `git clone`:
`pnpm install && pnpm -r build && pnpm -r test && pnpm demo` (all green; after a one-time `pnpm --filter @steplight/extension exec playwright install chromium`).

## Round 2 status

| Part | Status |
|---|---|
| A. Chrome Web Store readiness | ✅ standalone mode (`chrome.storage.local`, 8 MB cap, oldest-run eviction), mode shown in the popup, bundled `viewer.html`, JSON export/import, PRIVACY.md, docs/store-listing.md, `pnpm --filter @steplight/extension package` (zip), 16/32/48/128 icons |
| B. Viewer polish | ✅ Clean badge, auto-select newest run + first flagged step, Replay `aria-disabled`, hover titles + 2-line wrap, `steplight clear [--keep N]`, demo clears old demo runs, SVG logo, 1 MB / <500 ms performance guard |
| C1. Stuck loops + failure explainer | ✅ `stuckLoop` detector, SDK diagnosis (covered / disabled / hidden / off-screen / 0 or many matches / similar selectors), "Why did this fail?" panel, `stuck.html` fixture + demo run |
| C2. Run diff | ✅ `diffRuns` (LCS alignment), `steplight diff`, viewer Compare mode, demo prints the diff |
| C3. Playwright repro | ✅ `steplight replay-script`, Copy as Playwright test (both viewers); generated tests are executed in the test suite |
| C4. Agent CI checks | ✅ `steplight check` (rules YAML; text / JUnit / SARIF; exit 0/1/2), GitHub Action in `examples/github-action/` |
| C5. Red-team pack | ✅ `@steplight/redteam`: 13 attack pages, `steplight redteam serve`, `report` (text/markdown/json, score out of 100), gullible and resilient demo agents |
| C6. Token and context cost | ✅ per page-read estimates (visible / hidden / boilerplate), run total + top 3 pages, viewer, `steplight tokens`, OTel attribute |
| C7. Shareable HTML report | ✅ `steplight report [--diff]`, Export HTML report in both viewers, verified offline, <2 MB |
| D. Docs and wrap-up | ✅ README (Why Steplight, feature table, usage per feature), CONTRIBUTING.md, issue templates, clean-clone check |

## What works

- **Record**: Playwright SDK and Chrome extension (standalone or connected to the CLI) record navigations, clicks, field changes (values never recorded), form submits, page snapshots (hidden text included), flags, causal links, token estimates.
- **Detect**: hidden instructions (CSS-hidden, comments, aria-label/alt, zero-width, delayed injection), cross-domain data, sensitive outbound data, suspicious redirects, stuck loops.
- **Understand**: viewer with timeline, highlighted evidence, failure explainer, Compare, token summary; `diff`, `tokens`, `report`.
- **Reproduce and gate**: `replay-script`, `check` (JUnit/SARIF + Action), `redteam`.
- **Share**: JSON export/import, self-contained HTML report, all redacted again on export.

## How to run

```bash
pnpm install
pnpm --filter @steplight/extension exec playwright install chromium     # one-time
pnpm -r build && pnpm -r test
pnpm demo && pnpm view                    # http://localhost:4777
pnpm --filter @steplight/demo-agent redteam-demo && node packages/cli/dist/bin.js redteam report
pnpm --filter @steplight/extension package   # zip for the Chrome Web Store
```

## Tests: 276 passing

| Package | Tests |
|---|---|
| core | 182 (detectors, redaction, storage, local store, bundles, OTel, diff, repro, check rules, tokens, HTML report, perf guard) |
| cli | 42 (API/ingest/import, check formats, diff, clear, report, tokens, redteam, replay executed with Playwright Test, viewer e2e incl. replay, compare, copy-test, offline report, 375 px) |
| extension | 25 (message handling, standalone/connected, manifest + bundle checks, real-Chromium e2e for both modes) |
| redteam | 14 |
| viewer | 7 |
| sdk | 4 (real Chromium against fixtures) |
| demo-agent | 2 (the four demo scenarios; the full red-team pack end to end) |

## Bugs the tests found (all fixed)

- Email regex was quadratic, then still 500 ms/MB: replaced by an `@`-anchored scanner.
- URL-encoded form bodies bypassed email detection/redaction.
- Evidence masking leaked part of an email.
- **SDK lost page snapshots when an agent navigated immediately after `goto()`**: scans now run inside the page at load time.
- Run task titles and metadata were not redacted in exports and HTML reports.
- Invalid YAML in the GitHub Action's `action.yml` (caught by parsing it in a test).
- A blocking `spawnSync` deadlocked the in-process fixtures server in a test.

## Known gaps

- **Extension**: no fetch/XHR or SPA (pushState) capture, one tab at a time, and it cannot see an agent's failed actions (so no failure explainer there). The optional all-sites permission needs a human click; the e2e test uses a patched manifest copy. Not published to the Web Store (zip + listing material are ready); the store screenshots are still to be taken.
- **SDK**: only page-level action methods are wrapped for failure capture; Locator actions need `run.reportError()`. Playwright only (no Puppeteer / CDP SDK).
- **Detectors** are heuristic and English-only; they read DOM text, comments and aria-label/alt, not images, canvas, PDFs, shadow DOM or iframe internals. `causedBy` is lexical overlap.
- **Token figures are chars/4 estimates**, and boilerplate detection is heuristic.
- **Red-team**: attack pages cover 13 techniques but only test agents that read text; no image/OCR or multi-step attacks. The scorecard aggregates all runs in a directory.
- **Diff** aligns by URL path + target; very different flows produce a "changed" wall. Runs above ~2000 steps fall back to position-wise alignment.
- **GitHub Action** is validated by YAML parsing only (cannot run GitHub Actions offline). Packages are not published to npm.
- The viewer polls (3 s) instead of streaming, and long runs are not virtualised.
- Redaction is pattern-based: free-text personal data (names, addresses) is not caught.

## Next 5 tasks (priority order)

1. **Extension network + SPA capture** (`webRequest` / history API) and multi-tab runs, so CDP and Browser Use agents get full `network_request` coverage and cross-domain detection for fetch/XHR.
2. **Python SDK / Browser Use integration**: emit the same run format (or POST to `/api/ingest`), including failure diagnosis, so Python agents get every feature above.
3. **Publish**: npm release of `@steplight/core|sdk|cli|redteam` (bundle the viewer into the CLI), Chrome Web Store submission with screenshots, versioned releases.
4. **Detector quality corpus**: collect real injections and benign pages, measure false positives, add multilingual patterns, shadow DOM / iframe scanning and (opt-in) image-text detection; grow the red-team pack with multi-step and image attacks.
5. **Live view and MCP tracing**: stream steps to the viewer over SSE instead of polling and record MCP tool calls next to browser steps.
