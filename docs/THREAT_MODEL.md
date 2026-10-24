# Threat model

Steplight records and replays what an AI agent does in a browser. That makes it a high-value target: it sits next
to sensitive browsing data and it reads pages written by strangers. This document says what we protect, who we
worry about, where trust changes, and which control (and which test) answers each threat. It also lists what is
**not** protected, because an honest model is more useful than a reassuring one.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Recorded runs: page text, URLs, request metadata, optional request bodies | may contain personal or confidential data seen by the agent |
| The user's secrets in forms: passwords, card numbers, OTPs, API keys | must never be stored |
| The integrity of what the viewer shows | a person decides whether an agent was hijacked based on it |
| The pairing token and the encryption key / passphrase | access to the above |
| The extension's privileges (read pages, observe requests) | could be abused by a page or another extension |
| Exported files and reports | leave the device; the person sharing them must know what is in them |
| The release pipeline and dependencies | a compromised build ships to every user |

## 2. Actors

| Actor | Capability assumed |
|---|---|
| **Malicious web page** | arbitrary HTML, CSS, JavaScript and network requests; text crafted to attack Steplight or the viewer; may try to detect or interfere with the recorder |
| **Malicious local process / other local user** | can connect to `127.0.0.1`, read files the OS lets it read, send DNS-rebinding web pages |
| **Malicious or compromised extension** | can send messages to other extensions and read what Chrome exposes |
| **Person receiving an export** | gets a file; may open it in a browser |
| **Supply-chain attacker** | tries to get code into dependencies, CI or releases |
| **Curious administrator / the user's employer** | can set policy; should not be able to read content they were not given |

Not in scope: an attacker with full control of the user's OS account (they can read memory, profiles and keys), or a
malicious browser build. Steplight reduces what is *left behind*; it cannot hide data from the machine's owner.

## 3. Trust boundaries

```
 web page (untrusted) ──1──▶ content script ──2──▶ service worker ──3──▶ extension storage (encrypted)
        │                                               │  └──4──▶ CLI server (127.0.0.1, token) ──5──▶ run files (optional encryption)
        └── network ──6──▶ browser (webRequest, observe only) ─────┘
                                  viewer (extension page / CLI page) ──7──▶ exports (files that leave the device)
```

1. **Page → content script.** The page is hostile. The content script only reads the DOM; it never executes page strings,
   never injects markup, and runs in an isolated world.
2. **Content script → service worker.** Messages are validated field by field and size-capped; the worker accepts them only
   from this extension's own id, events only from content scripts and control messages only from extension pages.
3. **Worker → storage.** AES-256-GCM per record, key in IndexedDB.
4. **Worker → CLI.** Loopback only, bearer token from pairing, Host and Origin checks.
5. **CLI → disk.** Redacted again; optional AES-256-GCM; owner-only permissions on POSIX.
6. **Network → worker.** Observation only; no blocking, no header capture beyond `content-type` / `content-length`.
7. **Viewer → export.** Text-only rendering, strict CSP, a pre-export dialog and optional password protection.

## 4. Threats and mitigations

IDs are referenced from tests and from `DECISIONS.md`.

### Malicious web page

| ID | Threat | Mitigation | Where | Evidence |
|---|---|---|---|---|
| T1 | **Stored XSS** through snapshot text, URLs, selectors, request bodies, task titles or flag evidence rendered in a viewer or report | Everything is rendered as text nodes (React; the report uses escaping); evidence highlighting splits text, never injects HTML; no `innerHTML` anywhere | `viewer/src/components/StepDetail.tsx`, `core/src/htmlReport.ts` | `cli/src/xss.e2e.test.ts` (6 payload families in every field, real Chromium), `core/src/security.test.ts` |
| T2 | XSS impact if T1 failed | CSP on the viewer (`script-src 'self'; connect-src 'self'; default-src 'none'`), on extension pages (manifest), and on reports (hash-pinned inline style/script, no `connect-src`) | `cli/src/server.ts` (`VIEWER_CSP`), `manifest.json`, `core/src/htmlReport.ts` | injected inline script does not run and cross-origin `fetch` is blocked (xss e2e); manifest test |
| T3 | **Secrets in form fields** captured (passwords, cards, OTP, CVV, PIN, SSN, Aadhaar, PAN) | Always-on never-capture rules (type, `autocomplete`, name/label patterns, payment frames); redaction before data leaves the page; detectors work from redaction markers | `core/src/neverCapture.ts`, `extension/src/content.ts`, `sdk/src/inject.ts`, `core/src/collect.ts` | `extension/src/network.e2e.test.ts` and `sdk` tests prove none of the secrets reach disk at any capture level |
| T4 | **Regex denial of service**: crafted text that stalls redaction or detectors | Linear-time scanners, literal pre-checks, size truncation before matching, `findEmails` instead of a backtracking regex, performance guard | `core/src/redact.ts`, `core/src/perf.test.ts` | 1 MB of hostile text under the budget |
| T5 | ReDoS through a **user-supplied redaction pattern** | Length cap, structural checks (nested/ambiguous repetition), timing test on adversarial input, patterns re-validated on load, failures skip the pattern | `core/src/customPatterns.ts` | `core/src/redact.test.ts` (16 rejected shapes, 8 accepted) |
| T6 | **Spoofed recorder events** (page tries to fake steps or flood the worker) | Page code cannot reach the worker (isolated world; no `externally_connectable`); schema validation; deep-capture events go over a private `MessageChannel`, are rate-limited (50/s) and treated as untrusted | `extension/src/validate.ts`, `extension/src/deep-receiver.ts` | `validate.test.ts`, deep-capture e2e |
| T7 | Page **detects or breaks** the optional deep-capture hooks | Hooks are opt-in; `Proxy` wrappers keep native `name`, `length`, `toString()`; every hook is try/catch; a hostile page can at worst stop capture, not inject events | `extension/src/deep.ts` | e2e "native-looking and working" |
| T8 | **Prompt injection against the agent** (the thing Steplight exists to flag) | Detectors for hidden text (CSS, comments, aria/alt, zero-width, delayed), cross-domain data, sensitive outbound data, suspicious redirects, stuck loops, and **network exfiltration** (fetch/XHR/beacon/pixel/WebSocket) | `core/src/detectors/*`, `core/src/network.ts` | red-team pack: 18 pages, scripted gullible / resilient agents, extension e2e per network page |
| T9 | Page **text becomes a data leak** through its own redaction gaps (names, addresses, free text) | Documented gap. Mitigations: capture level `minimal` stores no text; `forceRedactionPatterns`; encryption at rest; retention | `core/src/captureLevel.ts` | tests prove levels; the gap itself is a known limitation (§5) |

### Malicious local process / other local user

| ID | Threat | Mitigation | Where | Evidence |
|---|---|---|---|---|
| T10 | Another process or web page **reads or writes** the CLI API | 256-bit random bearer token per start on every `/api` route (constant-time compare); binds `127.0.0.1` unless `--host` is given with a loud warning; token never in query strings | `cli/src/server.ts` | `cli/src/security.test.ts` (401 without token, wrong token, query token) |
| T11 | **DNS rebinding** / cross-origin fetch from a browser tab | Host allow-list on every request (static files too); `Origin` must be the server itself or a `chrome-extension://` origin (optionally one id); CORS echoes the exact origin, never `*` | `cli/src/server.ts` | 403 tests for foreign Host / Origin |
| T12 | **Path traversal** via run or step ids | Strict `[A-Za-z0-9_-]{1,128}` check everywhere an id reaches the file system; static files resolved and prefix-checked | `core/src/ids.ts`, `cli/src/server.ts` | traversal ids → 400 |
| T13 | Oversized or malformed requests, floods | zod schemas with bounds, 5 MB ingest / 8 MB import limits (413), unknown keys dropped, fixed-window rate limit (429) | `cli/src/ingestSchema.ts`, `server.ts` | 413 / 400 / 429 tests |
| T14 | **Reading run files at rest** (stolen disk, backup, other user) | Optional AES-256-GCM (key or scrypt passphrase), per-record IV, file identity in AAD; files 0600 / folders 0700 on POSIX; retention and `purge` | `core/src/storage/fileCrypto.ts`, `runStore.ts` | `fileCrypto.test.ts`, `cli/src/encryption.test.ts` |
| T15 | **Reading extension storage at rest** | AES-256-GCM, non-extractable key in IndexedDB, unique IV, key name bound as AAD, legacy data migrated | `core/src/encryptedStore.ts`, `idbKeyProvider.ts` | `encryption.test.ts`; e2e proves raw storage holds no plaintext and the key cannot be exported |
| T16 | Tampering with run files or the audit log without being noticed | GCM authentication detects changed encrypted files; the audit log is a SHA-256 hash chain | `core/src/auditLog.ts` | `enterprise.test.ts`, CLI and e2e tamper tests |

### Malicious or compromised extension / content script

| ID | Threat | Mitigation | Where | Evidence |
|---|---|---|---|---|
| T17 | Another extension or web page sends messages to the worker | `sender.id === chrome.runtime.id`; no `externally_connectable`; no `web_accessible_resources` | `extension/src/background.ts`, `validate.ts` | `validate.test.ts`, manifest test |
| T18 | A compromised **content script** (running next to a hostile page) starts/stops recording, pairs, deletes data or forges audit entries | `senderAllowed`: content scripts may only send `event`s; control messages (`start`, `stop`, `pair`, `delete_all`, `audit`) only from extension pages | `extension/src/validate.ts` | `validate.test.ts` |
| T19 | Excess privilege | Install-time permissions: `activeTab`, `scripting`, `storage`, `webRequest`, `webNavigation`, and `localhost:4777`; access to all sites is **optional and requested at runtime**; `webRequest` is observation-only and scoped to the recorded tab | `manifest.json` | manifest test; `docs/store-listing.md` |

### Exports

| ID | Threat | Mitigation | Where | Evidence |
|---|---|---|---|---|
| T20 | An export **leaks more than intended** | Everything is re-redacted at export; a pre-export dialog lists snapshots, bodies, URLs with queries, comparison and protection, with checkboxes to strip them | `core/src/exportPackage.ts`, `viewer/src/components/ExportDialog.tsx` | `export.e2e.test.ts` |
| T21 | Shared file read by the wrong person | Optional password protection (PBKDF2-SHA256, 600k iterations → AES-256-GCM) for JSON and HTML; the HTML variant is a small decrypt page (no network, CSP, sandboxed frame); organisation policy can require it | `core/src/crypto.ts`, `exportPackage.ts` | unit + browser tests: no plaintext in the file, wrong password refused |
| T22 | A **malicious run file** imported into the viewer | `parseBundle` validates and re-sanitises untrusted input, caps size; the server import path applies the same; rendering is text-only (T1) | `core/src/bundle.ts` | bundle tests |

### Python SDK

The Python package (`python/`) is a second recorder in the same trust model: it runs inside the agent's own process, reads the page through Playwright (or Browser Use's browser over CDP), redacts, and writes the run folder. It has no required dependencies and no network code. Analysis is done afterwards by the Node CLI (`steplight analyze`), which treats the run folder as untrusted input (T22).

| ID | Threat | Mitigation | Where | Evidence |
|---|---|---|---|---|
| T27 | A hostile page abuses the Python recorder (floods, giant strings, regex-bombs the redactor) | Page-supplied data is size-capped (node count, text length, body previews) and network and WebSocket steps are capped per run; one daemon writer thread; the redaction port is linear-time (card detection uses digit runs and prefix sums); the page cannot supply redaction patterns | `python/src/steplight/recorder.py`, `redact.py` | `test_misc.py` perf guard on 1 MB hostile inputs |
| T28 | Python redaction diverges from the TypeScript engine and leaks | The 562 vectors in `spec/redaction-vectors.json` are generated from the TS engine; Python must match them exactly; freshness is checked in CI; redaction failure drops the data | `spec/`, `python/tests/test_redact_vectors.py` | 562 vectors pass |
| T29 | Recorded input is analyzed with unredacted data | The material for analysis is redacted before it is written and removed by `steplight analyze`; only an explicit `analyzed=false` marks a run as pending | `core/src/storage/analyzeStore.ts` | `analyzeStore.test.ts`, `python/tests/test_conformance.py` |
| T30 | The recorder breaks or slows the agent | Every hook is wrapped and logs to stderr; the hooks never raise; policy that cannot be honoured means "record nothing" | `python/src/steplight/_attach.py` (`_safe`), `handles.py` | `test_recorder.py` fail-open tests |
| T31 | Browser Use steps expose typed secrets | Typed text parameters are replaced by `<N chars>`; model output is redacted like page text | `integrations/browser_use.py` | `test_browser_use.py` |
| T32 | Encrypted runs are unreadable or weaker across languages | Same AES-256-GCM envelope, AAD and scrypt parameters as the CLI, tested in both directions | `python/src/steplight/crypto.py` | `test_crosslang.py` |
| T33 | Compromised PyPI release | PyPI Trusted Publishing (OIDC) with attestations, no token; tag, npm and PEP 440 versions must agree; sdist and wheel content gate; `uv.lock`, `pip-audit`, SBOM, Dependabot with cooldown | `release.yml`, `python/scripts/` | `supplychain.test.ts`, `test_release_scripts.py` |

### Supply chain

| ID | Threat | Mitigation | Where | Evidence |
|---|---|---|---|---|
| T23 | Compromised dependency | Few runtime dependencies, each justified in `DECISIONS.md`; lockfile + `--frozen-lockfile`; `pnpm audit --audit-level=high` in CI and weekly; dependency review on PRs; Dependabot | `.github/workflows`, `dependabot.yml` | `cli/src/supplychain.test.ts`; audit currently clean |
| T24 | Compromised GitHub Action or workflow escalation | Every action pinned to a commit SHA; read-only default permissions, extra scopes only where needed (`security-events`, `id-token`); no `pull_request_target`; checkout without persisted credentials; one secret, only in the release job | `.github/workflows` | `supplychain.test.ts` |
| T25 | Tampered release | npm publish from CI with **provenance**; CycloneDX SBOM per build; release only from version tags after tests | `release.yml`, `sbom.yml` | `supplychain.test.ts` |
| T26 | Telemetry or remote code sneaking in | No network code except localhost; no `eval`, no remote scripts, no CDN; the extension's CSP only allows `localhost:4777` for connections; the built bundle is scanned for external URLs | `manifest.json`, `extension/src/manifest.test.ts` | bundle scan test |

## 5. Residual risks and known limits

- **Redaction is pattern-based.** Names, addresses and free text are not detected. Use the `minimal` capture level, custom
  patterns, or do not record sensitive sites (deny list; first-run suggestions).
- **Extension encryption protects data at rest, not from the profile owner.** The key lives in the same profile as the
  data. It defeats file scanners, backups and casual disclosure; it does not defeat malware running as the user.
- **Deep capture shares a JavaScript world with the page.** A hostile page that runs first can take over the hook's port
  (capture stops) or notice the hooks. It cannot inject events into the extension. Keep it off unless needed.
- **Deleting files does not erase them from the disk.** Use encryption (and full-disk encryption) when residue matters.
- **Windows file permissions.** POSIX modes are not available; run folders inherit the folder ACL.
- **Detectors are heuristic and English-only**; they cannot see images, canvas, PDFs, shadow DOM or iframe internals.
  A clean run is evidence, not proof.
- **Audit logs are tamper-evident, not tamper-proof**, and policy files are ordinary files (protect them with OS permissions).
- **The CLI viewer's token is in the link** printed to the terminal; anyone who can read your terminal history or screen
  can use it until the CLI exits. The viewer removes it from the address bar after loading.
- **Single recorded tab for network capture**; page events follow the agent across tabs.
- **Python runs are unanalyzed until the Node CLI sees them.** The Python package does not run the detectors; a run that was never analyzed has no flags (the CLI analyzes it automatically before `view`, `check`, `diff`, `report` and export).
- **`pip-audit` findings in Browser Use's own pinned dependencies** (0.13.x) are reported, not blocking, for that extra; the core package and the other extras must be clean.

## 6. Reviewing this model

Re-check it when: a new data path is added (anything that sends data between the boundaries above), a new permission is
requested, a new export format is added, or a dependency with network or native code is introduced. Security-relevant
decisions are logged in [DECISIONS.md](../DECISIONS.md) (Round 3, parts A–F); report problems through
[SECURITY.md](../SECURITY.md).
