import path from "node:path";
import type { Frame, Page, Request, WebSocket } from "playwright";
import {
  RunWriter,
  CAPTURE_LEVELS,
  analyzeStep,
  applyCaptureLevel,
  configureRedaction,
  effectiveEncryption,
  loadPolicy,
  purgeRuns,
  recordingBlockedReason,
  buildDiagnosis,
  collectFailureContext,
  computeTokenStats,
  exportRunOtlp,
  hiddenInstruction,
  inferCausedBy,
  isCrossSite,
  newRunId,
  newStepId,
  siteOf,
  truncate,
  VERSION,
  MAX_BODY_PREVIEW,
  DEFAULT_RUNS_DIR,
  type CaptureLevel,
  type EncryptionOptions,
  type FailureDiagnosis,
  type Policy,
  type PageScan,
  type Run,
  type RunStatus,
  type Step,
  type StepKind,
} from "@steplight/core/node";
import { BINDING_NAME, type PageEvent, type ScanEvent } from "./inject.js";
import { pageScanScript } from "./pageScript.js";

/** Origin and path of a URL (query and hash ignored): the key under which evidence already flagged on a page is remembered. */
function pageKey(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return url;
  }
}

/** Options for {@link record}. */
export interface RecordOptions {
  /** Human-readable description of what the agent is trying to do. */
  task: string;
  /** Where runs are written. Default: `$STEPLIGHT_DIR` or `.steplight/runs`. */
  dir?: string;
  /** Send the run to an OTLP endpoint on `end()`. Default: only if OTEL_EXPORTER_OTLP_ENDPOINT is set. */
  otel?: boolean;
  /** Extra key/value metadata stored on the run. */
  meta?: Record<string, string>;
  /**
   * How much to write to disk (default `"standard"`): `"minimal"` = URLs without query strings, step
   * kinds and flags only; `"standard"` = also redacted page text and request metadata, no request
   * bodies; `"full"` = also redacted request body previews. Detectors always see the full data in
   * memory first, and secrets are redacted at every level.
   */
  captureLevel?: CaptureLevel;
  /**
   * Encrypt the run files (AES-256-GCM). Give a 32-byte `key` (64 hex characters or base64) or a
   * `passphrase`; with neither, `$STEPLIGHT_ENCRYPTION_KEY` / `$STEPLIGHT_PASSPHRASE` are used if set.
   */
  encryption?: EncryptionOptions;
}

/** Handle for an in-progress recording. */
export interface RunHandle {
  /** The run id (also the folder name). */
  readonly id: string;
  /** Absolute-or-relative folder the run is written to. */
  readonly dir: string;
  /** Record a note about the agent's reasoning (shown as an `agent_note` step). */
  note(text: string): Promise<void>;
  /**
   * Record a failure the SDK could not see itself (for example from a Locator action) as an
   * `error` step. Pass the selector to also get the "Why did this fail?" analysis.
   * @example try { await page.locator("#x").click() } catch (e) { await run.reportError(e, "#x"); throw e; }
   */
  reportError(error: unknown, selector?: string): Promise<void>;
  /** Finish the run, flush everything to disk, and (optionally) export OTel spans. */
  end(status?: Exclude<RunStatus, "running">): Promise<Run>;
}

function logError(where: string, err: unknown): void {
  process.stderr.write(`[steplight] ${where}: ${err instanceof Error ? err.message : String(err)}\n`);
}

class Recorder implements RunHandle {
  readonly id = newRunId();
  readonly dir: string;
  private writer!: RunWriter;
  private run: Run;
  private steps: Step[] = [];
  private pages: { url?: string; text: string }[] = [];
  private chain: Promise<void> = Promise.resolve();
  private ended = false;
  private lastNavUrl: string | undefined;
  private readonly seenSelectors = new Set<string>();
  private readonly wrapped: string[] = [];
  /** Hidden-instruction evidence already flagged per page, so a re-read only reports what is new. */
  private readonly knownEvidence = new Map<string, Set<string>>();

  constructor(
    private readonly page: Page,
    private readonly options: RecordOptions,
    root: string,
    private readonly policy: Policy = {},
  ) {
    this.dir = path.join(root, this.id);
    this.run = {
      id: this.id,
      task: options.task,
      startedAt: Date.now(),
      status: "running",
      steps: [],
      meta: { ...options.meta, sdk: "typescript", sdkVersion: VERSION, captureLevel: options.captureLevel ?? "standard", analyzed: true },
    };
    this.root = root;
  }
  private readonly root: string;

  /** Queue work so steps are recorded in the order events happened. Never rejects. */
  private enqueue(where: string, job: () => Promise<void>): void {
    this.chain = this.chain.then(job).catch((err) => logError(where, err));
  }

  private async addStep(
    kind: StepKind,
    timestamp: number,
    fields: Partial<Step> = {},
    snapshotText?: string,
  ): Promise<Step> {
    const index = this.steps.length;
    const step: Step = {
      id: newStepId(index),
      runId: this.id,
      index,
      kind,
      timestamp,
      flags: [],
      ...fields,
    };
    // Organisation policy: sites that must not be recorded leave no trace at all.
    const rules = { siteAllowlist: this.policy.siteAllowlist ?? [], siteDenylist: this.policy.siteDenylist ?? [] };
    if (recordingBlockedReason(step.url, rules) || recordingBlockedReason(step.request?.url, { siteAllowlist: [], siteDenylist: rules.siteDenylist })) {
      return step;
    }
    step.flags.push(...analyzeStep(step, this.steps, this.pages));
    const cause = inferCausedBy(step, this.steps);
    if (cause) step.causedBy = cause;
    this.steps.push(step);
    const shaped = applyCaptureLevel(step, snapshotText, this.options.captureLevel ?? "standard");
    await this.writer.addStep(shaped.step, shaped.snapshot);
    return step;
  }

  async start(): Promise<void> {
    this.writer = await RunWriter.create(this.root, this.run, this.options.encryption);
    const page = this.page;

    await page.exposeBinding(BINDING_NAME, (source, event: PageEvent | ScanEvent) => {
      if (source.frame !== page.mainFrame()) return;
      const ts = Date.now();
      if (event.type === "scan") {
        this.enqueue("page_read", () => this.onScan(event.scan, ts, event.reason));
        return;
      }
      const url = page.url();
      this.enqueue("event", () => this.onPageEvent(event, ts, url));
    });
    // One standalone script (spec/page-scan.js, shared with the other SDKs) scans each page *inside*
    // the page and pushes the result through the binding, so an agent that navigates away immediately
    // after goto() cannot race the snapshot. It also reports clicks, field changes and form submits.
    const script = pageScanScript();
    await page.addInitScript({ content: script });

    page.on("framenavigated", (frame: Frame) => {
      if (frame !== page.mainFrame()) return;
      const ts = Date.now();
      const url = frame.url();
      this.enqueue("navigate", async () => {
        if (url === "about:blank" || url === this.lastNavUrl) return;
        this.lastNavUrl = url;
        await this.addStep("navigate", ts, { url });
      });
    });
    page.on("request", (req: Request) => this.onRequest(req));
    page.on("websocket", (ws: WebSocket) => this.onWebSocket(ws));
    page.on("download", (dl) => {
      const ts = Date.now();
      this.enqueue("download", async () => {
        await this.addStep("download", ts, { url: dl.url(), targetText: dl.suggestedFilename() });
      });
    });
    page.on("crash", () => {
      const ts = Date.now();
      this.enqueue("crash", async () => {
        await this.addStep("error", ts, { url: page.url(), targetText: "page crashed" });
      });
    });

    this.wrapActions();

    // Already on a page when recording started: record it too (the navigate step goes first, then the
    // script runs in the loaded document and reports its scan).
    if (page.url() && page.url() !== "about:blank") {
      const ts = Date.now();
      this.enqueue("initial", async () => {
        this.lastNavUrl = page.url();
        await this.addStep("navigate", ts, { url: page.url() });
      });
      await page.evaluate(script).catch(() => undefined);
    }
  }

  private async onScan(scan: PageScan, ts: number, reason: ScanEvent["reason"]): Promise<void> {
    const key = pageKey(scan.url);
    const known = this.knownEvidence.get(key) ?? new Set<string>();
    let flags = hiddenInstruction(scan.dom);
    let title = scan.title;
    if (reason !== "load") {
      // A re-read (text injected after load, client-side route change): only report what is new.
      flags = flags.filter((f) => !known.has(f.evidence));
      if (flags.length === 0) return;
      title = `${scan.title} (${reason === "spa" ? "client-side route change" : "content changed after load"})`;
    }
    for (const f of flags) known.add(f.evidence);
    this.knownEvidence.set(key, known);
    this.pages.push({ url: scan.url, text: scan.text });
    await this.addStep("page_read", ts, { url: scan.url, targetText: title, flags, tokens: computeTokenStats(scan) }, scan.text);
  }

  /** Record background requests: fetch, XHR, beacons and third-party images (pixels). */
  private onRequest(req: Request): void {
    try {
      const type = req.resourceType();
      const method = req.method();
      const url = req.url();
      const from = this.page.url();
      // Playwright's names -> the browser's (so the same detectors work for the SDK and the extension).
      let resourceType: string | undefined;
      if (type === "fetch" || type === "xhr") resourceType = "xmlhttprequest";
      else if (type === "image" && siteOf(url) !== siteOf(from)) resourceType = "image"; // tracking pixels
      else if ((type as string) === "ping") resourceType = "ping"; // navigator.sendBeacon
      if (!resourceType) return; // navigations/forms are recorded as navigate/form_submit
      const ts = Date.now();
      const body = req.postData();
      this.enqueue("request", async () => {
        await this.addStep("network_request", ts, {
          url: from,
          request: {
            method,
            url,
            resourceType,
            ...(body ? { bodyPreview: truncate(body, MAX_BODY_PREVIEW), bodyBytes: body.length } : {}),
          },
        });
      });
    } catch (err) {
      logError("request", err);
    }
  }

  /** Record WebSocket connections and the messages the page sends over them. */
  private onWebSocket(ws: WebSocket): void {
    try {
      const url = ws.url();
      const from = this.page.url();
      const ts = Date.now();
      this.enqueue("websocket", async () => {
        await this.addStep("network_request", ts, {
          url: from,
          request: { method: "GET", url, resourceType: "websocket" },
        });
      });
      ws.on("framesent", (frame) => {
        try {
          const payload = typeof frame.payload === "string" ? frame.payload : frame.payload.toString("utf8");
          const at = Date.now();
          this.enqueue("websocket", async () => {
            await this.addStep("network_request", at, {
              url: from,
              request: {
                method: "SEND",
                url,
                resourceType: "websocket",
                bodyPreview: truncate(payload, MAX_BODY_PREVIEW),
                bodyBytes: payload.length,
              },
            });
          });
        } catch (err) {
          logError("websocket", err);
        }
      });
    } catch (err) {
      logError("websocket", err);
    }
  }

  /**
   * Wrap the page's selector-based action methods so a failed action is recorded together with
   * a diagnosis of why it failed. The original error is always re-thrown unchanged.
   */
  private wrapActions(): void {
    const page = this.page as unknown as Record<string, unknown>;
    const actions: Record<string, StepKind> = {
      click: "click",
      dblclick: "click",
      check: "click",
      uncheck: "click",
      fill: "type",
      type: "type",
      press: "type",
      selectOption: "type",
    };
    for (const [name, kind] of Object.entries(actions)) {
      const original = page[name];
      if (typeof original !== "function") continue;
      page[name] = async (selector: unknown, ...rest: unknown[]) => {
        try {
          return await (original as (...a: unknown[]) => Promise<unknown>).call(this.page, selector, ...rest);
        } catch (err) {
          if (!this.ended && typeof selector === "string") await this.recordFailure(kind, name, selector, err);
          throw err;
        }
      };
      this.wrapped.push(name);
    }
    const goto = page["goto"];
    if (typeof goto === "function") {
      page["goto"] = async (url: unknown, ...rest: unknown[]) => {
        try {
          return await (goto as (...a: unknown[]) => Promise<unknown>).call(this.page, url, ...rest);
        } catch (err) {
          if (!this.ended) await this.reportError(err);
          throw err;
        }
      };
      this.wrapped.push("goto");
    }
  }

  private unwrapActions(): void {
    for (const name of this.wrapped) delete (this.page as unknown as Record<string, unknown>)[name];
    this.wrapped.length = 0;
  }

  /** Diagnose (bounded to 1.5 s) and record a failed action. Never throws. */
  private async recordFailure(kind: StepKind, action: string, selector: string, err: unknown): Promise<void> {
    try {
      const ts = Date.now();
      const url = this.page.url();
      let diagnosis: FailureDiagnosis | undefined;
      try {
        const ctx = await Promise.race([
          this.page.evaluate(collectFailureContext, selector),
          new Promise<undefined>((r) => setTimeout(() => r(undefined), 1500).unref?.()),
        ]);
        if (ctx) diagnosis = buildDiagnosis(ctx, this.seenSelectors.has(selector));
      } catch (e) {
        logError("diagnose", e);
      }
      const message = err instanceof Error ? err.message : String(err);
      this.enqueue("failure", async () => {
        await this.addStep(kind, ts, {
          url,
          targetSelector: selector,
          targetText: `${action} failed`,
          error: message,
          ...(diagnosis ? { diagnosis } : {}),
        });
      });
    } catch (e) {
      logError("recordFailure", e);
    }
  }

  async reportError(error: unknown, selector?: string): Promise<void> {
    try {
      const ts = Date.now();
      let diagnosis: FailureDiagnosis | undefined;
      if (selector) {
        try {
          const ctx = await this.page.evaluate(collectFailureContext, selector);
          diagnosis = buildDiagnosis(ctx, this.seenSelectors.has(selector));
        } catch (e) {
          logError("diagnose", e);
        }
      }
      const message = error instanceof Error ? error.message : String(error);
      this.enqueue("error", async () => {
        await this.addStep("error", ts, {
          url: this.page.url(),
          ...(selector ? { targetSelector: selector } : {}),
          targetText: (message.split("\n")[0] ?? message).slice(0, 200),
          error: message,
          ...(diagnosis ? { diagnosis } : {}),
        });
      });
      await this.chain;
    } catch (e) {
      logError("reportError", e);
    }
  }

  private async onPageEvent(ev: PageEvent, ts: number, url: string): Promise<void> {
    if (ev.selector) this.seenSelectors.add(ev.selector);
    if (ev.type === "click") {
      await this.addStep("click", ts, { url, targetSelector: ev.selector, targetText: ev.text });
    } else if (ev.type === "change") {
      await this.addStep("type", ts, { url, targetSelector: ev.selector, targetText: `${ev.text} (value not recorded)` });
    } else if (ev.type === "submit") {
      const method = ev.method ?? "GET";
      await this.addStep("form_submit", ts, {
        url,
        targetSelector: ev.selector,
        targetText: isCrossSite(url, ev.action) ? "form → other domain" : ev.text,
        request: {
          method,
          url: ev.action ?? url,
          ...(ev.body ? { bodyPreview: truncate(ev.body, MAX_BODY_PREVIEW) } : {}),
        },
      });
    }
  }

  async note(text: string): Promise<void> {
    const ts = Date.now();
    this.enqueue("note", async () => {
      await this.addStep("agent_note", ts, { url: this.page.url(), targetText: text });
    });
    await this.chain;
  }

  async end(status: Exclude<RunStatus, "running"> = "success"): Promise<Run> {
    if (!this.ended) {
      this.ended = true;
      this.unwrapActions();
      await this.chain;
      const endedAt = Date.now();
      this.run = { ...this.run, status, endedAt, steps: this.steps };
      try {
        await this.writer.finish(status, endedAt);
      } catch (err) {
        logError("finish", err);
      }
      if (this.options.otel ?? Boolean(process.env.OTEL_EXPORTER_OTLP_ENDPOINT)) {
        await exportRunOtlp(this.run);
      }
    }
    return this.run;
  }
}

/**
 * Start recording a Playwright page. Hooks navigation, requests, clicks, field changes and
 * form submits, snapshots every page load, runs the detectors and writes the run to disk.
 * Recording never throws into the agent: internal errors are logged to stderr.
 * @example
 * const run = await record(page, { task: "Book the cheapest flight" });
 * await page.goto("https://example.com");
 * await run.note("Picking the cheapest option");
 * await run.end("success");
 */
export async function record(page: Page, options: RecordOptions): Promise<RunHandle> {
  const root = options.dir ?? process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR;
  // Organisation policy (policy file, steplight.config.json, STEPLIGHT_* variables). Fail open for the
  // agent, closed for privacy: if the policy cannot be honoured, the agent runs but nothing is recorded.
  let policy: Policy;
  try {
    policy = loadPolicy().policy;
  } catch (err) {
    logError("policy", `${err instanceof Error ? err.message : String(err)} - NOT recording`);
    return disabledHandle(root);
  }
  if (policy.requireEncryption && !effectiveEncryption(options.encryption)) {
    logError("policy", "organisation policy requires encryption but no key is configured (set STEPLIGHT_ENCRYPTION_KEY) - NOT recording");
    return disabledHandle(root);
  }
  if (policy.forceRedactionPatterns?.length) configureRedaction({ customPatterns: policy.forceRedactionPatterns });
  let captureLevel = options.captureLevel ?? "standard";
  if (policy.maxCaptureLevel && CAPTURE_LEVELS.indexOf(captureLevel) > CAPTURE_LEVELS.indexOf(policy.maxCaptureLevel)) captureLevel = policy.maxCaptureLevel;
  if (policy.retentionDays !== undefined) await purgeRuns(root, { olderThanDays: policy.retentionDays }).catch(() => undefined);
  const recorder = new Recorder(page, { ...options, captureLevel }, root, policy);
  await recorder.start();
  return recorder;
}

/** A handle that records nothing (used when a policy forbids recording). The agent is not affected. */
function disabledHandle(root: string): RunHandle {
  const run: Run = { id: "", task: "", startedAt: Date.now(), status: "failed", steps: [], meta: {} };
  return { id: "", dir: root, note: async () => undefined, reportError: async () => undefined, end: async () => run };
}
