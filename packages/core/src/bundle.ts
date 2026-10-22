import { isSafeId } from "./ids.js";
import { redactText, sanitizeSnapshot } from "./redact.js";
import { sanitizeStep } from "./sanitize.js";
import type { Run, RunStatus, Step } from "./types.js";

/** Portable, self-contained representation of one run (export / import / share). */
export interface RunBundle {
  format: "steplight-run";
  version: 1;
  run: Run;
  /** Snapshot text keyed by step id. */
  snapshots: Record<string, string>;
}

/** Largest bundle accepted by {@link parseBundle}, in characters. */
export const MAX_BUNDLE_CHARS = 25 * 1024 * 1024;

const STATUSES: readonly RunStatus[] = ["running", "success", "failed"];

/**
 * Build a bundle from a run and its snapshots. Everything is redacted again.
 * @example const json = JSON.stringify(createBundle(run, { s1: "page text" }))
 */
export function createBundle(run: Run, snapshots: Record<string, string> = {}): RunBundle {
  const safeSnaps: Record<string, string> = {};
  for (const [id, text] of Object.entries(snapshots)) safeSnaps[id] = sanitizeSnapshot(text);
  return {
    format: "steplight-run",
    version: 1,
    run: { ...run, task: redactText(run.task), meta: redactMeta(run.meta), steps: run.steps.map(sanitizeStep) },
    snapshots: safeSnaps,
  };
}

function redactMeta(meta: Record<string, string | boolean>): Record<string, string | boolean> {
  return Object.fromEntries(Object.entries(meta).map(([k, v]) => [k, typeof v === "boolean" ? v : redactText(String(v))]));
}

function fail(reason: string): never {
  throw new Error(`Invalid Steplight run file: ${reason}`);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Parse and validate an exported run (untrusted input). Re-sanitizes steps and snapshots and
 * drops `snapshotRef` for steps with no snapshot.
 * @throws Error describing the first problem found.
 * @example const { run, snapshots } = parseBundle(await file.text())
 */
export function parseBundle(text: string): RunBundle {
  if (text.length > MAX_BUNDLE_CHARS) fail("file is too large");
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    fail("not valid JSON");
  }
  if (!isObject(raw) || raw["format"] !== "steplight-run") fail("missing format marker");
  if (raw["version"] !== 1) fail("unsupported version");
  const run = raw["run"];
  if (!isObject(run)) fail("missing run");
  if (typeof run["id"] !== "string" || !isSafeId(run["id"])) fail("bad run id");
  if (typeof run["task"] !== "string") fail("bad task");
  if (typeof run["startedAt"] !== "number") fail("bad startedAt");
  if (!STATUSES.includes(run["status"] as RunStatus)) fail("bad status");
  if (!Array.isArray(run["steps"])) fail("steps must be an array");

  const rawSnaps = isObject(raw["snapshots"]) ? raw["snapshots"] : {};
  const snapshots: Record<string, string> = {};
  const steps: Step[] = [];
  for (const [i, s] of (run["steps"] as unknown[]).entries()) {
    if (!isObject(s) || typeof s["id"] !== "string" || typeof s["kind"] !== "string") {
      fail(`step ${i} is malformed`);
    }
    if (typeof s["timestamp"] !== "number" || !Array.isArray(s["flags"])) fail(`step ${i} is malformed`);
    const step = sanitizeStep({ ...(s as unknown as Step), index: i, runId: run["id"] });
    const snap = rawSnaps[step.id];
    if (typeof snap === "string") snapshots[step.id] = sanitizeSnapshot(snap);
    else delete step.snapshotRef;
    steps.push(step);
  }
  const meta = isObject(run["meta"]) ? redactMeta(run["meta"] as Record<string, string | boolean>) : {};
  const out: Run = {
    id: run["id"],
    task: redactText(String(run["task"])),
    startedAt: run["startedAt"],
    status: run["status"] as RunStatus,
    steps,
    meta,
  };
  if (typeof run["endedAt"] === "number") out.endedAt = run["endedAt"];
  return { format: "steplight-run", version: 1, run: out, snapshots };
}
