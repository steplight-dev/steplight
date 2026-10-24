import { analyzeStep, inferCausedBy } from "./analyze.js";
import type { PageScan } from "./collect.js";
import type { HistoryPage } from "./detectors/crossDomainData.js";
import { hiddenInstruction, type DomTextNode } from "./detectors/hiddenInstruction.js";
import { MAX_BODY_PREVIEW, MAX_SNAPSHOT_TEXT } from "./redact.js";
import { computeTokenStats } from "./tokens.js";
import type { Flag, Step } from "./types.js";

/**
 * What an SDK that does not run the detectors itself (the Python SDK) leaves next to a run, one line of
 * `analysis-input.jsonl` per step that needs it. Everything in it is already redacted. Shape:
 * `analysisInput` in spec/run-format.schema.json.
 */
export interface AnalysisInput {
  stepId: string;
  /** The page as the page script reported it (page_read steps). */
  scan?: PageScan;
  /** The scan is a re-read of a page already read: only evidence not flagged before is reported. */
  rescan?: boolean;
  /** Redacted request body preview of the step's request. */
  body?: string;
}

const MAX_NODES = 1500;
const MAX_NODE_TEXT = 20_000;

const str = (v: unknown, max: number): string | undefined => (typeof v === "string" ? v.slice(0, max) : undefined);
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);

function parseNode(raw: unknown): DomTextNode | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as Record<string, unknown>;
  const text = str(r["text"], MAX_NODE_TEXT);
  if (text === undefined) return undefined;
  const node: DomTextNode = { text };
  for (const key of ["display", "visibility", "color", "backgroundColor"] as const) {
    const v = str(r[key], 200);
    if (v !== undefined) node[key] = v;
  }
  for (const key of ["opacity", "fontSizePx"] as const) {
    const v = num(r[key]);
    if (v !== undefined) node[key] = v;
  }
  if (typeof r["ariaHidden"] === "boolean") node.ariaHidden = r["ariaHidden"];
  if (typeof r["hiddenAttr"] === "boolean") node.hiddenAttr = r["hiddenAttr"];
  if (r["source"] === "text" || r["source"] === "comment" || r["source"] === "attribute") node.source = r["source"];
  if (r["landmark"] === "nav" || r["landmark"] === "footer" || r["landmark"] === "aside" || r["landmark"] === "cookie" || r["landmark"] === "ads") node.landmark = r["landmark"];
  const rect = r["rect"];
  if (typeof rect === "object" && rect !== null) {
    const q = rect as Record<string, unknown>;
    const x = num(q["x"]);
    const y = num(q["y"]);
    const width = num(q["width"]);
    const height = num(q["height"]);
    if (x !== undefined && y !== undefined && width !== undefined && height !== undefined) node.rect = { x, y, width, height };
  }
  return node;
}

/**
 * Parse one line of `analysis-input.jsonl`. The file is untrusted input (an SDK, or a person, wrote it), so
 * unknown keys are dropped and every field is type-checked and size-capped. Returns undefined for a line that
 * is not usable.
 * @example parseAnalysisInput('{"stepId":"s0001-ab12","body":"email=[REDACTED:email]"}')
 */
export function parseAnalysisInput(line: string): AnalysisInput | undefined {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as Record<string, unknown>;
  const stepId = str(r["stepId"], 128);
  if (!stepId || !/^[A-Za-z0-9_-]{1,128}$/.test(stepId)) return undefined;
  const out: AnalysisInput = { stepId };
  if (r["rescan"] === true) out.rescan = true;
  const body = str(r["body"], MAX_BODY_PREVIEW);
  if (body !== undefined) out.body = body;
  const scan = r["scan"];
  if (typeof scan === "object" && scan !== null) {
    const s = scan as Record<string, unknown>;
    const dom = s["dom"] as Record<string, unknown> | undefined;
    const url = str(s["url"], 4096);
    const text = str(s["text"], MAX_SNAPSHOT_TEXT);
    if (url !== undefined && text !== undefined && dom && Array.isArray(dom["nodes"])) {
      const nodes = (dom["nodes"] as unknown[]).slice(0, MAX_NODES).map(parseNode).filter((n): n is DomTextNode => n !== undefined);
      out.scan = { url, title: str(s["title"], 1000) ?? "", text, dom: { url, nodes } };
    }
  }
  return out;
}

/** Origin and path of a URL: the key under which evidence already flagged on a page is remembered. */
function pageKey(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return url;
  }
}

/**
 * Run the detectors over a run's steps, in order, exactly as the TypeScript SDK does while recording:
 * hidden instructions from the page scans, then the request / navigation / loop detectors against the run
 * history, then `causedBy`. Flags are *replaced* (not appended) on every step, so analysing the same inputs
 * twice gives the same result. Request bodies from `inputs` are used in memory only; they are not added to the
 * returned steps. Steps are returned in index order; fields other than `flags`, `causedBy` and `tokens` are untouched.
 * @example const analysed = analyzeRunSteps(run.steps, new Map(inputs.map((i) => [i.stepId, i])))
 */
export function analyzeRunSteps(steps: readonly Step[], inputs: ReadonlyMap<string, AnalysisInput>): Step[] {
  const ordered = [...steps].sort((a, b) => a.index - b.index);
  const history: Step[] = [];
  const pages: HistoryPage[] = [];
  const known = new Map<string, Set<string>>();
  const out: Step[] = [];
  for (const original of ordered) {
    const input = inputs.get(original.id);
    const step: Step = { ...original, flags: [] };
    delete step.causedBy;
    // The detectors see the body the SDK captured, whatever the capture level stores.
    const seen: Step = input?.body !== undefined && step.request ? { ...step, request: { ...step.request, bodyPreview: step.request.bodyPreview ?? input.body } } : step;
    if (step.kind === "page_read" && input?.scan) {
      const scan = input.scan;
      let flags: Flag[] = hiddenInstruction(scan.dom);
      const key = pageKey(scan.url);
      const evidence = known.get(key) ?? new Set<string>();
      if (input.rescan) flags = flags.filter((f) => !evidence.has(f.evidence));
      for (const f of flags) evidence.add(f.evidence);
      known.set(key, evidence);
      pages.push({ url: scan.url, text: scan.text });
      step.flags.push(...flags);
      step.tokens = computeTokenStats(scan);
    }
    step.flags.push(...analyzeStep(seen, history, pages));
    const cause = inferCausedBy(seen, history);
    if (cause) step.causedBy = cause;
    else if (original.causedBy !== undefined && step.kind !== "page_read") step.causedBy = original.causedBy;
    history.push({ ...seen, flags: step.flags, ...(step.causedBy ? { causedBy: step.causedBy } : {}) });
    out.push(step);
  }
  return out;
}
