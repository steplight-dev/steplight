/** Kinds of step a recorded agent can take. */
export type StepKind =
  | "navigate"
  | "page_read"
  | "click"
  | "type"
  | "form_submit"
  | "network_request"
  | "download"
  | "agent_note"
  | "error";

/** All step kinds, in display order. */
export const STEP_KINDS: readonly StepKind[] = [
  "navigate",
  "page_read",
  "click",
  "type",
  "form_submit",
  "network_request",
  "download",
  "agent_note",
  "error",
];

/** Kinds of suspicious moment a detector can flag. */
export type FlagType =
  | "hidden_instruction"
  | "cross_domain_data"
  | "sensitive_data_outbound"
  | "suspicious_redirect"
  | "stuck_loop";

/** Flag severity, ordered low → critical. */
export type Severity = "low" | "medium" | "high" | "critical";

/** A suspicious moment attached to a step. */
export interface Flag {
  type: FlagType;
  severity: Severity;
  message: string;
  evidence: string;
}

/** Summary of an outbound HTTP request. */
export interface StepRequest {
  method: string;
  url: string;
  bodyPreview?: string;
  /** Browser resource type: xmlhttprequest, ping (beacon), websocket, image, sub_frame, … */
  resourceType?: string;
  /** HTTP status of the response, when the request completed. */
  status?: number;
  /** Size of the request body in bytes (the body itself is only kept at the "full" capture level). */
  bodyBytes?: number;
  /** Response `content-type` (one of only two response headers ever kept). */
  contentType?: string;
  /** Response `content-length`. */
  contentLength?: number;
  /** Network error reported by the browser, e.g. `net::ERR_BLOCKED_BY_CLIENT`. */
  error?: string;
  /** Where the observation came from: the browser's request log or the opt-in page hooks. */
  source?: "webRequest" | "deep";
}

/** One element a failed selector matched (or nearly matched). */
export interface DiagnosedElement {
  selector: string;
  tag: string;
  text: string;
  visible: boolean;
  disabled: boolean;
  inViewport: boolean;
  pointerEvents?: string;
  /** Selector/text of the element on top of this one at its centre, if any. */
  coveredBy?: string;
}

/** "Why did this fail?" analysis captured when an action on a selector fails. */
export interface FailureDiagnosis {
  selector: string;
  /** Number of elements the selector matched; -1 when it could not be evaluated. */
  matchCount: number;
  elements: DiagnosedElement[];
  /** Human-readable explanations, most likely first. */
  reasons: string[];
  /** Nearest similar selectors found on the page. */
  similar: string[];
}

/** Estimated token cost of a page read (chars/4 heuristic, not a real tokenizer). */
export interface PageTokens {
  /** Estimated tokens of all text on the page, hidden included. */
  total: number;
  visibleChars: number;
  hiddenChars: number;
  boilerplateChars: number;
  /** boilerplateChars / (visibleChars + hiddenChars), 0–1. */
  boilerplateShare: number;
  estimated: true;
}

/** One action or observation inside a run. */
export interface Step {
  id: string;
  runId: string;
  index: number;
  kind: StepKind;
  timestamp: number;
  durationMs?: number;
  url?: string;
  targetSelector?: string;
  targetText?: string;
  request?: StepRequest;
  /** Path (relative to the run folder) of the stored DOM/text snapshot. */
  snapshotRef?: string;
  flags: Flag[];
  /** Id of the step that most likely caused this step. */
  causedBy?: string;
  /** Error message when the action failed (e.g. a click that timed out). */
  error?: string;
  /** Why the action failed. */
  diagnosis?: FailureDiagnosis;
  /** Token estimate for `page_read` steps. */
  tokens?: PageTokens;
}

/** Version of the run folder format (`formatVersion` in `run.json`); see `spec/run-format.schema.json`. */
export const FORMAT_VERSION = 1;

/** Final or current state of a run. */
export type RunStatus = "running" | "success" | "failed";

/** One agent task and all of its steps. */
export interface Run {
  /** Run folder format version. Absent in runs written before it existed. */
  formatVersion?: number;
  id: string;
  task: string;
  startedAt: number;
  endedAt?: number;
  status: RunStatus;
  steps: Step[];
  /**
   * Free-form metadata. Written by the SDKs: `sdk`, `sdkVersion`, `captureLevel` and `analyzed`
   * (false until `steplight analyze` has run the detectors; absent in runs recorded before it existed,
   * which were analysed while recording).
   */
  meta: Record<string, string | boolean>;
}

/** Lightweight listing entry for a stored run. */
export interface RunSummary {
  id: string;
  task: string;
  status: RunStatus;
  startedAt: number;
  endedAt?: number;
  stepCount: number;
  flagCount: number;
  maxSeverity?: Severity;
}
