import { promises as fs } from "node:fs";
import path from "node:path";
import { analyzeRunSteps, parseAnalysisInput, type AnalysisInput } from "../analysis.js";
import { isSafeId } from "../ids.js";
import { sanitizeStep } from "../sanitize.js";
import type { Run, Step } from "../types.js";
import { decryptFile, encryptFile, isEncryptedText, resolveKey, writePrivate, type EncryptionOptions } from "./fileCrypto.js";
import { readRun } from "./runStore.js";

/** File an SDK that does not run the detectors itself leaves in the run folder (see `analysisInput` in the schema). */
export const ANALYSIS_INPUT_FILE = "analysis-input.jsonl";

/** What happened to one run. */
export interface AnalyzeResult {
  runId: string;
  status: "analyzed" | "already-analyzed" | "still-running" | "error";
  /** Flags on the run after analysis (when analyzed). */
  flags?: number;
  /** Why it failed (when status is "error"). */
  error?: string;
}

/** Options for the analysis functions. */
export interface AnalyzeOptions {
  encryption?: EncryptionOptions;
  /** Also analyse runs whose status is still "running" (a recording that crashed). Never do this while an SDK is writing. */
  includeRunning?: boolean;
}

/** True when the run asks for analysis: only an explicit `meta.analyzed === false` does (older runs were analysed while recording). */
export const needsAnalysis = (run: Pick<Run, "meta">): boolean => run.meta["analyzed"] === false;

async function readAnalysisInputs(dir: string, runId: string, key: Buffer | undefined): Promise<Map<string, AnalysisInput>> {
  const out = new Map<string, AnalysisInput>();
  const raw = await fs.readFile(path.join(dir, ANALYSIS_INPUT_FILE), "utf8").catch(() => "");
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const input = parseAnalysisInput(decryptFile(line, key, `${runId}/${ANALYSIS_INPUT_FILE}`));
      if (input) out.set(input.stepId, input);
    } catch (err) {
      if (err instanceof Error && err.name === "EncryptedRunError") throw err;
      /* a partially written line: skip it */
    }
  }
  return out;
}

/**
 * Run the detectors on a stored run that asks for it (`meta.analyzed === false`), write the flags into
 * `steps.jsonl`, set `meta.analyzed` to true and delete `analysis-input.jsonl` (so the request bodies and page
 * text it held do not outlive the analysis). Safe to repeat: a second call finds nothing to do, and a crash in
 * the middle leaves the run marked as unanalysed with its inputs intact, so the next call redoes it.
 * @example await analyzeStoredRun(".steplight/runs", "20261008-101500-a1b2c3")
 */
export async function analyzeStoredRun(root: string, runId: string, options: AnalyzeOptions = {}): Promise<AnalyzeResult> {
  try {
    if (!isSafeId(runId)) throw new Error(`Unsafe run id: ${runId}`);
    const dir = path.join(root, runId);
    // Cheap check first (run.json only): the viewer asks on every poll.
    const metaText = await fs.readFile(path.join(dir, "run.json"), "utf8");
    const key = isEncryptedText(metaText) ? await resolveKey(root, options.encryption) : undefined;
    const meta = JSON.parse(decryptFile(metaText, key, `${runId}/run.json`)) as Run;
    if (!needsAnalysis(meta)) return { runId, status: "already-analyzed" };
    if (meta.status === "running" && !options.includeRunning) return { runId, status: "still-running" };
    const run = await readRun(root, runId, options.encryption);
    const inputs = await readAnalysisInputs(dir, runId, key);
    const analysed = analyzeRunSteps(run.steps, inputs);
    const seal = (text: string, file: string): string => (key ? encryptFile(text, key, `${runId}/${file}`) : text);

    // Steps first (through a temporary file, so a crash never leaves a half-written steps.jsonl) ...
    const stepsFile = path.join(dir, "steps.jsonl");
    const lines = analysed.map((s: Step) => seal(JSON.stringify(sanitizeStep(s)), "steps.jsonl")).join("\n");
    await writePrivate(`${stepsFile}.tmp`, lines ? `${lines}\n` : "");
    await fs.rename(`${stepsFile}.tmp`, stepsFile);
    // ... then the marker, then the inputs.
    await writePrivate(path.join(dir, "run.json"), seal(JSON.stringify({ ...meta, meta: { ...meta.meta, analyzed: true } }, null, 2), "run.json"));
    await fs.rm(path.join(dir, ANALYSIS_INPUT_FILE), { force: true });
    return { runId, status: "analyzed", flags: analysed.reduce((n, s) => n + s.flags.length, 0) };
  } catch (err) {
    return { runId, status: "error", error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Analyse every stored run that asks for it. Only valid run folders inside `root` are touched.
 * @example const results = await analyzeStoredRuns(".steplight/runs")
 */
export async function analyzeStoredRuns(root: string, options: AnalyzeOptions = {}): Promise<AnalyzeResult[]> {
  const entries = await fs.readdir(root, { withFileTypes: true }).catch(() => []);
  const out: AnalyzeResult[] = [];
  for (const e of entries) {
    if (!e.isDirectory() || !isSafeId(e.name)) continue;
    if (!(await fs.stat(path.join(root, e.name, "run.json")).then(() => true, () => false))) continue; // not a run folder
    out.push(await analyzeStoredRun(root, e.name, options));
  }
  return out;
}

/**
 * Make sure what a command is about to read has been analysed: one run, or (without an id) all of them.
 * Never throws, and never touches a run that does not ask for analysis; a failure is left for the command's own
 * read to report. Used by view, check, diff, report, export, tokens and the GitHub Action.
 * @example await ensureAnalyzed(dir, runId)
 */
export async function ensureAnalyzed(root: string, runId?: string, options: AnalyzeOptions = {}): Promise<void> {
  try {
    if (runId !== undefined) await analyzeStoredRun(root, runId, options);
    else await analyzeStoredRuns(root, options);
  } catch {
    /* the caller reads the run next and reports any real problem */
  }
}
