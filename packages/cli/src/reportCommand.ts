import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  createBundle,
  ensureAnalyzed,
  readRun,
  readSnapshot,
  packageHtmlExport,
  packageJsonExport,
  renderHtmlReport,
  type ExportOptions,
  type RunBundle,
} from "@steplight/core/node";

/**
 * Load a stored run and all its snapshots as a portable bundle.
 * @example const bundle = await loadBundle(".steplight/runs", "20261008-101500-a1b2c3")
 */
export async function loadBundle(root: string, runId: string): Promise<RunBundle> {
  await ensureAnalyzed(root, runId);
  const run = await readRun(root, runId);
  const snapshots: Record<string, string> = {};
  for (const step of run.steps) {
    const text = await readSnapshot(root, runId, step);
    if (text !== undefined) snapshots[step.id] = text;
  }
  return createBundle(run, snapshots);
}

/**
 * Render the single-file HTML report for a stored run (optionally compared with another run).
 * @example const html = await renderStoredReport(dir, runId, otherRunId)
 */
export async function renderStoredReport(root: string, runId: string, compareId?: string): Promise<string> {
  const bundle = await loadBundle(path.resolve(root), runId);
  const compare = compareId ? await loadBundle(path.resolve(root), compareId) : undefined;
  return renderHtmlReport(bundle, { compare });
}

/** Read a previously exported run file (JSON) from disk. Exposed for tests. */
export async function readBundleFile(file: string): Promise<string> {
  return readFile(file, "utf8");
}

/** Export flags shared by `report` and `export --bundle`. */
export interface ExportFlags {
  stripSnapshots?: boolean;
  stripBodies?: boolean;
  stripQuery?: boolean;
  /** Name of an environment variable that holds the password (never pass a password on the command line). */
  passwordEnv?: string;
}

/** Turn CLI flags into {@link ExportOptions}; the password is read from the named environment variable. */
export function exportOptionsFromFlags(flags: ExportFlags): ExportOptions {
  const password = flags.passwordEnv ? process.env[flags.passwordEnv] : undefined;
  if (flags.passwordEnv && !password) throw new Error(`Environment variable ${flags.passwordEnv} is not set (it should hold the password).`);
  return {
    ...(flags.stripSnapshots ? { stripSnapshots: true } : {}),
    ...(flags.stripBodies ? { stripBodies: true } : {}),
    ...(flags.stripQuery ? { stripQueryStrings: true } : {}),
    ...(password ? { password } : {}),
  };
}

/** The HTML report of a stored run with export options applied (and optionally encrypted). */
export async function renderStoredExport(root: string, runId: string, compareId: string | undefined, options: ExportOptions): Promise<string> {
  const bundle = await loadBundle(path.resolve(root), runId);
  const compare = compareId ? await loadBundle(path.resolve(root), compareId) : undefined;
  return packageHtmlExport(bundle, options, compare ? { compare } : {});
}

/** The run-file (JSON) export of a stored run with export options applied (and optionally encrypted). */
export async function renderStoredBundle(root: string, runId: string, options: ExportOptions): Promise<string> {
  return packageJsonExport(await loadBundle(path.resolve(root), runId), options);
}
