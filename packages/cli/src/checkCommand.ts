import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { VERSION, checkRun, ensureAnalyzed, listRuns, parseRules, readRun } from "@steplight/core/node";
import { parse as parseYaml } from "yaml";
import { formatCheck, type CheckFormat } from "./checkFormats.js";

/** Options for {@link runCheck}. */
export interface CheckOptions {
  runId?: string;
  latest?: boolean;
  rulesFile: string;
  format: CheckFormat;
  dir: string;
  out?: string;
}

/** Exit codes of `steplight check`. */
export const EXIT = { pass: 0, fail: 1, error: 2 } as const;

const toPosix = (p: string): string => p.split(path.sep).join("/");

/**
 * Evaluate a stored run against a rules file and render the report.
 * @returns the report text and the process exit code (0 pass, 1 findings, 2 usage error).
 * @example const { output, exitCode } = await runCheck({ latest: true, rulesFile: "steplight.rules.yml", format: "text", dir: ".steplight/runs" })
 */
export async function runCheck(opts: CheckOptions): Promise<{ output: string; exitCode: number }> {
  const dir = path.resolve(opts.dir);
  let rulesText: string;
  try {
    rulesText = await readFile(opts.rulesFile, "utf8");
  } catch {
    return { output: `steplight: cannot read rules file "${opts.rulesFile}" (use --rules <file>)`, exitCode: EXIT.error };
  }
  let rules;
  try {
    rules = parseRules(parseYaml(rulesText));
  } catch (err) {
    return { output: `steplight: invalid rules in ${opts.rulesFile}: ${err instanceof Error ? err.message : String(err)}`, exitCode: EXIT.error };
  }

  // Runs from SDKs that leave the detectors to us are analysed first, so the rules see the flags.
  await ensureAnalyzed(dir, opts.latest ? undefined : opts.runId);
  let runId = opts.runId;
  if (opts.latest) {
    runId = (await listRuns(dir))[0]?.id;
    if (!runId) return { output: `steplight: no runs found in ${dir}`, exitCode: EXIT.error };
  }
  if (!runId) return { output: "steplight: give a <runId> or --latest", exitCode: EXIT.error };

  let run;
  try {
    run = await readRun(dir, runId);
  } catch {
    return { output: `steplight: run "${runId}" not found in ${dir}`, exitCode: EXIT.error };
  }

  const result = checkRun(run, rules);
  const output = formatCheck(opts.format, {
    run,
    rules,
    result,
    stepsFile: toPosix(path.relative(process.cwd(), path.join(dir, run.id, "steps.jsonl"))),
    runFile: toPosix(path.relative(process.cwd(), path.join(dir, run.id, "run.json"))),
    version: VERSION,
  });
  if (opts.out) await writeFile(path.resolve(opts.out), output);
  return { output: opts.out ? `${opts.format} report written to ${opts.out}` : output, exitCode: result.passed ? EXIT.pass : EXIT.fail };
}
