import { promises as fs } from "node:fs";
import path from "node:path";
import { formatCheck, type CheckContext } from "@steplight/cli/check";
import { VERSION, checkRun, maxSeverity, parseRules, severityRank, type CheckResult, type Finding, type Rules, type Severity } from "@steplight/core";
import { ensureAnalyzed } from "@steplight/core/analyze";
import { listRuns, readRun } from "@steplight/core/run-store";
import { parse as parseYaml } from "yaml";
import { DEFAULT_RULES_FILE, type ActionInputs } from "./inputs.js";
import { InputError } from "./paths.js";
import { renderSummary } from "./summary.js";

const MAX_RULES_BYTES = 256 * 1024;

/** What one invocation of the action produces. */
export interface CheckOutcome {
  result: "pass" | "fail";
  flagCount: number;
  /** Highest flag severity of the run, or "none". */
  maxSeverity: Severity | "none";
  /** Absolute path of the report file, or "" when none was written. */
  reportFile: string;
  /** Text for the job log. */
  log: string;
  /** Markdown for the job summary. */
  summary: string;
}

const posix = (p: string): string => p.split(path.sep).join("/");

async function loadRules(inputs: ActionInputs, notes: string[]): Promise<Rules> {
  let text: string;
  try {
    const stat = await fs.stat(inputs.rulesFile);
    if (!stat.isFile() || stat.size > MAX_RULES_BYTES) throw new InputError("rules must be a regular file smaller than 256 KB");
    text = await fs.readFile(inputs.rulesFile, "utf8");
  } catch (err) {
    if (err instanceof InputError) throw err;
    if (inputs.rulesIsDefault) {
      notes.push(`No ${DEFAULT_RULES_FILE} found: only the fail-on severity threshold was checked.`);
      return {};
    }
    throw new InputError(`cannot read the rules file "${posix(path.relative(inputs.workspace, inputs.rulesFile))}"`);
  }
  try {
    return parseRules(parseYaml(text));
  } catch (err) {
    throw new InputError(`invalid rules file: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Evaluate one stored run: the rules file plus the `fail-on` severity threshold.
 * @throws InputError when the inputs, the rules or the run cannot be used.
 * @example const outcome = await runCheckAction(await readInputs(process.env))
 */
export async function runCheckAction(inputs: ActionInputs): Promise<CheckOutcome> {
  const notes: string[] = [];
  const rules = await loadRules(inputs, notes);

  // Runs recorded by the Python SDK carry no flags until the detectors have run: do that first.
  await ensureAnalyzed(inputs.runsDir, inputs.runId);
  let runId = inputs.runId;
  if (!runId) {
    runId = (await listRuns(inputs.runsDir))[0]?.id;
    if (!runId) throw new InputError(`no runs found in "${posix(path.relative(inputs.workspace, inputs.runsDir)) || "."}"`);
  }
  let run;
  try {
    run = await readRun(inputs.runsDir, runId);
  } catch (err) {
    if (err instanceof Error && err.name === "EncryptedRunError") throw new InputError("this run is encrypted; decrypt it first (steplight decrypt)");
    throw new InputError(`run "${runId}" not found in the runs directory`);
  }

  const base = checkRun(run, rules);
  const findings: Finding[] = [...base.findings];
  const evaluated = [...base.evaluated];

  // fail-on: any flag at or above the threshold fails the check, whatever the rules file says.
  const threshold = severityRank(inputs.failOn);
  for (const step of run.steps) {
    for (const flag of step.flags) {
      if (severityRank(flag.severity) < threshold) continue;
      if (findings.some((f) => f.stepId === step.id && f.severity === flag.severity && f.message.includes(flag.message))) continue;
      findings.push({
        ruleId: "max_severity",
        severity: flag.severity,
        message: `[${flag.severity}] ${flag.type}: ${flag.message} (step #${step.index})`,
        stepId: step.id,
        stepIndex: step.index,
      });
    }
  }
  if (!evaluated.includes("max_severity")) evaluated.push("max_severity");

  const result: CheckResult = { passed: findings.length === 0, evaluated, findings };
  const flags = run.steps.flatMap((s) => s.flags);
  const top = maxSeverity(flags);

  const ctx: CheckContext = {
    run,
    rules,
    result,
    stepsFile: posix(path.relative(inputs.workspace, path.join(inputs.runsDir, run.id, "steps.jsonl"))),
    runFile: posix(path.relative(inputs.workspace, path.join(inputs.runsDir, run.id, "run.json"))),
    version: VERSION,
  };
  const report = formatCheck(inputs.format, ctx);

  let reportFile = "";
  const ext = { text: "txt", junit: "xml", sarif: "sarif" }[inputs.format];
  const target = inputs.outputFile ?? (inputs.format === "text" ? undefined : path.join(inputs.workspace, `steplight-check.${ext}`));
  if (target) {
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, report);
    reportFile = target;
  }

  return {
    result: result.passed ? "pass" : "fail",
    flagCount: flags.length,
    maxSeverity: top ?? "none",
    reportFile,
    log: reportFile && inputs.format !== "text" ? `${formatCheck("text", ctx)}\n${inputs.format} report written to ${posix(path.relative(inputs.workspace, reportFile))}` : report,
    summary: renderSummary({ run, passed: result.passed, findings, failOn: inputs.failOn, notes }),
  };
}
