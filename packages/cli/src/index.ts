import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { DEFAULT_RUNS_DIR, analyzeStoredRun, analyzeStoredRuns, ensureAnalyzed, formatTokens, summarizeTokens, clearRuns, exportRunOtlp, generatePlaywrightTest, appendAudit, auditFilePath, countEncryptedRuns, effectiveEncryption, loadPolicy, readAuditFile, verifyAuditLog, type Policy, listRuns, purgeRuns, readRun, DEFAULT_OTLP_ENDPOINT } from "@steplight/core/node";
import { exportOptionsFromFlags, renderStoredBundle, renderStoredExport, renderStoredReport, type ExportFlags } from "./reportCommand.js";
import { runCheck } from "./checkCommand.js";
import { registerRedteam } from "./redteamCommand.js";
import type { CheckFormat } from "./checkFormats.js";
import { diffStored, formatDiff } from "./diffCommand.js";
import { createViewerServer, findViewerDir, isLoopbackHost } from "./server.js";

/** Default port of the local viewer / ingest server. */
export const DEFAULT_PORT = 4777;

/**
 * Build the `steplight` command-line program.
 * @example await buildProgram().parseAsync(["node", "steplight", "view", "--port", "4777"])
 */
/** Load the effective policy (org file + config + environment), print problems, and say what is in force. */
function activePolicy(policyFile: string | undefined, quiet = false): Policy {
  const { policy, sources, problems } = loadPolicy({ ...(policyFile ? { policyFile } : {}) });
  for (const p of problems) console.error(`steplight: policy: ${p.key}: ${p.reason}`);
  if (!quiet && sources.length > 0) {
    console.log(`Policy in force (${sources.join(", ")}): ${Object.keys(policy).join(", ") || "nothing restrictive"}.`);
  }
  return policy;
}

/** Throw a readable error when an organisation policy forbids what the command is about to do. */
function requireExportAllowed(policy: Policy, passwordEnv: string | undefined): void {
  if (policy.disableExport) throw new Error("Export is disabled by organisation policy.");
  if (policy.requireEncryption && !passwordEnv) throw new Error("Organisation policy requires exports to be password-protected: add --password-env <VAR>.");
}

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("steplight")
    .description("Replay and trace every step your AI agent takes.")
    .version("0.2.0-rc.1");

  program
    .command("view")
    .description("Serve the replay viewer and JSON API for recorded runs (localhost only)")
    .option("-p, --port <port>", "port to listen on", String(DEFAULT_PORT))
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .option("--host <address>", "address to bind (default 127.0.0.1; anything else exposes your data to the network)")
    .option("--extension-id <id...>", "only accept the API from this Chrome extension id (repeatable)")
    .option("--policy <file>", "organisation policy file (JSON) that restricts what Steplight may do")
    .option("--encrypt", "encrypt runs received from the extension (needs $STEPLIGHT_ENCRYPTION_KEY or $STEPLIGHT_PASSPHRASE)")
    .option("--retention-days <n>", "delete runs older than n days when the viewer starts (also $STEPLIGHT_RETENTION_DAYS)")
    .action(async (opts: { port: string; dir: string; host?: string; extensionId?: string[]; retentionDays?: string; encrypt?: boolean; policy?: string }) => {
      const here = path.dirname(fileURLToPath(import.meta.url));
      const runsDir = path.resolve(opts.dir);
      const host = opts.host ?? "127.0.0.1";
      let policy: Policy;
      try {
        policy = activePolicy(opts.policy);
      } catch (err) {
        console.error(`steplight: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 2;
        return;
      }
      if ((opts.encrypt || policy.requireEncryption) && !effectiveEncryption()) {
        console.error(`steplight: ${policy.requireEncryption ? "organisation policy requires encryption, which" : "--encrypt"} needs a key. Set STEPLIGHT_ENCRYPTION_KEY (64 hex characters) or STEPLIGHT_PASSPHRASE.`);
        process.exitCode = 2;
        return;
      }
      if (effectiveEncryption()) console.log("Encryption at rest: ON (AES-256-GCM). New runs are written encrypted.");
      else {
        const locked = await countEncryptedRuns(runsDir);
        if (locked > 0) console.log(`${locked} encrypted run(s) found. Set STEPLIGHT_ENCRYPTION_KEY or STEPLIGHT_PASSPHRASE to view them.`);
      }
      const retention = policy.retentionDays ?? Number(opts.retentionDays ?? process.env.STEPLIGHT_RETENTION_DAYS ?? "");
      if (policy.retentionDays !== undefined || opts.retentionDays !== undefined || process.env.STEPLIGHT_RETENTION_DAYS) {
        if (Number.isFinite(retention) && retention >= 0) {
          const gone = await purgeRuns(runsDir, { olderThanDays: retention });
          if (gone.length > 0) {
            console.log(`Retention: deleted ${gone.length} run(s) older than ${retention} day(s).`);
            appendAudit(auditFilePath(runsDir), "retention_delete", { runs: gone.length, days: retention });
          }
        } else {
          console.error("steplight: --retention-days must be a number of days.");
        }
      } else {
        // Nothing is deleted unless asked for: these are your files. A hint is enough.
        const old = (await listRuns(runsDir).catch(() => [])).filter((r) => r.startedAt < Date.now() - 7 * 86_400_000).length;
        if (old > 0) console.log(`${old} stored run(s) are older than 7 days. Remove them with: steplight purge --older-than-days 7`);
      }
      // Runs recorded by SDKs that leave the detectors to us (Python) are analysed before anything is shown.
      await ensureAnalyzed(runsDir);
      appendAudit(auditFilePath(runsDir), "server_started", { host, encrypted: Boolean(effectiveEncryption()), policy: Object.keys(policy).join(",") });
      const server = createViewerServer({
        runsDir,
        policy,
        auditFile: auditFilePath(runsDir),
        viewerDir: findViewerDir(here),
        ...(opts.extensionId ? { extensionIds: opts.extensionId } : {}),
        ...(isLoopbackHost(host) ? {} : { extraHosts: [host] }),
      });
      const port = Number(opts.port);
      server.on("error", (err) => {
        console.error(`steplight: cannot listen on port ${port}: ${err.message}`);
        process.exitCode = 1;
      });
      if (!isLoopbackHost(host)) {
        console.error(
          `
!!! WARNING: binding to ${host}. Other machines on your network can reach this server.
` +
            `!!! Recorded runs may contain sensitive page content. Only continue on a network you fully trust.
`,
        );
      }
      server.listen(port, host, () => {
        console.log(
          `Steplight viewer: http://127.0.0.1:${port}/#token=${server.token}
` +
            `Runs directory:   ${runsDir}
` +
            `Open the link above (it carries this session's access token) and paste the same link into
` +
            `the extension popup (Pair with CLI) to send runs here. The token changes on every start.`,
        );
      });
    });

  program
    .command("purge")
    .description("Delete stored runs: those older than N days, or all of them (run folders are removed, snapshots included)")
    .option("--older-than-days <n>", "delete runs that started more than n days ago")
    .option("--policy <file>", "organisation policy file (JSON) that restricts what Steplight may do")
    .option("--all", "delete every run (needs --yes)")
    .option("--yes", "confirm deleting everything")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (opts: { olderThanDays?: string; all?: boolean; yes?: boolean; dir: string; policy?: string }) => {
      const runsDir = path.resolve(opts.dir);
      if (opts.all && !opts.yes) {
        console.error("steplight: --all deletes every stored run. Add --yes to confirm.");
        process.exitCode = 2;
        return;
      }
      const days = opts.olderThanDays === undefined ? undefined : Number(opts.olderThanDays);
      if (!opts.all && (days === undefined || !Number.isFinite(days) || days < 0)) {
        console.error("steplight: give --older-than-days <n> or --all --yes.");
        process.exitCode = 2;
        return;
      }
      const deleted = await purgeRuns(runsDir, opts.all ? { all: true } : { olderThanDays: days! });
      console.log(`Deleted ${deleted.length} run${deleted.length === 1 ? "" : "s"} from ${runsDir}.`);
      appendAudit(auditFilePath(runsDir), "purge", { runs: deleted.length, all: Boolean(opts.all) });
      if (deleted.length > 0) {
        console.log("Note: deleting files does not overwrite them on disk. Use --encrypt (or disk encryption) if the data was sensitive.");
      }
    });

  program
    .command("export <runId>")
    .description("Export a stored run: print JSON, or re-send it as OpenTelemetry spans with --otlp")
    .option("--otlp", "send the run to the OTLP/HTTP endpoint")
    .option("--bundle", "write a complete run file (with page snapshots) that the viewer can import")
    .option("-o, --out <file>", "with --bundle: output file (default: steplight-<runId>.json)")
    .option("--policy <file>", "organisation policy file (JSON) that restricts what Steplight may do")
    .option("--strip-snapshots", "leave out all page snapshot text")
    .option("--strip-bodies", "leave out request body previews")
    .option("--strip-query", "remove query strings and fragments from URLs")
    .option("--password-env <VAR>", "encrypt the file with the password held in this environment variable")

    .option("--endpoint <url>", `OTLP endpoint (default: $OTEL_EXPORTER_OTLP_ENDPOINT or ${DEFAULT_OTLP_ENDPOINT})`)
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (runId: string, opts: { otlp?: boolean; endpoint?: string; dir: string; bundle?: boolean; out?: string; policy?: string } & ExportFlags) => {
      try {
        if (opts.bundle) {
          requireExportAllowed(activePolicy(opts.policy, true), opts.passwordEnv);
          const options = exportOptionsFromFlags(opts);
          const out = path.resolve(opts.out ?? `steplight-${runId}${options.password ? ".locked" : ""}.json`);
          await writeFile(out, await renderStoredBundle(opts.dir, runId, options));
          appendAudit(auditFilePath(opts.dir), "export", { kind: "json", encrypted: Boolean(options.password), snapshots: !options.stripSnapshots, bodies: !options.stripBodies });
          console.log(`Wrote ${out}${options.password ? " (password-protected)" : ""}.`);
          return;
        }
        await ensureAnalyzed(path.resolve(opts.dir), runId);
        const run = await readRun(path.resolve(opts.dir), runId);
        if (!opts.otlp) {
          console.log(JSON.stringify(run, null, 2));
          return;
        }
        const ok = await exportRunOtlp(run, { endpoint: opts.endpoint });
        console.log(
          ok
            ? `Sent run ${run.id} (${run.steps.length} steps) to ${opts.endpoint ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? DEFAULT_OTLP_ENDPOINT}`
            : "Export failed (is a collector listening?)",
        );
        if (!ok) process.exitCode = 1;
      } catch (err) {
        console.error(`steplight: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });

  program
    .command("clear")
    .description("Delete recorded runs (all, or all but the newest N with --keep)")
    .option("-k, --keep <n>", "keep the newest N runs", "0")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (opts: { keep: string; dir: string }) => {
      const keep = Number(opts.keep);
      if (!Number.isInteger(keep) || keep < 0) {
        console.error("steplight: --keep must be a non-negative integer");
        process.exitCode = 1;
        return;
      }
      const deleted = await clearRuns(path.resolve(opts.dir), { keep });
      console.log(`Deleted ${deleted.length} run${deleted.length === 1 ? "" : "s"}${keep ? `, kept the newest ${keep}` : ""}.`);
    });

  program
    .command("analyze [runId]")
    .description("Run the detectors on runs recorded by an SDK that leaves them to us (the Python SDK): writes the flags, then marks the run analysed")
    .option("--all", "analyze every run that has not been analyzed yet")
    .option("--include-running", "also analyze runs still marked as running (a recording that crashed; never while an SDK is writing)")
    .option("--json", "print the results as JSON")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (runId: string | undefined, opts: { all?: boolean; includeRunning?: boolean; json?: boolean; dir: string }) => {
      if (!runId === !opts.all) {
        console.error("steplight: give a <runId> or --all");
        process.exitCode = 2;
        return;
      }
      const dir = path.resolve(opts.dir);
      const options = { ...(opts.includeRunning ? { includeRunning: true } : {}) };
      const results = runId ? [await analyzeStoredRun(dir, runId, options)] : await analyzeStoredRuns(dir, options);
      if (opts.json) console.log(JSON.stringify(results, null, 2));
      else {
        for (const r of results) {
          const note =
            r.status === "analyzed" ? `analyzed, ${r.flags} flag${r.flags === 1 ? "" : "s"}` : r.status === "already-analyzed" ? "already analyzed" : r.status === "still-running" ? "still recording (use --include-running if it crashed)" : `error: ${r.error}`;
          if (r.status !== "already-analyzed" || runId) console.log(`${r.runId}: ${note}`);
        }
        const done = results.filter((r) => r.status === "analyzed").length;
        console.log(`${done} run${done === 1 ? "" : "s"} analyzed, ${results.filter((r) => r.status === "already-analyzed").length} already analyzed.`);
      }
      if (results.some((r) => r.status === "error")) process.exitCode = 1;
    });

  program
    .command("diff <runA> <runB>")
    .description("Compare two runs: find where they first diverge and what each saw there (exit 1 if they differ)")
    .option("--json", "print the diff as JSON")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (a: string, b: string, opts: { json?: boolean; dir: string }) => {
      try {
        const { diff } = await diffStored(path.resolve(opts.dir), a, b);
        console.log(opts.json ? JSON.stringify(diff, null, 2) : formatDiff(diff));
        if (!diff.identical) process.exitCode = 1;
      } catch (err) {
        console.error(`steplight: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 2;
      }
    });

  program
    .command("replay-script <runId>")
    .description("Generate a Playwright test that replays a recorded run (navigations, clicks, inputs, URL assertions)")
    .option("-o, --out <file>", "write to a file instead of stdout")
    .option("--base-url <url>", "origin the site was served from (default: the recorded one)")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (runId: string, opts: { out?: string; baseUrl?: string; dir: string }) => {
      try {
        const run = await readRun(path.resolve(opts.dir), runId);
        const code = generatePlaywrightTest(run, { baseUrl: opts.baseUrl });
        if (opts.out) {
          await writeFile(path.resolve(opts.out), code);
          console.log(`Wrote ${opts.out}. Run it with: BASE_URL=<site> npx playwright test ${opts.out}`);
        } else {
          process.stdout.write(code);
        }
      } catch (err) {
        console.error(`steplight: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });

  program
    .command("check [runId]")
    .description("Fail (exit 1) when a run breaks the rules in steplight.rules.yml: for CI")
    .option("--latest", "check the newest run")
    .option("-r, --rules <file>", "rules file", "steplight.rules.yml")
    .option("-f, --format <format>", "text | junit | sarif", "text")
    .option("-o, --out <file>", "write the report to a file")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (runId: string | undefined, opts: { latest?: boolean; rules: string; format: string; out?: string; dir: string }) => {
      if (!["text", "junit", "sarif"].includes(opts.format)) {
        console.error(`steplight: unknown format "${opts.format}" (use text, junit or sarif)`);
        process.exitCode = 2;
        return;
      }
      const { output, exitCode } = await runCheck({
        runId,
        latest: opts.latest,
        rulesFile: opts.rules,
        format: opts.format as CheckFormat,
        dir: opts.dir,
        out: opts.out,
      });
      (exitCode === 2 ? console.error : console.log)(output);
      process.exitCode = exitCode;
    });

  program
    .command("report <runId>")
    .description("Write a single-file, self-contained HTML report of a run (share it or attach it to an issue)")
    .option("-o, --out <file>", "output file (default: steplight-<runId>.html)")
    .option("--diff <runId>", "also include a comparison with this run")
    .option("--policy <file>", "organisation policy file (JSON) that restricts what Steplight may do")
    .option("--strip-snapshots", "leave out all page snapshot text")
    .option("--strip-bodies", "leave out request body previews")
    .option("--strip-query", "remove query strings and fragments from URLs")
    .option("--password-env <VAR>", "encrypt the file with the password held in this environment variable")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (runId: string, opts: { out?: string; diff?: string; dir: string; policy?: string } & ExportFlags) => {
      try {
        requireExportAllowed(activePolicy(opts.policy, true), opts.passwordEnv);
        const options = exportOptionsFromFlags(opts);
        const html = Object.keys(options).length > 0 ? await renderStoredExport(opts.dir, runId, opts.diff, options) : await renderStoredReport(opts.dir, runId, opts.diff);
        const out = path.resolve(opts.out ?? `steplight-${runId}.html`);
        await writeFile(out, html);
        appendAudit(auditFilePath(opts.dir), "export", { kind: "html-report", encrypted: Boolean(options.password), snapshots: !options.stripSnapshots, bodies: !options.stripBodies });
        console.log(`Wrote ${out} (${(Buffer.byteLength(html) / 1024).toFixed(0)} KB). It is self-contained and makes no network requests.${options.password ? " Encrypted: it asks for the password before showing anything." : ""}`);
      } catch (err) {
        console.error(`steplight: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });

  program
    .command("audit")
    .description("Show or verify the local audit log of Steplight's own actions (hash-chained, tamper-evident)")
    .option("--verify", "check the hash chain and exit 1 if it is broken")
    .option("--json", "print the entries as JSON")
    .option("-d, --dir <dir>", "runs directory (the log lives next to it)", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action((opts: { verify?: boolean; json?: boolean; dir: string }) => {
      const file = auditFilePath(opts.dir);
      const entries = readAuditFile(file);
      const result = verifyAuditLog(entries);
      if (opts.json) console.log(JSON.stringify({ file, verification: result, entries }, null, 2));
      else {
        for (const e of entries) console.log(`${new Date(e.ts).toISOString()}  ${e.action}  ${Object.entries(e.detail).map(([k, v]) => `${k}=${String(v)}`).join(" ")}`);
        console.log(result.ok ? `\n${entries.length} entries in ${file}. Hash chain intact.` : `\nTAMPERING DETECTED at entry ${result.brokenAt}: ${result.reason}.`);
      }
      if (opts.verify && !result.ok) process.exitCode = 1;
    });

  program
    .command("decrypt <file>")
    .description("Decrypt a password-protected export (run file or HTML report)")
    .option("--policy <file>", "organisation policy file (JSON) that restricts what Steplight may do")
    .requiredOption("--password-env <VAR>", "environment variable that holds the password")
    .option("-o, --out <file>", "output file (default: the input name without .locked)")
    .action(async (file: string, opts: { passwordEnv: string; out?: string; policy?: string }) => {
      try {
        if (activePolicy(opts.policy, true).disableExport) throw new Error("Export is disabled by organisation policy.");
        const password = process.env[opts.passwordEnv];
        if (!password) throw new Error(`Environment variable ${opts.passwordEnv} is not set.`);
        const { openProtectedExport } = await import("@steplight/core/node");
        const { readFile } = await import("node:fs/promises");
        const opened = await openProtectedExport(await readFile(file, "utf8"), password);
        const out = path.resolve(opts.out ?? file.replace(/\.locked(?=\.)/, ""));
        if (out === path.resolve(file)) throw new Error("Choose an output file with --out (it would overwrite the input).");
        await writeFile(out, opened.text);
        console.log(`Wrote ${out} (${opened.kind === "run-json" ? "run file" : "HTML report"}).`);
      } catch (err) {
        console.error(`steplight: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });

  program
    .command("tokens <runId>")
    .description("Estimated token cost of a run's page reads and its most expensive pages (chars/4 heuristic)")
    .option("--json", "print as JSON")
    .option("-d, --dir <dir>", "runs directory", process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR)
    .action(async (runId: string, opts: { json?: boolean; dir: string }) => {
      try {
        await ensureAnalyzed(path.resolve(opts.dir), runId);
        const s = summarizeTokens(await readRun(path.resolve(opts.dir), runId));
        if (opts.json) return void console.log(JSON.stringify(s, null, 2));
        if (s.pages === 0) return void console.log("No token estimates in this run (record page reads with the current SDK).");
        console.log(`~${formatTokens(s.total)} tokens (estimate) over ${s.pages} page reads; ${Math.round(s.boilerplateShare * 100)}% boilerplate, ${formatTokens(Math.ceil(s.hiddenChars / 4))} hidden`);
        console.log("Most expensive pages:");
        for (const p of s.top) console.log(`  ${formatTokens(p.tokens).padStart(6)}  #${p.index}  ${p.url ?? ""}  (${Math.round(p.boilerplateShare * 100)}% boilerplate)`);
      } catch (err) {
        console.error(`steplight: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });

  registerRedteam(program, process.env.STEPLIGHT_DIR ?? DEFAULT_RUNS_DIR);

  return program;
}
export { createViewerServer, findViewerDir, isLoopbackHost, VIEWER_CSP, type ViewerServer } from "./server.js";
export type { IngestMessage, ServerOptions } from "./server.js";
export { diffStored, formatDiff } from "./diffCommand.js";
export { runCheck } from "./checkCommand.js";
export { formatCheck } from "./checkFormats.js";
export { loadBundle, renderStoredReport } from "./reportCommand.js";
