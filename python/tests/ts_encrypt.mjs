// Writes an encrypted run with the TypeScript core, for the cross-language encryption tests.
//   node ts_encrypt.mjs <runsDir> key|passphrase   (the secret comes from $TEST_SECRET)
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const { writeRun } = await import(pathToFileURL(path.join(repo, "packages/core/dist/node.js")).href);

const [dir, mode] = process.argv.slice(2);
const secret = process.env.TEST_SECRET;
const encryption = mode === "key" ? { key: secret } : { passphrase: secret };
const id = `ts-written-${mode}`;
const steps = [
  { id: "s0000-aaaa", runId: id, index: 0, kind: "navigate", timestamp: 1_760_000_000_000, flags: [], url: "https://example.com/é" },
  { id: "s0001-aaaa", runId: id, index: 1, kind: "page_read", timestamp: 1_760_000_000_100, flags: [{ type: "hidden_instruction", severity: "high", message: "m", evidence: "e" }], url: "https://example.com/", snapshotRef: "snapshots/s0001-aaaa.txt" },
];
await writeRun(
  dir,
  { id, task: "Written by TypeScript ✓", startedAt: 1_760_000_000_000, endedAt: 1_760_000_001_000, status: "success", steps, meta: { sdk: "typescript", analyzed: true } },
  { "s0001-aaaa": "snapshot text from TypeScript" },
  encryption,
);
console.log(id);
