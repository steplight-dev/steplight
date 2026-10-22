import { diffRuns, ensureAnalyzed, readRun, readSnapshot, type Run, type RunDiff, type Step } from "@steplight/core/node";

/**
 * Load two stored runs and diff them, including the page text each was looking at when they
 * diverged.
 * @example const { diff } = await diffStored(".steplight/runs", "20261008-a", "20261008-b")
 */
export async function diffStored(
  root: string,
  idA: string,
  idB: string,
): Promise<{ diff: RunDiff; runA: Run; runB: Run }> {
  await ensureAnalyzed(root, idA);
  await ensureAnalyzed(root, idB);
  const [runA, runB] = await Promise.all([readRun(root, idA), readRun(root, idB)]);
  const first = diffRuns(runA, runB);
  const d = first.divergence;
  if (!d) return { diff: first, runA, runB };
  const load = async (runId: string, step: Step | undefined): Promise<Record<string, string>> => {
    const text = step ? await readSnapshot(root, runId, step) : undefined;
    return step && text !== undefined ? { [step.id]: text } : {};
  };
  const snapshots = {
    a: await load(idA, d.contextA),
    b: await load(idB, d.contextB),
  };
  return { diff: diffRuns(runA, runB, snapshots), runA, runB };
}

const brief = (s: Step | undefined): string =>
  s ? `#${s.index} ${s.kind}${s.targetText ? ` '${s.targetText}'` : s.targetSelector ? ` ${s.targetSelector}` : ""}${s.url ? ` @ ${new URL(s.url, "http://x").pathname}` : ""}` : "(no more steps)";

/**
 * Human-readable multi-line report of a diff.
 * @example console.log(formatDiff(diff))
 */
export function formatDiff(diff: RunDiff): string {
  const out = [diff.summary, diff.outcome];
  const d = diff.divergence;
  if (d) {
    out.push("", "First divergence:", `  A: ${brief(d.a)}`, `  B: ${brief(d.b)}`);
    if (d.contextA || d.contextB) {
      out.push("", `Page each run was looking at: A ${brief(d.contextA)} | B ${brief(d.contextB)}`);
    }
    const t = d.textDiff;
    if (t && (t.onlyA.length || t.onlyB.length)) {
      out.push("", "Text on that page seen by only one run:");
      for (const l of t.onlyA.slice(0, 8)) out.push(`  - only A: ${l}`);
      for (const l of t.onlyB.slice(0, 8)) out.push(`  + only B: ${l}`);
    }
  }
  return out.join("\n");
}
