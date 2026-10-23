import { useEffect, useState, type ReactNode } from "react";
import type { Run, Step } from "@steplight/core";
import { fetchSnapshot } from "../api";
import { formatTokens } from "@steplight/core";
import { KIND_ICON, SEVERITY_STYLE, clock, describeStep, requestMeta } from "../format";
import { SeverityBadge } from "./SeverityBadge";

/** Split text around every occurrence of the evidence strings, wrapping hits in <mark>. */
export function highlight(text: string, evidence: string[]): ReactNode[] {
  const needles = [...new Set(evidence.map((e) => e.trim()).filter((e) => e.length > 3))];
  if (needles.length === 0) return [text];
  const ranges: [number, number][] = [];
  for (const needle of needles) {
    let from = 0;
    for (;;) {
      const at = text.indexOf(needle, from);
      if (at < 0) break;
      ranges.push([at, at + needle.length]);
      from = at + needle.length;
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const out: ReactNode[] = [];
  let pos = 0;
  for (const [start, end] of ranges) {
    if (start < pos) continue;
    out.push(text.slice(pos, start));
    out.push(
      <mark key={start} className="evidence" data-testid="evidence">
        {text.slice(start, end)}
      </mark>,
    );
    pos = end;
  }
  out.push(text.slice(pos));
  return out;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-5">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
        {title}
      </h3>
      {children}
    </section>
  );
}

/** "Why did this fail?" panel: error, likely causes, matched elements and similar selectors. */
function FailurePanel({ step }: { step: Step }) {
  const d = step.diagnosis;
  return (
    <section
      data-testid="failure-panel"
      className="mt-4 rounded-lg border border-red-300 bg-red-50 p-3 dark:border-red-800 dark:bg-red-950/30"
    >
      <h3 className="text-sm font-semibold text-red-900 dark:text-red-200">Why did this fail?</h3>
      {d && d.reasons.length > 0 && (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm" data-testid="failure-reasons">
          {d.reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
      {d && d.similar.length > 0 && (
        <div className="mt-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Similar elements on the page
          </p>
          <ul className="mt-1 space-y-1 font-mono text-xs" data-testid="failure-similar">
            {d.similar.map((s, i) => (
              <li key={i} className="break-all">
                {s}
              </li>
            ))}
          </ul>
        </div>
      )}
      {d && d.elements.length > 0 && (
        <p className="mt-3 break-all font-mono text-xs text-slate-600 dark:text-slate-300">
          {d.selector} → {d.matchCount} match{d.matchCount === 1 ? "" : "es"}:{" "}
          {d.elements.map((e) => `${e.selector}${e.text ? ` "${e.text}"` : ""}`).join(", ")}
        </p>
      )}
      {step.error && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-slate-500 dark:text-slate-400">Error message</summary>
          <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-xs">
            {step.error}
          </pre>
        </details>
      )}
    </section>
  );
}

/** Estimated context cost of a page read: tokens and the visible / hidden / boilerplate split. */
function CostSection({ tokens }: { tokens: NonNullable<Step["tokens"]> }) {
  const all = tokens.visibleChars + tokens.hiddenChars || 1;
  const pct = (n: number) => `${Math.round((n / all) * 100)}%`;
  return (
    <Section title="Context cost (estimate)">
      <p data-testid="cost-total" className="text-sm">
        <span className="font-semibold">~{formatTokens(tokens.total)} tokens</span>{" "}
        <span className="text-xs text-slate-500 dark:text-slate-400">estimated as characters / 4, not a real tokenizer</span>
      </p>
      <div className="mt-2 flex h-2 overflow-hidden rounded bg-slate-200 dark:bg-slate-700" aria-hidden>
        <div className="bg-indigo-500" style={{ width: pct(tokens.visibleChars - Math.min(tokens.boilerplateChars, tokens.visibleChars)) }} />
        <div className="bg-slate-400" style={{ width: pct(Math.min(tokens.boilerplateChars, tokens.visibleChars)) }} />
        <div className="bg-orange-500" style={{ width: pct(tokens.hiddenChars) }} />
      </div>
      <ul className="mt-2 space-y-0.5 text-xs text-slate-600 dark:text-slate-300">
        <li>
          <span className="mr-1 inline-block h-2 w-2 rounded-full bg-indigo-500" /> Visible content:{" "}
          {pct(tokens.visibleChars - Math.min(tokens.boilerplateChars, tokens.visibleChars))}
        </li>
        <li>
          <span className="mr-1 inline-block h-2 w-2 rounded-full bg-slate-400" /> Boilerplate (nav, footer, cookie banner, ads):{" "}
          {Math.round(tokens.boilerplateShare * 100)}%
        </li>
        <li>
          <span className="mr-1 inline-block h-2 w-2 rounded-full bg-orange-500" /> Hidden text: {pct(tokens.hiddenChars)}
        </li>
      </ul>
    </Section>
  );
}

/** Details of the selected step: flags, causal links, request and highlighted snapshot. */
export function StepDetail(props: { run: Run; step: Step; onJump: (index: number) => void }) {
  const { run, step } = props;
  const [snapshot, setSnapshot] = useState<string | undefined>();
  useEffect(() => {
    setSnapshot(undefined);
    if (!step.snapshotRef) return;
    let live = true;
    fetchSnapshot(run.id, step.id)
      .then((t) => live && setSnapshot(t))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [run.id, step.id, step.snapshotRef]);

  const cause = step.causedBy ? run.steps.find((s) => s.id === step.causedBy) : undefined;
  const effects = run.steps.filter((s) => s.causedBy === step.id);
  const decider = step.decidedBy ? run.steps.find((s) => s.id === step.decidedBy) : undefined;
  const decisions = run.steps.filter((s) => s.decidedBy === step.id);
  const evidence = step.flags.filter((f) => f.type === "hidden_instruction").map((f) => f.evidence);

  return (
    <div data-testid="step-detail" className="p-4">
      <div className="flex items-center gap-2 text-lg font-semibold">
        <span aria-hidden>{KIND_ICON[step.kind]}</span>
        <span className="min-w-0 break-words">{describeStep(step)}</span>
      </div>
      <p className="mt-1 break-all text-xs text-slate-500 dark:text-slate-400">
        #{step.index} · {step.kind} · {clock(step.timestamp)}
        {step.url ? ` · ${step.url}` : ""}
      </p>

      {cause && (
        <button
          data-testid="caused-by"
          onClick={() => props.onJump(cause.index)}
          className="mt-3 w-full rounded-lg border border-indigo-300 bg-indigo-50 px-3 py-2 text-left text-sm text-indigo-900 hover:bg-indigo-100 dark:border-indigo-700 dark:bg-indigo-950/50 dark:text-indigo-200"
        >
          ↩ Caused by step #{cause.index} ({cause.kind}): {describeStep(cause)}
        </button>
      )}
      {decider && (
        <button
          data-testid="decided-by"
          onClick={() => props.onJump(decider.index)}
          className="mt-2 w-full rounded-lg border border-violet-300 bg-violet-50 px-3 py-2 text-left text-sm text-violet-900 hover:bg-violet-100 dark:border-violet-700 dark:bg-violet-950/50 dark:text-violet-200"
        >
          🧠 Decided in step #{decider.index}: {describeStep(decider)}
        </button>
      )}
      {decisions.map((e) => (
        <button
          key={e.id}
          onClick={() => props.onJump(e.index)}
          className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-left text-sm hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
        >
          ↪ Chose step #{e.index} ({e.kind}): {describeStep(e)}
        </button>
      ))}
      {effects.map((e) => (
        <button
          key={e.id}
          onClick={() => props.onJump(e.index)}
          className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-left text-sm hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
        >
          ↪ Led to step #{e.index} ({e.kind}): {describeStep(e)}
        </button>
      ))}

      {(step.error || step.diagnosis) && <FailurePanel step={step} />}

      {step.flags.length > 0 && (
        <Section title="Flags">
          <ul className="space-y-2">
            {step.flags.map((f, i) => (
              <li
                key={i}
                data-testid="flag"
                className={`rounded-lg border border-l-4 border-slate-200 p-3 dark:border-slate-800 ${SEVERITY_STYLE[f.severity].row}`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <code className="text-xs font-semibold">{f.type}</code>
                </div>
                <p className="mt-1 text-sm">{f.message}</p>
                <p className="mt-1 break-words rounded bg-black/5 p-2 font-mono text-xs dark:bg-white/10">
                  {f.evidence}
                </p>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {step.request && (
        <Section title="Request">
          <p className="break-all font-mono text-xs">
            <strong>{step.request.method}</strong> {step.request.url}
          </p>
          {requestMeta(step) && <p className="mt-1 text-xs text-slate-500" data-testid="request-meta">{requestMeta(step)}</p>}
          {step.request.bodyPreview && (
            <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-slate-100 p-3 font-mono text-xs dark:bg-slate-800">
              {step.request.bodyPreview}
            </pre>
          )}
        </Section>
      )}

      {step.tokens && <CostSection tokens={step.tokens} />}

      {step.snapshotRef && (
        <Section title="Page snapshot (all text the agent could read)">
          <pre
            data-testid="snapshot"
            className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-100 p-3 font-mono text-xs dark:bg-slate-800"
          >
            {snapshot === undefined ? "Loading…" : highlight(snapshot, evidence)}
          </pre>
        </Section>
      )}
    </div>
  );
}
