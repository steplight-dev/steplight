import { createBundle, type RunBundle } from "./bundle.js";
import { KIND_ICON, describeStep, offset, requestMeta, shortUrl } from "./describe.js";
import { sha256Base64 } from "./hash.js";
import { diffRuns, type RunDiff } from "./diff.js";
import { redactText } from "./redact.js";
import { maxSeverity, severityRank } from "./severity.js";
import { formatTokens, summarizeTokens } from "./tokens.js";
import type { Flag, Run, Severity, Step } from "./types.js";

/** Options for {@link renderHtmlReport}. */
export interface HtmlReportOptions {
  /** A second run to compare against; adds a "Comparison" section with the first divergence. */
  compare?: RunBundle;
}

/** Cap per snapshot and over the whole report, to keep the file small enough to attach anywhere. */
const MAX_SNAPSHOT_CHARS = 60_000;
const MAX_TOTAL_SNAPSHOT_CHARS = 1_200_000;

const esc = (s: string): string =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const sevClass = (s: Severity | undefined): string => (s ? `sev-${s}` : "");

/** Highest severity among medium-and-above flags (low flags only appear inside step details). */
function notable(flags: readonly Flag[]): Severity | undefined {
  const worst = maxSeverity(flags);
  return worst && severityRank(worst) >= severityRank("medium") ? worst : undefined;
}

/** Escape `text` and wrap occurrences of the evidence strings in `<mark>`. */
function highlight(text: string, evidence: string[]): string {
  const needles = [...new Set(evidence.map((e) => e.trim()).filter((e) => e.length > 3))];
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
  let out = "";
  let pos = 0;
  for (const [start, end] of ranges) {
    if (start < pos) continue;
    out += esc(text.slice(pos, start)) + `<mark>${esc(text.slice(start, end))}</mark>`;
    pos = end;
  }
  return out + esc(text.slice(pos));
}

function flagsHtml(flags: readonly Flag[]): string {
  if (flags.length === 0) return "";
  const items = flags
    .map(
      (f) => `<li class="flag ${sevClass(f.severity)}"><span class="badge ${sevClass(f.severity)}">${f.severity}</span> <code>${esc(f.type)}</code><p>${esc(f.message)}</p><pre class="small">${esc(f.evidence)}</pre></li>`,
    )
    .join("");
  return `<h4>Flags</h4><ul class="flags">${items}</ul>`;
}

function failureHtml(step: Step): string {
  if (!step.error && !step.diagnosis) return "";
  const d = step.diagnosis;
  const reasons = d?.reasons.length ? `<ul>${d.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : "";
  const similar = d?.similar.length ? `<p class="muted">Similar elements on the page:</p><ul class="mono">${d.similar.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : "";
  const err = step.error ? `<details><summary>Error message</summary><pre class="small">${esc(step.error)}</pre></details>` : "";
  return `<div class="failure"><h4>Why did this fail?</h4>${reasons}${similar}${err}</div>`;
}

function stepHtml(run: Run, step: Step, snapshots: Record<string, string>, budget: { left: number }): string {
  const worst = notable(step.flags);
  const badge = worst ? `<span class="badge ${sevClass(worst)}">${step.flags.length} · ${worst}</span>` : "";
  const failed = step.error ? `<span class="badge failed">failed</span>` : "";
  const cause = step.causedBy ? run.steps.find((s) => s.id === step.causedBy) : undefined;
  const effects = run.steps.filter((s) => s.causedBy === step.id);
  const decider = step.decidedBy ? run.steps.find((s) => s.id === step.decidedBy) : undefined;
  const decisions = run.steps.filter((s) => s.decidedBy === step.id);

  const parts: string[] = [];
  parts.push(`<p class="muted">#${step.index} · ${esc(step.kind)} · ${new Date(step.timestamp).toISOString()}${step.url ? ` · <span class="mono">${esc(step.url)}</span>` : ""}</p>`);
  if (cause) parts.push(`<p class="link"><a href="#step-${cause.index}">↩ Caused by step #${cause.index} (${esc(cause.kind)}): ${esc(describeStep(cause))}</a></p>`);
  if (decider) parts.push(`<p class="link"><a href="#step-${decider.index}">🧠 Decided in step #${decider.index}: ${esc(describeStep(decider))}</a></p>`);
  for (const e of decisions) parts.push(`<p class="link"><a href="#step-${e.index}">↪ Chose step #${e.index} (${esc(e.kind)}): ${esc(describeStep(e))}</a></p>`);
  for (const e of effects) parts.push(`<p class="link"><a href="#step-${e.index}">↪ Led to step #${e.index} (${esc(e.kind)}): ${esc(describeStep(e))}</a></p>`);
  parts.push(failureHtml(step));
  parts.push(flagsHtml(step.flags));
  if (step.request) {
    parts.push(
      `<h4>Request</h4><p class="mono"><strong>${esc(step.request.method)}</strong> ${esc(step.request.url)}</p>${requestMeta(step) ? `<p class="muted">${esc(requestMeta(step))}</p>` : ""}${step.request.bodyPreview ? `<pre class="small">${esc(step.request.bodyPreview)}</pre>` : ""}`,
    );
  }
  if (step.tokens) {
    parts.push(
      `<h4>Context cost (estimate)</h4><p>~${formatTokens(step.tokens.total)} tokens · ${Math.round(step.tokens.boilerplateShare * 100)}% boilerplate · ${formatTokens(Math.ceil(step.tokens.hiddenChars / 4))} hidden <span class="muted">(chars/4 heuristic)</span></p>`,
    );
  }
  let snap = snapshots[step.id];
  if (snap !== undefined) {
    const cap = Math.max(0, Math.min(MAX_SNAPSHOT_CHARS, budget.left));
    const clipped = snap.length > cap;
    snap = clipped ? `${snap.slice(0, cap)}…[truncated in this report]` : snap;
    budget.left -= Math.min(snap.length, cap);
    const evidence = step.flags.filter((f) => f.type === "hidden_instruction").map((f) => f.evidence);
    parts.push(`<h4>Page snapshot (all text the agent could read)</h4><pre class="snapshot">${highlight(snap, evidence)}</pre>`);
  }

  return `<details class="step ${sevClass(worst)}${step.error ? " failed" : ""}" id="step-${step.index}">
<summary><span class="t">${offset(step.timestamp, run.startedAt)}</span> <span class="ic">${KIND_ICON[step.kind]}</span> <span class="d">${esc(describeStep(step))}</span> <span class="u muted">${esc(shortUrl(step.url))}</span>${failed}${badge}</summary>
<div class="body">${parts.join("\n")}</div>
</details>`;
}

function diffHtml(diff: RunDiff, a: Run, b: Run): string {
  const cell = (s: Step | undefined): string =>
    s
      ? `<td>${KIND_ICON[s.kind]} ${esc(describeStep(s))}<br /><span class="muted mono">#${s.index}</span></td>`
      : `<td class="empty"></td>`;
  const rows = diff.pairs
    .map((p, i) => `<tr class="pair ${p.status}${i === diff.divergence?.pairIndex ? " first" : ""}">${cell(p.a)}${cell(p.b)}</tr>`)
    .join("");
  const t = diff.divergence?.textDiff;
  const text =
    t && (t.onlyA.length || t.onlyB.length)
      ? `<h3>What each run saw at the divergence</h3><div class="cols"><div><h4>Only in A</h4><pre class="small">${esc(t.onlyA.join("\n") || "(nothing)")}</pre></div><div><h4>Only in B</h4><pre class="small">${esc(t.onlyB.join("\n") || "(nothing)")}</pre></div></div>`
      : "";
  return `<section id="comparison"><h2>Comparison</h2>
<p class="summary ${diff.identical ? "ok" : "diverged"}"><strong>${esc(diff.summary)}</strong><br /><span class="muted">${esc(diff.outcome)}</span></p>
<table class="diff"><thead><tr><th>A · ${esc(a.task)}</th><th>B · ${esc(b.task)}</th></tr></thead><tbody>${rows}</tbody></table>${text}</section>`;
}

const STYLE = `
:root{color-scheme:light dark;--bg:#fff;--fg:#0f172a;--muted:#64748b;--card:#f8fafc;--line:#e2e8f0;--low:#0284c7;--medium:#d97706;--high:#ea580c;--critical:#dc2626;--mark:#fed7aa}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--fg:#e2e8f0;--muted:#94a3b8;--card:#111a30;--line:#24304d;--mark:#7c2d12}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:1.25rem 1rem 4rem}
h1{font-size:1.4rem;margin:.2rem 0}h2{font-size:1.1rem;margin:2rem 0 .6rem}h3{font-size:1rem}h4{margin:.9rem 0 .3rem;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.muted{color:var(--muted)}.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.mono{font-size:.8rem;word-break:break-all}
.meta{display:flex;flex-wrap:wrap;gap:.4rem 1.2rem;font-size:.85rem;color:var(--muted)}
.badge{display:inline-block;padding:0 .5rem;border-radius:999px;font-size:.7rem;font-weight:600;text-transform:uppercase;background:var(--line);color:var(--fg);margin-left:.4rem;white-space:nowrap}
.badge.sev-low{background:#e0f2fe;color:#075985}.badge.sev-medium{background:#fef3c7;color:#92400e}.badge.sev-high{background:#ffedd5;color:#9a3412}.badge.sev-critical{background:#fee2e2;color:#991b1b}.badge.failed{background:#fee2e2;color:#991b1b}
.toolbar{margin:.8rem 0}button{font:inherit;padding:.25rem .7rem;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);cursor:pointer}
details.step{border:1px solid var(--line);border-left:4px solid transparent;border-radius:8px;margin:.35rem 0;background:var(--card)}
details.step.sev-medium{border-left-color:var(--medium)}details.step.sev-high{border-left-color:var(--high)}details.step.sev-critical{border-left-color:var(--critical)}details.step.failed:not(.sev-medium):not(.sev-high):not(.sev-critical){border-left-color:var(--critical)}
details.step:target{outline:2px solid #6366f1}
summary{cursor:pointer;padding:.5rem .7rem;display:flex;flex-wrap:wrap;gap:.2rem .6rem;align-items:baseline}.t{font-family:ui-monospace,Menlo,monospace;font-size:.78rem;color:var(--muted);min-width:3.2rem}.d{font-weight:600}.u{font-size:.8rem}
.body{padding:.2rem .9rem .9rem;border-top:1px solid var(--line)}
pre{margin:.3rem 0;padding:.6rem;border:1px solid var(--line);border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:.78rem;background:var(--bg)}
pre.snapshot{max-height:24rem}mark{background:var(--mark);color:inherit;padding:0 2px;border-radius:3px}
.flags{list-style:none;padding:0;margin:0}.flag{border:1px solid var(--line);border-left:4px solid var(--low);border-radius:6px;padding:.4rem .6rem;margin:.3rem 0}.flag.sev-medium{border-left-color:var(--medium)}.flag.sev-high{border-left-color:var(--high)}.flag.sev-critical{border-left-color:var(--critical)}.flag p{margin:.2rem 0}
.failure{border:1px solid #fca5a5;background:rgba(220,38,38,.07);border-radius:6px;padding:.3rem .8rem;margin:.6rem 0}.link{margin:.3rem 0}a{color:#6366f1}
.cards.top{margin-top:.8rem}.cards{display:flex;flex-wrap:wrap;gap:.6rem}.card{border:1px solid var(--line);border-radius:8px;padding:.5rem .8rem;background:var(--card)}.card b{display:block;font-size:1.1rem}
table.diff{width:100%;border-collapse:collapse;table-layout:fixed}table.diff td,table.diff th{border:1px solid var(--line);padding:.35rem .5rem;vertical-align:top;font-size:.85rem;word-break:break-word;text-align:left}
tr.changed td{background:rgba(217,119,6,.12)}tr.onlyA td{background:rgba(220,38,38,.10)}tr.onlyB td{background:rgba(22,163,74,.12)}tr.first td{outline:2px solid #6366f1;outline-offset:-2px}td.empty{background:transparent!important}
.summary{border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem}.summary.diverged{border-color:var(--medium)}.summary.ok{border-color:#16a34a}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}@media (max-width:640px){.cols{grid-template-columns:1fr}}
footer{margin-top:2.5rem;font-size:.78rem;color:var(--muted)}
`;

const SCRIPT = `
(function(){
  var all=function(open){document.querySelectorAll("details.step").forEach(function(d){d.open=open;});};
  document.getElementById("expand").addEventListener("click",function(){all(true);});
  document.getElementById("collapse").addEventListener("click",function(){all(false);});
  var show=function(){var id=location.hash.slice(1);var el=id&&document.getElementById(id);if(el&&el.tagName==="DETAILS"){el.open=true;el.scrollIntoView();}};
  window.addEventListener("hashchange",show);show();
})();
`;

/** The report's one inline style and script, so a wrapper page can allow exactly these by hash. */
export function reportInlineSources(): { style: string; script: string } {
  return { style: STYLE, script: SCRIPT };
}

/**
 * Content-Security-Policy for the report: nothing loads from anywhere, no network (`connect-src`
 * falls back to `default-src 'none'`), and only the report's own inline style and script (by hash).
 */
export function reportCsp(style: string, script: string): string {
  return [
    "default-src 'none'",
    `style-src 'sha256-${sha256Base64(style)}'`,
    `script-src 'sha256-${sha256Base64(script)}'`,
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
}

/**
 * Render a run as ONE self-contained HTML file: timeline, flags, step details with highlighted
 * hidden-instruction evidence, request previews, failure analysis, token estimates and (optionally)
 * a comparison with a second run. The file makes no external requests (no scripts, fonts, images
 * or links are loaded from anywhere) and everything is redacted again before rendering.
 * @example await fs.writeFile("run.html", renderHtmlReport(createBundle(run, snapshots)))
 */
export function renderHtmlReport(input: RunBundle, options: HtmlReportOptions = {}): string {
  const { run, snapshots } = createBundle(input.run, input.snapshots); // re-redact before export
  const budget = { left: MAX_TOTAL_SNAPSHOT_CHARS };
  const flags = run.steps.flatMap((s) => s.flags);
  const counts = (["critical", "high", "medium", "low"] as const)
    .map((sev) => [sev, flags.filter((f) => f.severity === sev).length] as const)
    .filter(([, n]) => n > 0);
  const tokens = summarizeTokens(run);

  const cards = [
    `<div class="card"><b>${run.steps.length}</b>steps</div>`,
    `<div class="card"><b>${flags.length}</b>flags${counts.length ? ` <span class="muted">(${counts.map(([s, n]) => `${n} ${s}`).join(", ")})</span>` : ""}</div>`,
    run.steps.some((s) => s.error) ? `<div class="card"><b>${run.steps.filter((s) => s.error).length}</b>failed actions</div>` : "",
    tokens.pages ? `<div class="card"><b>~${formatTokens(tokens.total)}</b>tokens <span class="muted">(estimate)</span></div>` : "",
  ].join("");

  const expensive = tokens.top.length
    ? `<h3>Most expensive pages (estimated tokens)</h3><ol>${tokens.top.map((p) => `<li><a href="#step-${p.index}">${formatTokens(p.tokens)} · ${esc(shortUrl(p.url) || `step #${p.index}`)}</a> <span class="muted">${Math.round(p.boilerplateShare * 100)}% boilerplate</span></li>`).join("")}</ol>`
    : "";

  let comparison = "";
  if (options.compare) {
    const other = createBundle(options.compare.run, options.compare.snapshots);
    comparison = diffHtml(diffRuns(run, other.run, { a: snapshots, b: other.snapshots }), run, other.run);
  }

  const steps = run.steps.map((s) => stepHtml(run, s, snapshots, budget)).join("\n");
  const title = `Steplight report: ${redactText(run.task)}`;
  const csp = reportCsp(STYLE, SCRIPT);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="${csp}" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="generator" content="Steplight" />
<title>${esc(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
<p class="muted">Steplight run report</p>
<h1>${esc(run.task)}</h1>
<div class="meta"><span>Run <span class="mono">${esc(run.id)}</span></span><span>Status: ${esc(run.status)}</span><span>Started ${new Date(run.startedAt).toISOString()}</span>${run.endedAt ? `<span>Duration ${((run.endedAt - run.startedAt) / 1000).toFixed(1)}s</span>` : ""}</div>
<div class="cards top">${cards}</div>
${expensive}
${comparison}
<h2>Timeline</h2>
<div class="toolbar"><button id="expand" type="button">Expand all</button> <button id="collapse" type="button">Collapse all</button></div>
${steps}
<footer>Generated locally by Steplight. Emails, card numbers, API keys and tokens are redacted; typed values and passwords are never recorded. Token figures are estimates (characters / 4).</footer>
</main>
<script>${SCRIPT}</script>
</body>
</html>
`;
}
