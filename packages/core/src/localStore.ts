import { newRunId } from "./ids.js";
import { sanitizeSnapshot, truncate } from "./redact.js";
import { sanitizeStep } from "./sanitize.js";
import { maxSeverity } from "./severity.js";
import type { Run, RunStatus, RunSummary, Step } from "./types.js";

/** Minimal key/value store; `chrome.storage.local` satisfies it. */
export interface KeyValueStore {
  get(keys: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  /** All key names, if the store can list them without reading values (needed to delete encrypted entries). */
  keys?(): Promise<string[]>;
}

/** Limits for {@link LocalRunStore}. */
export interface LocalStoreOptions {
  /** Total budget for all stored runs, in characters (≈ bytes). Default 8 MB. */
  maxBytes?: number;
  /** Cap per stored snapshot. Default 60 000 characters. */
  maxSnapshotChars?: number;
}

interface RunMeta {
  id: string;
  task: string;
  status: RunStatus;
  startedAt: number;
  endedAt?: number;
  meta: Record<string, string | boolean>;
  stepCount: number;
  flagCount: number;
  maxSeverity?: RunSummary["maxSeverity"];
  bytes: number;
}

const INDEX = "sl:index";
const metaKey = (id: string) => `sl:meta:${id}`;
const stepKey = (id: string, i: number) => `sl:step:${id}:${i}`;
const snapKey = (id: string, stepId: string) => `sl:snap:${id}:${stepId}`;

/**
 * Run storage on top of a key/value store, with a size budget and oldest-run eviction.
 * Used by the extension in standalone mode (no CLI server) and by its bundled viewer.
 * Operations are serialised, and every write is redacted and truncated.
 * @example
 * const store = new LocalRunStore(chrome.storage.local);
 * await store.startRun({ id, task, startedAt: Date.now(), meta: {} });
 */
export class LocalRunStore {
  private maxBytes: number;
  private readonly maxSnap: number;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly kv: KeyValueStore,
    options: LocalStoreOptions = {},
  ) {
    this.maxBytes = options.maxBytes ?? 8 * 1024 * 1024;
    this.maxSnap = options.maxSnapshotChars ?? 60_000;
  }

  private serial<T>(job: () => Promise<T>): Promise<T> {
    const next = this.queue.then(job, job);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async index(): Promise<string[]> {
    const v = (await this.kv.get(INDEX))[INDEX];
    return Array.isArray(v) ? (v as string[]) : [];
  }

  private async metas(ids: string[]): Promise<Map<string, RunMeta>> {
    const got = ids.length ? await this.kv.get(ids.map(metaKey)) : {};
    const out = new Map<string, RunMeta>();
    for (const id of ids) {
      const m = got[metaKey(id)] as RunMeta | undefined;
      if (m) out.set(id, m);
    }
    return out;
  }

  private async removeRun(id: string, meta: RunMeta | undefined): Promise<void> {
    const keys = [metaKey(id)];
    for (let i = 0; i < (meta?.stepCount ?? 0); i++) keys.push(stepKey(id, i));
    const all = await this.kv.get(null);
    for (const k of Object.keys(all)) if (k.startsWith(`sl:snap:${id}:`)) keys.push(k);
    await this.kv.remove(keys);
  }

  /** Delete oldest runs until the budget fits, never touching `keepId`. */
  private async evict(keepId: string): Promise<void> {
    let ids = await this.index();
    const metas = await this.metas(ids);
    let total = [...metas.values()].reduce((n, m) => n + m.bytes, 0);
    while (total > this.maxBytes) {
      const victim = ids.find((id) => id !== keepId);
      if (!victim) break;
      total -= metas.get(victim)?.bytes ?? 0;
      await this.removeRun(victim, metas.get(victim));
      ids = ids.filter((id) => id !== victim);
      await this.kv.set({ [INDEX]: ids });
    }
  }

  /**
   * Begin a run. An existing run with the same id is replaced.
   * @example await store.startRun({ id: "r1", task: "demo", startedAt: Date.now(), meta: {} })
   */
  startRun(run: Pick<Run, "id" | "task" | "startedAt"> & { meta?: Run["meta"] }): Promise<void> {
    return this.serial(async () => {
      const ids = await this.index();
      if (ids.includes(run.id)) await this.removeRun(run.id, (await this.metas([run.id])).get(run.id));
      const meta: RunMeta = {
        id: run.id,
        task: sanitizeSnapshot(run.task).slice(0, 300),
        status: "running",
        startedAt: run.startedAt,
        meta: run.meta ?? {},
        stepCount: 0,
        flagCount: 0,
        bytes: 200,
      };
      await this.kv.set({ [metaKey(run.id)]: meta, [INDEX]: [...ids.filter((i) => i !== run.id), run.id] });
      await this.evict(run.id);
    });
  }

  /**
   * Append a step (and optional snapshot text). Ignored if the run no longer exists.
   * @example await store.addStep("r1", step, "page text")
   */
  addStep(runId: string, step: Step, snapshot?: string): Promise<void> {
    return this.serial(async () => {
      const meta = (await this.metas([runId])).get(runId);
      if (!meta) return;
      const safe = sanitizeStep({ ...step, runId, index: meta.stepCount });
      const items: Record<string, unknown> = {};
      let bytes = 0;
      if (snapshot !== undefined) {
        const text = truncate(sanitizeSnapshot(snapshot), this.maxSnap);
        safe.snapshotRef = `snapshots/${safe.id}.txt`;
        items[snapKey(runId, safe.id)] = text;
        bytes += text.length;
      } else {
        delete safe.snapshotRef;
      }
      items[stepKey(runId, meta.stepCount)] = safe;
      bytes += JSON.stringify(safe).length;
      const flags = safe.flags;
      const worst = maxSeverity([...flags, ...(meta.maxSeverity ? [{ severity: meta.maxSeverity }] : [])]);
      items[metaKey(runId)] = {
        ...meta,
        stepCount: meta.stepCount + 1,
        flagCount: meta.flagCount + flags.length,
        maxSeverity: worst,
        bytes: meta.bytes + bytes,
      } satisfies RunMeta;
      await this.kv.set(items);
      await this.evict(runId);
    });
  }

  /**
   * Mark a run finished.
   * @example await store.finishRun("r1", "success", Date.now())
   */
  finishRun(runId: string, status: RunStatus, endedAt: number): Promise<void> {
    return this.serial(async () => {
      const meta = (await this.metas([runId])).get(runId);
      if (meta) await this.kv.set({ [metaKey(runId)]: { ...meta, status, endedAt } });
    });
  }

  /**
   * Import a complete run (already validated). If the id exists a fresh id is used.
   * @returns the id the run was stored under.
   */
  importRun(run: Run, snapshots: Record<string, string> = {}): Promise<string> {
    return this.serial(async () => {
      const ids = await this.index();
      const id = ids.includes(run.id) ? newRunId() : run.id;
      const meta: RunMeta = {
        id,
        task: run.task.slice(0, 300),
        status: run.status,
        startedAt: run.startedAt,
        endedAt: run.endedAt,
        meta: run.meta,
        stepCount: 0,
        flagCount: 0,
        bytes: 200,
      };
      const items: Record<string, unknown> = {};
      const flags = [];
      for (const [i, s] of run.steps.entries()) {
        const safe = sanitizeStep({ ...s, runId: id, index: i });
        const snap = snapshots[s.id];
        if (snap !== undefined) {
          const text = truncate(sanitizeSnapshot(snap), this.maxSnap);
          items[snapKey(id, s.id)] = text;
          meta.bytes += text.length;
        } else delete safe.snapshotRef;
        items[stepKey(id, i)] = safe;
        meta.bytes += JSON.stringify(safe).length;
        flags.push(...safe.flags);
      }
      meta.stepCount = run.steps.length;
      meta.flagCount = flags.length;
      meta.maxSeverity = maxSeverity(flags);
      items[metaKey(id)] = meta;
      items[INDEX] = [...ids, id];
      await this.kv.set(items);
      await this.evict(id);
      return id;
    });
  }

  /** List stored runs, newest first. */
  listRuns(): Promise<RunSummary[]> {
    return this.serial(async () => {
      const metas = await this.metas(await this.index());
      return [...metas.values()]
        .map((m) => ({
          id: m.id,
          task: m.task,
          status: m.status,
          startedAt: m.startedAt,
          endedAt: m.endedAt,
          stepCount: m.stepCount,
          flagCount: m.flagCount,
          maxSeverity: m.maxSeverity,
        }))
        .sort((a, b) => b.startedAt - a.startedAt);
    });
  }

  /** Read a stored run with all steps, or undefined. */
  getRun(id: string): Promise<Run | undefined> {
    return this.serial(async () => {
      const meta = (await this.metas([id])).get(id);
      if (!meta) return undefined;
      const keys = Array.from({ length: meta.stepCount }, (_, i) => stepKey(id, i));
      const got = keys.length ? await this.kv.get(keys) : {};
      const steps = keys.map((k) => got[k] as Step | undefined).filter((s): s is Step => !!s);
      return {
        id: meta.id,
        task: meta.task,
        status: meta.status,
        startedAt: meta.startedAt,
        endedAt: meta.endedAt,
        meta: meta.meta,
        steps,
      };
    });
  }

  /** Read one step's snapshot text. */
  getSnapshot(runId: string, stepId: string): Promise<string | undefined> {
    return this.serial(async () => {
      const v = (await this.kv.get(snapKey(runId, stepId)))[snapKey(runId, stepId)];
      return typeof v === "string" ? v : undefined;
    });
  }

  /** Delete one run. */
  deleteRun(id: string): Promise<void> {
    return this.serial(async () => {
      const ids = await this.index();
      await this.removeRun(id, (await this.metas([id])).get(id));
      await this.kv.set({ [INDEX]: ids.filter((i) => i !== id) });
    });
  }

  /** Change the storage budget (e.g. when the user edits the setting). Existing runs are evicted on the next write. */
  setMaxBytes(bytes: number): void {
    if (Number.isFinite(bytes) && bytes > 0) this.maxBytes = Math.floor(bytes);
  }

  /**
   * Retention: delete every run that started before `cutoff` (epoch ms), except `keepId` (the run
   * being recorded right now). Returns the deleted ids.
   * @example await store.deleteOlderThan(Date.now() - 7 * 86_400_000, activeRunId)
   */
  deleteOlderThan(cutoff: number, keepId?: string): Promise<string[]> {
    return this.serial(async () => {
      const ids = await this.index();
      const metas = await this.metas(ids);
      const doomed = ids.filter((id) => id !== keepId && (metas.get(id)?.startedAt ?? 0) < cutoff);
      for (const id of doomed) await this.removeRun(id, metas.get(id));
      if (doomed.length > 0) await this.kv.set({ [INDEX]: ids.filter((i) => !doomed.includes(i)) });
      return doomed;
    });
  }

  /** Delete every stored run (and nothing else). */
  clear(): Promise<void> {
    return this.serial(async () => {
      const names = this.kv.keys ? await this.kv.keys() : Object.keys(await this.kv.get(null));
      await this.kv.remove(names.filter((k) => k.startsWith("sl:")));
    });
  }
}
