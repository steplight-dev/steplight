import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  RunWriter,
  isSafeId,
  listRuns,
  newRunId,
  appendAudit,
  applyCaptureLevel,
  ensureAnalyzed,
  configureRedaction,
  parseBundle,
  purgeRuns,
  recordingBlockedReason,
  writeRun,
  readRun,
  readSnapshot,
  type Policy,
  type Run,
  type Step,
} from "@steplight/core/node";
import { auditSchema, ingestSchema, purgeSchema } from "./ingestSchema.js";

/** Options for {@link createViewerServer}. */
export interface ServerOptions {
  /** Folder containing run folders (`.steplight/runs`). */
  runsDir: string;
  /** Folder holding the built viewer (index.html + assets). Optional. */
  viewerDir?: string;
  /** Session token required (as a Bearer token) on every /api request. Random when omitted. */
  token?: string;
  /**
   * Extension ids (`chrome-extension://<id>` origins) allowed to call the API. When empty, any
   * extension origin passes the CORS preflight but still needs the token.
   */
  extensionIds?: string[];
  /** Extra Host names accepted besides 127.0.0.1 and localhost (only for an explicit --host). */
  extraHosts?: string[];
  /** Largest accepted request body for ingest, in bytes (default 5 MB). */
  maxBodyBytes?: number;
  /** Largest accepted run import, in bytes (default 8 MB). */
  maxImportBytes?: number;
  /** Requests allowed per 10 s window across all clients (default 2000). */
  rateLimit?: number;
  /** Organisation policy: caps what is stored, blocks sites, can disable ingest and export. */
  policy?: Policy;
  /** Audit log file for actions reported by the viewer (export / import). */
  auditFile?: string;
}

/** The viewer server, plus the session token it requires. */
export type ViewerServer = Server & { readonly token: string };

/** Error carrying the HTTP status to answer with. */
class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** True for addresses that only accept connections from this machine. */
export function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1" || /^127\.\d+\.\d+\.\d+$/.test(host);
}

/** Policy for the viewer's Content-Security-Policy header (everything from this origin only). */
export const VIEWER_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join("; ");

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".ico": "image/x-icon",
  ".png": "image/png",
};

/**
 * Locate the built viewer: next to the CLI (published layout) or in the monorepo.
 * @example const dir = findViewerDir(import.meta.url)
 */
export function findViewerDir(fromDir: string): string | undefined {
  const candidates = [
    path.resolve(fromDir, "../viewer-dist"),
    path.resolve(fromDir, "../../viewer/dist"),
  ];
  return candidates.find((c) => existsSync(path.join(c, "index.html")));
}

function send(res: ServerResponse, status: number, body: string | Buffer, type: string): void {
  res.writeHead(status, {
    "content-type": type,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "cross-origin-resource-policy": "same-origin",
    ...(type.startsWith("text/html") ? { "content-security-policy": VIEWER_CSP } : {}),
  });
  res.end(body);
}

function json(res: ServerResponse, status: number, data: unknown): void {
  send(res, status, JSON.stringify(data), "application/json");
}

async function readBody(req: IncomingMessage, limit: number): Promise<string> {
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > limit) throw new HttpError(413, "request body too large");
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new HttpError(413, "request body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const digest = (value: string): Buffer => createHash("sha256").update(value).digest();

/** Message accepted by `POST /api/ingest` (sent by the Chrome extension). */
export type IngestMessage =
  | { type: "run_start"; run: Pick<Run, "id" | "task" | "startedAt"> & { meta?: Run["meta"] } }
  | { type: "step"; runId: string; step: Step; snapshot?: string }
  | { type: "run_end"; runId: string; status: "success" | "failed"; endedAt?: number };

/**
 * Create (but do not start) the local HTTP server: JSON API over the runs folder,
 * an ingest endpoint for the extension, and static files for the viewer.
 * Only meant to be bound to localhost.
 * @example createViewerServer({ runsDir: ".steplight/runs" }).listen(4777, "127.0.0.1")
 */
export function createViewerServer(options: ServerOptions): ViewerServer {
  const writers = new Map<string, RunWriter>();
  const token = options.token ?? randomBytes(32).toString("hex");
  const tokenDigest = digest(token);
  const maxBody = options.maxBodyBytes ?? 5 * 1024 * 1024;
  const maxImport = options.maxImportBytes ?? 8 * 1024 * 1024;
  const maxRequests = options.rateLimit ?? 2000;
  const extensionIds = new Set(options.extensionIds ?? []);
  const policy: Policy = options.policy ?? {};
  if (policy.forceRedactionPatterns?.length) configureRedaction({ customPatterns: policy.forceRedactionPatterns });
  const rate = { windowStart: Date.now(), count: 0 };

  const ownHosts = (): Set<string> => {
    const port = (server.address() as AddressInfo | null)?.port;
    const names = ["127.0.0.1", "localhost", "[::1]", ...(options.extraHosts ?? [])];
    return new Set(names.map((n) => `${n}:${port}`));
  };
  /** Origins that may call the API: this server itself, or an allowed Chrome extension. */
  const originAllowed = (origin: string): boolean => {
    if (origin.startsWith("chrome-extension://")) {
      return extensionIds.size === 0 || extensionIds.has(origin.slice("chrome-extension://".length));
    }
    try {
      const u = new URL(origin);
      return u.protocol === "http:" && ownHosts().has(u.host);
    } catch {
      return false;
    }
  };
  const rateLimited = (): boolean => {
    const now = Date.now();
    if (now - rate.windowStart > 10_000) {
      rate.windowStart = now;
      rate.count = 0;
    }
    return ++rate.count > maxRequests;
  };
  const authorized = (req: IncomingMessage): boolean => {
    const header = req.headers.authorization ?? "";
    const given = header.startsWith("Bearer ") ? header.slice(7) : "";
    return given.length > 0 && timingSafeEqual(digest(given), tokenDigest);
  };

  async function ingest(msg: IngestMessage): Promise<void> {
    if (msg.type === "run_start") {
      if (!isSafeId(msg.run.id)) throw new Error("bad run id");
      const run: Run = { ...msg.run, status: "running", steps: [], meta: msg.run.meta ?? {} };
      writers.set(msg.run.id, await RunWriter.create(options.runsDir, run));
      return;
    }
    const writer = writers.get(msg.runId);
    if (!writer) throw new Error("unknown run (send run_start first)");
    if (msg.type === "step") {
      // Policy: sites that must not be recorded are dropped, and the stored detail is capped.
      if (recordingBlockedReason(msg.step.url, { siteAllowlist: policy.siteAllowlist ?? [], siteDenylist: policy.siteDenylist ?? [] })) return;
      const shaped = policy.maxCaptureLevel
        ? applyCaptureLevel({ ...msg.step, runId: msg.runId }, msg.snapshot, policy.maxCaptureLevel)
        : { step: { ...msg.step, runId: msg.runId }, snapshot: msg.snapshot };
      await writer.addStep(shaped.step, shaped.snapshot);
    } else {
      await writer.finish(msg.status, msg.endedAt ?? Date.now());
      writers.delete(msg.runId);
    }
  }

  async function handleApi(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const parts = url.pathname.split("/").filter(Boolean); // ["api", ...]
    if (req.method === "GET" && url.pathname === "/api/policy") return json(res, 200, policy);
    if (req.method === "POST" && url.pathname === "/api/audit") {
      let raw: unknown;
      try {
        raw = JSON.parse(await readBody(req, 4096));
      } catch (err) {
        if (err instanceof HttpError) throw err;
        throw new HttpError(400, "invalid JSON");
      }
      const parsed = auditSchema.safeParse(raw);
      if (!parsed.success) throw new HttpError(400, "invalid audit message");
      if (options.auditFile) appendAudit(options.auditFile, parsed.data.action, parsed.data.detail ?? {});
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/ingest") {
      if (policy.disableCliConnection) throw new HttpError(403, "ingest is disabled by organisation policy");
      let raw: unknown;
      try {
        raw = JSON.parse(await readBody(req, maxBody));
      } catch (err) {
        if (err instanceof HttpError) throw err;
        throw new HttpError(400, "invalid JSON");
      }
      const parsed = ingestSchema.safeParse(raw);
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        throw new HttpError(400, `invalid ingest message: ${issue?.path.join(".") ?? ""} ${issue?.message ?? ""}`.trim());
      }
      await ingest(parsed.data as IngestMessage);
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/purge") {
      let raw: unknown;
      try {
        raw = JSON.parse(await readBody(req, 4096));
      } catch (err) {
        if (err instanceof HttpError) throw err;
        throw new HttpError(400, "invalid JSON");
      }
      const parsed = purgeSchema.safeParse(raw);
      if (!parsed.success) throw new HttpError(400, "send { all: true } or { olderThanDays: <number> }");
      const deleted = await purgeRuns(options.runsDir, parsed.data);
      for (const id of deleted) writers.delete(id);
      return json(res, 200, { deleted: deleted.length });
    }
    if (req.method === "POST" && url.pathname === "/api/import") {
      if (policy.disableExport) throw new HttpError(403, "import and export are disabled by organisation policy");
      const bundle = parseBundle(await readBody(req, maxImport));
      const exists = await readRun(options.runsDir, bundle.run.id).then(() => true, () => false);
      const run = exists ? { ...bundle.run, id: newRunId() } : bundle.run;
      await writeRun(options.runsDir, run, bundle.snapshots);
      return json(res, 200, { id: run.id });
    }
    if (req.method !== "GET") return json(res, 405, { error: "method not allowed" });
    if (url.pathname === "/api/runs") {
      await ensureAnalyzed(options.runsDir);
      return json(res, 200, await listRuns(options.runsDir));
    }
    if (parts[1] === "runs" && parts[2]) {
      let id: string;
      try {
        id = decodeURIComponent(parts[2]);
      } catch {
        return json(res, 400, { error: "bad run id" });
      }
      if (!isSafeId(id)) return json(res, 400, { error: "bad run id" });
      await ensureAnalyzed(options.runsDir, id);
      const run = await readRun(options.runsDir, id).catch(() => undefined);
      if (!run) return json(res, 404, { error: "run not found" });
      if (parts.length === 3) return json(res, 200, run);
      if (parts[3] === "snapshot" && parts[4]) {
        let stepId: string;
        try {
          stepId = decodeURIComponent(parts[4]);
        } catch {
          return json(res, 400, { error: "bad step id" });
        }
        if (!isSafeId(stepId)) return json(res, 400, { error: "bad step id" });
        const step = run.steps.find((s) => s.id === stepId);
        const text = step ? await readSnapshot(options.runsDir, id, step) : undefined;
        if (text === undefined) return json(res, 404, { error: "snapshot not found" });
        return send(res, 200, text, "text/plain; charset=utf-8");
      }
    }
    json(res, 404, { error: "not found" });
  }

  async function handleStatic(res: ServerResponse, url: URL): Promise<void> {
    const dir = options.viewerDir;
    if (!dir) {
      return send(res, 200, "Steplight API is running. Viewer is not built (run `pnpm -r build`).", "text/plain");
    }
    const rel = decodeURIComponent(url.pathname).replace(/^\/+/, "") || "index.html";
    let file = path.resolve(dir, rel);
    if (!file.startsWith(path.resolve(dir) + path.sep)) return send(res, 403, "forbidden", "text/plain");
    if (!existsSync(file)) file = path.join(dir, "index.html"); // SPA fallback
    const body = await readFile(file);
    send(res, 200, body, MIME[path.extname(file)] ?? "application/octet-stream");
  }

  const server = createServer((req, res) => {
    void (async () => {
      try {
        const host = req.headers.host ?? "";
        if (!ownHosts().has(host)) throw new HttpError(403, "forbidden host"); // DNS rebinding guard
        const origin = req.headers.origin;
        if (origin !== undefined) {
          if (!originAllowed(origin)) throw new HttpError(403, "forbidden origin");
          res.setHeader("access-control-allow-origin", origin);
          res.setHeader("vary", "Origin");
          res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
          res.setHeader("access-control-allow-headers", "content-type, authorization");
          res.setHeader("access-control-max-age", "600");
        }
        if (req.method === "OPTIONS") {
          res.writeHead(204);
          return void res.end();
        }
        if (rateLimited()) throw new HttpError(429, "too many requests");
        const url = new URL(req.url ?? "/", "http://localhost");
        if (url.pathname.startsWith("/api/")) {
          if (!authorized(req)) throw new HttpError(401, "missing or invalid session token");
          await handleApi(req, res, url);
        } else if (req.method === "GET" || req.method === "HEAD") {
          await handleStatic(res, url);
        } else {
          throw new HttpError(405, "method not allowed");
        }
      } catch (err) {
        if (res.headersSent) return void res.end();
        if (err instanceof HttpError) json(res, err.status, { error: err.message });
        else json(res, 400, { error: err instanceof Error ? err.message : "error" });
      }
    })();
  });
  return Object.defineProperty(server, "token", { value: token, enumerable: true }) as ViewerServer;
}
