import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { findSensitive, redactText, sanitizeBody, sanitizeSnapshot } from "./redact.js";
import { NEVER_CAPTURE_AUTOCOMPLETE, NEVER_CAPTURE_NAME_PATTERN, PAYMENT_FRAME_HOSTS, isNeverCaptureField, isPaymentFrameUrl, type FieldDescriptor } from "./neverCapture.js";

/* spec/*.json are the contract other SDKs are tested against. Regenerate with `pnpm -r build && pnpm spec`. */

const specDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../spec");
const readSpec = <T>(file: string): T => JSON.parse(readFileSync(path.join(specDir, file), "utf8")) as T;

// Text shaped like a provider key is stored as {join: [parts]} so no secret scanner sees it literally.
type Text = string | { join: string[] };
type Input = Text | { repeat: [string, number]; prefix?: string; suffix?: string };
const expand = (i: Input): string => {
  if (typeof i === "string") return i;
  if ("join" in i) return i.join.join("");
  return `${i.prefix ?? ""}${i.repeat[0].repeat(i.repeat[1])}${i.suffix ?? ""}`;
};

interface Vectors {
  formatVersion: number;
  counts: { total: number };
  cases: { id: string; group: string; input: Input; redact: Text; idempotent: boolean; find: string[]; findCredentials: string[] }[];
  sanitize: { id: string; kind: "body" | "snapshot"; input: Input; output?: Text; outputDigest?: { length: number; sha256: string } }[];
}
const vectors = readSpec<Vectors>("redaction-vectors.json");

describe("spec/redaction-vectors.json", () => {
  it("has 300+ cases that cover every pattern kind", () => {
    expect(vectors.formatVersion).toBe(1);
    expect(vectors.cases.length + vectors.sanitize.length).toBeGreaterThanOrEqual(300);
    expect(vectors.counts.total).toBe(vectors.cases.length + vectors.sanitize.length);
    const groups = new Set(vectors.cases.map((c) => c.group));
    for (const g of ["email", "card", "api_key", "jwt", "private_key", "bearer", "password", "url_param", "iban", "ssn", "aadhaar", "pan", "phone", "encoded", "clean", "escape", "mixed", "idempotent", "hostile"]) {
      expect(groups.has(g), g).toBe(true);
    }
    const kinds = new Set(vectors.cases.flatMap((c) => expand(c.redact).match(/\[REDACTED:([a-z_]+)\]/g) ?? []).map((m) => m.slice(10, -1)));
    for (const k of ["email", "card", "api_key", "jwt", "private_key", "bearer", "password", "url_param", "iban", "ssn", "aadhaar", "pan", "phone", "encoded"]) expect(kinds.has(k), k).toBe(true);
  });

  it("the engine still produces every expected output", () => {
    for (const c of vectors.cases) {
      const input = expand(c.input);
      expect(redactText(input), c.id).toBe(expand(c.redact));
      expect(redactText(expand(c.redact)) === expand(c.redact), `${c.id} idempotent`).toBe(c.idempotent);
      expect(findSensitive(input).map((m) => m.kind), `${c.id} find`).toEqual(c.find);
      expect(findSensitive(input, { credentials: true }).map((m) => m.kind), `${c.id} find+credentials`).toEqual(c.findCredentials);
    }
  });

  it("redacting twice changes nothing, except for hostile inputs longer than a scanner's length cap", () => {
    for (const c of vectors.cases.filter((x) => x.group !== "hostile")) expect(c.idempotent, c.id).toBe(true);
  });

  it("sanitizeBody / sanitizeSnapshot keep matching their cases", () => {
    for (const c of vectors.sanitize) {
      const out = c.kind === "body" ? sanitizeBody(expand(c.input)) : sanitizeSnapshot(expand(c.input));
      if (c.output !== undefined) expect(out, c.id).toBe(expand(c.output));
      else expect({ length: out.length, sha256: createHash("sha256").update(out, "utf8").digest("hex") }, c.id).toEqual(c.outputDigest);
    }
  });
});

interface NeverCapture {
  inputTypes: string[];
  autocompletePattern: { source: string; flags: string };
  namePattern: { source: string; flags: string };
  paymentFrameHosts: string[];
  fieldCases: { descriptor: FieldDescriptor; neverCapture: boolean }[];
  urlCases: { url: string; paymentFrame: boolean }[];
}
const never = readSpec<NeverCapture>("never-capture.json");

describe("spec/never-capture.json", () => {
  it("is generated from the rules the code uses", () => {
    expect(never.namePattern).toEqual({ source: NEVER_CAPTURE_NAME_PATTERN.source, flags: NEVER_CAPTURE_NAME_PATTERN.flags });
    expect(never.autocompletePattern).toEqual({ source: NEVER_CAPTURE_AUTOCOMPLETE.source, flags: NEVER_CAPTURE_AUTOCOMPLETE.flags });
    expect(never.paymentFrameHosts).toEqual([...PAYMENT_FRAME_HOSTS]);
    expect(never.inputTypes).toEqual(["password"]);
  });
  it("every case still gets the same verdict", () => {
    expect(never.fieldCases.length).toBeGreaterThan(40);
    for (const c of never.fieldCases) expect(isNeverCaptureField(c.descriptor), JSON.stringify(c.descriptor)).toBe(c.neverCapture);
    for (const c of never.urlCases) expect(isPaymentFrameUrl(c.url), c.url).toBe(c.paymentFrame);
  });
});
