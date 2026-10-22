import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { NEVER_CAPTURE_AUTOCOMPLETE, NEVER_CAPTURE_NAME_PATTERN } from "@steplight/core";
import { describe, expect, it } from "vitest";
import { pageScanScript } from "./pageScript.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

describe("spec/page-scan.js, the single page script every SDK injects", () => {
  it("is up to date with the code it is built from (run `pnpm -r build && pnpm spec` to regenerate)", () => {
    // Built output is what ships, so the generator reads the compiled packages: build first.
    const result = spawnSync(process.execPath, [path.join(root, "scripts", "generate-spec.mjs"), "--check"], { encoding: "utf8" });
    expect(result.stderr + result.stdout).toContain("up to date");
    expect(result.status).toBe(0);
  });

  it("is what the SDK loads at run time, and the Python package ships the same bytes", () => {
    const committed = readFileSync(path.join(root, "spec", "page-scan.js"), "utf8");
    expect(pageScanScript()).toBe(committed);
    expect(readFileSync(path.join(root, "python", "src", "steplight", "_data", "page-scan.js"), "utf8")).toBe(committed);
  });

  it("carries the shared never-capture rules and installs its listeners and scanner", () => {
    const script = readFileSync(path.join(root, "spec", "page-scan.js"), "utf8");
    expect(script).toContain(NEVER_CAPTURE_NAME_PATTERN.source);
    expect(script).toContain(NEVER_CAPTURE_AUTOCOMPLETE.source);
    expect(script).toContain('"__steplightEmit"');
    expect(script).toContain("installPageListeners(BINDING_NAME)");
    expect(script).toContain("installScanning(BINDING_NAME, collectPageScan)");
    expect(script).not.toMatch(/\bimport\s|require\(|fetch\(|XMLHttpRequest|sendBeacon/);
  });
});
