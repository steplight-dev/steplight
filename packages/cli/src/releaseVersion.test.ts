import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

// scripts/release-version.mjs bumps every place the version is written. These tests never run it on the real
// tree: they work on a copy of the files it touches, or use --dry-run.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const script = path.join(root, "scripts", "release-version.mjs");
const mod = (await import(pathToFileURL(script).href)) as {
  pep440: (v: string) => string;
  manifestVersion: (v: string) => string;
  plan: (root: string, v: string) => { file: string; before: string; after: string; text: string }[];
  apply: (root: string, v: string) => { file: string }[];
};

const tmpRoots: string[] = [];
afterAll(() => {
  for (const dir of tmpRoots) rmSync(dir, { recursive: true, force: true });
});

/** A copy of just the files the script reads or writes. */
function copyOfTheTree(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "steplight-relver-"));
  tmpRoots.push(dir);
  const files = [
    "package.json",
    "packages/core/src/index.ts",
    "packages/cli/src/index.ts",
    "packages/extension/public/manifest.json",
    "python/pyproject.toml",
    "python/src/steplight/__init__.py",
  ];
  for (const name of ["steplight", "core", "sdk", "cli", "redteam", "viewer", "extension", "check-action"]) files.push(`packages/${name}/package.json`);
  for (const name of ["demo-agent", "fixtures-site"]) files.push(`examples/${name}/package.json`);
  for (const file of files) {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    cpSync(path.join(root, file), path.join(dir, file));
  }
  return dir;
}

describe("version mapping", () => {
  it.each([
    ["0.2.0", "0.2.0"],
    ["0.2.0-rc.1", "0.2.0rc1"],
    ["1.10.3-rc.12", "1.10.3rc12"],
    ["10.0.0", "10.0.0"],
  ])("%s is %s in PEP 440", (version, expected) => {
    expect(mod.pep440(version)).toBe(expected);
  });

  it("the extension manifest gets the numbers only", () => {
    expect(mod.manifestVersion("0.2.0-rc.1")).toBe("0.2.0");
    expect(mod.manifestVersion("0.2.0")).toBe("0.2.0");
  });

  it.each(["", "0.2", "v0.2.0", "0.2.0-beta.1", "0.2.0-alpha.1", "0.2.0-rc1", "0.2.0-rc.", "0.2.0-rc.1.2", "0.2.0+local", "latest", "0.2.0 ", "01.2.3x"])(
    "rejects %j",
    (version) => {
      expect(() => mod.pep440(version)).toThrow(/not a release version/);
    },
  );

  it("agrees with the Python release gate (check_version.py) on the same versions", () => {
    const python = ["python3", "python"].find((exe) => !spawnSync(exe, ["--version"]).error);
    if (!python) return; // no interpreter here; the gate runs in CI
    const code =
      "import sys; sys.path.insert(0, 'python/scripts'); import check_version as c; " +
      "print(c.pep440('v0.2.0-rc.1'), c.pep440('v0.2.0'), c.pep440('v1.10.3-rc.12'))";
    const out = spawnSync(python, ["-c", code], { cwd: root, encoding: "utf8" });
    expect(out.stdout.trim()).toBe(`${mod.pep440("0.2.0-rc.1")} ${mod.pep440("0.2.0")} ${mod.pep440("1.10.3-rc.12")}`);
  });
});

describe("what it changes", () => {
  const EXPECTED = [
    "package.json",
    "packages/steplight/package.json",
    "packages/core/package.json",
    "packages/sdk/package.json",
    "packages/cli/package.json",
    "packages/redteam/package.json",
    "packages/viewer/package.json",
    "packages/extension/package.json",
    "examples/demo-agent/package.json",
    "examples/fixtures-site/package.json",
    "packages/core/src/index.ts",
    "packages/cli/src/index.ts",
    "packages/extension/public/manifest.json",
    "python/pyproject.toml",
    "python/src/steplight/__init__.py",
  ].sort();

  it("touches exactly the versioned files, never the GitHub Action", () => {
    const dir = copyOfTheTree();
    const changed = mod.apply(dir, "9.8.7-rc.2").map((e) => e.file);
    expect([...changed].sort()).toEqual(EXPECTED);
    expect(changed).not.toContain("packages/check-action/package.json");
    expect(JSON.parse(readFileSync(path.join(dir, "packages/check-action/package.json"), "utf8")).version).toBe(
      JSON.parse(readFileSync(path.join(root, "packages/check-action/package.json"), "utf8")).version,
    );
  });

  it("writes the npm form, the PEP 440 form and the numbers-only manifest form", () => {
    const dir = copyOfTheTree();
    mod.apply(dir, "9.8.7-rc.2");
    const text = (file: string) => readFileSync(path.join(dir, file), "utf8");
    for (const name of ["steplight", "core", "sdk", "cli", "redteam"]) {
      expect(JSON.parse(text(`packages/${name}/package.json`)).version).toBe("9.8.7-rc.2");
    }
    expect(text("packages/core/src/index.ts")).toContain('export const VERSION = "9.8.7-rc.2"');
    expect(text("packages/cli/src/index.ts")).toContain('.version("9.8.7-rc.2")');
    expect(text("python/pyproject.toml")).toMatch(/^version = "9\.8\.7rc2"$/m);
    expect(text("python/src/steplight/__init__.py")).toMatch(/^__version__ = "9\.8\.7rc2"$/m);
    expect(JSON.parse(text("packages/extension/public/manifest.json")).version).toBe("9.8.7");
  });

  it("changes nothing else in the files (formatting is preserved) and a second run is a no-op", () => {
    const dir = copyOfTheTree();
    const before = readFileSync(path.join(dir, "packages/cli/package.json"), "utf8");
    mod.apply(dir, "9.8.7");
    const after = readFileSync(path.join(dir, "packages/cli/package.json"), "utf8");
    expect(after).toBe(before.replace(/("version": ")[^"]+"/, '$19.8.7"'));
    expect(mod.plan(dir, "9.8.7")).toEqual([]);
  });

  it("refuses, without writing, when a file is not in the shape it expects", () => {
    const dir = copyOfTheTree();
    const index = path.join(dir, "packages/cli/src/index.ts");
    writeFileSync(index, readFileSync(index, "utf8").replace(/\.version\("[^"]*"\)/, ".version(VERSION)"));
    expect(() => mod.apply(dir, "9.8.7")).toThrow(/not written the way this script expects/);
    expect(JSON.parse(readFileSync(path.join(dir, "packages/core/package.json"), "utf8")).version).toBe(
      JSON.parse(readFileSync(path.join(root, "packages/core/package.json"), "utf8")).version,
    );
  });
});

describe("the command line", () => {
  const cli = (...args: string[]) => spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: "utf8" });

  it.each([[[]], [["0.2"]], [["v0.2.0"]], [["0.2.0-beta.1"]], [["0.2.0", "0.3.0"]]])("exits 2 for %j and prints usage or the reason", (args) => {
    const done = cli(...(args as string[]));
    expect(done.status).toBe(2);
    expect(done.stderr).toMatch(/usage:|not a release version/);
  });

  it("--dry-run lists every file and changes none", () => {
    const watched = ["package.json", "python/pyproject.toml", "packages/core/src/index.ts"];
    const snapshot = () => watched.map((f) => readFileSync(path.join(root, f), "utf8"));
    const before = snapshot();
    const done = cli("9.8.7-rc.2", "--dry-run");
    expect(done.status, done.stderr).toBe(0);
    expect(done.stdout).toContain("would change 15 files for 9.8.7-rc.2 (python 9.8.7rc2)");
    for (const file of ["python/pyproject.toml", "packages/cli/src/index.ts", "packages/extension/public/manifest.json"]) expect(done.stdout).toContain(file);
    expect(snapshot()).toEqual(before);
  });
});
