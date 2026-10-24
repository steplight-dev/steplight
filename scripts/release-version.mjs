// Sets the release version everywhere it is written, in one go:
//
//   pnpm release:version 0.2.0-rc.1        (or 0.2.0)           add --dry-run to only list what would change
//
//   - "version" of the five published npm packages (steplight, core, sdk, cli, redteam) and of every other
//     workspace package that carries the same version (root, viewer, extension, examples). The GitHub Action
//     (packages/check-action) is versioned separately and is never touched.
//   - VERSION in packages/core/src/index.ts and .version() in packages/cli/src/index.ts
//   - the PEP 440 form (0.2.0-rc.1 -> 0.2.0rc1) in python/pyproject.toml and python/src/steplight/__init__.py
//   - the Chrome extension manifest, which only allows numbers: 0.2.0-rc.1 -> 0.2.0
//
// Then `uv lock` in python/ and python/scripts/check_version.py, and it fails loudly if anything disagrees.
// Node only, no shell syntax: it works the same in Git Bash, PowerShell and Linux. It never tags or publishes.
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?$/;
const PUBLISHED = ["steplight", "core", "sdk", "cli", "redteam"];
const SEPARATELY_VERSIONED = new Set(["check-action"]);

/** 0.2.0-rc.1 -> 0.2.0rc1, 0.2.0 -> 0.2.0. Throws for anything that is not X.Y.Z or X.Y.Z-rc.N. */
export function pep440(version) {
  const m = SEMVER.exec(version);
  if (!m) throw new Error(`"${version}" is not a release version: use X.Y.Z or X.Y.Z-rc.N (for example 0.2.0 or 0.2.0-rc.1)`);
  return `${m[1]}.${m[2]}.${m[3]}${m[4] === undefined ? "" : `rc${m[4]}`}`;
}

/** The numbers-only form Chrome accepts in manifest.json. */
export function manifestVersion(version) {
  pep440(version);
  return version.split("-")[0];
}

const read = (root, file) => readFileSync(path.join(root, file), "utf8");

/** Replace the first match of `pattern` (which must capture prefix, value, suffix) and report the old value. */
function replaceOnce(text, pattern, value, where) {
  const m = pattern.exec(text);
  if (!m) throw new Error(`${where}: the version is not written the way this script expects (${pattern})`);
  return { text: text.slice(0, m.index) + m[1] + value + m[3] + text.slice(m.index + m[0].length), before: m[2] };
}

const JSON_VERSION = /^(\s*"version"\s*:\s*")([^"]*)(")/m;

/**
 * Work out every edit without writing anything. Returns [{file, before, after, text}] for the files whose
 * content changes; throws before anything is touched when a file is missing or in an unexpected shape.
 */
export function plan(root, version) {
  const python = pep440(version);
  const edits = [];
  const add = (file, pattern, value) => {
    const { text, before } = replaceOnce(read(root, file), pattern, value, file);
    edits.push({ file, before, after: value, text });
  };

  // Which workspace packages move with the published five: the ones that share their current version.
  const current = new Set(PUBLISHED.map((name) => JSON.parse(read(root, `packages/${name}/package.json`)).version));
  if (current.size !== 1) throw new Error(`the five published packages do not share one version now: ${[...current].join(", ")}`);
  const [from] = [...current];
  const manifests = ["package.json"];
  for (const group of ["packages", "examples"]) {
    for (const dir of readdirSync(path.join(root, group), { withFileTypes: true })) {
      if (!dir.isDirectory() || SEPARATELY_VERSIONED.has(dir.name)) continue;
      const file = `${group}/${dir.name}/package.json`;
      try {
        read(root, file);
      } catch {
        continue;
      }
      manifests.push(file);
    }
  }
  for (const file of manifests) {
    const found = JSON.parse(read(root, file)).version;
    if (found !== from) {
      if (PUBLISHED.some((name) => file === `packages/${name}/package.json`)) throw new Error(`${file} has version ${found}`);
      continue; // a package versioned on its own
    }
    add(file, JSON_VERSION, version);
  }

  add("packages/core/src/index.ts", /^(export const VERSION = ")([^"]*)(")/m, version);
  add("packages/cli/src/index.ts", /(\.version\(")([^"]*)("\))/, version);
  add("packages/extension/public/manifest.json", JSON_VERSION, manifestVersion(version));
  add("python/pyproject.toml", /^(version\s*=\s*")([^"]*)(")/m, python);
  add("python/src/steplight/__init__.py", /^(__version__\s*=\s*")([^"]*)(")/m, python);
  return edits.filter((e) => e.before !== e.after);
}

/** Write the planned edits. Returns the files changed. */
export function apply(root, version) {
  const edits = plan(root, version);
  for (const e of edits) writeFileSync(path.join(root, e.file), e.text);
  return edits;
}

function run(command, args, cwd) {
  const done = spawnSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return { ok: done.status === 0, out: `${done.stdout ?? ""}${done.stderr ?? ""}`.trim(), missing: done.error?.code === "ENOENT" };
}

/** python3 on Linux and macOS, python on Windows: the first interpreter that exists. */
function runPython(args, cwd) {
  for (const exe of ["python3", "python"]) {
    const result = run(exe, args, cwd);
    if (!result.missing) return result;
  }
  return { ok: false, out: "no python3 or python on PATH", missing: true };
}

function main(argv) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const dry = argv.includes("--dry-run");
  const [version, ...extra] = argv.filter((a) => a !== "--dry-run");
  if (!version || extra.length > 0) {
    console.error("usage: pnpm release:version <version> [--dry-run]   (for example 0.2.0-rc.1 or 0.2.0)");
    return 2;
  }
  try {
    pep440(version);
  } catch (err) {
    console.error(`error: ${err.message}`);
    return 2;
  }

  let edits;
  try {
    edits = dry ? plan(root, version) : apply(root, version);
  } catch (err) {
    console.error(`error: ${err.message}\nnothing was changed`);
    return 1;
  }
  console.log(`${dry ? "would change" : "changed"} ${edits.length} files for ${version} (python ${pep440(version)}):`);
  for (const e of edits) console.log(`  ${e.file}: ${e.before} -> ${e.after}`);
  if (dry) return 0;

  const problems = [];
  const lock = run("uv", ["lock"], path.join(root, "python"));
  console.log(lock.ok ? "uv lock: ok" : `uv lock: FAILED\n${lock.out}`);
  if (!lock.ok) problems.push("uv lock failed (install uv, or run it by hand in python/)");

  const check = runPython([path.join("python", "scripts", "check_version.py"), `v${version}`], root);
  console.log(check.ok ? check.out : `check_version: FAILED\n${check.out}`);
  if (!check.ok) problems.push("python/scripts/check_version.py does not accept the result");

  // The edits are re-read, so a script bug cannot pass silently either.
  const leftovers = plan(root, version);
  if (leftovers.length > 0) problems.push(`not at ${version} after writing: ${leftovers.map((e) => e.file).join(", ")}`);

  if (problems.length > 0) {
    console.error(`\nFAILED:\n${problems.map((p) => `  - ${p}`).join("\n")}\nThe files above were already changed; undo with git checkout -- . if you want to start over.`);
    return 1;
  }
  console.log(`\nversion ${version} is consistent. Review with git diff, run the tests, commit; tagging is a separate step (docs/releasing.md).`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) process.exit(main(process.argv.slice(2)));
