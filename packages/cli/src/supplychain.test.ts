import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";

/* Guards for the project's own supply chain: pinned actions, minimal permissions, provenance. */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const workflowsDir = path.join(root, ".github", "workflows");
type Doc = Record<string, unknown> & { jobs: Record<string, { permissions?: Record<string, string> }>; permissions?: unknown; on?: unknown };
const workflows = readdirSync(workflowsDir)
  .filter((f) => f.endsWith(".yml"))
  .map((f) => ({ file: f, text: readFileSync(path.join(workflowsDir, f), "utf8"), doc: parse(readFileSync(path.join(workflowsDir, f), "utf8")) as Doc }));

describe("GitHub workflows", () => {
  it("exist for tests, lint, audit, CodeQL, dependency review, SBOM and release", () => {
    expect(workflows.map((w) => w.file).sort()).toEqual(["audit.yml", "ci.yml", "codeql.yml", "dependency-review.yml", "release.yml", "sbom.yml"]);
  });

  it("pin every action to a full commit SHA, with the version in a comment", () => {
    for (const w of workflows) {
      const uses = [...w.text.matchAll(/^\s*-?\s*uses:\s*(\S+)(.*)$/gm)];
      expect(uses.length, w.file).toBeGreaterThan(0);
      for (const [, ref, rest] of uses) {
        expect(ref, `${w.file}: ${ref}`).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/);
        expect(rest, `${w.file}: ${ref} needs a version comment`).toMatch(/#\s*v\d+(\.\d+){0,2}/);
      }
    }
  });

  it("declare minimal permissions at the top and never write-all", () => {
    for (const w of workflows) {
      expect(w.doc.permissions, `${w.file} top-level permissions`).toEqual({ contents: "read" });
      expect(w.text, w.file).not.toMatch(/write-all|permissions:\s*\n\s*actions:\s*write/);
      for (const [name, job] of Object.entries(w.doc.jobs)) {
        const perms = job.permissions ?? {};
        for (const [scope, level] of Object.entries(perms)) {
          // only two extra scopes are ever needed, each in exactly one place
          if (level === "write") expect(["security-events", "id-token"], `${w.file}/${name}: ${scope}`).toContain(scope);
        }
      }
    }
    expect(workflows.find((w) => w.file === "codeql.yml")!.doc["jobs"]["analyze"]["permissions"]).toMatchObject({ "security-events": "write" });
    expect(workflows.find((w) => w.file === "release.yml")!.doc["jobs"]["publish"]["permissions"]).toMatchObject({ "id-token": "write" });
    // the OIDC scope exists on the three publishing jobs and nowhere else (the Python build job never has it)
    const withOidc = Object.entries(workflows.find((w) => w.file === "release.yml")!.doc.jobs)
      .filter(([, job]) => job.permissions?.["id-token"] === "write")
      .map(([name]) => name)
      .sort();
    expect(withOidc).toEqual(["publish", "publish-pypi", "publish-testpypi"]);
  });

  it("never run untrusted pull-request code with secrets, and never persist the checkout token", () => {
    for (const w of workflows) {
      expect(w.text, w.file).not.toContain("pull_request_target");
      for (const m of w.text.matchAll(/actions\/checkout@[^\n]*\n(\s+with:\n(?:\s+.*\n)*)?/g)) {
        expect(m[0], `${w.file} checkout`).toContain("persist-credentials: false");
      }
    }
  });

  it("no workflow uses a secret: npm publishes through OIDC trusted publishing", () => {
    for (const w of workflows) {
      expect([...w.text.matchAll(/secrets\.(\w+)/g)].map((m) => m[1]), w.file).toEqual([]);
      expect(w.text, w.file).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN|_authToken/);
    }
  });

  it("the release workflow verifies first, publishes with provenance, and `next` for pre-releases", () => {
    const release = workflows.find((w) => w.file === "release.yml")!;
    const jobs = release.doc.jobs as Record<string, { permissions?: Record<string, string>; environment?: string; needs?: string | string[]; if?: string; steps: { run?: string; uses?: string; with?: Record<string, unknown> }[] }>;
    expect(Object.keys(jobs).sort()).toEqual(["publish", "publish-pypi", "publish-testpypi", "python-build", "verify"]);
    // the OIDC permission exists on the publish job only
    expect(jobs["publish"]!.permissions).toEqual({ contents: "read", "id-token": "write" });
    expect(jobs["verify"]!.permissions?.["id-token"]).toBeUndefined();
    expect(jobs["publish"]!.environment).toBe("npm-release");
    expect(jobs["publish"]!.needs).toEqual(["verify", "python-build"]); // npm publishes only if the Python package is buildable too
    // tag trigger only, and lint + build + tests run before anything is published
    expect(release.text).toContain('tags: ["v*"]');
    const verify = jobs["verify"]!.steps.map((s) => s.run ?? "").join("\n");
    for (const cmd of ["pnpm lint", "pnpm -r build", "pnpm -r test"]) expect(verify).toContain(cmd);
    const publish = jobs["publish"]!.steps.map((s) => s.run ?? "").join("\n");
    expect(publish).toContain("npm publish");
    expect(publish).toContain("--provenance");
    expect(publish).toContain("--access public");
    expect(publish).toContain("*-*) dist_tag=next");
    expect(publish).toContain('--tag "$dist_tag"');
    // all five packages are packed and published, dependencies first, the unscoped one last
    expect(release.text).toContain("@steplight/core @steplight/redteam @steplight/sdk @steplight/cli steplight");
    expect(release.text).toContain("steplight-core steplight-redteam steplight-sdk steplight-cli steplight;");
    expect(verify).toContain("for pkg in core sdk cli redteam steplight");
    // the publish job never checks out or installs repository code
    expect(jobs["publish"]!.steps.map((s) => JSON.stringify(s)).join("")).not.toMatch(/actions\/checkout|pnpm install/);
    // the tag must match every package version
    expect(verify).toContain("does not match");
  });


  it("the Python package is built and verified, then published through PyPI Trusted Publishing (no token), after the npm jobs", () => {
    const release = workflows.find((w) => w.file === "release.yml")!;
    const jobs = release.doc.jobs as Record<string, { permissions?: Record<string, string>; environment?: string; needs?: string | string[]; if?: string; steps: { run?: string; uses?: string; with?: Record<string, unknown> }[] }>;
    // build: version gate (tag == pyproject, PEP 440), current lock file, sdist + wheel with uv, content gate, clean install
    const build = jobs["python-build"]!;
    const buildRuns = build.steps.map((s) => s.run ?? "").join(" ; ");
    for (const cmd of ["check_version.py", "uv lock --check", "uv build", "verify_dist.py"]) expect(buildRuns).toContain(cmd);
    expect(build.permissions?.["id-token"]).toBeUndefined();
    expect(build.environment).toBeUndefined();
    // publishing: final tags -> PyPI, pre-releases (a "-" in the tag) -> TestPyPI, each in its own environment
    const pypi = jobs["publish-pypi"]!;
    const testpypi = jobs["publish-testpypi"]!;
    expect(pypi.environment).toBe("pypi-release");
    expect(testpypi.environment).toBe("testpypi-release");
    expect(pypi.if).toContain("!contains(github.ref_name, '-')");
    expect(testpypi.if).toContain("contains(github.ref_name, '-')");
    expect(pypi.if).not.toBe(testpypi.if);
    for (const job of [pypi, testpypi]) {
      expect(job.needs).toEqual(["publish", "python-build"]); // after the npm jobs
      expect(job.permissions).toEqual({ contents: "read", "id-token": "write" });
      const publish = job.steps.find((s) => s.uses?.startsWith("pypa/gh-action-pypi-publish@"))!;
      expect(publish.uses).toMatch(/^pypa\/gh-action-pypi-publish@[0-9a-f]{40}$/);
      expect(publish.with?.["attestations"]).toBe(true);
      expect(publish.with).not.toHaveProperty("password");
      expect(JSON.stringify(job.steps)).not.toMatch(/actions\/checkout|pnpm install|uv sync|pip install/);
    }
    expect(testpypi.steps.find((s) => s.uses?.startsWith("pypa/"))!.with?.["repository-url"]).toBe("https://test.pypi.org/legacy/");
    expect(pypi.steps.find((s) => s.uses?.startsWith("pypa/"))!.with).not.toHaveProperty("repository-url");
    expect(release.text).not.toMatch(/PYPI_API_TOKEN|TWINE_PASSWORD|__token__/);
  });

  it("CI runs the Python tests on 3.10 to 3.13, ubuntu and windows, with lint, mypy, the conformance tests and a pinned uv", () => {
    const ci = workflows.find((w) => w.file === "ci.yml")!;
    const python = (ci.doc.jobs as unknown as Record<string, { strategy: { matrix: { os: string[]; python: string[] } }; steps: { run?: string; uses?: string }[] }>)["python"]!;
    expect(python.strategy.matrix.python).toEqual(["3.10", "3.11", "3.12", "3.13"]);
    expect(python.strategy.matrix.os).toEqual(["ubuntu-latest", "windows-latest"]);
    const runs = python.steps.map((s) => s.run ?? "").join(" ; ");
    for (const cmd of ["uv sync --frozen", "ruff check", "ruff format --check", "uv run mypy", "uv run pytest", "pnpm -r build"]) expect(runs).toContain(cmd);
    expect(python.steps.some((s) => s.uses?.startsWith("astral-sh/setup-uv@"))).toBe(true);
  });

  it("pip-audit fails the audit on the package's own dependency tree, and the SBOM covers the Python dependencies", () => {
    const audit = workflows.find((w) => w.file === "audit.yml")!;
    expect(audit.text).toContain("pip-audit -r ../audit-core.txt");
    expect(audit.text).toContain("--strict");
    expect(audit.text).toContain("python/uv.lock");
    const sbom = workflows.find((w) => w.file === "sbom.yml")!;
    expect(sbom.text).toContain("uv export --frozen --all-extras --format cyclonedx1.5");
    expect(Object.keys(sbom.doc.jobs).sort()).toEqual(["sbom", "sbom-python"]);
  });

  it("CI runs lint, build and the full test suite; audit fails on high severity", () => {
    const ci = workflows.find((w) => w.file === "ci.yml")!.text;
    for (const step of ["pnpm lint", "pnpm -r build", "pnpm -r test", "--frozen-lockfile"]) expect(ci).toContain(step);
    expect(workflows.find((w) => w.file === "audit.yml")!.text).toContain("pnpm audit --audit-level=high");
    expect(workflows.find((w) => w.file === "dependency-review.yml")!.text).toContain("fail-on-severity: high");
  });

  it("the SBOM is CycloneDX from a pinned generator", () => {
    const sbom = workflows.find((w) => w.file === "sbom.yml")!.text;
    expect(sbom).toMatch(/@cyclonedx\/cdxgen@\d+\.\d+\.\d+/);
    expect(sbom).toContain("--spec-version 1.6");
  });

  it("release publishes only on version tags, with provenance, after tests", () => {
    const release = workflows.find((w) => w.file === "release.yml")!;
    expect(release.doc.on).toEqual({ push: { tags: ["v*"] } });
    expect(release.text.indexOf("pnpm -r test")).toBeLessThan(release.text.indexOf('npm publish "./tarballs'));
  });
});

describe("Dependabot", () => {
  const dependabot = parse(readFileSync(path.join(root, ".github", "dependabot.yml"), "utf8")) as { updates: { "package-ecosystem": string; schedule: { interval: string } }[] };
  it("watches npm packages, the Python package (uv) and GitHub Actions weekly", () => {
    expect(dependabot.updates.map((u) => u["package-ecosystem"]).sort()).toEqual(["github-actions", "npm", "uv"]);
    for (const u of dependabot.updates) expect(u.schedule.interval).toBe("weekly");
  });
  it("uses the same cooldown for Python as for npm, and keeps Browser Use inside its tested range", () => {
    const updates = parse(readFileSync(path.join(root, ".github", "dependabot.yml"), "utf8")).updates as { "package-ecosystem": string; directory: string; cooldown?: unknown; ignore?: { "dependency-name": string }[] }[];
    const npm = updates.find((u) => u["package-ecosystem"] === "npm")!;
    const uv = updates.find((u) => u["package-ecosystem"] === "uv")!;
    expect(uv.directory).toBe("/python");
    expect(uv.cooldown).toEqual(npm.cooldown);
    expect(uv.ignore?.map((i) => i["dependency-name"])).toContain("browser-use");
  });
});

describe("published packages", () => {
  for (const name of ["core", "sdk", "cli", "redteam", "steplight"]) {
    it(`${name === "steplight" ? "steplight" : `@steplight/${name}`} publishes publicly with provenance and ships only built files`, () => {
      const pkg = JSON.parse(readFileSync(path.join(root, "packages", name, "package.json"), "utf8"));
      expect(pkg.publishConfig).toEqual({ access: "public", provenance: true });
      expect(pkg.license).toBe("Apache-2.0");
      expect(pkg.repository?.url).toContain("github.com/steplight-dev/steplight");
      expect(pkg.private).toBeUndefined();
      expect(pkg.files.every((f: string) => ["dist", "viewer-dist"].includes(f))).toBe(true);
    });
  }
  it("the five packages share one version, which the code reports, and each ships a README and LICENSE", () => {
    const versions = new Set<string>();
    for (const name of ["core", "sdk", "cli", "redteam", "steplight"]) {
      versions.add(JSON.parse(readFileSync(path.join(root, "packages", name, "package.json"), "utf8")).version);
      expect(existsSync(path.join(root, "packages", name, "README.md")), `${name} README`).toBe(true);
      expect(readFileSync(path.join(root, "packages", name, "LICENSE"), "utf8"), `${name} LICENSE`).toContain("Apache License");
    }
    expect([...versions]).toHaveLength(1);
    const [version] = [...versions];
    expect(readFileSync(path.join(root, "packages", "core", "src", "index.ts"), "utf8")).toContain(`VERSION = "${version}"`);
    expect(readFileSync(path.join(root, "packages", "cli", "src", "index.ts"), "utf8")).toContain(`.version("${version}")`);
  });
  it("the CLI bundles the viewer when packed", () => {
    const pkg = JSON.parse(readFileSync(path.join(root, "packages", "cli", "package.json"), "utf8"));
    expect(pkg.scripts.prepack).toContain("copy-viewer");
    expect(existsSync(path.join(root, "packages", "cli", "scripts", "copy-viewer.mjs"))).toBe(true);
  });
  it("internal packages stay private", () => {
    for (const name of ["viewer", "extension"]) {
      expect(JSON.parse(readFileSync(path.join(root, "packages", name, "package.json"), "utf8")).private).toBe(true);
    }
  });
});
