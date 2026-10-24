# Releasing the npm packages

`steplight` (the unscoped one-install package: SDK + `steplight` command), `@steplight/core`, `@steplight/sdk`, `@steplight/redteam` and `@steplight/cli` are published by the **Release** workflow ([.github/workflows/release.yml](../.github/workflows/release.yml)) when a version tag is pushed. Nobody publishes from a laptop, and there is no npm token anywhere: the workflow uses npm **trusted publishing** (GitHub OIDC), which also attaches a signed provenance statement to every version.

(The GitHub Action is released separately: see [releasing-action.md](releasing-action.md).)

## One-time setup (done)

- On npmjs.com, each of the five packages has a Trusted Publisher: repository `steplight-dev/steplight`, workflow `release.yml`, environment `npm-release`. A newly added publisher stays "Pending validation" until the first successful CI publish uses it.
- On GitHub, the environment `npm-release` exists in `steplight-dev/steplight` and only deploys from tags matching `v*`. Add required reviewers there if you want a human approval before every publish.
- The repository has no secrets. A test (`packages/cli/src/supplychain.test.ts`) fails if a workflow references `secrets.*`, `NPM_TOKEN` or `NODE_AUTH_TOKEN`.

## Cutting a release

1. Decide the version. Final: `0.1.0`. Pre-release: `0.1.0-rc.1`, `0.1.0-rc.2`, …
2. Set it in **six** places (a test checks they agree): `version` in `packages/{core,sdk,cli,redteam,steplight}/package.json`, `VERSION` in `packages/core/src/index.ts`, and `.version(...)` in `packages/cli/src/index.ts`.
3. Verify locally: `pnpm lint && pnpm -r build && pnpm -r test`.
4. Check what would be published. Pack each package and look at the file list; only `dist/`, `package.json`, `README.md` and `LICENSE` may appear (plus `viewer-dist/` for the CLI):
   ```bash
   mkdir -p /tmp/tarballs && for p in @steplight/core @steplight/redteam @steplight/sdk @steplight/cli steplight; do pnpm --filter $p pack --pack-destination /tmp/tarballs; done
   for t in /tmp/tarballs/*.tgz; do tar -tzf "$t"; done
   ```
5. Commit, push `main`, wait for CI to be green, then tag and push the tag (the tag must be `v` plus the exact version):
   ```bash
   git tag v0.1.0-rc.2 && git push origin v0.1.0-rc.2
   ```
6. Watch it: `gh run watch` (Release workflow). The `verify` job lints, builds, tests and packs; the `publish` job (the only one with `id-token: write`, and the only one in the `npm-release` environment) publishes exactly those tarballs.
7. Check the result:
   ```bash
   for p in @steplight/core @steplight/sdk @steplight/cli @steplight/redteam steplight; do npm view $p dist-tags --json; done
   npm view @steplight/core@0.1.0-rc.2 dist.attestations   # provenance attestation
   ```

## Dist-tags

A tag that contains `-` (a pre-release) is published with `--tag next`, so `latest` keeps pointing at the last final release. A tag without `-` is published as `latest`. To move a dist-tag by hand later you need an npm session with publish rights; the workflow never does it.

## If a publish fails

Read the log (`gh run view --log-failed`), fix the cause, and release the **next** version (`rc.2`): a version that npm accepted can never be published again, and a partly published set (for example `core` published but `cli` failed) is completed by the next version, not by re-running. Typical causes: the trusted publisher on npmjs.com does not match the workflow file or environment name exactly; npm older than 11.5 (the workflow uses Node 24); the package's `repository.url` not matching the repository (provenance requires it).

## The Python package (PyPI)

The same tag also publishes the Python package `steplight` ([python/](../python)). The release workflow builds it with `uv build` in the `python-build` job, which also gates the release: `python/scripts/check_version.py` requires the tag, `python/pyproject.toml` and `steplight.__version__` to agree in PEP 440 form (`v0.2.0` is `0.2.0`, `v0.2.0-rc.1` is `0.2.0rc1`), `uv lock --check` requires an up-to-date `uv.lock`, and `python/scripts/verify_dist.py` requires that the sdist and wheel contain only the package, `py.typed`, `page-scan.js`, the license and metadata, and no required dependency. `publish` (npm) waits for it, so nothing is published if the Python side is wrong.

- A tag **without** `-` publishes to **PyPI** (job `publish-pypi`, environment `pypi-release`).
- A tag **with** `-` (pre-release) publishes to **TestPyPI** (job `publish-testpypi`, environment `testpypi-release`), never to PyPI.
- Both use `pypa/gh-action-pypi-publish` with **Trusted Publishing** (OIDC, `id-token: write` only on those jobs) and publish attestations. There is no PyPI token.

One-time setup (the GitHub environments exist, restricted to `v*` tags; the PyPI side is manual because it needs your PyPI accounts): on pypi.org and on test.pypi.org, add a **pending publisher** for project `steplight`: owner `steplight-dev`, repository `steplight`, workflow `release.yml`, environment `pypi-release` (PyPI) or `testpypi-release` (TestPyPI). The first successful publish turns it into a normal publisher.

To cut a release, additionally set `version` in `python/pyproject.toml` and `__version__` in `python/src/steplight/__init__.py` to the PEP 440 form of the tag, and run `uv lock` in `python/` if the lock changed. Check locally with `python python/scripts/check_version.py v0.2.0-rc.1` and `uv build --out-dir dist python && python python/scripts/verify_dist.py dist`. Failure handling is as for npm: a version PyPI accepted cannot be reused, so release the next one.

## Rules of thumb

- Never run `npm publish` locally.
- Publish order is `core`, `redteam`, `sdk`, `cli`, then `steplight`, so dependencies exist before the packages that need them.
- The extension and the viewer are private; the Chrome Web Store package is built with `pnpm --filter @steplight/extension package`.
