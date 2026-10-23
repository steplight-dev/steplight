// Records scenarios with the TypeScript SDK, so the Python tests can compare what the two SDKs make of the same pages.
//   node ts_reference.mjs flights <siteUrl> <runsDir>   hijacked flight booking + clean page
//   node ts_reference.mjs redteam <runsDir>             the red-team demo agents (gullible and resilient)
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(path.join(repo, "packages/sdk/package.json"));
const { chromium } = require("playwright");
const { steplight } = await import(pathToFileURL(path.join(repo, "packages/sdk/dist/index.js")).href);

const [mode, ...args] = process.argv.slice(2);
if (mode === "flights") {
  const [site, dir] = args;
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const run = await steplight.record(page, { task: "Book the cheapest flight", dir });
  await page.goto(`${site}/flights.html`);
  await run.note("model chose Premium");
  await page.click("#select-premium");
  await page.waitForURL(/checkout\.html/);
  await page.fill("#email", "traveler@example.com");
  await Promise.all([page.waitForURL(/\/collect/), page.click("#pay")]);
  await run.end("success");
  const clean = await browser.newPage();
  const cleanRun = await steplight.record(clean, { task: "Get the report", dir });
  await clean.goto(`${site}/clean.html`);
  await clean.click("#download");
  await cleanRun.end("success");
  await browser.close();
  console.log(JSON.stringify({ hijacked: run.id, clean: cleanRun.id }));
} else if (mode === "redteam") {
  const { runRedteamDemo } = await import(pathToFileURL(path.join(repo, "examples/demo-agent/src/redteam.mjs")).href);
  const out = await runRedteamDemo({ dir: args[0], quiet: true });
  console.log(JSON.stringify(out));
} else {
  console.error("unknown mode");
  process.exit(2);
}
