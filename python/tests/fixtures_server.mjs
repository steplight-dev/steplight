// Starts the repository's fixtures site (flights / checkout / clean pages and a collector origin) on free ports,
// prints {"url": ..., "collectorUrl": ...} as one JSON line, and keeps running until it is killed.
import { startFixtureSites } from "../../examples/fixtures-site/server.mjs";

const site = await startFixtureSites();
console.log(JSON.stringify({ url: site.url, collectorUrl: site.collectorUrl }));
process.stdin.resume();
process.on("SIGTERM", () => site.close().then(() => process.exit(0)));
