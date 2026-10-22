// Copies the committed spec/page-scan.js next to the built SDK so `@steplight/sdk` ships (and reads) the
// one shared page script. Runs as part of the SDK build; it never generates anything: `pnpm spec` does that.
import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const target = path.join(root, "packages", "sdk", "dist");
await mkdir(target, { recursive: true });
await copyFile(path.join(root, "spec", "page-scan.js"), path.join(target, "page-scan.js"));
