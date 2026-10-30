import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runCachedTool } from "./checked-build";
import { privateHutchEnvironment } from "./private-hutch-home";
import { requirePatchedBun } from "./require-patched-bun";

requirePatchedBun();
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const args = process.argv.slice(2);
if (args[0] !== "dev" && !(args[0] === "prepare" && args.length === 2 && args[1] === "--env=stable")) {
  throw new Error("Use desktop:prepare, desktop:build, desktop:dev, or desktop:watch.");
}
runCachedTool([process.execPath, join(root, "node_modules", "electrobun", "bin", "electrobun.cjs"), ...args],
  root, privateHutchEnvironment(root));
