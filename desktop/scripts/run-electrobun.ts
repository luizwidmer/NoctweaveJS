import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runCachedTool } from "./checked-build";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const args = process.argv.slice(2);
if (args[0] !== "dev") throw new Error("Use desktop:build for checked build artifacts, or desktop:dev / desktop:watch.");
runCachedTool([process.execPath, join(root, "node_modules", "electrobun", "bin", "electrobun.cjs"), ...args], root);
