import { lstatSync, mkdirSync } from "node:fs";
import { isAbsolute, join } from "node:path";

function requirePrivateDirectory(path: string): void {
  mkdirSync(path, { mode: 0o700, recursive: true });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Hutch cache path must be a real directory: ${path}`);
  }
  if (process.platform !== "win32" &&
      (stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0)) {
    throw new Error(`Hutch cache path must be owned by this user and inaccessible to other users: ${path}`);
  }
}

// Hutch's managed Bun can be executable before a version-only cache check.
// Keep its store behind owner-only directories instead of sharing ~/.hutch.
export function privateHutchEnvironment(root: string, inherited = process.env): NodeJS.ProcessEnv {
  let parent: string;
  if (process.platform === "win32") {
    const localAppData = inherited.LOCALAPPDATA;
    if (!localAppData || !isAbsolute(localAppData)) {
      throw new Error("A per-user LOCALAPPDATA directory is required for the desktop Hutch cache.");
    }
    requirePrivateDirectory(localAppData);
    parent = join(localAppData, "NoctweaveJS");
  } else {
    parent = join(root, ".local");
  }
  requirePrivateDirectory(parent);
  const home = join(parent, "hutch-store");
  requirePrivateDirectory(home);
  const environment: NodeJS.ProcessEnv = { ...inherited, HUTCH_HOME: home };
  delete environment.ELECTROBUN_HUTCH_BINARY;
  delete environment.HUTCH_ENGINE_BINARY;
  delete environment.HUTCH_ELECTROBUN_DEVKIT_ROOT;
  return environment;
}
