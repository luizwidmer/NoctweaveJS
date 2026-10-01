import { execFileSync, spawnSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export interface BuildOutput {
  path: string;
  fresh?: boolean;
}

function fingerprint(path: string): string | undefined {
  try {
    const stat = lstatSync(path, { bigint: true });
    if (!stat.isFile()) throw new Error(`Build output is not a regular file: ${path}`);
    return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

// Keep signal and missing-tool failures explicit, including through Electrobun
// 2's installed npm bootstrap. Do not invoke an on-demand package installer.
export function runCachedTool(command: string[], cwd: string): void {
  const result = spawnSync(command[0]!, command.slice(1), { cwd, stdio: "inherit" });
  if (result.error) throw new Error(`Cannot start the cached build tool: ${result.error.message}`);
  if (result.signal) throw new Error(`Tool terminated by ${result.signal}.`);
  if (result.status !== 0) throw new Error(`Build tool exited with status ${result.status ?? "unknown"}.`);
}

export function runCheckedBuild(options: {
  command: string[];
  cwd: string;
  outputs: BuildOutput[];
  verify?: () => void;
}): void {
  const before = new Map(options.outputs.filter(output => output.fresh)
    .map(output => [output.path, fingerprint(output.path)]));
  runCachedTool(options.command, options.cwd);

  for (const output of options.outputs) {
    const after = fingerprint(output.path);
    if (after === undefined || lstatSync(output.path, { bigint: true }).size === 0n) {
      throw new Error(`Build did not produce a nonempty output: ${output.path}`);
    }
    if (output.fresh && before.get(output.path) === after) {
      throw new Error(`Build left a stale artifact unchanged: ${output.path}`);
    }
  }
  options.verify?.();
}

export function verifyBuildMetadata(
  updatePath: string,
  versionPath: string,
  expected: { version: string; identifier: string; platform: string; arch: string },
): void {
  const update = JSON.parse(readFileSync(updatePath, "utf8"));
  const bundle = JSON.parse(readFileSync(versionPath, "utf8"));
  verifyMetadata(update, bundle, expected);
}

function verifyMetadata(
  update: any,
  bundle: any,
  expected: { version: string; identifier: string; platform: string; arch: string },
): void {
  if (update.version !== expected.version || bundle.version !== expected.version
      || update.platform !== expected.platform || update.arch !== expected.arch
      || bundle.identifier !== expected.identifier || bundle.channel !== "stable"
      || typeof update.hash !== "string" || update.hash.length === 0
      || bundle.hash !== update.hash) {
    throw new Error("Build artifact metadata does not match the requested app, version and platform.");
  }
}

// Stable v2 output is an installer wrapper around the actual app archive.
// Inspect archive members without unpacking or executing the payload.
export function verifyReleaseArchive(options: {
  archive: string;
  update: string;
  wrapperMetadata: string;
  versionEntry: string;
  buildEntry: string;
  requiredEntries: string[];
  expected: {
    version: string; identifier: string; platform: string; arch: string;
    name: string; electrobunVersion: string; mainProcess: string;
  };
}): void {
  const entries = execFileSync("tar", ["-tf", options.archive], {
    encoding: "utf8", maxBuffer: 4 * 1024 * 1024,
  }).trimEnd().split("\n");
  const readEntry = (entry: string): Buffer => {
    if (entries.filter(value => value === entry).length !== 1) {
      throw new Error(`Archive must contain exactly one required member: ${entry}`);
    }
    const value = execFileSync("tar", ["-xOf", options.archive, entry], {
      maxBuffer: 16 * 1024 * 1024,
    });
    if (value.length === 0) throw new Error(`Archive member is empty or not a regular file: ${entry}`);
    return value;
  };
  const update = JSON.parse(readFileSync(options.update, "utf8"));
  const bundle = JSON.parse(readEntry(options.versionEntry).toString("utf8"));
  const build = JSON.parse(readEntry(options.buildEntry).toString("utf8"));
  const wrapper = JSON.parse(readFileSync(options.wrapperMetadata, "utf8"));
  verifyMetadata(update, bundle, options.expected);
  if (update.identifier !== options.expected.identifier || update.channel !== "stable"
      || update.artifact?.file !== basename(options.archive)
      || !/^[a-z0-9]{1,128}$/.test(update.hash)
      || wrapper.identifier !== options.expected.identifier || wrapper.channel !== "stable"
      || wrapper.name !== options.expected.name || wrapper.hash !== update.hash
      || build.electrobunVersion !== options.expected.electrobunVersion
      || build.mainProcess !== options.expected.mainProcess || build.buildEnvironment !== "stable") {
    throw new Error("Release archive, wrapper or runtime metadata does not match the requested build.");
  }
  const wrapperPayload = join(dirname(options.wrapperMetadata), `${update.hash}.tar.zst`);
  if (fingerprint(wrapperPayload) === undefined
      || !readFileSync(wrapperPayload).equals(new Uint8Array(readFileSync(options.archive)))) {
    throw new Error("Installer wrapper does not contain the verified app archive.");
  }
  for (const entry of options.requiredEntries) readEntry(entry);
}
