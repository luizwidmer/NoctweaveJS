// Keep Bun-only harness checks outside Node's protocol-test discovery.
import { test, expect } from "bun:test";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runCachedTool, runCheckedBuild, verifyBuildMetadata, verifyReleaseArchive } from "../scripts/checked-build";

function fixture(body: (root: string, output: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "noctweave-build-test-"));
  try { body(root, join(root, "artifact")); }
  finally { rmSync(root, { recursive: true, force: true }); }
}

function build(root: string, output: string, script: string): void {
  runCheckedBuild({ command: [process.execPath, "-e", script], cwd: root,
    outputs: [{ path: output, fresh: true }] });
}

test("signal termination cannot become successful exit", () => fixture((root, output) => {
  expect(() => build(root, output, 'process.kill(process.pid, "SIGKILL")')).toThrow("SIGKILL");
}));
test("development commands also reject signal termination without artifact checks", () => fixture((root) => {
  expect(() => runCachedTool([process.execPath, "-e", 'process.kill(process.pid, "SIGKILL")'], root)).toThrow("SIGKILL");
}));
test("nonzero exit remains a failure", () => fixture((root, output) => {
  expect(() => build(root, output, "process.exit(7)")).toThrow("status 7");
}));
test("zero exit without artifacts fails", () => fixture((root, output) => {
  expect(() => build(root, output, "process.exit(0)")).toThrow("nonempty output");
}));
test("old artifacts cannot satisfy a fresh build", () => fixture((root, output) => {
  writeFileSync(output, "old build");
  expect(() => build(root, output, "process.exit(0)")).toThrow("stale artifact");
}));
test("empty artifacts and symlinks fail", () => fixture((root, output) => {
  expect(() => build(root, output, 'require("node:fs").writeFileSync("artifact", "")')).toThrow("nonempty output");
  rmSync(output);
  writeFileSync(join(root, "other"), "another build");
  symlinkSync(join(root, "other"), output);
  expect(() => build(root, output, "process.exit(0)")).toThrow("regular file");
}));
test("fresh nonempty outputs pass, then run metadata verification", () => fixture((root, output) => {
  let verified = false;
  runCheckedBuild({ command: [process.execPath, "-e", 'require("node:fs").writeFileSync("artifact", "fresh build")'],
    cwd: root, outputs: [{ path: output, fresh: true }], verify: () => { verified = true; } });
  expect(verified).toBe(true);
}));
test("a partial build is rejected", () => fixture((root, output) => {
  expect(() => runCheckedBuild({ command: [process.execPath, "-e", 'require("node:fs").writeFileSync("artifact", "fresh build")'],
    cwd: root, outputs: [{ path: output, fresh: true }, { path: join(root, "launcher") }] })).toThrow("launcher");
}));
test("missing cached tool fails without installation", () => fixture((root, output) => {
  expect(() => runCheckedBuild({ command: [join(root, "missing-cli")], cwd: root,
    outputs: [{ path: output }] })).toThrow("Cannot start the cached build tool");
}));
test("metadata must match app, version, platform and bundle hash", () => fixture((root) => {
  const update = join(root, "update.json");
  const version = join(root, "version.json");
  const expected = { version: "0.1.0", identifier: "org.noctweave.test", platform: "macos", arch: "arm64" };
  writeFileSync(update, JSON.stringify({ ...expected, hash: "bundle-hash" }));
  writeFileSync(version, JSON.stringify({ ...expected, channel: "stable", hash: "bundle-hash" }));
  expect(() => verifyBuildMetadata(update, version, expected)).not.toThrow();
  writeFileSync(version, JSON.stringify({ ...expected, channel: "stable", hash: "old-hash" }));
  expect(() => verifyBuildMetadata(update, version, expected)).toThrow("metadata");
  writeFileSync(version, JSON.stringify({ ...expected, identifier: "another-app", channel: "stable", hash: "bundle-hash" }));
  expect(() => verifyBuildMetadata(update, version, expected)).toThrow("metadata");
}));

function releaseFixture(body: (options: Parameters<typeof verifyReleaseArchive>[0],
  root: string, publish: () => void) => void): void {
  fixture((root) => {
    const resources = "Fixture.app/Contents/Resources";
    const expected = { version: "0.1.0", identifier: "org.noctweave.test", platform: "macos",
      arch: "arm64", name: "Fixture", electrobunVersion: "2.0.2", mainProcess: "bun" };
    const options = {
      archive: join(root, "payload.tar.zst"), update: join(root, "update.json"),
      wrapperMetadata: join(root, "wrapper", "metadata.json"),
      versionEntry: `${resources}/version.json`, buildEntry: `${resources}/build.json`,
      requiredEntries: [`${resources}/app/views/mainview/index.js`], expected,
    };
    const put = (path: string, value: string) => {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), value);
    };
    put(options.versionEntry, JSON.stringify({ ...expected, hash: "abc123", channel: "stable" }));
    put(options.buildEntry, JSON.stringify({ electrobunVersion: "2.0.2", mainProcess: "bun", buildEnvironment: "stable" }));
    put(options.requiredEntries[0]!, "fresh bundled view");
    put("update.json", JSON.stringify({ ...expected, channel: "stable", hash: "abc123", artifact: { file: "payload.tar.zst" } }));
    put("wrapper/metadata.json", JSON.stringify({ ...expected, channel: "stable", hash: "abc123" }));
    const publish = () => {
      execFileSync("tar", ["-cf", join(root, "payload.tar"), "-C", root, "Fixture.app"]);
      writeFileSync(options.archive, new Uint8Array(Bun.zstdCompressSync(readFileSync(join(root, "payload.tar")))));
      copyFileSync(options.archive, join(root, "wrapper", "abc123.tar.zst"));
    };
    publish(); body(options, root, publish);
  });
}

test("v2 installer verifies its actual compressed app payload", () => releaseFixture((options) => {
  expect(() => verifyReleaseArchive(options)).not.toThrow();
}));
test("v2 payload must include the bundled application files", () => releaseFixture((options, root, publish) => {
  rmSync(join(root, options.requiredEntries[0]!)); publish();
  expect(() => verifyReleaseArchive(options)).toThrow("exactly one required member");
}));
test("v2 rejects mismatched wrapper, SDK and bundled archive", () => releaseFixture((options, root, publish) => {
  writeFileSync(options.wrapperMetadata, JSON.stringify({ ...options.expected, channel: "stable", hash: "wrong" }));
  expect(() => verifyReleaseArchive(options)).toThrow("metadata");
  writeFileSync(options.wrapperMetadata, JSON.stringify({ ...options.expected, channel: "stable", hash: "abc123" }));
  writeFileSync(join(root, options.buildEntry), JSON.stringify({ electrobunVersion: "1.18.1", mainProcess: "bun", buildEnvironment: "stable" }));
  publish(); expect(() => verifyReleaseArchive(options)).toThrow("metadata");
  writeFileSync(join(root, options.buildEntry), JSON.stringify({ electrobunVersion: "2.0.2", mainProcess: "bun", buildEnvironment: "stable" }));
  publish(); writeFileSync(join(root, "wrapper", "abc123.tar.zst"), "unrelated payload");
  expect(() => verifyReleaseArchive(options)).toThrow("verified app archive");
}));
test("v2 rejects duplicate required archive members", () => releaseFixture((options, root) => {
  execFileSync("tar", ["-rf", join(root, "payload.tar"), "-C", root, options.requiredEntries[0]!]);
  writeFileSync(options.archive, new Uint8Array(Bun.zstdCompressSync(readFileSync(join(root, "payload.tar")))));
  copyFileSync(options.archive, join(root, "wrapper", "abc123.tar.zst"));
  expect(() => verifyReleaseArchive(options)).toThrow("exactly one required member");
}));
test("v2 required archive files cannot be replaced with symlinks", () => releaseFixture((options, root, publish) => {
  const path = join(root, options.requiredEntries[0]!);
  rmSync(path); symlinkSync("../../../version.json", path); publish();
  expect(() => verifyReleaseArchive(options)).toThrow();
}));
