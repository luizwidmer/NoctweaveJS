import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ElectrobunConfig } from "electrobun";
import config from "../../electrobun.config";
import hutchConfig from "../../hutch.config";
import { runCheckedBuild, verifyReleaseArchive } from "./checked-build";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const settings: ElectrobunConfig = config;
const platform = process.platform === "darwin" ? "macos" : process.platform === "win32" ? "win" : process.platform;
if (!["macos", "linux", "win"].includes(platform)) throw new Error(`Unsupported build platform: ${platform}`);
if (process.argv.length > 2) throw new Error("desktop:build builds the stable app for the current platform.");
const prefix = `stable-${platform}-${process.arch}`;
const artifactName = settings.app.name.replaceAll(" ", "");
const bundle = join(root, settings.build?.buildFolder ?? "build", prefix,
  platform === "macos" ? `${settings.app.name}.app` : artifactName);
const resources = join(bundle, ...(platform === "macos" ? ["Contents", "Resources"] : ["Resources"]));
const archive = join(root, settings.build?.artifactFolder ?? "artifacts",
  `${prefix}-${artifactName}${platform === "macos" ? ".app" : ""}.tar.zst`);
const update = join(root, settings.build?.artifactFolder ?? "artifacts", `${prefix}-update.json`);
const metadata = join(resources, "metadata.json");
const payloadBundle = platform === "macos" ? `${settings.app.name}.app` : artifactName;
const payloadResources = posix.join(payloadBundle, ...(platform === "macos" ? ["Contents", "Resources"] : ["Resources"]));

runCheckedBuild({
  command: [process.execPath, join(root, "node_modules", "electrobun", "bin", "electrobun.cjs"), "build", "--env=stable"],
  cwd: root,
  outputs: [
    { path: archive, fresh: true }, { path: update, fresh: true }, { path: metadata },
    ...(platform === "macos" ? [{ path: join(root, settings.build?.artifactFolder ?? "artifacts", `macos-${process.arch}-${artifactName}.dmg`), fresh: true }] : []),
    { path: join(bundle, ...(platform === "macos" ? ["Contents", "MacOS", "launcher"] : ["bin", platform === "win" ? "launcher.exe" : "launcher"])) },
  ],
  verify: () => verifyReleaseArchive({
    archive, update, wrapperMetadata: metadata,
    versionEntry: posix.join(payloadResources, "version.json"),
    buildEntry: posix.join(payloadResources, "build.json"),
    requiredEntries: [
      posix.join(payloadBundle, ...(platform === "macos" ? ["Contents", "MacOS", "launcher"] : ["bin", platform === "win" ? "launcher.exe" : "launcher"])),
      posix.join(payloadResources, "app", "bun", "index.js"),
      posix.join(payloadResources, "app", "views", "mainview", "index.html"),
      posix.join(payloadResources, "app", "views", "mainview", "index.js"),
      ...(platform === "macos" ? [posix.join(payloadResources, "AppIcon.icns")] : []),
    ],
    expected: {
      version: settings.app.version, identifier: settings.app.identifier,
      platform, arch: process.arch, name: settings.app.name,
      electrobunVersion: hutchConfig.electrobun.version,
      mainProcess: settings.build?.mainProcess ?? "cottontail",
    },
  }),
});
console.log(`Verified fresh desktop artifacts: ${archive}`);
