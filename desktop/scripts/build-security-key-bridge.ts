import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, chmodSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform === "darwin") {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const source = resolve(process.env.NOCTWEAVE_SECURITY_KEYS_PACKAGE ?? join(root, "../NoctweaveSecurityKeys"));
  if (!existsSync(join(source, "Package.swift"))) {
    throw new Error("Building the macOS app requires the NoctweaveSecurityKeys package from the Noctweave checkout.");
  }
  const scratch = join(root, ".build", "security-key-bridge");
  const flags = ["--package-path", source, "--scratch-path", scratch, "-c", "release", "--product", "NoctweaveSecurityKeyBridge"];
  execFileSync("xcrun", ["swift", "build", ...flags], { stdio: "inherit" });
  const bin = execFileSync("xcrun", ["swift", "build", ...flags, "--show-bin-path"], { encoding: "utf8" }).trim();
  const target = join(root, ".build", "security-key-bundle");
  mkdirSync(target, { recursive: true });
  copyFileSync(join(bin, "NoctweaveSecurityKeyBridge"), join(target, "NoctweaveSecurityKeyBridge"));
  chmodSync(join(target, "NoctweaveSecurityKeyBridge"), 0o755);
  copyFileSync(join(source, "LICENSE"), join(target, "NoctweaveSecurityKeys-LICENSE.txt"));
  copyFileSync(join(source, "YubiKit-LICENSE.txt"), join(target, "YubiKit-LICENSE.txt"));
  copyFileSync(join(source, "NOTICE.md"), join(target, "NOTICE.md"));
}
