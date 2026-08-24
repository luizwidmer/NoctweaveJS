import { copyFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

if (process.env.ELECTROBUN_OS === "macos") {
  const source = new URL("../assets/app-icon.icns", import.meta.url);
  const wrapperBundle = process.env.ELECTROBUN_WRAPPER_BUNDLE_PATH;
  const buildDirectory = process.env.ELECTROBUN_BUILD_DIR;
  const appName = process.env.ELECTROBUN_APP_NAME;
  const directBuildBundle = buildDirectory && appName
    ? join(buildDirectory, `${appName}.app`)
    : null;
  const displayBundleName = buildDirectory && appName && existsSync(buildDirectory)
    ? readdirSync(buildDirectory).find((entry) =>
      entry.endsWith(".app") && entry.replaceAll(" ", "") === `${appName}.app`)
    : null;
  const buildBundle = directBuildBundle && existsSync(directBuildBundle)
    ? directBuildBundle
    : displayBundleName && buildDirectory
      ? join(buildDirectory, displayBundleName)
      : null;
  const bundle = wrapperBundle && existsSync(wrapperBundle)
    ? wrapperBundle
    : buildBundle;

  if (!bundle || !existsSync(bundle)) {
    throw new Error("Electrobun did not provide a valid macOS bundle path.");
  }

  copyFileSync(source, join(bundle, "Contents", "Resources", "AppIcon.icns"));
}
