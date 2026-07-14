import { copyFileSync, existsSync } from "node:fs";
import { join } from "node:path";

if (process.env.ELECTROBUN_OS === "macos") {
  const source = new URL("../assets/app-icon.icns", import.meta.url);
  const wrapperBundle = process.env.ELECTROBUN_WRAPPER_BUNDLE_PATH;
  const buildDirectory = process.env.ELECTROBUN_BUILD_DIR;
  const appName = process.env.ELECTROBUN_APP_NAME;
  const bundle = wrapperBundle ?? (buildDirectory && appName
    ? join(buildDirectory, `${appName}.app`)
    : null);

  if (!bundle || !existsSync(bundle)) {
    throw new Error("Electrobun did not provide a valid macOS bundle path.");
  }

  copyFileSync(source, join(bundle, "Contents", "Resources", "AppIcon.icns"));
}
