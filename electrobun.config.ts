import type { ElectrobunConfig } from "electrobun";

const isUITestBuild = process.env.NOCTWEAVE_UI_TEST_BUILD === "1";
const requestedUITestProfile = process.env.NOCTWEAVE_UI_TEST_PROFILE;
const uiTestProfile = requestedUITestProfile !== undefined
  && /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(requestedUITestProfile)
  ? requestedUITestProfile
  : "instance";
const uiTestProfileName = uiTestProfile
  .split("-")
  .map((part) => part[0].toUpperCase() + part.slice(1))
  .join(" ");

export default {
  app: {
    name: isUITestBuild ? `NoctweaveJS UI Test ${uiTestProfileName}` : "NoctweaveJS",
    identifier: isUITestBuild
      ? `org.noctweave.js-client.ui-test.${uiTestProfile}`
      : "org.noctweave.js-client",
    version: "0.1.0",
    description: "Open-source post-quantum Noctweave messaging client."
  },
  build: {
    bun: {
      entrypoint: isUITestBuild
        ? "desktop/ui-test-bun/index.ts"
        : "desktop/bun/index.ts"
    },
    views: {
      mainview: {
        entrypoint: "desktop/view/index.ts"
      }
    },
    copy: {
      ...(process.platform === "darwin" ? { ".build/security-key-bundle": "security-keys" } : {}),
      "client/index.html": "views/mainview/index.html",
      "client/styles.css": "views/mainview/styles.css",
      "client/assets": "views/mainview/assets",
      "wasm/dist/noctweave_oqs.wasm": "views/mainview/noctweave_oqs.wasm"
    },
    targets: "current",
    useAsar: false,
    watch: ["client", "desktop", "src", "wasm/dist"],
    mac: {
      bundleCEF: false,
      codesign: false,
      notarize: false
    },
    linux: {
      bundleCEF: false,
      icon: "desktop/assets/app-icon.png"
    },
    win: {
      bundleCEF: false,
      icon: "desktop/assets/app-icon.ico"
    }
  },
  scripts: {
    preBuild: "desktop/scripts/build-security-key-bridge.ts",
    postBuild: "desktop/scripts/install-mac-icon.ts",
    postWrap: "desktop/scripts/install-mac-icon.ts"
  }
} satisfies ElectrobunConfig;
