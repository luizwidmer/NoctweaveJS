import type { ElectrobunConfig } from "electrobun";

export default {
  app: {
    name: "NoctweaveJS",
    identifier: "org.noctweave.js-client",
    version: "0.1.0",
    description: "Open-source post-quantum Noctweave messaging client."
  },
  build: {
    bun: {
      entrypoint: "desktop/bun/index.ts"
    },
    views: {
      mainview: {
        entrypoint: "desktop/view/index.ts"
      }
    },
    copy: {
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
    postBuild: "desktop/scripts/install-mac-icon.ts",
    postWrap: "desktop/scripts/install-mac-icon.ts"
  }
} satisfies ElectrobunConfig;
