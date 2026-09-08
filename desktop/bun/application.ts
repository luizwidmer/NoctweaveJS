import { DesktopSecurityKeyHost } from "./security-key-host.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { BrowserView, BrowserWindow, PATHS, Utils } from "electrobun/bun";
import type { NoctweaveDesktopRPC } from "../rpc.js";
import { DesktopAttachmentExporter } from "./attachment-export.js";
import { proxyRelayRequest } from "./relay-proxy.js";
import type { DesktopRelationshipStateStore } from "./relationship-state-store.js";

const maximumWasmBytes = 2 * 1024 * 1024;
let cachedWasmBase64: string | undefined;

async function loadPostQuantumWasm(): Promise<string> {
  if (cachedWasmBase64) return cachedWasmBase64;
  const bytes = await readFile(join(PATHS.VIEWS_FOLDER, "mainview", "noctweave_oqs.wasm"));
  if (bytes.byteLength === 0 || bytes.byteLength > maximumWasmBytes) {
    throw new Error("Packaged post-quantum runtime has an invalid size.");
  }
  cachedWasmBase64 = bytes.toString("base64");
  return cachedWasmBase64;
}

export async function startDesktopApplication({
  relationshipStateStore,
  title
}: {
  relationshipStateStore: DesktopRelationshipStateStore;
  title: string;
}) {
  const securityKeys = new DesktopSecurityKeyHost(join(PATHS.RESOURCES_FOLDER, "app", "security-keys", "NoctweaveSecurityKeyBridge"));
  const attachmentExporter = new DesktopAttachmentExporter({
    selectDirectory: async () => {
      const selected = await Utils.openFileDialog({
        startingFolder: Utils.paths.downloads,
        allowedFileTypes: "*",
        canChooseFiles: false,
        canChooseDirectory: true,
        allowsMultipleSelection: false
      });
      return selected.find((path) => path.trim().length > 0) ?? null;
    }
  });
  const desktopRPC = BrowserView.defineRPC<NoctweaveDesktopRPC>({
    maxRequestTime: 120_000,
    handlers: {
      requests: {
        loadPostQuantumWasm: () => loadPostQuantumWasm(),
        securityKeyCapability: () => securityKeys.capability(),
        securityKeyPresence: () => securityKeys.presenceStatus(),
        securityKeyAttachments: () => securityKeys.attachmentStatus(),
        stopSecurityKeyAttachments: () => securityKeys.stopWatchingAttached(),
        releaseSecurityKeyPresence: () => securityKeys.releasePresence(),
        securityKeyRequest: (request) => securityKeys.request(request),
        cancelSecurityKeyRequest: () => securityKeys.cancel(),
        relayFetch: (request) => proxyRelayRequest(request),
        authorizeAttachmentExport: (request) => attachmentExporter.authorize(request),
        writeAttachmentExport: (request) => attachmentExporter.write(request),
        relationshipStateCapability: () => relationshipStateStore.capabilityReport(),
        relationshipStateErasureStatus: (request) => relationshipStateStore.erasureStatus(request),
        loadRelationshipState: (request) => relationshipStateStore.load(request),
        commitRelationshipState: (request) => relationshipStateStore.commit(request),
        destroyRelationshipState: (request) => relationshipStateStore.destroy(request)
      },
      messages: {}
    }
  });

  const window = new BrowserWindow({
    title,
    url: "views://mainview/index.html",
    // Native rules use last-match-wins. Only the bundled document may receive privileged RPC.
    navigationRules: JSON.stringify(["^*", "views://mainview/index.html", "views://mainview/index.html#*"]),
    rpc: desktopRPC,
    renderer: "native",
    sandbox: false,
    transparent: false,
    titleBarStyle: "default",
    frame: {
      width: 1120,
      height: 760,
      x: 80,
      y: 60
    }
  });
  window.on("close", () => { securityKeys.cancel(); securityKeys.releasePresence(); securityKeys.stopWatchingAttached(); });
}
