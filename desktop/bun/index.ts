import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { BrowserView, BrowserWindow, PATHS } from "electrobun/bun";
import type { NoctweaveDesktopRPC } from "../rpc.js";
import { proxyRelayRequest } from "./relay-proxy.js";
import { DesktopRelationshipStateStore } from "./relationship-state-store.js";

const maximumWasmBytes = 2 * 1024 * 1024;
let cachedWasmBase64: string | undefined;
const relationshipStateStore = new DesktopRelationshipStateStore();

async function loadPostQuantumWasm(): Promise<string> {
  if (cachedWasmBase64) {
    return cachedWasmBase64;
  }
  const bytes = await readFile(join(PATHS.VIEWS_FOLDER, "mainview", "noctweave_oqs.wasm"));
  if (bytes.byteLength === 0 || bytes.byteLength > maximumWasmBytes) {
    throw new Error("Packaged post-quantum runtime has an invalid size.");
  }
  cachedWasmBase64 = bytes.toString("base64");
  return cachedWasmBase64;
}

const desktopRPC = BrowserView.defineRPC<NoctweaveDesktopRPC>({
  maxRequestTime: 60_000,
  handlers: {
    requests: {
      loadPostQuantumWasm: () => loadPostQuantumWasm(),
      relayFetch: (request) => proxyRelayRequest(request),
      relationshipStateCapability: () => relationshipStateStore.capabilityReport(),
      relationshipStateErasureStatus: (request) => relationshipStateStore.erasureStatus(request),
      loadRelationshipState: (request) => relationshipStateStore.load(request),
      commitRelationshipState: (request) => relationshipStateStore.commit(request),
      destroyRelationshipState: (request) => relationshipStateStore.destroy(request)
    },
    messages: {}
  }
});

new BrowserWindow({
  title: "NoctweaveJS",
  url: "views://mainview/index.html",
  rpc: desktopRPC,
  renderer: "native",
  sandbox: false,
  transparent: false,
  titleBarStyle: "default",
  frame: {
    width: 1280,
    height: 820,
    x: 120,
    y: 100
  }
});
