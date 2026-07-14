import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { BrowserView, BrowserWindow, PATHS } from "electrobun/bun";
import type { NoctweaveDesktopRPC } from "../rpc.js";
import { proxyRelayRequest } from "./relay-proxy.js";

const maximumWasmBytes = 2 * 1024 * 1024;
let cachedWasmBase64: string | undefined;

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
  maxRequestTime: 20_000,
  handlers: {
    requests: {
      loadPostQuantumWasm: () => loadPostQuantumWasm(),
      relayFetch: (request) => proxyRelayRequest(request)
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
