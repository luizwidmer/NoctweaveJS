import Electrobun, { Electroview } from "electrobun/view";
import type {
  DesktopRelayRequest,
  NoctweaveDesktopRPC
} from "../rpc.js";
import { installDesktopRelationshipStateAnchorFactory } from "./relationship-state-anchor.js";

document.documentElement.dataset.runtime = "desktop";

declare global {
  var __noctweaveDesktopRelayFetch: ((request: DesktopRelayRequest) => Promise<Response>) | undefined;
  var __noctweaveDesktopWasmBinary: Uint8Array | undefined;
}

const desktopRPC = Electroview.defineRPC<NoctweaveDesktopRPC>({
  maxRequestTime: 20_000,
  handlers: {
    requests: {},
    messages: {}
  }
});

const desktop = new Electrobun.Electroview({ rpc: desktopRPC });

await installDesktopRelationshipStateAnchorFactory({
  requests: desktop.rpc!.request
});

globalThis.__noctweaveDesktopWasmBinary = decodeBase64(
  await desktop.rpc!.request.loadPostQuantumWasm({})
);
globalThis.__noctweaveDesktopRelayFetch = async (request) => {
  const response = await desktop.rpc!.request.relayFetch(request);
  return new Response(response.body, {
    status: response.status,
    headers: {
      "content-type": response.contentType,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
  });
};

await import("../../client/app.js");

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
