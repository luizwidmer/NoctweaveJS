import type { SecurityKeyRequest, SecurityKeyResult } from "../bun/security-key-host.js";
import Electrobun, { Electroview } from "electrobun/view";
import type {
  DesktopRelayRequest,
  NoctweaveDesktopRPC
} from "../rpc.js";
import { installDesktopRelationshipStateAnchorFactory } from "./relationship-state-anchor.js";

document.documentElement.dataset.runtime = "desktop";

// The companion page depends on the browser client's local server and is not
// bundled into the desktop host. Keep the shortcut explicit about availability.
const groupsShortcut = document.querySelector<HTMLAnchorElement>(".groupsShortcut");
if (groupsShortcut) {
  const groupsAvailability = document.createElement("button");
  groupsAvailability.className = groupsShortcut.className;
  groupsAvailability.textContent = "Groups";
  groupsAvailability.disabled = true;
  groupsAvailability.title = "Groups are available in the browser companion.";
  groupsAvailability.setAttribute("aria-label", "Groups: available in the browser companion");
  groupsShortcut.replaceWith(groupsAvailability);
}

declare global {
  var __noctweaveDesktopSecurityKeys: {
    available: boolean; rpID: string; origin: string; continuousPresence: boolean;
    presence: () => Promise<{ present: boolean; credentialID: string | null }>;
    releasePresence: () => Promise<{ released: boolean }>;
    request: (request: SecurityKeyRequest) => Promise<SecurityKeyResult>;
    cancel: () => Promise<{ cancelled: boolean }>;
  } | undefined;
  var __noctweaveDesktopRelayFetch: ((request: DesktopRelayRequest) => Promise<Response>) | undefined;
  var __noctweaveDesktopWasmBinary: Uint8Array | undefined;
  var __noctweaveDesktopExportAttachment: ((request: {
    bytes: Uint8Array;
    mimeType: string;
    sha256: string;
  }) => Promise<{ saved: boolean; fileName: string | null; byteCount: number }>) | undefined;
}

const desktopRPC = Electroview.defineRPC<NoctweaveDesktopRPC>({
  maxRequestTime: 120_000,
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
globalThis.__noctweaveDesktopExportAttachment = async ({ bytes, mimeType, sha256 }) => {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
    throw new TypeError("Desktop attachment export bytes are invalid.");
  }
  const authorization = await desktop.rpc!.request.authorizeAttachmentExport({
    mimeType,
    byteCount: bytes.byteLength,
    sha256
  });
  if (authorization.token === null) {
    return Object.freeze({ saved: false, fileName: null, byteCount: bytes.byteLength });
  }
  return desktop.rpc!.request.writeAttachmentExport({
    token: authorization.token,
    bytesBase64: encodeBase64(bytes)
  });
};

globalThis.__noctweaveDesktopSecurityKeys = Object.freeze({
  ...await desktop.rpc!.request.securityKeyCapability({}),
  presence: () => desktop.rpc!.request.securityKeyPresence({}),
  attachments: () => desktop.rpc!.request.securityKeyAttachments({}),
  stopAttachments: () => desktop.rpc!.request.stopSecurityKeyAttachments({}),
  releasePresence: () => desktop.rpc!.request.releaseSecurityKeyPresence({}),
  request: (request: SecurityKeyRequest) => desktop.rpc!.request.securityKeyRequest(request),
  cancel: () => desktop.rpc!.request.cancelSecurityKeyRequest({})
});

await import("../../client/app.js");

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function encodeBase64(bytes: Uint8Array) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}
