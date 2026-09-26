#!/usr/bin/env node
import { createServer } from "node:http";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRelayEndpoint, relayEndpointURL } from "../../src/endpoint.js";
import { createCompanionAccessToken, hasCompanionAccess } from "./companion-access.js";
import { NoctweaveGroupCompanion } from "./group-companion.js";

const root = normalize(join(fileURLToPath(new URL("../..", import.meta.url))));
const port = Number(process.env.PORT ?? 5173);
const maxBodyBytes = 1_000_000;
const proxyTimeoutMs = 10_000;
const maximumStaticBytes = 8 * 1024 * 1024;
const canonicalRoot = await realpath(root);
const defaultClientPath = process.env.NOCTWEAVE_CLIENT === "production"
  ? "/client/"
  : "/examples/browser-client/";
const defaultCLIPath = normalize(join(
  root,
  "..",
  ".build-caches",
  "core-cli",
  "debug",
  "NoctweaveCLI"
));
const companionDirectory = normalize(join(root, ".local", "group-companion"));
// A prerelease token file is never read or silently destroyed. Its presence
// means the operator must remove legacy plaintext data explicitly.
try {
  await lstat(join(companionDirectory, "access-token"));
  throw new Error("Legacy plaintext group companion token exists; remove .local/group-companion/access-token before starting.");
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}
const groupCompanionAccess = createCompanionAccessToken();
const groupCompanion = new NoctweaveGroupCompanion({
  cliPath: process.env.NOCTWEAVE_CLI_PATH ?? defaultCLIPath,
  statePath: join(companionDirectory, "client-state.json"),
  plaintextForTesting: false
});

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8"
};

const server = createServer(async (request, response) => {
  try {
    if (!isAllowedLoopbackHost(request.headers.host)) {
      writeResponse(response, 421, "Misdirected request", "text/plain; charset=utf-8");
      return;
    }
    if (request.url?.startsWith("/proxy/")) {
      await proxyRelay(request, response);
      return;
    }
    if (request.url?.startsWith("/api/group-companion")) {
      await serveGroupCompanion(request, response);
      return;
    }
    await serveStatic(request, response);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    writeResponse(response, 500, "Internal server error", "text/plain; charset=utf-8");
  }
});

async function serveGroupCompanion(request, response) {
  if (!isSameOriginBrowserRequest(request)) {
    writeJSON(response, 403, { error: "The group companion accepts same-origin loopback requests only." });
    return;
  }
  if (!hasCompanionAccess(request, groupCompanionAccess.token)) {
    writeJSON(response, 401, { error: "Enter the local companion access token to continue." });
    return;
  }
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  const path = url.pathname.replace(/^\/api\/group-companion\/?/u, "");
  const segments = path.split("/").filter(Boolean);
  try {
    if (request.method === "GET" && segments.length === 1 && segments[0] === "status") {
      writeJSON(response, 200, await groupCompanion.status());
      return;
    }
    if (request.method === "POST" && segments.length === 1 && segments[0] === "setup") {
      writeJSON(response, 200, await groupCompanion.setup(await readJSONBody(request)));
      return;
    }
    if (request.method === "GET" && segments.length === 1 && segments[0] === "groups") {
      writeJSON(response, 200, await groupCompanion.groups());
      return;
    }
    if (request.method === "POST" && segments.length === 1 && segments[0] === "groups") {
      writeJSON(response, 201, await groupCompanion.createGroup(await readJSONBody(request)));
      return;
    }
    if (segments.length === 3 && segments[0] === "groups" && segments[2] === "events") {
      if (request.method !== "GET") {
        writeJSON(response, 405, { error: "Method not allowed" });
        return;
      }
      const synchronize = url.searchParams.get("sync") !== "false";
      const events = synchronize
        ? await groupCompanion.syncAndReadEvents(segments[1])
        : await groupCompanion.readEvents(segments[1]);
      writeJSON(response, 200, events);
      return;
    }
    if (segments.length === 3 && segments[0] === "groups" && segments[2] === "messages") {
      if (request.method !== "POST") {
        writeJSON(response, 405, { error: "Method not allowed" });
        return;
      }
      const body = await readJSONBody(request);
      writeJSON(response, 201, await groupCompanion.sendMessage(segments[1], body.text));
      return;
    }
    if (segments.length === 3 && segments[0] === "groups" && segments[2] === "admissions") {
      if (request.method !== "POST") {
        writeJSON(response, 405, { error: "Method not allowed" });
        return;
      }
      const body = await readJSONBody(request);
      writeJSON(
        response,
        201,
        await groupCompanion.acceptAdmissionRequest(segments[1], body.requestLink)
      );
      return;
    }
    writeJSON(response, 404, { error: "Not found" });
  } catch (error) {
    writeJSON(response, 400, {
      error: String(error?.message ?? error).slice(0, 2_048)
    });
  }
}

server.listen(port, "127.0.0.1", () => {
  console.log(`NoctweaveJS client: http://127.0.0.1:${port}${defaultClientPath}`);
  if (groupCompanionAccess.reveal) {
    console.log(`One-time group companion token for this server run: ${groupCompanionAccess.token}`);
  }
});

async function proxyRelay(request, response) {
  const endpoint = request.headers["x-relay-endpoint"];
  if (typeof endpoint !== "string" || endpoint.trim() === "") {
    writeJSON(response, 400, { type: "error", error: "Missing x-relay-endpoint header" });
    return;
  }

  const isRelay = request.url === "/proxy/relay";
  if (!isRelay || request.method !== "POST") {
    writeJSON(response, 404, { type: "error", error: "Not found" });
    return;
  }
  let parsedEndpoint;
  try {
    parsedEndpoint = parseRelayEndpoint(endpoint);
  } catch {
    writeJSON(response, 400, { type: "error", error: "Invalid relay endpoint" });
    return;
  }
  if (parsedEndpoint.transport !== "http") {
    writeJSON(response, 400, { type: "error", error: "The HTTP proxy accepts only HTTP or HTTPS relays" });
    return;
  }

  const target = relayEndpointURL(parsedEndpoint, "/relay");
  const body = await readBody(request);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), proxyTimeoutMs);
  try {
    const relayResponse = await fetch(target, {
      method: request.method,
      headers: {
        "accept": request.headers.accept ?? "application/json",
        "content-type": request.headers["content-type"] ?? "application/json"
      },
      body,
      redirect: "error",
      signal: controller.signal
    });
    const bytes = await readBoundedResponse(relayResponse, maxBodyBytes);
    writeResponse(
      response,
      relayResponse.status,
      bytes,
      relayResponse.headers.get("content-type") ?? "application/json; charset=utf-8"
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function serveStatic(request, response) {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  const decodedPath = decodeURIComponent(url.pathname);
  if (decodedPath === "/") {
    writeResponse(response, 302, "", "text/plain; charset=utf-8", {
      location: defaultClientPath
    });
    return;
  }
  const pathname = decodedPath.endsWith("/")
    ? `${decodedPath}index.html`
    : decodedPath;
  // Only browser runtime assets are public. The checkout also contains private
  // companion state, Git metadata, and host-side code that must never be served.
  if (!isPublicAsset(pathname)) {
    writeResponse(response, 404, "Not found", "text/plain; charset=utf-8");
    return;
  }
  const filePath = join(canonicalRoot, pathname);
  let handle;
  try {
    // Reject symlinks anywhere beneath the served root, including directory
    // links. A permitted asset name must not make an outside file public.
    if (await realpath(filePath) !== filePath) {
      writeResponse(response, 404, "Not found", "text/plain; charset=utf-8");
      return;
    }
    handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const info = await handle.stat();
    if (!info.isFile() || info.size > maximumStaticBytes) {
      writeResponse(response, 404, "Not found", "text/plain; charset=utf-8");
      return;
    }
    const chunks = [];
    let total = 0;
    while (true) {
      const chunk = Buffer.alloc(64 * 1024);
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (!bytesRead) break;
      total += bytesRead;
      if (total > maximumStaticBytes) throw new Error("Static asset exceeds size limit.");
      chunks.push(chunk.subarray(0, bytesRead));
    }
    writeResponse(response, 200, Buffer.concat(chunks, total), mimeTypes[extname(filePath)] ?? "application/octet-stream");
  } catch {
    writeResponse(response, 404, "Not found", "text/plain; charset=utf-8");
  } finally {
    await handle?.close();
  }
}

function isPublicAsset(pathname) {
  if (pathname.includes("\\") || pathname.includes("\0") ||
      pathname.split("/").some((part) => part.startsWith("."))) return false;
  if (/^\/src\/.+\.js$/u.test(pathname)) return true;
  if (/^\/client\/.+\.(?:html|js|css|svg)$/u.test(pathname)) return true;
  if (/^\/examples\/browser-client\/(?:index\.html|app\.js|styles\.css|assets\/[^/]+\.svg)$/u.test(pathname)) return true;
  return pathname === "/wasm/dist/noctweave_oqs.js" || pathname === "/wasm/dist/noctweave_oqs.wasm";
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    let byteCount = 0;
    let settled = false;
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      if (settled) {
        return;
      }
      byteCount += Buffer.byteLength(chunk);
      if (byteCount > maxBodyBytes) {
        settled = true;
        reject(new Error("Request body too large"));
        request.destroy();
        return;
      }
      body += chunk;
    });
    request.on("end", () => {
      if (!settled) {
        settled = true;
        resolve(body);
      }
    });
    request.on("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
  });
}

async function readJSONBody(request) {
  const body = await readBody(request);
  try {
    return JSON.parse(body);
  } catch {
    throw new Error("Request body must be valid JSON.");
  }
}

async function readBoundedResponse(relayResponse, maximumBytes) {
  const declaredLength = Number(relayResponse.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error("Relay response too large");
  }
  if (!relayResponse.body?.getReader) {
    const bytes = new Uint8Array(await relayResponse.arrayBuffer());
    if (bytes.byteLength > maximumBytes) {
      throw new Error("Relay response too large");
    }
    return bytes;
  }
  const reader = relayResponse.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel("Relay response too large");
        throw new Error("Relay response too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function writeJSON(response, status, payload) {
  writeResponse(response, status, JSON.stringify(payload), "application/json; charset=utf-8");
}

function writeResponse(response, status, body, contentType, additionalHeaders = {}) {
  const headers = {
    "content-type": contentType,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' http: https: ws: wss:; img-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ...additionalHeaders
  };
  response.writeHead(status, headers);
  response.end(body);
}

function isAllowedLoopbackHost(value) {
  if (typeof value !== "string") {
    return false;
  }
  const normalized = value.toLowerCase();
  return normalized === `127.0.0.1:${port}` ||
    normalized === `localhost:${port}` ||
    normalized === `[::1]:${port}`;
}

function isSameOriginBrowserRequest(request) {
  const fetchSite = request.headers["sec-fetch-site"];
  if (fetchSite !== undefined && fetchSite !== "same-origin") {
    return false;
  }
  const origin = request.headers.origin;
  if (origin === undefined) {
    return fetchSite === "same-origin" || process.env.NODE_ENV === "test";
  }
  return origin === `http://127.0.0.1:${port}` || origin === `http://localhost:${port}`;
}
