#!/usr/bin/env node
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRelayEndpoint, relayEndpointURL } from "../../src/endpoint.js";
import { NoctweaveGroupCompanion } from "./group-companion.js";

const root = normalize(join(fileURLToPath(new URL("../..", import.meta.url))));
const port = Number(process.env.PORT ?? 5173);
const maxBodyBytes = 1_000_000;
const proxyTimeoutMs = 10_000;
const rootPrefix = root.endsWith(sep) ? root : `${root}${sep}`;
const defaultClientDocument = process.env.NOCTWEAVE_CLIENT === "production"
  ? "/client/index.html"
  : "/examples/browser-client/index.html";
const defaultCLIPath = normalize(join(
  root,
  "..",
  ".build-caches",
  "core-cli",
  "debug",
  "NoctweaveCLI"
));
const groupCompanion = new NoctweaveGroupCompanion({
  cliPath: process.env.NOCTWEAVE_CLI_PATH ?? defaultCLIPath,
  statePath: normalize(join(root, ".local", "group-companion", "client-state.json")),
  plaintextForTesting: process.env.NOCTWEAVE_GROUP_COMPANION_PLAINTEXT === "1"
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
  const path = process.env.NOCTWEAVE_CLIENT === "production" ? "/client/" : "/examples/browser-client/";
  console.log(`NoctweaveJS client: http://127.0.0.1:${port}${path}`);
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
  const pathname = decodedPath === "/"
    ? defaultClientDocument
    : decodedPath.endsWith("/")
      ? `${decodedPath}index.html`
      : decodedPath;
  const filePath = normalize(join(root, pathname));
  if (filePath !== root && !filePath.startsWith(rootPrefix)) {
    writeResponse(response, 403, "Forbidden", "text/plain; charset=utf-8");
    return;
  }
  try {
    const bytes = await readFile(filePath);
    writeResponse(response, 200, bytes, mimeTypes[extname(filePath)] ?? "application/octet-stream");
  } catch {
    writeResponse(response, 404, "Not found", "text/plain; charset=utf-8");
  }
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

function writeResponse(response, status, body, contentType) {
  const headers = {
    "content-type": contentType,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' http: https: ws: wss:; img-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
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
