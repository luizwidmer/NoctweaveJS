#!/usr/bin/env node
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = normalize(join(fileURLToPath(new URL("../..", import.meta.url))));
const port = Number(process.env.PORT ?? 5173);

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8"
};

const server = createServer(async (request, response) => {
  try {
    if (request.url?.startsWith("/proxy/")) {
      await proxyRelay(request, response);
      return;
    }
    await serveStatic(request, response);
  } catch (error) {
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end(error instanceof Error ? error.stack : String(error));
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`NoctweaveJS browser client: http://127.0.0.1:${port}/examples/browser-client/`);
});

async function proxyRelay(request, response) {
  const endpoint = request.headers["x-relay-endpoint"];
  if (typeof endpoint !== "string" || endpoint.trim() === "") {
    response.writeHead(400, { "content-type": "application/json" });
    response.end(JSON.stringify({ type: "error", error: "Missing x-relay-endpoint header" }));
    return;
  }

  const path = request.url === "/proxy/health" ? "/health" : "/relay";
  const target = new URL(path, endpoint.endsWith("/") ? endpoint : `${endpoint}/`);
  const body = request.method === "POST" ? await readBody(request) : undefined;
  const relayResponse = await fetch(target, {
    method: request.method,
    headers: {
      "accept": request.headers.accept ?? "application/json",
      "content-type": request.headers["content-type"] ?? "application/json"
    },
    body
  });
  const text = await relayResponse.text();
  response.writeHead(relayResponse.status, {
    "content-type": relayResponse.headers.get("content-type") ?? "application/json; charset=utf-8"
  });
  response.end(text);
}

async function serveStatic(request, response) {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  const decodedPath = decodeURIComponent(url.pathname);
  const pathname = decodedPath === "/"
    ? "/examples/browser-client/index.html"
    : decodedPath.endsWith("/")
      ? `${decodedPath}index.html`
      : decodedPath;
  const filePath = normalize(join(root, pathname));
  if (!filePath.startsWith(root)) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }
  try {
    const bytes = await readFile(filePath);
    response.writeHead(200, { "content-type": mimeTypes[extname(filePath)] ?? "application/octet-stream" });
    response.end(bytes);
  } catch {
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Request body too large"));
      }
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}
