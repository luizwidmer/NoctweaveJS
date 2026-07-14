import { parseRelayEndpoint, relayEndpointURL } from "../../src/endpoint.js";

const MAX_ENDPOINT_BYTES = 2 * 1024;
const MAX_REQUEST_BYTES = 512 * 1024;
const MAX_RESPONSE_BYTES = 1_000_000;
const DEFAULT_TIMEOUT_MS = 15_000;

export async function proxyRelayRequest(input, options = {}) {
  const request = validatedRequest(input);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("Desktop relay transport is unavailable.");
  }

  const parsed = parseRelayEndpoint(request.endpoint);
  if (parsed.transport !== "http") {
    throw new Error("Desktop relay proxy accepts only HTTP or HTTPS endpoints.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const response = await fetchImpl(relayEndpointURL(parsed, request.route === "health" ? "/health" : "/relay"), {
      method: request.route === "health" ? "GET" : "POST",
      headers: request.route === "health"
        ? { accept: "application/json, text/plain;q=0.9" }
        : { accept: "application/json", "content-type": "application/json" },
      body: request.route === "relay" ? request.body : undefined,
      redirect: "error",
      signal: controller.signal
    });
    const body = await boundedResponseText(response, MAX_RESPONSE_BYTES);
    return {
      status: response.status,
      contentType: boundedContentType(response.headers.get("content-type")),
      body
    };
  } finally {
    clearTimeout(timeout);
  }
}

function validatedRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Desktop relay request must be an object.");
  }
  const endpoint = input.endpoint;
  if (typeof endpoint !== "string" || endpoint.trim() === "" || byteLength(endpoint) > MAX_ENDPOINT_BYTES) {
    throw new TypeError("Desktop relay endpoint is invalid.");
  }
  if (input.route !== "health" && input.route !== "relay") {
    throw new TypeError("Desktop relay route is invalid.");
  }
  if (input.route === "relay") {
    if (typeof input.body !== "string") {
      throw new TypeError("Desktop relay request body must be text.");
    }
    if (byteLength(input.body) > MAX_REQUEST_BYTES) {
      throw new Error("Desktop relay request exceeds the size limit.");
    }
  }
  return { endpoint: endpoint.trim(), route: input.route, body: input.body };
}

async function boundedResponseText(response, maximumBytes) {
  const declaredLength = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error("Desktop relay response exceeds the size limit.");
  }
  if (!response.body?.getReader) {
    return "";
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let output = "";
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        output += decoder.decode();
        return output;
      }
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel("Response too large");
        throw new Error("Desktop relay response exceeds the size limit.");
      }
      output += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

function boundedContentType(value) {
  if (typeof value !== "string" || value.length > 256) {
    return "application/json; charset=utf-8";
  }
  return value;
}

function byteLength(value) {
  return new TextEncoder().encode(value).byteLength;
}
