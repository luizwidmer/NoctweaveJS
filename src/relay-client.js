import { normalizeRelayEndpoint, relayEndpointURL } from "./endpoint.js";
import { relayRequests } from "./requests.js";

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_RESPONSE_BYTES = 1_000_000;
const MAX_REQUEST_BYTES = 512 * 1024;

export class NoctweaveRelayClient {
  constructor(endpoint, options = {}) {
    this.endpoint = normalizeRelayEndpoint(endpoint);
    this.authToken = options.authToken ?? null;
    if (this.authToken !== null &&
        (typeof this.authToken !== "string" || new TextEncoder().encode(this.authToken).byteLength > 4096)) {
      throw new TypeError("Relay authentication token must be a string no larger than 4096 bytes.");
    }
    this.fetch = options.fetch ?? globalThis.fetch?.bind(globalThis);
    this.WebSocket = options.WebSocket ?? globalThis.WebSocket;
    this.timeoutMs = normalizedTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    if (!this.fetch) {
      throw new Error("fetch is not available. Pass a fetch implementation in options.");
    }
  }

  async health(options = {}) {
    return this.send(relayRequests.health(), options);
  }

  async info(options = {}) {
    return this.send(relayRequests.info(), options);
  }

  async send(request, options = {}) {
    const authenticated = this.withAuthToken(request);
    const timeoutMs = normalizedTimeout(options.timeoutMs ?? this.timeoutMs);

    if (this.endpoint.transport === "websocket") {
      return this.sendWebSocket(authenticated, timeoutMs);
    }
    if (this.endpoint.transport === "tcp") {
      throw new Error("Browser JavaScript clients support HTTP/HTTPS and WebSocket/WSS relay endpoints, not raw TCP.");
    }
    return this.sendHTTP(authenticated, timeoutMs);
  }

  async sendHTTP(request, timeoutMs) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const body = encodedRequest(request);
      const response = await this.fetch(relayEndpointURL(this.endpoint, "/relay"), {
        method: "POST",
        headers: {
          "accept": "application/json",
          "content-type": "application/json"
        },
        body,
        redirect: "error",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        cache: "no-store",
        signal: controller.signal
      });
      const text = await boundedResponseText(response);
      if (!response.ok) {
        throw new Error(redactedHTTPError("Relay returned", response.status, text));
      }
      return decodeRelayResponse(text, request.type);
    } catch (error) {
      if (request.type === "health") {
        return this.sendHTTPHealthProbe(timeoutMs);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  async sendHTTPHealthProbe(timeoutMs) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await this.fetch(relayEndpointURL(this.endpoint, "/health"), {
        method: "GET",
        headers: { "accept": "application/json, text/plain;q=0.9" },
        redirect: "error",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        cache: "no-store",
        signal: controller.signal
      });
      const text = await boundedResponseText(response);
      if (!response.ok) {
        throw new Error(redactedHTTPError("Relay health probe returned", response.status, text));
      }
      return decodeRelayResponse(text, "health");
    } finally {
      clearTimeout(timeout);
    }
  }

  sendWebSocket(request, timeoutMs) {
    if (!this.WebSocket) {
      throw new Error("WebSocket is not available. Pass a WebSocket implementation in options.");
    }

    return new Promise((resolve, reject) => {
      const socket = new this.WebSocket(relayEndpointURL(this.endpoint, "/relay"));
      let settled = false;
      const finish = (operation, value) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        tryClose(socket);
        operation(value);
      };
      const timeout = setTimeout(() => {
        finish(reject, new Error("Relay WebSocket request timed out."));
      }, timeoutMs);

      socket.onopen = () => {
        try {
          socket.send(encodedRequest(request));
        } catch (error) {
          finish(reject, error);
        }
      };
      socket.onerror = () => {
        finish(reject, new Error("Relay WebSocket connection failed."));
      };
      socket.onclose = () => finish(reject, new Error("Relay WebSocket closed before returning a response."));
      socket.onmessage = async (event) => {
        try {
          const text = typeof event.data === "string" ? event.data : await blobLikeToText(event.data);
          if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
            throw new Error("Relay response exceeds client size limit.");
          }
          finish(resolve, decodeRelayResponse(text, request.type));
        } catch (error) {
          finish(reject, error);
        }
      };
    });
  }

  withAuthToken(request) {
    if (request.authToken || !this.authToken) {
      return request;
    }
    return { ...request, authToken: this.authToken };
  }
}

function decodeRelayResponse(text, requestType) {
  const trimmed = text.trim();
  if (trimmed === "" && requestType === "health") {
    return { type: "ok" };
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    const lowered = trimmed.toLowerCase();
    if (requestType === "health" && ["ok", "healthy", "up", "\"ok\""].includes(lowered)) {
      return { type: "ok" };
    }
    throw new Error(`Relay returned invalid JSON: ${responseClassification(trimmed)}`);
  }
}

async function boundedResponseText(response) {
  const contentLength = Number(response.headers?.get?.("content-length") ?? 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
    throw new Error("Relay response exceeds client size limit.");
  }
  if (!response.body?.getReader) {
    throw new Error("Fetch implementation must expose a streaming response body for bounded relay reads.");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let byteCount = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        text += decoder.decode();
        break;
      }
      byteCount += value.byteLength;
      if (byteCount > MAX_RESPONSE_BYTES) {
        await reader.cancel("Relay response exceeds client size limit.");
        throw new Error("Relay response exceeds client size limit.");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
  if (byteCount > MAX_RESPONSE_BYTES) {
    throw new Error("Relay response exceeds client size limit.");
  }
  return text;
}

function normalizedTimeout(value) {
  const timeout = Number(value);
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > MAX_TIMEOUT_MS) {
    throw new TypeError(`Relay timeout must be between 1 and ${MAX_TIMEOUT_MS} milliseconds.`);
  }
  return Math.ceil(timeout);
}

function redactedHTTPError(prefix, status, text) {
  return `${prefix} HTTP ${status}: ${responseClassification(text)}`;
}

function responseClassification(text) {
  const byteCount = new TextEncoder().encode(text).byteLength;
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return "empty response";
  }
  if (looksLikeHTML(trimmed)) {
    return `html response (${byteCount} bytes)`;
  }
  if (looksLikeJSON(trimmed)) {
    return `json response (${byteCount} bytes)`;
  }
  return `non-json response (${byteCount} bytes)`;
}

function looksLikeHTML(text) {
  return /^<!doctype\s+html/i.test(text) || /^<html[\s>]/i.test(text);
}

function looksLikeJSON(text) {
  return /^[\[{]/.test(text);
}

async function blobLikeToText(data) {
  if (data == null) {
    return "";
  }
  if (typeof data.text === "function") {
    if (Number.isFinite(data.size) && data.size > MAX_RESPONSE_BYTES) {
      throw new Error("Relay response exceeds client size limit.");
    }
    return data.text();
  }
  if (data instanceof ArrayBuffer) {
    if (data.byteLength > MAX_RESPONSE_BYTES) {
      throw new Error("Relay response exceeds client size limit.");
    }
    return new TextDecoder().decode(data);
  }
  if (ArrayBuffer.isView(data)) {
    if (data.byteLength > MAX_RESPONSE_BYTES) {
      throw new Error("Relay response exceeds client size limit.");
    }
    return new TextDecoder().decode(data);
  }
  return String(data);
}

function encodedRequest(request) {
  const body = JSON.stringify(request);
  if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BYTES) {
    throw new Error("Relay request exceeds client size limit.");
  }
  return body;
}

function tryClose(socket) {
  try {
    socket.close?.();
  } catch {
    // Ignore close failures.
  }
}
