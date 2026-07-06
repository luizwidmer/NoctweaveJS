import { parseRelayEndpoint, relayEndpointURL } from "./endpoint.js";
import { relayRequests } from "./requests.js";

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_RESPONSE_BYTES = 1_000_000;

export class NoctweaveRelayClient {
  constructor(endpoint, options = {}) {
    this.endpoint = typeof endpoint === "string" ? parseRelayEndpoint(endpoint) : endpoint;
    this.authToken = options.authToken ?? null;
    this.fetch = options.fetch ?? globalThis.fetch?.bind(globalThis);
    this.WebSocket = options.WebSocket ?? globalThis.WebSocket;
    this.timeoutMs = Number(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

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
    const timeoutMs = Number(options.timeoutMs ?? this.timeoutMs);

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
      const response = await this.fetch(relayEndpointURL(this.endpoint, "/relay"), {
        method: "POST",
        headers: {
          "accept": "application/json",
          "content-type": "application/json"
        },
        body: JSON.stringify(request),
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
      const timeout = setTimeout(() => {
        tryClose(socket);
        reject(new Error("Relay WebSocket request timed out."));
      }, timeoutMs);

      socket.onopen = () => socket.send(JSON.stringify(request));
      socket.onerror = () => {
        clearTimeout(timeout);
        reject(new Error("Relay WebSocket connection failed."));
      };
      socket.onmessage = async (event) => {
        clearTimeout(timeout);
        try {
          const text = typeof event.data === "string" ? event.data : await blobLikeToText(event.data);
          if (text.length > MAX_RESPONSE_BYTES) {
            throw new Error("Relay response exceeds client size limit.");
          }
          resolve(decodeRelayResponse(text, request.type));
        } catch (error) {
          reject(error);
        } finally {
          tryClose(socket);
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
  if (contentLength > MAX_RESPONSE_BYTES) {
    throw new Error("Relay response exceeds client size limit.");
  }
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) {
    throw new Error("Relay response exceeds client size limit.");
  }
  return text;
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
    return data.text();
  }
  if (data instanceof ArrayBuffer) {
    return new TextDecoder().decode(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new TextDecoder().decode(data);
  }
  return String(data);
}

function tryClose(socket) {
  try {
    socket.close?.();
  } catch {
    // Ignore close failures.
  }
}
