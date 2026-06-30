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
      const text = await response.text();
      if (text.length > MAX_RESPONSE_BYTES) {
        throw new Error("Relay response exceeds client size limit.");
      }
      if (!response.ok) {
        throw new Error(`Relay returned HTTP ${response.status}: ${text.slice(0, 160)}`);
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
      const text = await response.text();
      if (!response.ok) {
        throw new Error(`Relay health probe returned HTTP ${response.status}: ${text.slice(0, 160)}`);
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
    throw new Error(`Relay returned invalid JSON: ${trimmed.slice(0, 160)}`);
  }
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
