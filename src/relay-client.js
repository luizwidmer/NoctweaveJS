import { normalizeRelayEndpoint, relayEndpointURL } from "./endpoint.js";
import { relayRequests, validateRelayRequestEnvelopeV2 } from "./requests.js";
import {
  validateOpaqueRouteCommitResponseV2,
  validateOpaqueRouteCommitSubmissionV2,
  validateOpaqueRouteCreateSubmissionV2,
  validateOpaqueRouteEnqueueResponseV2,
  validateOpaqueRouteEnqueueSubmissionV2,
  validateOpaqueRouteRenewSubmissionV2,
  validateOpaqueRouteStateResponseV2,
  validateOpaqueRouteSyncResponseV2,
  validateOpaqueRouteSyncSubmissionV2,
  validateOpaqueRouteTeardownSubmissionV2
} from "./opaque-route-relay-v2.js";

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_TIMEOUT_MS = 10 * 60 * 1000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_000_000;
const DEFAULT_MAX_REQUEST_BYTES = 512 * 1024;
const ABSOLUTE_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const ABSOLUTE_MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const DEFAULT_TCP_PORT = 9339;

export const relayClientPolicyDefaults = Object.freeze({
  timeoutMs: DEFAULT_TIMEOUT_MS,
  defaultTCPPort: DEFAULT_TCP_PORT,
  maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES,
  maxRequestBytes: DEFAULT_MAX_REQUEST_BYTES
});

export const relayClientPolicyLimits = Object.freeze({
  maximumTimeoutMs: MAX_TIMEOUT_MS,
  maximumResponseBytes: ABSOLUTE_MAX_RESPONSE_BYTES,
  maximumRequestBytes: ABSOLUTE_MAX_REQUEST_BYTES
});

export function normalizeRelayClientPolicy(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Relay client policy must be an object.");
  }
  return Object.freeze({
    timeoutMs: normalizedTimeout(value.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    defaultTCPPort: normalizedPort(value.defaultTCPPort ?? DEFAULT_TCP_PORT),
    maxResponseBytes: normalizedByteBudget(
      value.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      "response",
      ABSOLUTE_MAX_RESPONSE_BYTES
    ),
    maxRequestBytes: normalizedByteBudget(
      value.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES,
      "request",
      ABSOLUTE_MAX_REQUEST_BYTES
    )
  });
}

export class NoctweaveRelayClient {
  constructor(endpoint, options = {}) {
    this.policy = normalizeRelayClientPolicy(options.policy);
    this.endpoint = normalizeRelayEndpoint(endpoint, { defaultPort: this.policy.defaultTCPPort });
    this.authToken = options.authToken ?? null;
    if (this.authToken !== null &&
        (typeof this.authToken !== "string" || new TextEncoder().encode(this.authToken).byteLength > 4096)) {
      throw new TypeError("Relay authentication token must be a string no larger than 4096 bytes.");
    }
    this.fetch = options.fetch ?? globalThis.fetch?.bind(globalThis);
    this.WebSocket = options.WebSocket ?? globalThis.WebSocket;
    this.protocolCrypto = options.crypto ?? null;
    this.timeoutMs = normalizedTimeout(options.timeoutMs ?? this.policy.timeoutMs);

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

  async createOpaqueRoute(request, options = {}) {
    const crypto = this.validationCrypto(options);
    const submission = await validateOpaqueRouteCreateSubmissionV2({
      crypto,
      submission: request
    });
    const response = requireOpaqueRouteResponse(
      await this.send(relayRequests.createOpaqueRoute(submission), options)
    );
    return validateOpaqueRouteStateResponseV2(response, submission.transition);
  }

  async renewOpaqueRoute(request, options = {}) {
    const crypto = this.validationCrypto(options);
    const submission = await validateOpaqueRouteRenewSubmissionV2({
      crypto,
      submission: request
    });
    const response = requireOpaqueRouteResponse(
      await this.send(relayRequests.renewOpaqueRoute(submission), options)
    );
    return validateOpaqueRouteStateResponseV2(response, submission.transition);
  }

  async teardownOpaqueRoute(request, options = {}) {
    const crypto = this.validationCrypto(options);
    const submission = await validateOpaqueRouteTeardownSubmissionV2({
      crypto,
      submission: request
    });
    const response = requireOpaqueRouteResponse(
      await this.send(relayRequests.teardownOpaqueRoute(submission), options)
    );
    return validateOpaqueRouteStateResponseV2(response, submission.transition);
  }

  async enqueueOpaqueRoute(request, options = {}) {
    const crypto = this.validationCrypto(options);
    const submission = await validateOpaqueRouteEnqueueSubmissionV2({
      crypto,
      submission: request
    });
    const response = requireOpaqueRouteResponse(
      await this.send(relayRequests.enqueueOpaqueRoute(submission), options)
    );
    return validateOpaqueRouteEnqueueResponseV2(response, submission.packet);
  }

  async syncOpaqueRoute(request, options = {}) {
    const crypto = this.validationCrypto(options);
    const submission = await validateOpaqueRouteSyncSubmissionV2({
      crypto,
      submission: request
    });
    const response = requireOpaqueRouteResponse(
      await this.send(relayRequests.syncOpaqueRoute(submission), options)
    );
    return validateOpaqueRouteSyncResponseV2({
      crypto,
      response,
      request: submission.request
    });
  }

  async commitOpaqueRoute(request, options = {}) {
    const crypto = this.validationCrypto(options);
    const submission = await validateOpaqueRouteCommitSubmissionV2({
      crypto,
      submission: request
    });
    const response = requireOpaqueRouteResponse(
      await this.send(relayRequests.commitOpaqueRoute(submission), options)
    );
    return validateOpaqueRouteCommitResponseV2(response, submission.request);
  }

  async send(request, options = {}) {
    const authenticated = validateRelayRequestEnvelopeV2(this.withAuthToken(request));
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
      const body = encodedRequest(request, this.policy.maxRequestBytes);
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
      const text = await boundedResponseText(response, this.policy.maxResponseBytes);
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
      const text = await boundedResponseText(response, this.policy.maxResponseBytes);
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
          socket.send(encodedRequest(request, this.policy.maxRequestBytes));
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
          const text = typeof event.data === "string"
            ? event.data
            : await blobLikeToText(event.data, this.policy.maxResponseBytes);
          if (new TextEncoder().encode(text).byteLength > this.policy.maxResponseBytes) {
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

  validationCrypto(options) {
    const crypto = options.crypto ?? this.protocolCrypto;
    if (typeof crypto?.sha256 !== "function" || typeof crypto?.hmacSha256 !== "function") {
      throw new TypeError("Opaque route operations require SHA-256 and HMAC-SHA-256 primitives.");
    }
    return crypto;
  }
}

function requireOpaqueRouteResponse(response) {
  if (response?.type === "error") {
    throw new Error("Relay rejected the opaque route operation.");
  }
  return response;
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

async function boundedResponseText(response, maximumBytes) {
  const contentLength = Number(response.headers?.get?.("content-length") ?? 0);
  if (Number.isFinite(contentLength) && contentLength > maximumBytes) {
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
      if (byteCount > maximumBytes) {
        await reader.cancel("Relay response exceeds client size limit.");
        throw new Error("Relay response exceeds client size limit.");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
  if (byteCount > maximumBytes) {
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

function normalizedPort(value) {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new TypeError("Relay client default TCP port must be between 1 and 65535.");
  }
  return port;
}

function normalizedByteBudget(value, label, absoluteMaximum) {
  const bytes = Number(value);
  if (!Number.isSafeInteger(bytes) || bytes < 1_024 || bytes > absoluteMaximum) {
    throw new TypeError(
      `Relay client ${label} budget must be between 1024 and ${absoluteMaximum} bytes.`
    );
  }
  return bytes;
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

async function blobLikeToText(data, maximumBytes = DEFAULT_MAX_RESPONSE_BYTES) {
  if (data == null) {
    return "";
  }
  if (typeof data.text === "function") {
    if (Number.isFinite(data.size) && data.size > maximumBytes) {
      throw new Error("Relay response exceeds client size limit.");
    }
    return data.text();
  }
  if (data instanceof ArrayBuffer) {
    if (data.byteLength > maximumBytes) {
      throw new Error("Relay response exceeds client size limit.");
    }
    return new TextDecoder().decode(data);
  }
  if (ArrayBuffer.isView(data)) {
    if (data.byteLength > maximumBytes) {
      throw new Error("Relay response exceeds client size limit.");
    }
    return new TextDecoder().decode(data);
  }
  return String(data);
}

function encodedRequest(request, maximumBytes) {
  const body = JSON.stringify(request);
  if (new TextEncoder().encode(body).byteLength > maximumBytes) {
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
