import {
  validateOpaqueRouteCommitSubmissionShapeV2,
  validateOpaqueRouteCreateSubmissionShapeV2,
  validateOpaqueRouteEnqueueSubmissionShapeV2,
  validateOpaqueRouteRenewSubmissionShapeV2,
  validateOpaqueRouteSyncSubmissionShapeV2,
  validateOpaqueRouteTeardownSubmissionShapeV2
} from "./opaque-route-relay-v2.js";
import {
  validateAppendRendezvousTransportV2Request,
  validateDeleteRendezvousTransportV2Request,
  validateRegisterRendezvousTransportV2Request,
  validateSyncRendezvousTransportV2Request
} from "./rendezvous-relay-v2.js";
import { requireExactRecord, requireRecord } from "./private-v2.js";
import { swiftUUID } from "./crypto/swift-canonical.js";

const relayErrorCodes = new Set([
  "authentication-required",
  "rate-limited",
  "invalid-request",
  "unavailable",
  "not-found",
  "conflict",
  "capacity",
  "internal-failure"
]);

const bindings = Object.freeze({
  health: Object.freeze({ module: "nw.core", version: 2, method: "health", body: null }),
  info: Object.freeze({ module: "nw.core", version: 2, method: "info", body: "relayInfo" }),
  createOpaqueRoute: Object.freeze({ module: "nw.opaque-route", version: 2, method: "create", body: "route" }),
  renewOpaqueRoute: Object.freeze({ module: "nw.opaque-route", version: 2, method: "renew", body: "route" }),
  teardownOpaqueRoute: Object.freeze({ module: "nw.opaque-route", version: 2, method: "teardown", body: "route" }),
  enqueueOpaqueRoute: Object.freeze({ module: "nw.opaque-route", version: 2, method: "append", body: "receipt" }),
  syncOpaqueRoute: Object.freeze({ module: "nw.opaque-route", version: 2, method: "sync", body: "batch" }),
  commitOpaqueRoute: Object.freeze({ module: "nw.opaque-route", version: 2, method: "commit", body: "commit" }),
  registerRendezvousTransportV2: Object.freeze({
    module: "nw.rendezvous-transport", version: 2, method: "register", body: null
  }),
  appendRendezvousTransportV2: Object.freeze({
    module: "nw.rendezvous-transport", version: 2, method: "append", body: null
  }),
  syncRendezvousTransportV2: Object.freeze({
    module: "nw.rendezvous-transport", version: 2, method: "sync", body: "batch"
  }),
  deleteRendezvousTransportV2: Object.freeze({
    module: "nw.rendezvous-transport", version: 2, method: "delete", body: null
  }),
  uploadAttachment: Object.freeze({ module: "nw.blobs", version: 1, method: "upload", body: "chunk" }),
  fetchAttachment: Object.freeze({ module: "nw.blobs", version: 1, method: "fetch", body: "chunk" })
});

export const relayRequests = Object.freeze({
  health(authToken) { return makeRequest(bindings.health, {}, authToken); },
  info(authToken) { return makeRequest(bindings.info, {}, authToken); },
  createOpaqueRoute(request, authToken) {
    return makeRequest(bindings.createOpaqueRoute, validateOpaqueRouteCreateSubmissionShapeV2(request), authToken);
  },
  renewOpaqueRoute(request, authToken) {
    return makeRequest(bindings.renewOpaqueRoute, validateOpaqueRouteRenewSubmissionShapeV2(request), authToken);
  },
  teardownOpaqueRoute(request, authToken) {
    return makeRequest(bindings.teardownOpaqueRoute, validateOpaqueRouteTeardownSubmissionShapeV2(request), authToken);
  },
  enqueueOpaqueRoute(request, authToken) {
    return makeRequest(bindings.enqueueOpaqueRoute, validateOpaqueRouteEnqueueSubmissionShapeV2(request), authToken);
  },
  syncOpaqueRoute(request, authToken) {
    return makeRequest(bindings.syncOpaqueRoute, validateOpaqueRouteSyncSubmissionShapeV2(request), authToken);
  },
  commitOpaqueRoute(request, authToken) {
    return makeRequest(bindings.commitOpaqueRoute, validateOpaqueRouteCommitSubmissionShapeV2(request), authToken);
  },
  registerRendezvousTransportV2(request, authToken) {
    return makeRequest(
      bindings.registerRendezvousTransportV2,
      validateRegisterRendezvousTransportV2Request(request, { at: new Date() }),
      authToken
    );
  },
  appendRendezvousTransportV2(request, authToken) {
    return makeRequest(
      bindings.appendRendezvousTransportV2,
      validateAppendRendezvousTransportV2Request(request),
      authToken
    );
  },
  syncRendezvousTransportV2(request, authToken) {
    return makeRequest(
      bindings.syncRendezvousTransportV2,
      validateSyncRendezvousTransportV2Request(request),
      authToken
    );
  },
  deleteRendezvousTransportV2(request, authToken) {
    return makeRequest(
      bindings.deleteRendezvousTransportV2,
      validateDeleteRendezvousTransportV2Request(request),
      authToken
    );
  },
  uploadAttachment(request, authToken) {
    requireRecord(request, "Attachment upload request");
    return makeRequest(bindings.uploadAttachment, {
      attachmentId: request.attachmentId,
      chunkIndex: request.chunkIndex,
      payload: request.payload,
      ttlSeconds: request.ttlSeconds ?? null
    }, authToken);
  },
  fetchAttachment(request, authToken) {
    requireRecord(request, "Attachment retrieval request");
    return makeRequest(bindings.fetchAttachment, request, authToken);
  }
});

export function validateRelayRequestEnvelopeV2(value) {
  requireExactRecord(
    value,
    ["requestID", "module", "version", "method", "body", "authToken"],
    [],
    "Relay request"
  );
  if (!canonicalUUID(value.requestID)) throw new TypeError("Relay requestID is invalid.");
  const binding = currentBinding(value.module, value.version, value.method);
  validateAuthToken(value.authToken);
  requireRecord(value.body, "Relay request body");
  validateRequestBody(binding, value.body);
  return value;
}

export function validateRelayResponseEnvelopeV2(value, request) {
  validateRelayRequestEnvelopeV2(request);
  requireExactRecord(
    value,
    ["requestID", "module", "version", "method", "status", "body", "error"],
    [],
    "Relay response"
  );
  if (value.requestID !== request.requestID || value.module !== request.module ||
      value.version !== request.version || value.method !== request.method) {
    throw new Error("Relay response does not correlate to its request.");
  }
  const binding = currentBinding(value.module, value.version, value.method);
  if (value.status === "success") {
    if (value.error !== null) throw new TypeError("Successful relay response error must be null.");
    requireRecord(value.body, "Relay success body");
    const expected = binding.body === null ? [] : [binding.body];
    requireExactRecord(value.body, expected, [], "Relay success body");
    return value.body;
  }
  if (value.status === "error") {
    if (value.body !== null) throw new TypeError("Error relay response body must be null.");
    requireExactRecord(value.error, ["code", "message", "retryable"], [], "Relay error");
    if (!relayErrorCodes.has(value.error.code) || typeof value.error.message !== "string" ||
        value.error.message.length === 0 || new TextEncoder().encode(value.error.message).byteLength > 512 ||
        typeof value.error.retryable !== "boolean") {
      throw new TypeError("Relay error body is invalid.");
    }
    const error = new Error("Relay rejected the request.");
    error.code = value.error.code;
    error.retryable = value.error.retryable;
    throw error;
  }
  throw new TypeError("Relay response status is invalid.");
}

function makeRequest(binding, body, authToken) {
  validateAuthToken(authToken ?? null);
  return validateRelayRequestEnvelopeV2({
    requestID: swiftUUID(),
    module: binding.module,
    version: binding.version,
    method: binding.method,
    body,
    authToken: authToken == null || authToken === "" ? null : authToken
  });
}

function currentBinding(module, version, method) {
  const binding = Object.values(bindings).find((candidate) =>
    candidate.module === module && candidate.version === version && candidate.method === method);
  if (!binding) throw new TypeError("Relay module, version, or method is unsupported.");
  return binding;
}

function validateRequestBody(binding, body) {
  switch (`${binding.module}/${binding.method}`) {
  case "nw.core/health":
  case "nw.core/info": requireExactRecord(body, [], [], "Core relay request body"); break;
  case "nw.opaque-route/create": validateOpaqueRouteCreateSubmissionShapeV2(body); break;
  case "nw.opaque-route/renew": validateOpaqueRouteRenewSubmissionShapeV2(body); break;
  case "nw.opaque-route/teardown": validateOpaqueRouteTeardownSubmissionShapeV2(body); break;
  case "nw.opaque-route/append": validateOpaqueRouteEnqueueSubmissionShapeV2(body); break;
  case "nw.opaque-route/sync": validateOpaqueRouteSyncSubmissionShapeV2(body); break;
  case "nw.opaque-route/commit": validateOpaqueRouteCommitSubmissionShapeV2(body); break;
  case "nw.rendezvous-transport/register":
    validateRegisterRendezvousTransportV2Request(body, { at: new Date() });
    break;
  case "nw.rendezvous-transport/append": validateAppendRendezvousTransportV2Request(body); break;
  case "nw.rendezvous-transport/sync": validateSyncRendezvousTransportV2Request(body); break;
  case "nw.rendezvous-transport/delete": validateDeleteRendezvousTransportV2Request(body); break;
  case "nw.blobs/upload":
    requireExactRecord(body, ["attachmentId", "chunkIndex", "payload", "ttlSeconds"], [],
      "Attachment upload body");
    validateAttachmentCoordinates(body);
    requireRecord(body.payload, "Encrypted attachment payload");
    if (body.ttlSeconds !== null && (!Number.isSafeInteger(body.ttlSeconds) || body.ttlSeconds < 1)) {
      throw new TypeError("Attachment TTL is invalid.");
    }
    break;
  case "nw.blobs/fetch":
    requireExactRecord(body, ["attachmentId", "chunkIndex"], [], "Attachment fetch body");
    validateAttachmentCoordinates(body);
    break;
  default: throw new TypeError("Relay request binding has no body validator.");
  }
}

function validateAttachmentCoordinates(body) {
  if (!canonicalUUID(body.attachmentId) || !Number.isSafeInteger(body.chunkIndex) || body.chunkIndex < 0) {
    throw new TypeError("Attachment coordinates are invalid.");
  }
}

function validateAuthToken(value) {
  if (value !== null && (typeof value !== "string" || value.length === 0 ||
      new TextEncoder().encode(value).byteLength > 4_096)) {
    throw new TypeError("Relay authentication token must be null or 1 to 4096 UTF-8 bytes.");
  }
}

function canonicalUUID(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value);
}
