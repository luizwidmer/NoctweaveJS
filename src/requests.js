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
import { validateProtocolModuleCapability } from "./architecture-v2.js";
import { normalizeRelayEndpoint } from "./endpoint.js";
import {
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireRecord
} from "./private-v2.js";
import { swiftUUID } from "./crypto/swift-canonical.js";

const encryptedAttachmentPayloadLimits = Object.freeze({
  nonceBytes: 12,
  tagBytes: 16,
  maximumEncodedBytes: 128 * 1_024
});

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
    validateResponseBody(binding, value.body, request);
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

function validateResponseBody(binding, body, request) {
  switch (`${binding.module}/${binding.method}`) {
  case "nw.core/health": break;
  case "nw.core/info": validateRelayInfoV2(body.relayInfo); break;
  case "nw.blobs/upload":
  case "nw.blobs/fetch": validateAttachmentChunkResponse(body.chunk, request.body); break;
  // These response families require the request and cryptographic context held
  // by their high-level client methods, which perform the complete validation.
  case "nw.opaque-route/create":
  case "nw.opaque-route/renew":
  case "nw.opaque-route/teardown":
  case "nw.opaque-route/append":
  case "nw.opaque-route/sync":
  case "nw.opaque-route/commit":
  case "nw.rendezvous-transport/register":
  case "nw.rendezvous-transport/append":
  case "nw.rendezvous-transport/sync":
  case "nw.rendezvous-transport/delete": break;
  default: throw new TypeError("Relay response binding has no body validator.");
  }
}

function validateRelayInfoV2(value) {
  requireExactRecord(
    value,
    [
      "kind",
      "federation",
      "temporalBucketSeconds",
      "temporalBucketScheduleSeconds",
      "attachmentDefaultTTLSeconds",
      "attachmentMaxTTLSeconds",
      "attachmentsEnabled",
      "attachmentStorageBackend",
      "hiddenRetrieval",
      "onionTransport",
      "mixnetTransport",
      "wakeSupport",
      "relayName",
      "operatorNote",
      "softwareVersion",
      "protocolCapabilities",
      "requiresPassword",
      "tlsEnabled",
      "transport",
      "federationCoordinatorEndpoints",
      "coordinatorReportedRelayCount",
      "coordinatorRegistrationAuthRequired",
      "curatedStrictPolicyEnabled",
      "curatedCoordinatorQuorum",
      "curatedRequireSignedDirectory",
      "federationDirectoryPublicKey",
      "knownOpenPeers",
      "openFederationDiscovery",
      "advertisedAt"
    ],
    [],
    "Relay info"
  );
  if (!["standard", "discovery", "bridge", "privateRelay", "coordinator"].includes(value.kind)) {
    throw new TypeError("Relay kind is invalid.");
  }
  validateFederationDescriptor(value.federation);
  requireInteger(value.temporalBucketSeconds, "Relay temporal bucket", 0, 86_400);
  requireCanonicalTimestamp(value.advertisedAt, "Relay advertisedAt");

  if (value.temporalBucketScheduleSeconds !== null) {
    validateCanonicalIntegerList(
      value.temporalBucketScheduleSeconds,
      "Relay temporal bucket schedule",
      1,
      16,
      1,
      86_400
    );
  }
  if (value.attachmentDefaultTTLSeconds !== null) {
    requireInteger(value.attachmentDefaultTTLSeconds, "Attachment default TTL", 60, 2_592_000);
  }
  if (value.attachmentMaxTTLSeconds !== null) {
    requireInteger(value.attachmentMaxTTLSeconds, "Attachment maximum TTL", 60, 2_592_000);
    if (value.attachmentDefaultTTLSeconds !== null &&
        value.attachmentMaxTTLSeconds < value.attachmentDefaultTTLSeconds) {
      throw new TypeError("Attachment maximum TTL must cover the default TTL.");
    }
  }
  validateOptionalBooleanFields(value, [
    "attachmentsEnabled",
    "requiresPassword",
    "tlsEnabled",
    "coordinatorRegistrationAuthRequired",
    "curatedStrictPolicyEnabled",
    "curatedRequireSignedDirectory"
  ]);
  for (const field of ["attachmentStorageBackend", "relayName", "operatorNote", "softwareVersion"]) {
    if (value[field] !== null) validateBoundedText(value[field], `Relay ${field}`, 1_024);
  }
  if (value.hiddenRetrieval !== null) validateHiddenRetrievalSupport(value.hiddenRetrieval);
  if (value.onionTransport !== null) validateOnionTransportSupport(value.onionTransport);
  if (value.mixnetTransport !== null) validateMixnetTransportSupport(value.mixnetTransport);
  if (value.wakeSupport !== null) validateWakeSupport(value.wakeSupport);
  if (value.protocolCapabilities !== null) {
    validateRelayCapabilityManifestV2(value.protocolCapabilities);
  }
  if (value.transport !== null && !["tcp", "http", "websocket"].includes(value.transport)) {
    throw new TypeError("Relay transport is invalid.");
  }
  if (value.federationCoordinatorEndpoints !== null) {
    validateEndpointList(value.federationCoordinatorEndpoints, "Federation coordinator endpoints", 16);
  }
  if (value.coordinatorReportedRelayCount !== null) {
    requireInteger(value.coordinatorReportedRelayCount, "Coordinator relay count", 0, 1_000_000);
  }
  if (value.curatedCoordinatorQuorum !== null) {
    requireInteger(value.curatedCoordinatorQuorum, "Curated coordinator quorum", 1, 16);
  }
  if (value.federationDirectoryPublicKey !== null) {
    const key = requireBase64(value.federationDirectoryPublicKey, undefined, "Federation directory public key");
    if (key.byteLength > 4_096) throw new TypeError("Federation directory public key exceeds its bound.");
  }
  if (value.knownOpenPeers !== null) {
    validateEndpointList(value.knownOpenPeers, "Known open peers", 128);
  }
  if (value.openFederationDiscovery !== null) {
    validateOpenFederationDiscoverySupport(value.openFederationDiscovery);
  }
  return value;
}

function validateFederationDescriptor(value) {
  requireExactRecord(value, ["mode", "name", "description"], [], "Federation descriptor");
  if (!["solo", "manual", "curated", "open"].includes(value.mode)) {
    throw new TypeError("Federation mode is invalid.");
  }
  if (value.name !== null) validateBoundedText(value.name, "Federation name", 1_024);
  if (value.description !== null) {
    validateBoundedText(value.description, "Federation description", 1_024);
  }
}

function validateRelayCapabilityManifestV2(value) {
  requireExactRecord(value, ["architectureVersion", "modules"], [], "Relay capability manifest");
  if (value.architectureVersion !== 2 || !Array.isArray(value.modules) ||
      value.modules.length === 0 || value.modules.length > 64) {
    throw new TypeError("Relay capability manifest is outside its protocol bounds.");
  }
  const modules = value.modules.map(validateProtocolModuleCapability);
  const moduleNames = modules.map(({ module }) => module);
  if (moduleNames.some((module, index) => index > 0 && module <= moduleNames[index - 1]) ||
      !modules.some(({ module, versions }) => module === "nw.core" && versions.includes(2))) {
    throw new TypeError("Relay capability modules must be unique, sorted, and include nw.core v2.");
  }
}

function validateHiddenRetrievalSupport(value) {
  requireExactRecord(
    value,
    ["mode", "defaultCoverSetSize", "maxCoverSetSize", "replicatedXorPIRReplicas"],
    [],
    "Hidden retrieval support"
  );
  if (!["coverQuery", "replicatedXorPIR"].includes(value.mode)) {
    throw new TypeError("Hidden retrieval mode is invalid.");
  }
  requireInteger(value.defaultCoverSetSize, "Default cover set size", 2, 4_096);
  requireInteger(value.maxCoverSetSize, "Maximum cover set size", value.defaultCoverSetSize, 4_096);
  if (value.replicatedXorPIRReplicas !== null) {
    if (!Array.isArray(value.replicatedXorPIRReplicas) ||
        value.replicatedXorPIRReplicas.length === 0 ||
        value.replicatedXorPIRReplicas.length > 256) {
      throw new TypeError("Hidden retrieval replicas exceed their protocol bounds.");
    }
    const identities = new Set();
    const operators = new Set();
    const endpoints = new Set();
    for (const replica of value.replicatedXorPIRReplicas) {
      requireExactRecord(replica, ["replicaId", "operatorId", "endpoint"], [], "Hidden retrieval replica");
      validateBoundedText(replica.replicaId, "Hidden retrieval replica ID", 1_024);
      validateBoundedText(replica.operatorId, "Hidden retrieval operator ID", 1_024);
      const endpointKey = validateRelayEndpoint(replica.endpoint);
      const identity = replica.replicaId.toLowerCase();
      const operator = replica.operatorId.toLowerCase();
      if (identities.has(identity) || operators.has(operator) || endpoints.has(endpointKey)) {
        throw new TypeError("Hidden retrieval replicas must be distinct.");
      }
      identities.add(identity);
      operators.add(operator);
      endpoints.add(endpointKey);
    }
  }
  if (value.mode === "replicatedXorPIR" &&
      (value.replicatedXorPIRReplicas === null || value.replicatedXorPIRReplicas.length < 2)) {
    throw new TypeError("Replicated XOR-PIR requires at least two replicas.");
  }
}

function validateOnionTransportSupport(value) {
  requireExactRecord(
    value,
    ["enabled", "maxHops", "requiresFixedSizePackets"],
    [],
    "Onion transport support"
  );
  validateBoolean(value.enabled, "Onion transport enabled");
  requireInteger(value.maxHops, "Onion transport maxHops", 1, 8);
  validateBoolean(value.requiresFixedSizePackets, "Onion fixed-size packet requirement");
}

function validateMixnetTransportSupport(value) {
  requireExactRecord(
    value,
    ["enabled", "batchIntervalSeconds", "minBatchSize", "coverPacketsPerBatch", "maxDelaySeconds"],
    [],
    "Mixnet transport support"
  );
  validateBoolean(value.enabled, "Mixnet transport enabled");
  requireInteger(value.batchIntervalSeconds, "Mixnet batch interval", 5, 3_600);
  requireInteger(value.minBatchSize, "Mixnet minimum batch size", 1, 256);
  requireInteger(value.coverPacketsPerBatch, "Mixnet cover packets", 0, 256);
  requireInteger(value.maxDelaySeconds, "Mixnet maximum delay", 0, 3_600);
}

function validateWakeSupport(value) {
  requireExactRecord(
    value,
    ["mode", "minPollIntervalSeconds", "maxPollIntervalSeconds", "jitterPermille", "longPollTimeoutSeconds"],
    [],
    "Wake support"
  );
  if (!["pullOnly", "longPoll"].includes(value.mode)) throw new TypeError("Wake mode is invalid.");
  requireInteger(value.minPollIntervalSeconds, "Wake minimum poll interval", 5, 86_400);
  requireInteger(
    value.maxPollIntervalSeconds,
    "Wake maximum poll interval",
    value.minPollIntervalSeconds,
    86_400
  );
  requireInteger(value.jitterPermille, "Wake jitter", 0, 1_000);
  if (value.mode === "pullOnly") {
    if (value.longPollTimeoutSeconds !== null) throw new TypeError("Pull-only wake timeout must be null.");
  } else {
    requireInteger(
      value.longPollTimeoutSeconds,
      "Wake long-poll timeout",
      5,
      value.maxPollIntervalSeconds
    );
  }
}

function validateOpenFederationDiscoverySupport(value) {
  requireExactRecord(
    value,
    [
      "dhtNodeEnabled",
      "peerExchangeEnabled",
      "peerExchangeLimit",
      "requirePublicEndpoint",
      "maxDHTRecords",
      "maxDHTRecordsPerHost",
      "maxDHTQueryRecords"
    ],
    [],
    "Open federation discovery support"
  );
  validateBoolean(value.dhtNodeEnabled, "DHT node enabled");
  validateBoolean(value.peerExchangeEnabled, "Peer exchange enabled");
  validateBoolean(value.requirePublicEndpoint, "Public endpoint requirement");
  requireInteger(value.peerExchangeLimit, "Peer exchange limit", 0, 128);
  requireInteger(value.maxDHTRecords, "Maximum DHT records", 1, 256);
  requireInteger(value.maxDHTRecordsPerHost, "Maximum DHT records per host", 1, 16);
  if (value.maxDHTRecordsPerHost > value.maxDHTRecords) {
    throw new TypeError("DHT records per host cannot exceed the total record bound.");
  }
  requireInteger(value.maxDHTQueryRecords, "Maximum DHT query records", 1, 512);
}

function validateEndpointList(value, label, maximum) {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new TypeError(`${label} exceed their protocol bounds.`);
  }
  const endpointKeys = value.map(validateRelayEndpoint);
  if (new Set(endpointKeys).size !== endpointKeys.length) {
    throw new TypeError(`${label} must be unique.`);
  }
}

function validateRelayEndpoint(value) {
  requireExactRecord(
    value,
    [
      "host",
      "port",
      "useTLS",
      "transport",
      "tlsCertificateFingerprintSHA256",
      "directorySigningPublicKey"
    ],
    [],
    "Relay endpoint"
  );
  const normalized = normalizeRelayEndpoint(value);
  validateBoundedText(normalized.host, "Relay endpoint host", 255);
  if (value.tlsCertificateFingerprintSHA256 !== null) {
    requireBase64(value.tlsCertificateFingerprintSHA256, 32, "TLS certificate fingerprint");
  }
  if (value.directorySigningPublicKey !== null) {
    const key = requireBase64(value.directorySigningPublicKey, undefined, "Directory signing public key");
    if (key.byteLength > 4_096) throw new TypeError("Directory signing public key exceeds its bound.");
  }
  return `${normalized.host.toLowerCase()}\0${normalized.port}\0${normalized.useTLS}\0${normalized.transport}`;
}

function validateAttachmentChunkResponse(value, requestBody) {
  requireExactRecord(value, ["attachmentId", "chunkIndex", "payload"], [], "Attachment chunk");
  validateAttachmentCoordinates(value);
  validateEncryptedAttachmentPayload(value.payload);
  if (value.attachmentId.toLowerCase() !== requestBody.attachmentId.toLowerCase() ||
      value.chunkIndex !== requestBody.chunkIndex) {
    throw new TypeError("Attachment response does not correlate to its request coordinates.");
  }
}

function validateCanonicalIntegerList(value, label, minimumCount, maximumCount, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimumCount || value.length > maximumCount) {
    throw new TypeError(`${label} exceeds its protocol bounds.`);
  }
  const normalized = value.map((entry) => requireInteger(entry, label, minimum, maximum));
  if (new Set(normalized).size !== normalized.length ||
      normalized.some((entry, index) => index > 0 && entry <= normalized[index - 1])) {
    throw new TypeError(`${label} must be unique and sorted.`);
  }
}

function validateOptionalBooleanFields(value, fields) {
  for (const field of fields) {
    if (value[field] !== null) validateBoolean(value[field], `Relay ${field}`);
  }
}

function validateBoolean(value, label) {
  if (typeof value !== "boolean") throw new TypeError(`${label} must be a boolean.`);
}

function validateBoundedText(value, label, maximumBytes) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value ||
      new TextEncoder().encode(value).byteLength > maximumBytes || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new TypeError(`${label} is outside its protocol bounds.`);
  }
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
    validateEncryptedAttachmentPayload(body.payload);
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

function validateEncryptedAttachmentPayload(value) {
  requireExactRecord(value, ["nonce", "ciphertext", "tag"], [], "Encrypted attachment payload");
  const maximumCiphertextBytes = encryptedAttachmentPayloadLimits.maximumEncodedBytes -
    encryptedAttachmentPayloadLimits.nonceBytes - encryptedAttachmentPayloadLimits.tagBytes;
  const maximumCiphertextBase64Bytes = 4 * Math.ceil(maximumCiphertextBytes / 3);
  if (typeof value.ciphertext !== "string" || value.ciphertext.length > maximumCiphertextBase64Bytes) {
    throw new TypeError("Encrypted attachment ciphertext exceeds the protocol size limit.");
  }
  const nonce = requireBase64(
    value.nonce,
    encryptedAttachmentPayloadLimits.nonceBytes,
    "Encrypted attachment nonce"
  );
  const ciphertext = requireBase64(value.ciphertext, undefined, "Encrypted attachment ciphertext");
  const tag = requireBase64(
    value.tag,
    encryptedAttachmentPayloadLimits.tagBytes,
    "Encrypted attachment tag"
  );
  if (ciphertext.byteLength === 0 ||
      nonce.byteLength + ciphertext.byteLength + tag.byteLength >
        encryptedAttachmentPayloadLimits.maximumEncodedBytes) {
    throw new TypeError("Encrypted attachment payload has invalid cryptographic field lengths.");
  }
  return value;
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
