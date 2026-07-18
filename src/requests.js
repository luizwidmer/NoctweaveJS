import {
  validateOpaqueRouteCommitResponseShapeV2,
  validateOpaqueRouteCommitSubmissionShapeV2,
  validateOpaqueRouteCreateSubmissionShapeV2,
  validateOpaqueRouteEnqueueResponseShapeV2,
  validateOpaqueRouteEnqueueSubmissionShapeV2,
  validateOpaqueRouteRenewSubmissionShapeV2,
  validateOpaqueRouteSyncResponseShapeV2,
  validateOpaqueRouteSyncSubmissionShapeV2,
  validateOpaqueRouteTeardownSubmissionShapeV2
} from "./opaque-route-relay-v2.js";
import { validateOpaqueReceiveRouteV2 } from "./opaque-route-v2.js";
import {
  validateAppendRendezvousTransportV2Request,
  validateDeleteRendezvousTransportV2Request,
  validateRegisterRendezvousTransportV2Request,
  validateRendezvousRelaySyncBatchV2,
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
import { canonicalJson, swiftUUID } from "./crypto/swift-canonical.js";

const encryptedAttachmentPayloadLimits = Object.freeze({
  nonceBytes: 12,
  tagBytes: 16,
  maximumEncodedBytes: 128 * 1_024,
  maximumChunkCount: 512
});
const mlDsa65PublicKeyBytes = 1_952;
const mlDsa65SignatureBytes = 3_309;
const maximumFederationNodes = 10_000;

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
  fetchAttachment: Object.freeze({ module: "nw.blobs", version: 1, method: "fetch", body: "chunk" }),
  registerFederationNode: Object.freeze({
    module: "nw.federation", version: 1, method: "register",
    body: Object.freeze(["nodes", "snapshot"])
  }),
  listFederationNodes: Object.freeze({
    module: "nw.federation", version: 1, method: "list",
    body: Object.freeze(["nodes", "snapshot"])
  })
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
    requireExactRecord(
      request,
      ["attachmentId", "chunkIndex", "payload"],
      ["ttlSeconds"],
      "Attachment upload request"
    );
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
  },
  registerFederationNode(request, authToken) {
    return makeRequest(
      bindings.registerFederationNode,
      normalizeFederationNodeRegistrationRequest(request),
      authToken
    );
  },
  listFederationNodes(request = {}, authToken) {
    return makeRequest(
      bindings.listFederationNodes,
      normalizeListFederationNodesRequest(request),
      authToken
    );
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
    const expected = binding.body === null
      ? []
      : Array.isArray(binding.body) ? binding.body : [binding.body];
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
  case "nw.opaque-route/create":
  case "nw.opaque-route/renew":
  case "nw.opaque-route/teardown": validateOpaqueReceiveRouteV2(body.route); break;
  case "nw.opaque-route/append": validateOpaqueRouteEnqueueResponseShapeV2(body.receipt); break;
  case "nw.opaque-route/sync": validateOpaqueRouteSyncResponseShapeV2(body.batch); break;
  case "nw.opaque-route/commit": validateOpaqueRouteCommitResponseShapeV2(body.commit); break;
  case "nw.rendezvous-transport/register":
  case "nw.rendezvous-transport/append":
  case "nw.rendezvous-transport/delete": break;
  case "nw.rendezvous-transport/sync": validateRendezvousRelaySyncBatchV2(body.batch); break;
  case "nw.federation/register":
  case "nw.federation/list": validateFederationNodesResponse(body); break;
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
  boundedRelayTimestamp(value.advertisedAt, "Relay advertisedAt");

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
    requireBase64(
      value.federationDirectoryPublicKey,
      mlDsa65PublicKeyBytes,
      "Federation directory public key"
    );
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
    requireBase64(
      value.directorySigningPublicKey,
      mlDsa65PublicKeyBytes,
      "Directory signing public key"
    );
  }
  return `${normalized.host.toLowerCase()}\0${normalized.port}\0${normalized.useTLS}\0${normalized.transport}`;
}

function normalizeFederationNodeRegistrationRequest(value) {
  requireExactRecord(
    value,
    ["endpoint", "relayInfo"],
    ["ttlSeconds"],
    "Federation node registration request"
  );
  return validateFederationNodeRegistrationRequest({
    endpoint: value.endpoint,
    relayInfo: value.relayInfo,
    ttlSeconds: value.ttlSeconds ?? null
  });
}

function validateFederationNodeRegistrationRequest(value) {
  requireExactRecord(
    value,
    ["endpoint", "relayInfo", "ttlSeconds"],
    [],
    "Federation node registration request"
  );
  validateRelayEndpoint(value.endpoint);
  validateRelayInfoV2(value.relayInfo);
  if (value.ttlSeconds !== null) {
    requireInteger(value.ttlSeconds, "Federation node TTL", 1, 900);
  }
  return value;
}

function normalizeListFederationNodesRequest(value) {
  requireExactRecord(
    value,
    [],
    ["mode", "federationName", "onlyHealthy", "maxStalenessSeconds", "requireSignedSnapshot"],
    "Federation node list request"
  );
  return validateListFederationNodesRequest({
    mode: value.mode ?? null,
    federationName: value.federationName ?? null,
    onlyHealthy: value.onlyHealthy ?? null,
    maxStalenessSeconds: value.maxStalenessSeconds ?? null,
    requireSignedSnapshot: value.requireSignedSnapshot ?? null
  });
}

function validateListFederationNodesRequest(value) {
  requireExactRecord(
    value,
    ["mode", "federationName", "onlyHealthy", "maxStalenessSeconds", "requireSignedSnapshot"],
    [],
    "Federation node list request"
  );
  if (value.mode !== null && !["solo", "manual", "curated", "open"].includes(value.mode)) {
    throw new TypeError("Federation list mode is invalid.");
  }
  if (value.federationName !== null) {
    validateBoundedText(value.federationName, "Federation list name", 1_024);
  }
  if (value.onlyHealthy !== null) validateBoolean(value.onlyHealthy, "Federation healthy filter");
  if (value.maxStalenessSeconds !== null) {
    requireInteger(value.maxStalenessSeconds, "Federation maximum staleness", 1, 86_400);
  }
  if (value.requireSignedSnapshot !== null) {
    validateBoolean(value.requireSignedSnapshot, "Federation signed-snapshot requirement");
  }
  return value;
}

function validateFederationNodesResponse(value) {
  requireExactRecord(value, ["nodes", "snapshot"], [], "Federation nodes response");
  validateFederationNodeList(value.nodes, "Federation response nodes");
  if (value.snapshot !== null) {
    validateFederationDirectorySnapshot(value.snapshot);
    if (canonicalJson(value.snapshot.nodes) !== canonicalJson(value.nodes)) {
      throw new TypeError("Federation snapshot nodes do not match the response directory.");
    }
  }
  return value;
}

function validateFederationNodeList(value, label) {
  if (!Array.isArray(value) || value.length > maximumFederationNodes) {
    throw new TypeError(`${label} exceed their protocol bounds.`);
  }
  const endpoints = value.map(validateFederationNodeRecord);
  if (new Set(endpoints).size !== endpoints.length) {
    throw new TypeError(`${label} must use unique canonical endpoints.`);
  }
  return value;
}

function validateFederationNodeRecord(value) {
  requireExactRecord(
    value,
    ["endpoint", "relayInfo", "lastHeartbeatAt", "expiresAt"],
    [],
    "Federation node record"
  );
  const endpoint = validateRelayEndpoint(value.endpoint);
  validateRelayInfoV2(value.relayInfo);
  const heartbeat = boundedRelayTimestamp(value.lastHeartbeatAt, "Federation node heartbeat");
  const expiry = boundedRelayTimestamp(value.expiresAt, "Federation node expiry");
  if (expiry <= heartbeat || expiry - heartbeat > 900_000) {
    throw new TypeError("Federation node expiry is outside its heartbeat lease.");
  }
  return endpoint;
}

function validateFederationDirectorySnapshot(value) {
  requireExactRecord(
    value,
    [
      "version",
      "mode",
      "federationName",
      "issuedAt",
      "validUntil",
      "maxStalenessSeconds",
      "nodes",
      "signatureAlgorithm",
      "signature"
    ],
    [],
    "Federation directory snapshot"
  );
  if (value.version !== 1 || !["solo", "manual", "curated", "open"].includes(value.mode)) {
    throw new TypeError("Federation directory snapshot version or mode is invalid.");
  }
  if (value.federationName !== null) {
    validateBoundedText(value.federationName, "Federation snapshot name", 1_024);
  }
  const issued = boundedRelayTimestamp(value.issuedAt, "Federation snapshot issue time");
  const validUntil = boundedRelayTimestamp(value.validUntil, "Federation snapshot validity");
  const maximumStaleness = requireInteger(
    value.maxStalenessSeconds,
    "Federation snapshot maximum staleness",
    1,
    86_400
  );
  if (validUntil <= issued || validUntil - issued > maximumStaleness * 1_000) {
    throw new TypeError("Federation snapshot validity is outside its staleness bound.");
  }
  validateFederationNodeList(value.nodes, "Federation snapshot nodes");
  if (value.signatureAlgorithm === null || value.signature === null) {
    if (value.signatureAlgorithm !== null || value.signature !== null) {
      throw new TypeError("Federation snapshot signature fields must both be null or both be present.");
    }
  } else {
    if (value.signatureAlgorithm !== "ML-DSA-65") {
      throw new TypeError("Federation snapshot signature algorithm is invalid.");
    }
    requireBase64(value.signature, mlDsa65SignatureBytes, "Federation snapshot signature");
  }
  return value;
}

function boundedRelayTimestamp(value, label) {
  const timestamp = new Date(requireCanonicalTimestamp(value, label)).getTime();
  if (timestamp > 4_102_444_800_000) {
    throw new TypeError(`${label} exceeds the protocol timestamp horizon.`);
  }
  return timestamp;
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
    if (body.ttlSeconds !== null) {
      requireInteger(body.ttlSeconds, "Attachment TTL", 60, 2_592_000);
    }
    break;
  case "nw.blobs/fetch":
    requireExactRecord(body, ["attachmentId", "chunkIndex"], [], "Attachment fetch body");
    validateAttachmentCoordinates(body);
    break;
  case "nw.federation/register": validateFederationNodeRegistrationRequest(body); break;
  case "nw.federation/list": validateListFederationNodesRequest(body); break;
  default: throw new TypeError("Relay request binding has no body validator.");
  }
}

function validateAttachmentCoordinates(body) {
  if (!canonicalUUID(body.attachmentId) || !Number.isSafeInteger(body.chunkIndex) ||
      body.chunkIndex < 0 ||
      body.chunkIndex >= encryptedAttachmentPayloadLimits.maximumChunkCount) {
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
