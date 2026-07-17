import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./crypto/swift-canonical.js";
import { bytes, WebCryptoPrimitives } from "./crypto/webcrypto.js";

const encoder = new TextEncoder();
const controlCharacters = /\p{Cc}/u;
const unsafeDisplayControls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const extensionStatuses = new Set(["experimental", "provisional", "stable", "deprecated"]);
const eventKinds = new Set(["application", "control", "receipt"]);
const relationKinds = new Set(["reply", "replacement", "reaction", "retraction", "reference"]);
const dispositions = new Set(["visible", "silent"]);
const earliestConversationEventTime = 0;
const latestConversationEventTime = 4_102_444_800_000;
const deliveryStateOrder = Object.freeze([
  "locallyPersisted",
  "relayAccepted",
  "peerEndpointStored",
  "peerRead"
]);

export const noctweaveArchitectureV2 = Object.freeze({
  version: 2,
  maximumEndpoints: 16,
  maximumModules: 64,
  maximumModuleNameBytes: 96,
  maximumModuleVersions: 8,
  maximumContentTypeBytes: 96,
  maximumContentParameters: 32,
  maximumContentParameterBytes: 256,
  maximumContentPayloadBytes: 65_536,
  maximumFallbackBytes: 2_048,
  maximumReactionBytes: 64,
  maximumRetractionReasonBytes: 512,
  maximumRoutes: 8,
  maximumIntentDependencies: 32,
  maximumIntentAttempts: 64,
  maximumQuarantinedControlEvents: 128
});

export const protocolExtensionStatuses = Object.freeze([...extensionStatuses]);
export const messageDeliveryStates = deliveryStateOrder;

export const directV4CipherSuite =
  "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm";

const directV4Requirements = Object.freeze([
  {
    module: "nw.core",
    versions: [2],
    limits: { maxCiphertextBytes: 65_536 },
    minimums: { maxCiphertextBytes: 512 }
  },
  {
    module: "nw.relationship-endpoints",
    versions: [2],
    // Direct-v4 currently addresses one certified preferred peer endpoint.
    // maximumEndpoints is a structural manifest bound, not fan-out support.
    limits: { maxActiveEndpoints: 1 },
    minimums: { maxActiveEndpoints: 1 }
  },
  {
    module: "nw.events",
    versions: [2],
    limits: {
      maxContentParameterBytes: 256,
      maxContentParameters: 32,
      maxContentPayloadBytes: 65_536,
      maxFallbackBytes: 2_048
    },
    minimums: {
      maxContentParameterBytes: 1,
      maxContentParameters: 1,
      maxContentPayloadBytes: 1
    }
  },
  {
    module: "nw.prekeys",
    versions: [2],
    limits: { maxPrekeyAgeSeconds: 691_200 },
    minimums: { maxPrekeyAgeSeconds: 1 }
  },
  {
    module: "nw.routes",
    versions: [2],
    limits: { maxRoutes: 8 },
    minimums: { maxRoutes: 1 }
  }
]);

export const directV4RequiredModules = Object.freeze(
  directV4Requirements.map(({ module, versions, limits }) => Object.freeze({
    module,
    versions: Object.freeze([...versions]),
    limits: Object.freeze({ ...limits })
  }))
);

export function validateProtocolModuleCapability(value) {
  requireRecord(value, "Protocol module capability");
  const module = boundedString(value.module, "Protocol module name", {
    maximumBytes: noctweaveArchitectureV2.maximumModuleNameBytes,
    trimmed: true
  });
  if (!module.startsWith("nw.")) {
    throw new TypeError("Protocol module names must begin with nw.");
  }
  if (!Array.isArray(value.versions) || value.versions.length === 0 ||
      value.versions.length > noctweaveArchitectureV2.maximumModuleVersions) {
    throw new TypeError("Protocol module versions must contain 1 to 8 entries.");
  }
  const versions = [...new Set(value.versions.map((version) => uint16(version, "Protocol module version")))]
    .sort((left, right) => left - right);
  if (versions.length !== value.versions.length) {
    throw new TypeError("Protocol module versions must be unique.");
  }
  if (!extensionStatuses.has(value.status)) {
    throw new TypeError("Protocol module status is invalid.");
  }

  const rawLimits = value.limits ?? {};
  requireRecord(rawLimits, "Protocol module limits");
  const entries = Object.entries(rawLimits);
  if (entries.length > 32) {
    throw new TypeError("Protocol module limits exceed the 32-entry bound.");
  }
  const limits = {};
  for (const [key, limit] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    boundedString(key, "Protocol module limit name", { maximumBytes: 96 });
    if (!Number.isSafeInteger(limit) || limit < 0) {
      throw new TypeError("Protocol module limits must be non-negative safe integers.");
    }
    limits[key] = limit;
  }
  return freezeRecord({ module, versions: Object.freeze(versions), status: value.status, limits: Object.freeze(limits) });
}

export function createProtocolCapabilityManifest({
  architectureVersion = noctweaveArchitectureV2.version,
  modules = defaultActiveEndpointModules
} = {}) {
  return validateProtocolCapabilityManifest({ architectureVersion, modules });
}

export function validateProtocolCapabilityManifest(value) {
  requireRecord(value, "Protocol capability manifest");
  if (value.architectureVersion !== noctweaveArchitectureV2.version) {
    throw new TypeError("Protocol capability manifest architectureVersion must be 2.");
  }
  if (!Array.isArray(value.modules) || value.modules.length === 0 ||
      value.modules.length > noctweaveArchitectureV2.maximumModules) {
    throw new TypeError("Protocol capability manifest modules exceed their bounds.");
  }
  const modules = value.modules.map(validateProtocolModuleCapability)
    .sort((left, right) => left.module.localeCompare(right.module));
  if (new Set(modules.map(({ module }) => module)).size !== modules.length) {
    throw new TypeError("Protocol capability manifest module names must be unique.");
  }
  if (!supportsModule(modules, "nw.core", 2)) {
    throw new TypeError("Protocol capability manifest must support nw.core version 2.");
  }
  return freezeRecord({
    architectureVersion: noctweaveArchitectureV2.version,
    modules: Object.freeze(modules)
  });
}

export function negotiateProtocolCapabilities(localValue, peerValue) {
  const local = validateProtocolCapabilityManifest(localValue);
  const peer = validateProtocolCapabilityManifest(peerValue);
  const peerByModule = new Map(peer.modules.map((module) => [module.module, module]));
  const modules = [];
  for (const localModule of local.modules) {
    const peerModule = peerByModule.get(localModule.module);
    if (!peerModule) {
      continue;
    }
    const peerVersions = new Set(peerModule.versions);
    const sharedVersions = localModule.versions.filter((version) => peerVersions.has(version));
    if (sharedVersions.length === 0) {
      continue;
    }
    const limitKeys = new Set([...Object.keys(localModule.limits), ...Object.keys(peerModule.limits)]);
    const limits = {};
    for (const key of [...limitKeys].sort()) {
      const localLimit = localModule.limits[key];
      const peerLimit = peerModule.limits[key];
      limits[key] = localLimit === undefined
        ? peerLimit
        : peerLimit === undefined
          ? localLimit
          : Math.min(localLimit, peerLimit);
    }
    modules.push(validateProtocolModuleCapability({
      module: localModule.module,
      versions: [sharedVersions.at(-1)],
      status: localModule.status,
      limits
    }));
  }
  if (!supportsModule(modules, "nw.core", 2)) {
    return null;
  }
  return validateProtocolCapabilityManifest({ architectureVersion: 2, modules });
}

/// Deterministic direct-v4 projection of two relationship-scoped endpoint
/// manifests. Optional modules and status labels are intentionally excluded
/// from the cryptographic transcript.
export function negotiateDirectV4Capabilities(localValue, peerValue) {
  const local = validateProtocolCapabilityManifest(localValue);
  const peer = validateProtocolCapabilityManifest(peerValue);
  const localByModule = new Map(local.modules.map((module) => [module.module, module]));
  const peerByModule = new Map(peer.modules.map((module) => [module.module, module]));
  const modules = directV4Requirements.map((requirement) => {
    const localModule = localByModule.get(requirement.module);
    const peerModule = peerByModule.get(requirement.module);
    if (!localModule || !peerModule) {
      throw new Error(`Direct-v4 requires ${requirement.module}.`);
    }
    const peerVersions = new Set(peerModule.versions);
    const supportedVersions = new Set(requirement.versions);
    const sharedVersions = localModule.versions.filter((version) =>
      peerVersions.has(version) && supportedVersions.has(version));
    if (sharedVersions.length === 0) {
      throw new Error(`Direct-v4 has no shared ${requirement.module} version.`);
    }
    const limits = {};
    for (const [name, ceiling] of Object.entries(requirement.limits).sort(([left], [right]) =>
      left.localeCompare(right))) {
      limits[name] = Math.min(
        ceiling,
        localModule.limits[name] ?? ceiling,
        peerModule.limits[name] ?? ceiling
      );
      if (limits[name] < (requirement.minimums[name] ?? 0)) {
        throw new Error(`Direct-v4 negotiated an invalid ${requirement.module}.${name} limit.`);
      }
    }
    return Object.freeze({
      module: requirement.module,
      version: sharedVersions.at(-1),
      limits: Object.freeze(limits)
    });
  });
  return Object.freeze({
    version: 1,
    architectureVersion: noctweaveArchitectureV2.version,
    cipherSuite: directV4CipherSuite,
    modules: Object.freeze(modules)
  });
}

const knownModuleValues = [
  { module: "nw.core", versions: [2], status: "stable" },
  { module: "nw.prekeys", versions: [2], status: "stable" },
  { module: "nw.events", versions: [2], status: "stable" },
  { module: "nw.relationship-endpoints", versions: [2], status: "stable" },
  { module: "nw.routes", versions: [2], status: "stable" },
  { module: "nw.opaque-route", versions: [2], status: "stable" },
  { module: "nw.rendezvous-transport", versions: [2], status: "stable" },
  { module: "nw.blobs", versions: [1], status: "stable" },
  { module: "nw.groups", versions: [2], status: "experimental" },
  { module: "nw.wake", versions: [1], status: "experimental" },
  { module: "nw.federation", versions: [1], status: "stable" },
  { module: "nw.privacy.hidden-retrieval", versions: [1], status: "experimental" },
  { module: "nw.privacy.onion", versions: [1], status: "experimental" },
  { module: "nw.privacy.mixnet", versions: [1], status: "experimental" }
];

/// Descriptive registry only. A module's presence here is not an endpoint
/// support claim; optional modules require explicit opt-in by wired callers.
export const protocolKnownModuleCatalog = Object.freeze(knownModuleValues.map((value) =>
  validateProtocolModuleCapability({ ...value, limits: {} })));

/// Capabilities actually wired by the current direct-v4 endpoint path.
export const defaultActiveEndpointModules = Object.freeze([
  {
    module: "nw.core",
    versions: [2],
    status: "stable",
    limits: { maxCiphertextBytes: 65_536 }
  },
  {
    module: "nw.relationship-endpoints",
    versions: [2],
    status: "stable",
    limits: { maxActiveEndpoints: 1 }
  },
  {
    module: "nw.events",
    versions: [2],
    status: "stable",
    limits: {
      maxContentParameterBytes: 256,
      maxContentParameters: 32,
      maxContentPayloadBytes: 65_536,
      maxFallbackBytes: 2_048
    }
  },
  {
    module: "nw.prekeys",
    versions: [2],
    status: "stable",
    limits: { maxPrekeyAgeSeconds: 691_200 }
  },
  {
    module: "nw.routes",
    versions: [2],
    status: "stable",
    limits: { maxRoutes: 8 }
  }
].map(validateProtocolModuleCapability).sort((left, right) => left.module.localeCompare(right.module)));

export function createRelationshipEndpointHandle(rawValue) {
  return validateRelationshipEndpointHandle(
    typeof rawValue === "string" ? { rawValue } : rawValue
  );
}

export function validateRelationshipEndpointHandle(value) {
  requireRecord(value, "Relationship endpoint handle");
  const rawValue = canonicalBase64(value.rawValue, "Relationship endpoint handle", 32);
  return freezeRecord({ rawValue });
}

export async function generateRelationshipEndpointHandle({
  identityGenerationId,
  endpointId,
  relationshipId,
  nonce = swiftUUID(),
  crypto = globalThis.crypto
}) {
  const ids = [identityGenerationId, endpointId, relationshipId, nonce]
    .map((value, index) => normalizeUUID(value, [
      "identityGenerationId",
      "endpointId",
      "relationshipId",
      "nonce"
    ][index]).toLowerCase());
  const material = encoder.encode(`Noctweave/relationship-endpoint-handle/v2${ids.join("")}`);
  const digest = await new WebCryptoPrimitives({ crypto }).sha256(material);
  return createRelationshipEndpointHandle(base64(digest));
}

export function createContentTypeId(value) {
  return validateContentTypeId(value);
}

export function validateContentTypeId(value) {
  requireRecord(value, "Content type ID");
  const authority = boundedString(value.authority, "Content type authority", {
    maximumBytes: noctweaveArchitectureV2.maximumContentTypeBytes,
    trimmed: true,
    controls: false
  });
  const name = boundedString(value.name, "Content type name", {
    maximumBytes: noctweaveArchitectureV2.maximumContentTypeBytes,
    trimmed: true,
    controls: false
  });
  if (!/^[A-Za-z0-9._-]+$/.test(authority) || !/^[A-Za-z0-9._-]+$/.test(name)) {
    throw new TypeError("Content type authority and name use unsupported delimiter characters.");
  }
  return freezeRecord({
    authority,
    name,
    major: positiveUInt16(value.major, "Content type major version"),
    minor: uint16(value.minor ?? 0, "Content type minor version", true)
  });
}

export function contentTypeCanonicalName(value) {
  const type = validateContentTypeId(value);
  return `${type.authority}/${type.name}:${type.major}.${type.minor}`;
}

export const standardContentTypes = Object.freeze({
  text: createContentTypeId({ authority: "org.noctweave", name: "text", major: 1, minor: 0 }),
  attachment: createContentTypeId({ authority: "org.noctweave", name: "attachment", major: 1, minor: 0 }),
  reaction: createContentTypeId({ authority: "org.noctweave", name: "reaction", major: 1, minor: 0 }),
  retraction: createContentTypeId({ authority: "org.noctweave", name: "retraction", major: 1, minor: 0 }),
  deliveryReceipt: createContentTypeId({
    authority: "org.noctweave.receipt",
    name: "delivery",
    major: 1,
    minor: 0
  }),
  readReceipt: createContentTypeId({
    authority: "org.noctweave.receipt",
    name: "read",
    major: 1,
    minor: 0
  })
});

export const retractionRetainedCopyScope = "received-copies-may-remain";
export const retractionFallbackText = "Message retracted; received copies may remain";

export function createEncodedContent({
  type,
  parameters = {},
  payload,
  fallbackText,
  disposition = "visible"
}) {
  return validateEncodedContent({ type, parameters, payload, fallbackText, disposition });
}

export function createTextEncodedContent(value) {
  if (typeof value !== "string") {
    throw new TypeError("Text content must be a string.");
  }
  return createEncodedContent({
    type: standardContentTypes.text,
    payload: encoder.encode(value),
    fallbackText: value
  });
}

export function createReactionEncodedContent(value) {
  const reaction = boundedDisplayString(value, "Reaction value", {
    maximumBytes: noctweaveArchitectureV2.maximumReactionBytes,
    trimmed: true
  });
  return createEncodedContent({
    type: standardContentTypes.reaction,
    payload: canonicalJsonBytes({ value: reaction }),
    fallbackText: `Reacted ${reaction} to a message`,
    disposition: "visible"
  });
}

export function createRetractionEncodedContent({ reason } = {}) {
  const payload = { scope: retractionRetainedCopyScope };
  if (reason != null) {
    payload.reason = boundedDisplayString(reason, "Retraction reason", {
      maximumBytes: noctweaveArchitectureV2.maximumRetractionReasonBytes,
      trimmed: true
    });
  }
  return createEncodedContent({
    type: standardContentTypes.retraction,
    payload: canonicalJsonBytes(payload),
    fallbackText: retractionFallbackText,
    disposition: "visible"
  });
}

export function createDeliveryReceiptEncodedContent(targetEventId) {
  return createReceiptEncodedContent(standardContentTypes.deliveryReceipt, targetEventId);
}

export function createReadReceiptEncodedContent(targetEventId) {
  return createReceiptEncodedContent(standardContentTypes.readReceipt, targetEventId);
}

function createReceiptEncodedContent(type, targetEventId) {
  return createEncodedContent({
    type,
    payload: canonicalJsonBytes({
      targetEventId: normalizeUUID(targetEventId, "Receipt targetEventId")
    }),
    disposition: "silent"
  });
}

export function validateEncodedContent(value) {
  requireRecord(value, "Encoded content");
  const type = validateContentTypeId(value.type);
  const rawParameters = value.parameters ?? {};
  requireRecord(rawParameters, "Encoded content parameters");
  const entries = Object.entries(rawParameters);
  if (entries.length > noctweaveArchitectureV2.maximumContentParameters) {
    throw new TypeError("Encoded content parameters exceed the 32-entry bound.");
  }
  const parameters = {};
  for (const [key, rawValue] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    boundedString(key, "Encoded content parameter name", {
      maximumBytes: noctweaveArchitectureV2.maximumContentParameterBytes,
      controls: false
    });
    parameters[key] = boundedString(rawValue, "Encoded content parameter value", {
      maximumBytes: noctweaveArchitectureV2.maximumContentParameterBytes,
      empty: true,
      controls: false
    });
  }
  const payload = normalizePayload(value.payload);
  if (!dispositions.has(value.disposition)) {
    throw new TypeError("Encoded content disposition is invalid.");
  }
  const result = {
    type,
    parameters: Object.freeze(parameters),
    payload,
    disposition: value.disposition
  };
  if (value.fallbackText != null) {
    result.fallbackText = boundedDisplayString(value.fallbackText, "Encoded content fallback", {
      maximumBytes: noctweaveArchitectureV2.maximumFallbackBytes,
      empty: true
    });
  }
  return freezeRecord(result);
}

export function createConversationEvent({
  version = noctweaveArchitectureV2.version,
  id = swiftUUID(),
  clientTransactionId = swiftUUID(),
  conversationId,
  authorEndpointHandle,
  createdAt = new Date(),
  kind,
  content,
  relation
}) {
  return validateConversationEvent({
    version,
    id,
    clientTransactionId,
    conversationId,
    authorEndpointHandle,
    createdAt,
    kind,
    content,
    relation
  });
}

export function validateConversationEvent(value) {
  requireRecord(value, "Conversation event");
  if (value.version !== noctweaveArchitectureV2.version) {
    throw new TypeError("Conversation event version must be 2.");
  }
  if (!eventKinds.has(value.kind)) {
    throw new TypeError("Conversation event kind is invalid.");
  }
  const id = normalizeUUID(value.id, "Conversation event id");
  const createdAt = normalizeDate(value.createdAt, "Conversation event createdAt");
  const createdAtTime = Date.parse(createdAt);
  if (createdAtTime < earliestConversationEventTime || createdAtTime > latestConversationEventTime) {
    throw new TypeError("Conversation event createdAt is outside its protocol time bounds.");
  }
  const content = validateEncodedContent(value.content);
  const result = {
    version: noctweaveArchitectureV2.version,
    id,
    clientTransactionId: normalizeUUID(value.clientTransactionId, "Conversation event clientTransactionId"),
    conversationId: boundedString(value.conversationId, "Conversation event conversationId", {
      maximumBytes: 256,
      controls: false
    }),
    authorEndpointHandle: validateRelationshipEndpointHandle(value.authorEndpointHandle),
    createdAt,
    kind: value.kind,
    content
  };
  if (value.relation != null) {
    if (value.kind !== "application") {
      throw new TypeError("Only application events may contain a relation.");
    }
    result.relation = validateEventRelation(value.relation);
    if (result.relation.targetEventId === id) {
      throw new TypeError("Conversation event relations cannot target their own event.");
    }
  }
  if (value.kind === "application") {
    if (content.type.authority === "org.noctweave.control" ||
        content.type.authority === "org.noctweave.receipt") {
      throw new TypeError("Application events cannot carry control or receipt content.");
    }
    const canonicalType = contentTypeCanonicalName(content.type);
    const reactionType = contentTypeCanonicalName(standardContentTypes.reaction);
    const retractionType = contentTypeCanonicalName(standardContentTypes.retraction);
    const relationKind = result.relation?.kind;
    if ((canonicalType === reactionType && relationKind !== "reaction") ||
        (canonicalType === retractionType && relationKind !== "retraction") ||
        (canonicalType !== reactionType && relationKind === "reaction") ||
        (canonicalType !== retractionType && relationKind === "retraction")) {
      throw new TypeError("Reserved reaction and retraction relations require matching content.");
    }
  } else if (value.kind === "receipt") {
    const canonicalType = contentTypeCanonicalName(content.type);
    const knownReceipt = canonicalType === contentTypeCanonicalName(standardContentTypes.deliveryReceipt) ||
      canonicalType === contentTypeCanonicalName(standardContentTypes.readReceipt);
    if (!knownReceipt || content.disposition !== "silent") {
      throw new TypeError("Receipt events require a known silent receipt content type.");
    }
  } else if (content.type.authority !== "org.noctweave.control" ||
      content.disposition !== "silent") {
    throw new TypeError("Control events require silent authenticated control content.");
  }
  return freezeRecord(result);
}

export function mayMutateControlState(eventValue, supportedControlTypes) {
  const event = validateConversationEvent(eventValue);
  if (event.kind !== "control") {
    return false;
  }
  const supported = supportedControlTypes instanceof Set
    ? [...supportedControlTypes]
    : supportedControlTypes;
  if (!Array.isArray(supported)) {
    throw new TypeError("Supported control types must be an array or Set.");
  }
  const canonical = contentTypeCanonicalName(event.content.type);
  return supported.some((value) =>
    (typeof value === "string" ? value : contentTypeCanonicalName(value)) === canonical);
}

export function createDeliveryStateRecord({
  eventId,
  destinationEndpoint,
  state,
  updatedAt = new Date()
}) {
  return validateDeliveryStateRecord({ eventId, destinationEndpoint, state, updatedAt });
}

export function validateDeliveryStateRecord(value) {
  requireRecord(value, "Delivery state record");
  if (!deliveryStateOrder.includes(value.state)) {
    throw new TypeError("Message delivery state is invalid.");
  }
  return freezeRecord({
    eventId: normalizeUUID(value.eventId, "Delivery state eventId"),
    destinationEndpoint: validateRelationshipEndpointHandle(value.destinationEndpoint),
    state: value.state,
    updatedAt: normalizeDate(value.updatedAt, "Delivery state updatedAt")
  });
}

export function advanceDeliveryState(recordValue, newState, { updatedAt = new Date() } = {}) {
  const record = validateDeliveryStateRecord(recordValue);
  if (!deliveryStateOrder.includes(newState)) {
    throw new TypeError("Message delivery state is invalid.");
  }
  if (deliveryStateOrder.indexOf(newState) < deliveryStateOrder.indexOf(record.state)) {
    return null;
  }
  const normalizedUpdatedAt = normalizeDate(updatedAt, "Delivery state updatedAt");
  if (Date.parse(normalizedUpdatedAt) < Date.parse(record.updatedAt)) {
    return null;
  }
  return createDeliveryStateRecord({ ...record, state: newState, updatedAt: normalizedUpdatedAt });
}

function validateEventRelation(value) {
  requireRecord(value, "Event relation");
  if (!relationKinds.has(value.kind)) {
    throw new TypeError("Event relation kind is invalid.");
  }
  return freezeRecord({
    kind: value.kind,
    targetEventId: normalizeUUID(value.targetEventId, "Event relation targetEventId")
  });
}

function normalizePayload(value) {
  if (typeof value === "string") {
    return canonicalBase64(value, "Encoded content payload", undefined,
      noctweaveArchitectureV2.maximumContentPayloadBytes);
  }
  const data = bytes(value, "Encoded content payload");
  if (data.byteLength > noctweaveArchitectureV2.maximumContentPayloadBytes) {
    throw new TypeError("Encoded content payload exceeds 65536 bytes.");
  }
  return base64(data);
}

function canonicalBase64(value, label, exactBytes, maximumBytes = exactBytes) {
  const encodedMaximum = maximumBytes === undefined
    ? undefined
    : Math.ceil(maximumBytes / 3) * 4;
  if (typeof value !== "string" ||
      (encodedMaximum !== undefined && value.length > encodedMaximum)) {
    throw new TypeError(`${label} must be canonical base64.`);
  }
  try {
    const binary = atob(value);
    if ((exactBytes !== undefined && binary.length !== exactBytes) ||
        (maximumBytes !== undefined && binary.length > maximumBytes) ||
        btoa(binary) !== value) {
      throw new TypeError(`${label} must be canonical base64.`);
    }
    return value;
  } catch (error) {
    if (error instanceof TypeError && error.message.includes("canonical base64")) {
      throw error;
    }
    throw new TypeError(`${label} must be canonical base64.`);
  }
}

function normalizeUUID(value, label) {
  if (typeof value !== "string" || !uuidPattern.test(value)) {
    throw new TypeError(`${label} must be a UUID.`);
  }
  return value.toUpperCase();
}

function equalBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function normalizeDate(value, label) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError(`${label} must be a finite date.`);
  }
  return swiftISODate(date);
}

function supportsModule(modules, module, version) {
  return modules.some((candidate) =>
    candidate.module === module && candidate.versions.includes(version));
}

function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
}

function boundedString(value, label, {
  maximumBytes,
  empty = false,
  trimmed = false,
  controls = true
}) {
  if (typeof value !== "string" || (!empty && value.length === 0) ||
      encoder.encode(value).byteLength > maximumBytes ||
      (trimmed && value.trim() !== value) ||
      (!controls && controlCharacters.test(value))) {
    throw new TypeError(`${label} is outside its protocol bounds.`);
  }
  return value;
}

function boundedDisplayString(value, label, {
  maximumBytes,
  empty = false,
  trimmed = false
}) {
  if (typeof value !== "string" || (!empty && value.length === 0) ||
      encoder.encode(value).byteLength > maximumBytes ||
      (trimmed && value.trim() !== value) || unsafeDisplayControls.test(value)) {
    throw new TypeError(`${label} is outside its protocol bounds.`);
  }
  return value;
}

function uint16(value, label, allowZero = false) {
  if (!Number.isInteger(value) || value < (allowZero ? 0 : 1) || value > 65_535) {
    throw new TypeError(`${label} must be a ${allowZero ? "non-negative" : "positive"} UInt16.`);
  }
  return value;
}

function positiveUInt16(value, label) {
  return uint16(value, label);
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function uint64(value, label, allowZero = false) {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) {
    throw new TypeError(`${label} must be a ${allowZero ? "non-negative" : "positive"} safe integer.`);
  }
  return value;
}

function freezeRecord(value) {
  return Object.freeze(value);
}
