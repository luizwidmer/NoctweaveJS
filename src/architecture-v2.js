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
const mailboxConsumerStates = new Set(["active", "revoked"]);
const mailboxProofOperations = new Set([
  "register-authority",
  "register-possession",
  "register-sponsor",
  "sync",
  "commit",
  "revoke-authority"
]);
const ML_DSA_65_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_65_SECRET_KEY_BYTES = 4_032;
const ML_DSA_65_SIGNATURE_BYTES = 3_309;
const MAXIMUM_MAILBOX_PAGE = 256;
const MAXIMUM_LONG_POLL_SECONDS = 600;
const MAXIMUM_SEQUENCED_ENVELOPE_BYTES = 512 * 1024;
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const deliveryStateOrder = Object.freeze([
  "locallyPersisted",
  "relayAccepted",
  "peerEndpointStored",
  "peerRead"
]);

export const noctweaveArchitectureV2 = Object.freeze({
  version: 2,
  maximumInstallations: 16,
  maximumMailboxConsumerHistory: 64,
  maximumMailboxPage: MAXIMUM_MAILBOX_PAGE,
  maximumLongPollTimeoutSeconds: MAXIMUM_LONG_POLL_SECONDS,
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
  maximumCursorBytes: 512,
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
    module: "nw.endpoints",
    versions: [2],
    // Direct-v4 currently addresses one certified preferred peer endpoint.
    // maximumInstallations is a structural manifest bound, not fan-out support.
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

/// Deterministic direct-v4 projection of two identity-signed endpoint
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
  { module: "nw.core", versions: [2], status: "provisional" },
  { module: "nw.mailbox", versions: [2], status: "provisional" },
  { module: "nw.prekeys", versions: [2], status: "stable" },
  { module: "nw.events", versions: [2], status: "provisional" },
  { module: "nw.endpoints", versions: [2], status: "provisional" },
  { module: "nw.routes", versions: [2, 3], status: "experimental" },
  { module: "nw.blobs", versions: [1], status: "stable" },
  { module: "nw.groups", versions: [1], status: "experimental" },
  { module: "nw.wake", versions: [1], status: "experimental" },
  { module: "nw.federation", versions: [1], status: "provisional" },
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
    status: "provisional",
    limits: { maxCiphertextBytes: 65_536 }
  },
  {
    module: "nw.endpoints",
    versions: [2],
    status: "provisional",
    limits: { maxActiveEndpoints: 1 }
  },
  {
    module: "nw.events",
    versions: [2],
    status: "provisional",
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
  }
].map(validateProtocolModuleCapability));

export function createRelationshipInstallationHandle(rawValue) {
  return validateRelationshipInstallationHandle(
    typeof rawValue === "string" ? { rawValue } : rawValue
  );
}

export function validateRelationshipInstallationHandle(value) {
  requireRecord(value, "Relationship installation handle");
  const rawValue = canonicalBase64(value.rawValue, "Relationship installation handle", 32);
  return freezeRecord({ rawValue });
}

export async function generateRelationshipInstallationHandle({
  identityGenerationId,
  installationId,
  relationshipId,
  nonce = swiftUUID(),
  crypto = globalThis.crypto
}) {
  const ids = [identityGenerationId, installationId, relationshipId, nonce]
    .map((value, index) => normalizeUUID(value, [
      "identityGenerationId",
      "installationId",
      "relationshipId",
      "nonce"
    ][index]).toLowerCase());
  const material = encoder.encode(`Noctweave/relationship-installation-handle/v2${ids.join("")}`);
  const digest = await new WebCryptoPrimitives({ crypto }).sha256(material);
  return createRelationshipInstallationHandle(base64(digest));
}

export function createMailboxConsumerId(rawValue) {
  return validateMailboxConsumerId(rawValue);
}

export function validateMailboxConsumerId(value) {
  // Swift RawRepresentable/Codable values are single JSON strings. Keeping
  // this validator wire-native also makes mailbox proof bytes identical
  // across Swift, Linux, and JavaScript.
  return canonicalBase64(value, "Mailbox consumer ID", 32);
}

export async function generateMailboxConsumerId({ nonce = swiftUUID(), crypto = globalThis.crypto } = {}) {
  const normalizedNonce = normalizeUUID(nonce, "Mailbox consumer nonce").toLowerCase();
  const material = encoder.encode(`Noctweave/mailbox-consumer/v2${normalizedNonce}`);
  return createMailboxConsumerId(base64(await sha256(crypto, material)));
}

export function validateMailboxConsumerRegistration(value) {
  requireRecord(value, "Mailbox consumer registration");
  if (!mailboxConsumerStates.has(value.state)) {
    throw new TypeError("Mailbox consumer registration state is invalid.");
  }
  const consumerSigningPublicKey = canonicalBase64(
    value.consumerSigningPublicKey,
    "Mailbox consumer signing public key",
    ML_DSA_65_PUBLIC_KEY_BYTES
  );
  const registeredAt = normalizeDate(value.registeredAt, "Mailbox consumer registeredAt");
  let revokedAt;
  if (value.state === "active") {
    if (value.revokedAt != null) {
      throw new TypeError("An active mailbox consumer cannot have revokedAt.");
    }
  } else {
    if (value.revokedAt == null) {
      throw new TypeError("A revoked mailbox consumer must have revokedAt.");
    }
    revokedAt = normalizeDate(value.revokedAt, "Mailbox consumer revokedAt");
    if (new Date(revokedAt) < new Date(registeredAt)) {
      throw new TypeError("Mailbox consumer revokedAt cannot precede registeredAt.");
    }
  }
  const result = {
    consumerId: validateMailboxConsumerId(value.consumerId),
    consumerSigningPublicKey,
    state: value.state,
    committedSequence: uint64(value.committedSequence, "Mailbox consumer committedSequence", true),
    registeredAt
  };
  if (revokedAt !== undefined) {
    result.revokedAt = revokedAt;
  }
  return freezeRecord(result);
}

export function validateMailboxSyncBatch(value) {
  requireRecord(value, "Mailbox sync batch");
  if (!Array.isArray(value.events) || value.events.length > MAXIMUM_MAILBOX_PAGE) {
    throw new TypeError("Mailbox sync batch events exceed the 256-event bound.");
  }
  const events = value.events.map(validateSequencedEnvelope);
  const nextSequence = uint64(value.nextSequence, "Mailbox sync nextSequence", true);
  const highWatermark = uint64(value.highWatermark, "Mailbox sync highWatermark", true);
  const retentionFloor = uint64(value.retentionFloor, "Mailbox sync retentionFloor", true);
  if (typeof value.hasMore !== "boolean") {
    throw new TypeError("Mailbox sync hasMore must be a boolean.");
  }
  if (nextSequence > highWatermark || retentionFloor > highWatermark) {
    throw new TypeError("Mailbox sync sequence bounds are inconsistent.");
  }
  for (let index = 0; index < events.length; index += 1) {
    const sequence = events[index].sequence;
    if (sequence <= retentionFloor || sequence > highWatermark ||
        (index > 0 && sequence !== events[index - 1].sequence + 1)) {
      throw new TypeError("Mailbox sync events are outside their ordered sequence bounds.");
    }
  }
  if ((events.at(-1)?.sequence ?? nextSequence) !== nextSequence) {
    throw new TypeError("Mailbox sync nextSequence does not match the final event.");
  }
  return freezeRecord({
    events: Object.freeze(events),
    nextCursor: validateMailboxCursor(value.nextCursor),
    nextSequence,
    highWatermark,
    retentionFloor,
    hasMore: value.hasMore
  });
}

export function validateMailboxSyncContinuity(value, committedSequenceValue) {
  const batch = validateMailboxSyncBatch(value);
  const committedSequence = uint64(
    committedSequenceValue,
    "Mailbox committed sequence",
    true
  );
  if (batch.events.length === 0) {
    if (batch.nextSequence !== committedSequence) {
      throw new TypeError("Mailbox sync empty batch does not match the committed sequence.");
    }
    return batch;
  }
  if (committedSequence >= Number.MAX_SAFE_INTEGER ||
      batch.events[0].sequence !== committedSequence + 1) {
    throw new TypeError("Mailbox sync batch begins after a sequence gap.");
  }
  return batch;
}

export function validateRelayActorProof(value) {
  requireRecord(value, "Relay actor proof");
  return freezeRecord({
    fingerprint: canonicalBase64(value.fingerprint, "Relay actor fingerprint", 32),
    publicSigningKey: canonicalBase64(
      value.publicSigningKey,
      "Relay actor public signing key",
      ML_DSA_65_PUBLIC_KEY_BYTES
    ),
    signedAt: normalizeDate(value.signedAt, "Relay actor proof signedAt"),
    nonce: normalizeUUID(value.nonce, "Relay actor proof nonce"),
    signature: canonicalBase64(value.signature, "Relay actor signature", ML_DSA_65_SIGNATURE_BYTES)
  });
}

export function mailboxConsumerProofPayload({
  operation,
  inboxId,
  consumerId,
  consumerSigningPublicKey,
  sponsorConsumerId,
  cursor,
  sequence,
  maxCount,
  longPollTimeoutSeconds,
  signedAt,
  nonce
}) {
  if (!mailboxProofOperations.has(operation)) {
    throw new TypeError("Mailbox consumer proof operation is invalid.");
  }
  const isRegistration = operation.startsWith("register-");
  if (isRegistration) {
    if (consumerSigningPublicKey == null || cursor != null || maxCount != null || longPollTimeoutSeconds != null) {
      throw new TypeError("Mailbox registration proof fields are invalid.");
    }
  } else if (operation === "sync") {
    if (consumerSigningPublicKey != null || sponsorConsumerId != null || sequence != null) {
      throw new TypeError("Mailbox sync proof fields are invalid.");
    }
  } else if (operation === "commit") {
    if (consumerSigningPublicKey != null || sponsorConsumerId != null || cursor == null || sequence == null ||
        maxCount != null || longPollTimeoutSeconds != null) {
      throw new TypeError("Mailbox commit proof fields are invalid.");
    }
  } else if (consumerSigningPublicKey != null || sponsorConsumerId != null || cursor != null || sequence != null ||
      maxCount != null || longPollTimeoutSeconds != null) {
    throw new TypeError("Mailbox revocation proof fields are invalid.");
  }
  const result = {
    operation,
    inboxId: validateInboxId(inboxId),
    consumerId: validateMailboxConsumerId(consumerId),
    signedAt: normalizeDate(signedAt, "Mailbox consumer proof signedAt"),
    nonce: normalizeUUID(nonce, "Mailbox consumer proof nonce")
  };
  if (consumerSigningPublicKey !== undefined && consumerSigningPublicKey !== null) {
    result.consumerSigningPublicKey = normalizeSigningPublicKey(consumerSigningPublicKey);
  }
  if (sponsorConsumerId !== undefined && sponsorConsumerId !== null) {
    result.sponsorConsumerId = validateMailboxConsumerId(sponsorConsumerId);
  }
  if (cursor !== undefined && cursor !== null) {
    result.cursor = validateMailboxCursor(cursor);
  }
  if (sequence !== undefined && sequence !== null) {
    result.sequence = uint64(sequence, "Mailbox consumer proof sequence", true);
  }
  if (maxCount !== undefined && maxCount !== null) {
    result.maxCount = boundedInteger(maxCount, "Mailbox sync maxCount", 1, MAXIMUM_MAILBOX_PAGE);
  }
  if (longPollTimeoutSeconds !== undefined && longPollTimeoutSeconds !== null) {
    result.longPollTimeoutSeconds = boundedInteger(
      longPollTimeoutSeconds,
      "Mailbox sync longPollTimeoutSeconds",
      1,
      MAXIMUM_LONG_POLL_SECONDS
    );
  }
  return freezeRecord(result);
}

export async function createMailboxConsumerProof({
  operation,
  request,
  signingKey,
  fingerprint,
  signedAt = new Date(),
  nonce = swiftUUID(),
  pqc,
  crypto = globalThis.crypto
}) {
  if (typeof pqc?.sign !== "function") {
    throw new TypeError("A compatible ML-DSA signer is required.");
  }
  const key = normalizeSigningKeyPair(signingKey);
  try {
    const proofMetadata = {
      signedAt: normalizeDate(signedAt, "Mailbox consumer proof signedAt"),
      nonce: normalizeUUID(nonce, "Mailbox consumer proof nonce")
    };
    const payload = mailboxConsumerProofPayloadForRequest(operation, request, proofMetadata);
    const calculatedFingerprint = base64(await sha256(crypto, key.publicKey));
    if (fingerprint != null && canonicalBase64(fingerprint, "Relay actor fingerprint", 32) !== calculatedFingerprint) {
      throw new TypeError("Relay actor fingerprint does not match the signing key.");
    }
    const signature = bytes(pqc.sign(canonicalJsonBytes(payload), key.secretKey), "ML-DSA signature");
    if (signature.byteLength !== ML_DSA_65_SIGNATURE_BYTES) {
      throw new TypeError("ML-DSA-65 signer returned an invalid signature length.");
    }
    return validateRelayActorProof({
      fingerprint: calculatedFingerprint,
      publicSigningKey: base64(key.publicKey),
      signedAt: proofMetadata.signedAt,
      nonce: proofMetadata.nonce,
      signature: base64(signature)
    });
  } finally {
    key.secretKey.fill(0);
  }
}

export async function verifyMailboxConsumerProof({
  operation,
  request,
  proof,
  expectedPublicKey,
  pqc,
  crypto = globalThis.crypto
}) {
  if (typeof pqc?.verify !== "function") {
    throw new TypeError("A compatible ML-DSA verifier is required.");
  }
  const validatedProof = validateRelayActorProof(proof);
  const publicKey = decodeCanonicalBase64(
    validatedProof.publicSigningKey,
    "Relay actor public signing key",
    ML_DSA_65_PUBLIC_KEY_BYTES
  );
  if (expectedPublicKey != null &&
      normalizeSigningPublicKey(expectedPublicKey) !== validatedProof.publicSigningKey) {
    return false;
  }
  if (base64(await sha256(crypto, publicKey)) !== validatedProof.fingerprint) {
    return false;
  }
  const payload = mailboxConsumerProofPayloadForRequest(operation, request, validatedProof);
  return pqc.verify(
    canonicalJsonBytes(payload),
    decodeCanonicalBase64(validatedProof.signature, "Relay actor signature", ML_DSA_65_SIGNATURE_BYTES),
    publicKey
  ) === true;
}

export async function buildRegisterMailboxConsumerRequest({
  inboxId,
  consumerId,
  consumerSigningKey,
  authoritySigningKey,
  authorityFingerprint,
  consumerFingerprint,
  sponsorConsumerId,
  sponsorSigningKey,
  sponsorFingerprint,
  startingSequence,
  authorityProofOptions = {},
  consumerProofOptions = {},
  sponsorProofOptions = {},
  pqc,
  crypto = globalThis.crypto
}) {
  requireRecord(consumerSigningKey, "ML-DSA signing keypair");
  const draft = {
    inboxId: validateInboxId(inboxId),
    consumerId: validateMailboxConsumerId(consumerId),
    consumerSigningPublicKey: normalizeSigningPublicKey(consumerSigningKey.publicKey)
  };
  if (startingSequence !== undefined && startingSequence !== null) {
    draft.startingSequence = uint64(startingSequence, "Mailbox consumer startingSequence", true);
  }
  if (sponsorConsumerId != null) {
    draft.sponsorConsumerId = validateMailboxConsumerId(sponsorConsumerId);
  }
  draft.authorityProof = await createMailboxConsumerProof({
    ...authorityProofOptions,
    operation: "register-authority",
    request: draft,
    signingKey: authoritySigningKey,
    fingerprint: authorityFingerprint,
    pqc,
    crypto
  });
  draft.consumerProof = await createMailboxConsumerProof({
    ...consumerProofOptions,
    operation: "register-possession",
    request: draft,
    signingKey: consumerSigningKey,
    fingerprint: consumerFingerprint,
    pqc,
    crypto
  });
  if (draft.sponsorConsumerId != null) {
    if (sponsorSigningKey == null) {
      throw new TypeError("A sponsor signing key is required when sponsorConsumerId is present.");
    }
    draft.sponsorProof = await createMailboxConsumerProof({
      ...sponsorProofOptions,
      operation: "register-sponsor",
      request: draft,
      signingKey: sponsorSigningKey,
      fingerprint: sponsorFingerprint,
      pqc,
      crypto
    });
  } else if (sponsorSigningKey != null || sponsorFingerprint != null) {
    throw new TypeError("sponsorConsumerId is required when a sponsor signer is provided.");
  }
  return validateRegisterMailboxConsumerRequest(draft);
}

export async function buildSyncMailboxRequest({
  inboxId,
  consumerId,
  cursor,
  maxCount,
  longPollTimeoutSeconds,
  consumerSigningKey,
  consumerFingerprint,
  proofOptions = {},
  pqc,
  crypto = globalThis.crypto
}) {
  const draft = {
    inboxId: validateInboxId(inboxId),
    consumerId: validateMailboxConsumerId(consumerId)
  };
  if (cursor != null) draft.cursor = validateMailboxCursor(cursor);
  if (maxCount != null) draft.maxCount = boundedInteger(maxCount, "Mailbox sync maxCount", 1, MAXIMUM_MAILBOX_PAGE);
  if (longPollTimeoutSeconds != null) {
    draft.longPollTimeoutSeconds = boundedInteger(
      longPollTimeoutSeconds,
      "Mailbox sync longPollTimeoutSeconds",
      1,
      MAXIMUM_LONG_POLL_SECONDS
    );
  }
  draft.consumerProof = await createMailboxConsumerProof({
    ...proofOptions,
    operation: "sync",
    request: draft,
    signingKey: consumerSigningKey,
    fingerprint: consumerFingerprint,
    pqc,
    crypto
  });
  return validateSyncMailboxRequest(draft);
}

export async function buildCommitMailboxCursorRequest({
  inboxId,
  consumerId,
  cursor,
  sequence,
  consumerSigningKey,
  consumerFingerprint,
  proofOptions = {},
  pqc,
  crypto = globalThis.crypto
}) {
  const draft = {
    inboxId: validateInboxId(inboxId),
    consumerId: validateMailboxConsumerId(consumerId),
    cursor: validateMailboxCursor(cursor),
    sequence: uint64(sequence, "Mailbox cursor sequence", true)
  };
  draft.consumerProof = await createMailboxConsumerProof({
    ...proofOptions,
    operation: "commit",
    request: draft,
    signingKey: consumerSigningKey,
    fingerprint: consumerFingerprint,
    pqc,
    crypto
  });
  return validateCommitMailboxCursorRequest(draft);
}

export async function buildRevokeMailboxConsumerRequest({
  inboxId,
  consumerId,
  authoritySigningKey,
  authorityFingerprint,
  proofOptions = {},
  pqc,
  crypto = globalThis.crypto
}) {
  const draft = {
    inboxId: validateInboxId(inboxId),
    consumerId: validateMailboxConsumerId(consumerId)
  };
  draft.authorityProof = await createMailboxConsumerProof({
    ...proofOptions,
    operation: "revoke-authority",
    request: draft,
    signingKey: authoritySigningKey,
    fingerprint: authorityFingerprint,
    pqc,
    crypto
  });
  return validateRevokeMailboxConsumerRequest(draft);
}

export function inboxRetirementProofPayload({ inboxId, signedAt, nonce }) {
  return freezeRecord({
    domain: "org.noctweave.relay.retire-inbox",
    version: 1,
    inboxId: validateInboxId(inboxId),
    signedAt: normalizeDate(signedAt, "Inbox retirement proof signedAt"),
    nonce: normalizeUUID(nonce, "Inbox retirement proof nonce")
  });
}

/// Builds the exact self-contained request that may be durably journaled
/// before deleting an identity generation's inbox-access private key. The
/// proof intentionally has no freshness expiry so an interrupted burn can
/// retry the identical authorized deletion until every known relay accepts it.
export async function buildRetireInboxRequest({
  inboxId,
  accessSigningKey,
  accessFingerprint,
  signedAt = new Date(),
  nonce = swiftUUID(),
  pqc,
  crypto = globalThis.crypto
}) {
  if (typeof pqc?.sign !== "function") {
    throw new TypeError("A compatible ML-DSA signer is required.");
  }
  const canonicalInboxId = validateInboxId(inboxId);
  const key = normalizeSigningKeyPair(accessSigningKey);
  try {
    const digest = await sha256(crypto, key.publicKey);
    const inboxBytes = decodeNoctweaveInbox(canonicalInboxId);
    if (inboxBytes == null || !equalBytes(inboxBytes, digest)) {
      throw new TypeError("Inbox retirement key does not control this inbox.");
    }
    const fingerprint = base64(digest);
    if (accessFingerprint != null &&
        canonicalBase64(accessFingerprint, "Relay actor fingerprint", 32) !== fingerprint) {
      throw new TypeError("Relay actor fingerprint does not match the inbox-access key.");
    }
    const metadata = {
      signedAt: normalizeDate(signedAt, "Inbox retirement proof signedAt"),
      nonce: normalizeUUID(nonce, "Inbox retirement proof nonce")
    };
    const signature = bytes(
      pqc.sign(canonicalJsonBytes(inboxRetirementProofPayload({
        inboxId: canonicalInboxId,
        ...metadata
      })), key.secretKey),
      "ML-DSA signature"
    );
    if (signature.byteLength !== ML_DSA_65_SIGNATURE_BYTES) {
      throw new TypeError("ML-DSA-65 signer returned an invalid signature length.");
    }
    return validateRetireInboxRequest({
      inboxId: canonicalInboxId,
      accessProof: {
        fingerprint,
        publicSigningKey: base64(key.publicKey),
        ...metadata,
        signature: base64(signature)
      }
    });
  } finally {
    key.secretKey.fill(0);
  }
}

export function validateRetireInboxRequest(value) {
  requireRecord(value, "Retire inbox request");
  return freezeRecord({
    inboxId: validateInboxId(value.inboxId),
    accessProof: validateRelayActorProof(value.accessProof)
  });
}

export async function verifyInboxRetirementProof({
  request,
  pqc,
  crypto = globalThis.crypto
}) {
  if (typeof pqc?.verify !== "function") {
    throw new TypeError("A compatible ML-DSA verifier is required.");
  }
  const validated = validateRetireInboxRequest(request);
  const proof = validated.accessProof;
  const publicKey = decodeCanonicalBase64(
    proof.publicSigningKey,
    "Inbox-access public signing key",
    ML_DSA_65_PUBLIC_KEY_BYTES
  );
  const digest = await sha256(crypto, publicKey);
  const inboxBytes = decodeNoctweaveInbox(validated.inboxId);
  if (inboxBytes == null || !equalBytes(inboxBytes, digest) ||
      proof.fingerprint !== base64(digest)) {
    return false;
  }
  return pqc.verify(
    canonicalJsonBytes(inboxRetirementProofPayload({
      inboxId: validated.inboxId,
      signedAt: proof.signedAt,
      nonce: proof.nonce
    })),
    decodeCanonicalBase64(proof.signature, "Relay actor signature", ML_DSA_65_SIGNATURE_BYTES),
    publicKey
  ) === true;
}

export function validateRegisterMailboxConsumerRequest(value) {
  requireRecord(value, "Register mailbox consumer request");
  const result = {
    inboxId: validateInboxId(value.inboxId),
    consumerId: validateMailboxConsumerId(value.consumerId),
    consumerSigningPublicKey: normalizeSigningPublicKey(value.consumerSigningPublicKey)
  };
  if (value.sponsorConsumerId != null) {
    result.sponsorConsumerId = validateMailboxConsumerId(value.sponsorConsumerId);
  }
  if (value.startingSequence != null) {
    result.startingSequence = uint64(value.startingSequence, "Mailbox consumer startingSequence", true);
  }
  result.authorityProof = validateRelayActorProof(value.authorityProof);
  result.consumerProof = validateRelayActorProof(value.consumerProof);
  if (result.consumerProof.publicSigningKey !== result.consumerSigningPublicKey) {
    throw new TypeError("Mailbox consumer possession proof uses a different signing key.");
  }
  if (result.sponsorConsumerId != null) {
    result.sponsorProof = validateRelayActorProof(value.sponsorProof);
  } else if (value.sponsorProof != null) {
    throw new TypeError("Mailbox consumer sponsorProof requires sponsorConsumerId.");
  }
  return freezeRecord(result);
}

export function validateSyncMailboxRequest(value) {
  requireRecord(value, "Sync mailbox request");
  const result = {
    inboxId: validateInboxId(value.inboxId),
    consumerId: validateMailboxConsumerId(value.consumerId)
  };
  if (value.cursor != null) result.cursor = validateMailboxCursor(value.cursor);
  if (value.maxCount != null) {
    result.maxCount = boundedInteger(value.maxCount, "Mailbox sync maxCount", 1, MAXIMUM_MAILBOX_PAGE);
  }
  if (value.longPollTimeoutSeconds != null) {
    result.longPollTimeoutSeconds = boundedInteger(
      value.longPollTimeoutSeconds,
      "Mailbox sync longPollTimeoutSeconds",
      1,
      MAXIMUM_LONG_POLL_SECONDS
    );
  }
  result.consumerProof = validateRelayActorProof(value.consumerProof);
  return freezeRecord(result);
}

export function validateCommitMailboxCursorRequest(value) {
  requireRecord(value, "Commit mailbox cursor request");
  return freezeRecord({
    inboxId: validateInboxId(value.inboxId),
    consumerId: validateMailboxConsumerId(value.consumerId),
    cursor: validateMailboxCursor(value.cursor),
    sequence: uint64(value.sequence, "Mailbox cursor sequence", true),
    consumerProof: validateRelayActorProof(value.consumerProof)
  });
}

export function validateRevokeMailboxConsumerRequest(value) {
  requireRecord(value, "Revoke mailbox consumer request");
  return freezeRecord({
    inboxId: validateInboxId(value.inboxId),
    consumerId: validateMailboxConsumerId(value.consumerId),
    authorityProof: validateRelayActorProof(value.authorityProof)
  });
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
  authorInstallationHandle,
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
    authorInstallationHandle,
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
    authorInstallationHandle: validateRelationshipInstallationHandle(value.authorInstallationHandle),
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

export function createMailboxCursor(rawValue) {
  return validateMailboxCursor(rawValue);
}

export function validateMailboxCursor(value) {
  return boundedString(value, "Mailbox cursor", {
    maximumBytes: noctweaveArchitectureV2.maximumCursorBytes,
    controls: false
  });
}

export function createDeliveryStateRecord({
  eventId,
  destinationInstallation,
  state,
  updatedAt = new Date()
}) {
  return validateDeliveryStateRecord({ eventId, destinationInstallation, state, updatedAt });
}

export function validateDeliveryStateRecord(value) {
  requireRecord(value, "Delivery state record");
  if (!deliveryStateOrder.includes(value.state)) {
    throw new TypeError("Message delivery state is invalid.");
  }
  return freezeRecord({
    eventId: normalizeUUID(value.eventId, "Delivery state eventId"),
    destinationInstallation: validateRelationshipInstallationHandle(value.destinationInstallation),
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

function mailboxConsumerProofPayloadForRequest(operation, request, proof) {
  requireRecord(request, "Mailbox consumer proof request");
  const shared = {
    operation,
    inboxId: request.inboxId,
    consumerId: request.consumerId,
    signedAt: proof.signedAt,
    nonce: proof.nonce
  };
  switch (operation) {
  case "register-authority":
  case "register-possession":
  case "register-sponsor":
    return mailboxConsumerProofPayload({
      ...shared,
      consumerSigningPublicKey: request.consumerSigningPublicKey,
      sponsorConsumerId: request.sponsorConsumerId,
      sequence: request.startingSequence
    });
  case "sync":
    return mailboxConsumerProofPayload({
      ...shared,
      cursor: request.cursor,
      maxCount: request.maxCount,
      longPollTimeoutSeconds: request.longPollTimeoutSeconds
    });
  case "commit":
    return mailboxConsumerProofPayload({
      ...shared,
      cursor: request.cursor,
      sequence: request.sequence
    });
  case "revoke-authority":
    return mailboxConsumerProofPayload(shared);
  default:
    throw new TypeError("Mailbox consumer proof operation is invalid.");
  }
}

function validateSequencedEnvelope(value) {
  requireRecord(value, "Sequenced envelope");
  requireRecord(value.envelope, "Sequenced envelope payload");
  let encoded;
  try {
    encoded = JSON.stringify(value.envelope);
  } catch {
    throw new TypeError("Sequenced envelope payload must be JSON serializable.");
  }
  if (typeof encoded !== "string" || encoder.encode(encoded).byteLength > MAXIMUM_SEQUENCED_ENVELOPE_BYTES) {
    throw new TypeError("Sequenced envelope payload exceeds its size bound.");
  }
  const envelope = freezeRecord({
    ...value.envelope,
    id: normalizeUUID(value.envelope.id, "Sequenced envelope id")
  });
  return freezeRecord({
    sequence: uint64(value.sequence, "Sequenced envelope sequence"),
    envelope,
    storedAt: normalizeDate(value.storedAt, "Sequenced envelope storedAt")
  });
}

function validateInboxId(value) {
  const inboxId = boundedString(value, "Inbox ID", {
    maximumBytes: 128,
    trimmed: true,
    controls: false
  });
  if (!isValidNoctweaveInbox(inboxId)) {
    throw new TypeError("Inbox ID is not a structurally valid Noctweave address.");
  }
  if (inboxId !== inboxId.toLowerCase()) {
    throw new TypeError("Inbox ID must use its canonical lowercase encoding.");
  }
  return inboxId;
}

function isValidNoctweaveInbox(value) {
  return decodeNoctweaveInbox(value) != null;
}

function decodeNoctweaveInbox(value) {
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  if (hasLower && hasUpper) return null;
  const normalized = value.toLowerCase();
  const separator = normalized.lastIndexOf("1");
  if (separator !== "noctweave".length || normalized.slice(0, separator) !== "noctweave") return null;
  const encoded = normalized.slice(separator + 1);
  if (encoded.length < 6) return null;
  const data = [];
  for (const character of encoded) {
    const index = BECH32_CHARSET.indexOf(character);
    if (index < 0) return null;
    data.push(index);
  }
  if (bech32Polymod([
    ...bech32HrpExpand("noctweave"),
    ...data
  ]) !== 1) return null;
  const decoded = convertBech32Bits(data.slice(0, -6), 5, 8, false);
  return decoded?.length === 32 ? Uint8Array.from(decoded) : null;
}

function bech32HrpExpand(value) {
  return [
    ...Array.from(value, (character) => character.charCodeAt(0) >> 5),
    0,
    ...Array.from(value, (character) => character.charCodeAt(0) & 31)
  ];
}

function bech32Polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = (((checksum & 0x1ffffff) << 5) ^ value) >>> 0;
    for (let index = 0; index < 5; index += 1) {
      if ((top >>> index) & 1) checksum = (checksum ^ BECH32_GENERATOR[index]) >>> 0;
    }
  }
  return checksum >>> 0;
}

function convertBech32Bits(data, from, to, pad) {
  let accumulator = 0;
  let bits = 0;
  const output = [];
  const maximum = (1 << to) - 1;
  const maximumAccumulator = (1 << (from + to - 1)) - 1;
  for (const value of data) {
    if (value < 0 || (value >> from) !== 0) return null;
    accumulator = ((accumulator << from) | value) & maximumAccumulator;
    bits += from;
    while (bits >= to) {
      bits -= to;
      output.push((accumulator >> bits) & maximum);
    }
  }
  if (pad) {
    if (bits > 0) output.push((accumulator << (to - bits)) & maximum);
  } else if (bits >= from || ((accumulator << (to - bits)) & maximum) !== 0) {
    return null;
  }
  return output;
}

function normalizeSigningPublicKey(value) {
  if (typeof value === "string") {
    return canonicalBase64(value, "Mailbox consumer signing public key", ML_DSA_65_PUBLIC_KEY_BYTES);
  }
  const publicKey = bytes(value, "Mailbox consumer signing public key");
  if (publicKey.byteLength !== ML_DSA_65_PUBLIC_KEY_BYTES) {
    throw new TypeError("Mailbox consumer signing public key must be an ML-DSA-65 public key.");
  }
  return base64(publicKey);
}

function normalizeSigningKeyPair(value) {
  requireRecord(value, "ML-DSA signing keypair");
  const publicKey = typeof value.publicKey === "string"
    ? decodeCanonicalBase64(
      value.publicKey,
      "ML-DSA public key",
      ML_DSA_65_PUBLIC_KEY_BYTES
    )
    : new Uint8Array(bytes(value.publicKey, "ML-DSA public key"));
  const secretKey = typeof value.secretKey === "string"
    ? decodeCanonicalBase64(
      value.secretKey,
      "ML-DSA secret key",
      ML_DSA_65_SECRET_KEY_BYTES
    )
    : new Uint8Array(bytes(value.secretKey, "ML-DSA secret key"));
  if (publicKey.byteLength !== ML_DSA_65_PUBLIC_KEY_BYTES ||
      secretKey.byteLength !== ML_DSA_65_SECRET_KEY_BYTES) {
    throw new TypeError("ML-DSA-65 signing keypair has invalid key lengths.");
  }
  return { publicKey, secretKey };
}

async function sha256(crypto, value) {
  if (typeof crypto?.sha256 === "function") {
    const digest = bytes(await crypto.sha256(value), "SHA-256 digest");
    if (digest.byteLength !== 32) {
      throw new TypeError("SHA-256 implementation returned an invalid digest length.");
    }
    return digest;
  }
  return new WebCryptoPrimitives({ crypto }).sha256(value);
}

function decodeCanonicalBase64(value, label, exactBytes) {
  canonicalBase64(value, label, exactBytes);
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
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
