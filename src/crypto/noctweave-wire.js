import { base64, canonicalJsonBytes, swiftISODate } from "./swift-canonical.js";
import { parseExactJSON } from "../strict-json.js";

const DIRECT_VERSION = 4;
const PROTOCOL_ENVELOPE_VERSION = 1;
const GROUP_APPLICATION_VERSION = 2;
const DIRECT_PAYLOAD_FORMAT = "nw.wire-payload.v2";
const DIRECT_CIPHER_SUITE =
  "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm";
const GROUP_PROFILE = "nw.pq-group.experimental-2";
const GROUP_CIPHER_SUITE =
  "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2";
const MAX_DIRECT_CIPHERTEXT_BYTES = 65_536;
const MIN_DIRECT_CIPHERTEXT_BYTES = 512;
const MAX_GROUP_CIPHERTEXT_BYTES = 65_536;
const ML_DSA_SIGNATURE_BYTES = 3_309;
const ML_KEM_CIPHERTEXT_BYTES = 1_088;
const DIGEST_BYTES = 32;
const TIMESTAMP_BUCKET_SECONDS = 300;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const directHeaderKeys = Object.freeze([
  "version",
  "id",
  "payloadFormat",
  "conversationId",
  "sessionId",
  "eventId",
  "senderEndpointHandle",
  "senderBindingDigest",
  "recipientEndpointHandle",
  "recipientBindingDigest",
  "cipherSuite",
  "negotiatedCapabilitiesDigest",
  "bootstrap",
  "sentAt",
  "messageCounter"
]);
const directEnvelopeKeys = Object.freeze([...directHeaderKeys, "payload", "signature"]);
const groupEnvelopeKeys = Object.freeze([
  "version",
  "profile",
  "cipherSuite",
  "groupId",
  "epoch",
  "transcriptHash",
  "senderCredentialHandle",
  "eventId",
  "messageCounter",
  "sentAt",
  "payload",
  "signature"
]);
const protocolCaseKeys = Object.freeze(["directV4", "groupApplicationV2"]);

export const directEnvelopeV4Wire = Object.freeze({
  version: DIRECT_VERSION,
  payloadFormat: DIRECT_PAYLOAD_FORMAT,
  cipherSuite: DIRECT_CIPHER_SUITE
});

export const groupApplicationEnvelopeV2Wire = Object.freeze({
  version: GROUP_APPLICATION_VERSION,
  profile: GROUP_PROFILE,
  cipherSuite: GROUP_CIPHER_SUITE,
  timestampBucketSeconds: TIMESTAMP_BUCKET_SECONDS
});

export function validateDirectBootstrapV4(value) {
  requireRecord(value, "DirectBootstrapV4");
  if (value.kind === "none") {
    requireExactKeys(value, ["kind"], "DirectBootstrapV4.none");
    return Object.freeze({ kind: "none" });
  }
  if (value.kind !== "signedPrekey") {
    throw new TypeError("DirectBootstrapV4 kind is invalid.");
  }
  requireExactKeys(
    value,
    ["kind", "kemCiphertext", "prekey"],
    "DirectBootstrapV4.signedPrekey"
  );
  const kemCiphertext = canonicalBase64(
    value.kemCiphertext,
    "DirectBootstrapV4 KEM ciphertext",
    ML_KEM_CIPHERTEXT_BYTES,
    ML_KEM_CIPHERTEXT_BYTES
  );
  requireExactKeys(value.prekey, ["kind", "id"], "DirectBootstrapV4 prekey reference");
  if (value.prekey.kind !== "signed") {
    throw new TypeError("DirectBootstrapV4 requires a signed prekey reference.");
  }
  return Object.freeze({
    kind: "signedPrekey",
    kemCiphertext,
    prekey: Object.freeze({
      kind: "signed",
      id: canonicalUUID(value.prekey.id, "DirectBootstrapV4 prekey ID")
    })
  });
}

export function validateDirectEnvelopeV4(value) {
  requireExactKeys(value, directEnvelopeKeys, "DirectEnvelopeV4");
  const header = validateDirectEnvelopeV4Header(pick(value, directHeaderKeys));
  const payload = validateEncryptedPayload(value.payload, {
    label: "DirectEnvelopeV4 payload",
    minimumCiphertextBytes: MIN_DIRECT_CIPHERTEXT_BYTES,
    maximumCiphertextBytes: MAX_DIRECT_CIPHERTEXT_BYTES,
    requirePowerOfTwo: true
  });
  const signature = canonicalBase64(
    value.signature,
    "DirectEnvelopeV4 signature",
    ML_DSA_SIGNATURE_BYTES,
    ML_DSA_SIGNATURE_BYTES
  );
  const envelope = Object.freeze({ ...header, payload, signature });
  if (directEnvelopeV4SignableBytes(envelope, { allowUnsigned: false }).byteLength > 512 * 1_024) {
    throw new TypeError("DirectEnvelopeV4 signature payload exceeds its size bound.");
  }
  return envelope;
}

export function validateDirectEnvelopeV4Header(value) {
  requireExactKeys(value, directHeaderKeys, "DirectEnvelopeV4 authenticated header");
  if (value.version !== DIRECT_VERSION || value.payloadFormat !== DIRECT_PAYLOAD_FORMAT ||
      value.cipherSuite !== DIRECT_CIPHER_SUITE) {
    throw new TypeError("DirectEnvelopeV4 version, payload format, or cipher suite is invalid.");
  }
  const conversationId = boundedString(value.conversationId, "DirectEnvelopeV4 conversation ID", 256);
  const sessionId = boundedString(value.sessionId, "DirectEnvelopeV4 session ID", 128);
  return Object.freeze({
    version: DIRECT_VERSION,
    id: canonicalUUID(value.id, "DirectEnvelopeV4 ID"),
    payloadFormat: DIRECT_PAYLOAD_FORMAT,
    conversationId,
    sessionId,
    eventId: canonicalUUID(value.eventId, "DirectEnvelopeV4 event ID"),
    senderEndpointHandle: validateOpaqueHandle(
      value.senderEndpointHandle,
      "DirectEnvelopeV4 sender endpoint handle"
    ),
    senderBindingDigest: canonicalBase64(
      value.senderBindingDigest,
      "DirectEnvelopeV4 sender endpoint-binding digest",
      DIGEST_BYTES,
      DIGEST_BYTES
    ),
    recipientEndpointHandle: validateOpaqueHandle(
      value.recipientEndpointHandle,
      "DirectEnvelopeV4 recipient endpoint handle"
    ),
    recipientBindingDigest: canonicalBase64(
      value.recipientBindingDigest,
      "DirectEnvelopeV4 recipient endpoint-binding digest",
      DIGEST_BYTES,
      DIGEST_BYTES
    ),
    cipherSuite: DIRECT_CIPHER_SUITE,
    negotiatedCapabilitiesDigest: canonicalBase64(
      value.negotiatedCapabilitiesDigest,
      "DirectEnvelopeV4 negotiated-capabilities digest",
      DIGEST_BYTES,
      DIGEST_BYTES
    ),
    bootstrap: validateDirectBootstrapV4(value.bootstrap),
    sentAt: canonicalTimestamp(value.sentAt, "DirectEnvelopeV4 sentAt"),
    messageCounter: uint64(value.messageCounter, "DirectEnvelopeV4 message counter")
  });
}

export function directEnvelopeV4AuthenticatedDataBytes(header) {
  return canonicalJsonBytes(validateDirectEnvelopeV4Header(header));
}

export function directEnvelopeV4SignablePayload(value, { allowUnsigned = true } = {}) {
  requireExactKeys(value, directEnvelopeKeys, "DirectEnvelopeV4");
  const header = validateDirectEnvelopeV4Header(pick(value, directHeaderKeys));
  const payload = validateEncryptedPayload(value.payload, {
    label: "DirectEnvelopeV4 payload",
    minimumCiphertextBytes: MIN_DIRECT_CIPHERTEXT_BYTES,
    maximumCiphertextBytes: MAX_DIRECT_CIPHERTEXT_BYTES,
    requirePowerOfTwo: true
  });
  if (allowUnsigned && value.signature === "") {
    // The Swift signer constructs the signature transcript from an envelope
    // whose signature Data is empty. The signature field itself is excluded.
  } else {
    canonicalBase64(
      value.signature,
      "DirectEnvelopeV4 signature",
      ML_DSA_SIGNATURE_BYTES,
      ML_DSA_SIGNATURE_BYTES
    );
  }
  return Object.freeze({ ...header, payload });
}

export function directEnvelopeV4SignableBytes(value, options) {
  return canonicalJsonBytes(directEnvelopeV4SignablePayload(value, options));
}

export function validateGroupApplicationEnvelopeV2(value) {
  requireExactKeys(value, groupEnvelopeKeys, "GroupApplicationEnvelopeV2");
  const signable = groupApplicationEnvelopeV2SignablePayload(value);
  const signature = canonicalBase64(
    value.signature,
    "GroupApplicationEnvelopeV2 signature",
    ML_DSA_SIGNATURE_BYTES,
    ML_DSA_SIGNATURE_BYTES
  );
  return Object.freeze({ ...signable, signature });
}

export function groupApplicationEnvelopeV2SignablePayload(value) {
  requireExactKeys(value, groupEnvelopeKeys, "GroupApplicationEnvelopeV2");
  if (value.version !== GROUP_APPLICATION_VERSION || value.profile !== GROUP_PROFILE ||
      value.cipherSuite !== GROUP_CIPHER_SUITE) {
    throw new TypeError("GroupApplicationEnvelopeV2 profile is invalid.");
  }
  const sentAt = canonicalTimestamp(value.sentAt, "GroupApplicationEnvelopeV2 sentAt");
  if ((Date.parse(sentAt) / 1_000) % TIMESTAMP_BUCKET_SECONDS !== 0) {
    throw new TypeError("GroupApplicationEnvelopeV2 sentAt is not in a five-minute bucket.");
  }
  const epoch = uint64(value.epoch, "GroupApplicationEnvelopeV2 epoch");
  if (epoch === 0) {
    throw new TypeError("GroupApplicationEnvelopeV2 epoch must be positive.");
  }
  return Object.freeze({
    version: GROUP_APPLICATION_VERSION,
    profile: GROUP_PROFILE,
    cipherSuite: GROUP_CIPHER_SUITE,
    groupId: canonicalUUID(value.groupId, "GroupApplicationEnvelopeV2 group ID"),
    epoch,
    transcriptHash: canonicalBase64(
      value.transcriptHash,
      "GroupApplicationEnvelopeV2 transcript hash",
      DIGEST_BYTES,
      DIGEST_BYTES
    ),
    senderCredentialHandle: validateOpaqueHandle(
      value.senderCredentialHandle,
      "GroupApplicationEnvelopeV2 sender credential handle"
    ),
    eventId: canonicalUUID(value.eventId, "GroupApplicationEnvelopeV2 event ID"),
    messageCounter: uint64(
      value.messageCounter,
      "GroupApplicationEnvelopeV2 message counter"
    ),
    sentAt,
    payload: validateEncryptedPayload(value.payload, {
      label: "GroupApplicationEnvelopeV2 payload",
      minimumCiphertextBytes: 1,
      maximumCiphertextBytes: MAX_GROUP_CIPHERTEXT_BYTES,
      requirePowerOfTwo: false
    })
  });
}

export function groupApplicationEnvelopeV2SignableBytes(value) {
  return canonicalJsonBytes(groupApplicationEnvelopeV2SignablePayload(value));
}

export function validateProtocolEnvelopeV1(value) {
  requireRecord(value, "ProtocolEnvelopeV1");
  const keys = Object.keys(value);
  if (value.version !== PROTOCOL_ENVELOPE_VERSION || keys.length !== 2 ||
      !keys.includes("version")) {
    throw new TypeError("ProtocolEnvelopeV1 must contain version and exactly one case.");
  }
  const cases = protocolCaseKeys.filter((key) => Object.hasOwn(value, key));
  if (cases.length !== 1 || keys.some((key) => key !== "version" && !protocolCaseKeys.includes(key))) {
    throw new TypeError("ProtocolEnvelopeV1 has an unknown, missing, or multiple case.");
  }
  switch (cases[0]) {
  case "directV4":
    return Object.freeze({
      version: PROTOCOL_ENVELOPE_VERSION,
      directV4: validateDirectEnvelopeV4(value.directV4)
    });
  case "groupApplicationV2":
    return Object.freeze({
      version: PROTOCOL_ENVELOPE_VERSION,
      groupApplicationV2: validateGroupApplicationEnvelopeV2(value.groupApplicationV2)
    });
  default:
    throw new TypeError("ProtocolEnvelopeV1 case is unsupported.");
  }
}

export function encodeProtocolEnvelopeV1(value) {
  return canonicalJsonBytes(validateProtocolEnvelopeV1(value));
}

export function decodeProtocolEnvelopeV1(value) {
  let parsed;
  try {
    const text = typeof value === "string"
      ? value
      : decoder.decode(value instanceof Uint8Array ? value : new Uint8Array(value));
    parsed = parseExactJSON(text);
  } catch (error) {
    throw new TypeError("ProtocolEnvelopeV1 encoding is invalid JSON.", { cause: error });
  }
  return validateProtocolEnvelopeV1(parsed);
}

export function protocolEnvelopeV1Id(value) {
  const envelope = validateProtocolEnvelopeV1(value);
  return envelope.directV4?.id ?? envelope.groupApplicationV2.eventId;
}

function validateEncryptedPayload(value, {
  label,
  minimumCiphertextBytes,
  maximumCiphertextBytes,
  requirePowerOfTwo
}) {
  requireExactKeys(value, ["nonce", "ciphertext", "tag"], label);
  const nonce = canonicalBase64(value.nonce, `${label} nonce`, 12, 12);
  const ciphertext = canonicalBase64(
    value.ciphertext,
    `${label} ciphertext`,
    minimumCiphertextBytes,
    maximumCiphertextBytes
  );
  const ciphertextBytes = decodeCanonicalBase64(ciphertext).byteLength;
  if (requirePowerOfTwo && (ciphertextBytes & (ciphertextBytes - 1)) !== 0) {
    throw new TypeError(`${label} ciphertext is not in a power-of-two padding bucket.`);
  }
  return Object.freeze({
    nonce,
    ciphertext,
    tag: canonicalBase64(value.tag, `${label} tag`, 16, 16)
  });
}

function validateOpaqueHandle(value, label) {
  requireExactKeys(value, ["rawValue"], label);
  return Object.freeze({
    rawValue: canonicalBase64(value.rawValue, label, DIGEST_BYTES, DIGEST_BYTES)
  });
}

function canonicalBase64(value, label, minimumBytes, maximumBytes = minimumBytes) {
  if (typeof value !== "string" || value.length === 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError(`${label} is not canonical base64.`);
  }
  const bytes = decodeCanonicalBase64(value);
  if (bytes.byteLength < minimumBytes || bytes.byteLength > maximumBytes || base64(bytes) !== value) {
    throw new TypeError(`${label} has an invalid byte length or encoding.`);
  }
  return value;
}

function decodeCanonicalBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function canonicalTimestamp(value, label) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) ||
      swiftISODate(new Date(value)) !== value) {
    throw new TypeError(`${label} is not a canonical ISO-8601 timestamp.`);
  }
  return value;
}

function canonicalUUID(value, label) {
  if (typeof value !== "string" ||
      !/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(value)) {
    throw new TypeError(`${label} is not a canonical UUID.`);
  }
  return value;
}

function uint64(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer.`);
  }
  return value;
}

function boundedString(value, label, maximumBytes) {
  if (typeof value !== "string" || value.length === 0 ||
      encoder.encode(value).byteLength > maximumBytes) {
    throw new TypeError(`${label} is empty or exceeds its byte bound.`);
  }
  return value;
}

function requireRecord(value, label) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
}

function requireExactKeys(value, expectedKeys, label) {
  requireRecord(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} requires exactly its canonical field set.`);
  }
}

function pick(value, keys) {
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}
