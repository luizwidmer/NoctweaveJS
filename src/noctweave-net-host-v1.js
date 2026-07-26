import { base64 } from "./crypto/swift-canonical.js";
import { bytes } from "./crypto/webcrypto.js";
import {
  concatBytes,
  cryptoSha256,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  uint64Bytes
} from "./private-v2.js";

const textEncoder = new TextEncoder();
const objectIDPattern = /^[0-9a-f]{64}$/u;
const releaseDigestDomain = textEncoder.encode("org.noctweave.net/host-release/v1");
const receiptSignatureDomain = textEncoder.encode("org.noctweave.net/hosting-receipt/v1");

export const noctweaveNetHostV1Limits = Object.freeze({
  maximumObjectBytes: 1_024 * 1_024,
  minimumRetentionSeconds: 60,
  maximumRetentionSeconds: 2_592_000,
  releaseCapabilityBytes: 32,
  idempotencyKeyBytes: 32
});

export function validateNoctweaveNetHostObjectID(value) {
  if (typeof value !== "string" || !objectIDPattern.test(value)) {
    throw new TypeError("Noctweave Net host object ID must be 64 lowercase hexadecimal characters.");
  }
  return value;
}

export async function noctweaveNetHostObjectID(crypto, payload) {
  const payloadBytes = boundedPayloadBytes(payload);
  return hexadecimal(await cryptoSha256(crypto, payloadBytes));
}

export async function noctweaveNetHostReleaseDigest(crypto, releaseCapability) {
  const capability = exactBytes(
    releaseCapability,
    noctweaveNetHostV1Limits.releaseCapabilityBytes,
    "Noctweave Net release capability"
  );
  return cryptoSha256(crypto, concatBytes(releaseDigestDomain, Uint8Array.of(0), capability));
}

export async function createNoctweaveNetHostPutV1({
  crypto,
  payload,
  ttlSeconds = null,
  releaseCapability = undefined,
  idempotencyKey = undefined
}) {
  requireHostCrypto(crypto, true);
  const payloadBytes = new Uint8Array(boundedPayloadBytes(payload));
  const release = releaseCapability === undefined
    ? exactRandomBytes(crypto, noctweaveNetHostV1Limits.releaseCapabilityBytes, "release capability")
    : exactBytes(
      releaseCapability,
      noctweaveNetHostV1Limits.releaseCapabilityBytes,
      "Noctweave Net release capability"
    );
  const idempotency = idempotencyKey === undefined
    ? exactRandomBytes(crypto, noctweaveNetHostV1Limits.idempotencyKeyBytes, "idempotency key")
    : exactBytes(
      idempotencyKey,
      noctweaveNetHostV1Limits.idempotencyKeyBytes,
      "Noctweave Net idempotency key"
    );
  const request = validateNoctweaveNetHostPutBody({
    objectID: await noctweaveNetHostObjectID(crypto, payloadBytes),
    payload: base64(payloadBytes),
    ttlSeconds: normalizeTTL(ttlSeconds),
    releaseCapabilityDigest: base64(
      await noctweaveNetHostReleaseDigest(crypto, release)
    ),
    idempotencyKey: base64(idempotency)
  });
  return Object.freeze({
    request,
    byteCount: payloadBytes.byteLength,
    releaseCapability: new Uint8Array(release),
    idempotencyKey: new Uint8Array(idempotency)
  });
}

export function validateNoctweaveNetHostPutBody(value) {
  requireExactRecord(
    value,
    ["objectID", "payload", "ttlSeconds", "releaseCapabilityDigest", "idempotencyKey"],
    [],
    "Noctweave Net host put body"
  );
  validateNoctweaveNetHostObjectID(value.objectID);
  const payload = requireBase64(value.payload, undefined, "Noctweave Net host payload");
  if (payload.byteLength === 0 ||
      payload.byteLength > noctweaveNetHostV1Limits.maximumObjectBytes) {
    throw new TypeError("Noctweave Net host payload is outside the protocol size bound.");
  }
  normalizeTTL(value.ttlSeconds);
  requireBase64(value.releaseCapabilityDigest, 32, "Noctweave Net release capability digest");
  requireBase64(
    value.idempotencyKey,
    noctweaveNetHostV1Limits.idempotencyKeyBytes,
    "Noctweave Net host idempotency key"
  );
  return value;
}

export function validateNoctweaveNetHostObjectBody(value) {
  requireExactRecord(value, ["objectID"], [], "Noctweave Net host object request");
  validateNoctweaveNetHostObjectID(value.objectID);
  return value;
}

export function validateNoctweaveNetHostReleaseBody(value) {
  requireExactRecord(
    value,
    ["objectID", "releaseCapability"],
    [],
    "Noctweave Net host release body"
  );
  validateNoctweaveNetHostObjectID(value.objectID);
  requireBase64(
    value.releaseCapability,
    noctweaveNetHostV1Limits.releaseCapabilityBytes,
    "Noctweave Net release capability"
  );
  return value;
}

export function validateNoctweaveNetHostingReceiptV1(value, expectedObjectID = undefined) {
  requireExactRecord(
    value,
    [
      "objectID",
      "byteCount",
      "storedAt",
      "expiresAt",
      "signingPublicKey",
      "signatureAlgorithm",
      "signature"
    ],
    [],
    "Noctweave Net hosting receipt"
  );
  validateNoctweaveNetHostObjectID(value.objectID);
  if (expectedObjectID !== undefined && value.objectID !== expectedObjectID) {
    throw new TypeError("Noctweave Net hosting receipt object ID does not match the request.");
  }
  requireInteger(
    value.byteCount,
    "Noctweave Net hosted byte count",
    1,
    noctweaveNetHostV1Limits.maximumObjectBytes
  );
  const storedAt = timestampSeconds(value.storedAt, "Noctweave Net hosted-at timestamp");
  const expiresAt = timestampSeconds(value.expiresAt, "Noctweave Net expiry timestamp");
  if (expiresAt <= storedAt ||
      expiresAt - storedAt > noctweaveNetHostV1Limits.maximumRetentionSeconds) {
    throw new TypeError("Noctweave Net hosting receipt retention is invalid.");
  }
  requireBase64(value.signingPublicKey, 32, "Noctweave Net hosting receipt public key");
  if (value.signatureAlgorithm !== "Ed25519") {
    throw new TypeError("Noctweave Net hosting receipt signature algorithm is invalid.");
  }
  requireBase64(value.signature, 64, "Noctweave Net hosting receipt signature");
  return value;
}

export function validateNoctweaveNetHostFetchV1(value, expectedObjectID) {
  requireExactRecord(value, ["receipt", "payload"], [], "Noctweave Net host object");
  const receipt = validateNoctweaveNetHostingReceiptV1(value.receipt, expectedObjectID);
  const payload = requireBase64(value.payload, undefined, "Noctweave Net hosted payload");
  if (payload.byteLength !== receipt.byteCount ||
      payload.byteLength === 0 ||
      payload.byteLength > noctweaveNetHostV1Limits.maximumObjectBytes) {
    throw new TypeError("Noctweave Net hosted payload does not match its receipt.");
  }
  return value;
}

export function validateNoctweaveNetHostPresenceV1(value, expectedObjectID) {
  requireExactRecord(
    value,
    ["objectID", "present", "expiresAt"],
    [],
    "Noctweave Net host presence"
  );
  validateNoctweaveNetHostObjectID(value.objectID);
  if (value.objectID !== expectedObjectID || typeof value.present !== "boolean") {
    throw new TypeError("Noctweave Net host presence does not match its request.");
  }
  if (value.present) {
    timestampSeconds(value.expiresAt, "Noctweave Net host presence expiry");
  } else if (value.expiresAt !== null) {
    throw new TypeError("An absent Noctweave Net host object must not claim an expiry.");
  }
  return value;
}

export function validateNoctweaveNetHostReleaseReceiptV1(value, expectedObjectID) {
  requireExactRecord(
    value,
    ["objectID", "released"],
    [],
    "Noctweave Net host release receipt"
  );
  validateNoctweaveNetHostObjectID(value.objectID);
  if (value.objectID !== expectedObjectID || typeof value.released !== "boolean") {
    throw new TypeError("Noctweave Net host release receipt does not match its request.");
  }
  return value;
}

export async function verifyNoctweaveNetHostingReceiptV1(
  receipt,
  { subtle = globalThis.crypto?.subtle } = {}
) {
  validateNoctweaveNetHostingReceiptV1(receipt);
  if (!subtle) {
    throw new Error("WebCrypto is required to verify a Noctweave Net hosting receipt.");
  }
  const publicKey = await subtle.importKey(
    "raw",
    requireBase64(receipt.signingPublicKey, 32, "Noctweave Net hosting receipt public key"),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  return subtle.verify(
    { name: "Ed25519" },
    publicKey,
    requireBase64(receipt.signature, 64, "Noctweave Net hosting receipt signature"),
    hostingReceiptSigningPayload(receipt)
  );
}

export async function verifyNoctweaveNetHostFetchV1(
  crypto,
  value,
  expectedObjectID,
  options = {}
) {
  validateNoctweaveNetHostFetchV1(value, expectedObjectID);
  const payload = requireBase64(value.payload, undefined, "Noctweave Net hosted payload");
  const computedObjectID = await noctweaveNetHostObjectID(crypto, payload);
  if (computedObjectID !== expectedObjectID) {
    throw new Error("Noctweave Net hosted payload failed its content-address check.");
  }
  if (!await verifyNoctweaveNetHostingReceiptV1(value.receipt, options)) {
    throw new Error("Noctweave Net hosting receipt signature is invalid.");
  }
  return Object.freeze({
    receipt: value.receipt,
    payload: new Uint8Array(payload)
  });
}

function hostingReceiptSigningPayload(receipt) {
  const storedAt = timestampSeconds(receipt.storedAt, "Noctweave Net hosted-at timestamp");
  const expiresAt = timestampSeconds(receipt.expiresAt, "Noctweave Net expiry timestamp");
  return concatBytes(
    receiptSignatureDomain,
    Uint8Array.of(0),
    textEncoder.encode(receipt.objectID),
    uint64Bytes(receipt.byteCount),
    uint64Bytes(storedAt),
    uint64Bytes(expiresAt)
  );
}

function requireHostCrypto(crypto, randomnessRequired) {
  if (typeof crypto?.sha256 !== "function" ||
      (randomnessRequired && typeof crypto?.randomBytes !== "function")) {
    throw new TypeError(
      randomnessRequired
        ? "Noctweave Net hosting requires SHA-256 and cryptographic randomness."
        : "Noctweave Net hosting requires SHA-256."
    );
  }
  return crypto;
}

function exactRandomBytes(crypto, length, label) {
  const output = bytes(crypto.randomBytes(length), label);
  if (output.byteLength !== length) {
    throw new Error(`Noctweave Net ${label} generator returned an invalid length.`);
  }
  return new Uint8Array(output);
}

function exactBytes(value, length, label) {
  const output = bytes(value, label);
  if (output.byteLength !== length) {
    throw new TypeError(`${label} must contain exactly ${length} bytes.`);
  }
  return new Uint8Array(output);
}

function boundedPayloadBytes(value) {
  const output = bytes(value, "Noctweave Net host payload");
  if (output.byteLength === 0 ||
      output.byteLength > noctweaveNetHostV1Limits.maximumObjectBytes) {
    throw new TypeError("Noctweave Net host payload is outside the protocol size bound.");
  }
  return output;
}

function normalizeTTL(value) {
  if (value === null) return null;
  return requireInteger(
    value,
    "Noctweave Net host TTL",
    noctweaveNetHostV1Limits.minimumRetentionSeconds,
    noctweaveNetHostV1Limits.maximumRetentionSeconds
  );
}

function timestampSeconds(value, label) {
  const canonical = requireCanonicalTimestamp(value, label);
  const milliseconds = new Date(canonical).getTime();
  if (!Number.isFinite(milliseconds) || milliseconds < 0 ||
      milliseconds > 4_102_444_800_000 || milliseconds % 1_000 !== 0) {
    throw new TypeError(`${label} is outside the protocol timestamp bound.`);
  }
  return milliseconds / 1_000;
}

function hexadecimal(value) {
  return [...bytes(value, "digest")]
    .map((octet) => octet.toString(16).padStart(2, "0"))
    .join("");
}
