import {
  createEncodedContent,
  standardContentTypes
} from "./architecture-v2.js";
import {
  base64,
  canonicalJsonBytes,
  swiftUUID
} from "./crypto/swift-canonical.js";

const encoder = new TextEncoder();
const ATTACHMENT_SALT = encoder.encode("NOCTWEAVE-ATTACH");
const MAXIMUM_BYTES = 8 * 1024 * 1024;
const MAXIMUM_CHUNKS = 128;
const MAXIMUM_CHUNK_BYTES = 64 * 1024;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

export const directAttachmentV1 = Object.freeze({
  maximumBytes: MAXIMUM_BYTES,
  maximumChunks: MAXIMUM_CHUNKS,
  maximumChunkBytes: MAXIMUM_CHUNK_BYTES,
  nonceBytes: NONCE_BYTES,
  tagBytes: TAG_BYTES
});

export async function createDirectAttachmentDescriptorV1({
  crypto,
  bytes,
  mimeType,
  attachmentId = swiftUUID(),
  chunkSize = MAXIMUM_CHUNK_BYTES,
  relayTTLSeconds = null
}) {
  requireAttachmentCrypto(crypto);
  const payload = copyBytes(bytes, "Attachment bytes");
  try {
    if (payload.byteLength === 0 || payload.byteLength > MAXIMUM_BYTES) {
      throw new TypeError("Attachment bytes must contain 1 to 8388608 bytes.");
    }
    const normalizedChunkSize = integer(
      chunkSize,
      "Attachment chunk size",
      1,
      MAXIMUM_CHUNK_BYTES
    );
    const descriptor = {
      id: canonicalUUID(attachmentId, "Attachment ID"),
      fileName: null,
      mimeType: canonicalMIME(mimeType),
      byteCount: payload.byteLength,
      sha256: base64(await crypto.sha256(payload)),
      chunkCount: Math.ceil(payload.byteLength / normalizedChunkSize),
      chunkSize: normalizedChunkSize,
      relayTTLSeconds: relayTTLSeconds === null
        ? null
        : integer(relayTTLSeconds, "Attachment relay TTL", 60, 2_592_000)
    };
    return validateDirectAttachmentDescriptorV1(descriptor);
  } finally {
    payload.fill(0);
  }
}

export function validateDirectAttachmentDescriptorV1(value) {
  exact(value, [
    "id",
    "fileName",
    "mimeType",
    "byteCount",
    "sha256",
    "chunkCount",
    "chunkSize",
    "relayTTLSeconds"
  ], "Attachment descriptor");
  const descriptor = {
    id: canonicalUUID(value.id, "Attachment ID"),
    fileName: value.fileName,
    mimeType: canonicalMIME(value.mimeType),
    byteCount: integer(value.byteCount, "Attachment byte count", 1, MAXIMUM_BYTES),
    sha256: canonicalBase64(value.sha256, 32, "Attachment SHA-256"),
    chunkCount: integer(value.chunkCount, "Attachment chunk count", 1, MAXIMUM_CHUNKS),
    chunkSize: integer(value.chunkSize, "Attachment chunk size", 1, MAXIMUM_CHUNK_BYTES),
    relayTTLSeconds: value.relayTTLSeconds === null
      ? null
      : integer(value.relayTTLSeconds, "Attachment relay TTL", 60, 2_592_000)
  };
  if (descriptor.fileName !== null ||
      Math.ceil(descriptor.byteCount / descriptor.chunkSize) !== descriptor.chunkCount) {
    throw new TypeError("Attachment descriptor is structurally invalid.");
  }
  return Object.freeze(descriptor);
}

export function createDirectAttachmentEncodedContentV1(descriptor) {
  const validated = validateDirectAttachmentDescriptorV1(descriptor);
  return createEncodedContent({
    type: standardContentTypes.attachment,
    payload: canonicalJsonBytes(validated),
    fallbackText: attachmentFallbackText(validated),
    disposition: "visible"
  });
}

export async function encryptDirectAttachmentChunkV1({
  crypto,
  descriptor,
  messageKey,
  conversationId,
  sessionId,
  messageCounter,
  chunkIndex,
  plaintext,
  eventId
}) {
  requireAttachmentCrypto(crypto);
  const validated = validateDirectAttachmentDescriptorV1(descriptor);
  const index = attachmentChunkIndex(validated, chunkIndex);
  const bytes = copyBytes(plaintext, "Attachment chunk plaintext");
  const key = copyBytes(messageKey, "Attachment message key");
  let derived;
  let encrypted;
  let nonce;
  try {
    if (key.byteLength !== 32 || bytes.byteLength !== expectedChunkBytes(validated, index)) {
      throw new TypeError("Attachment chunk key or byte count is invalid.");
    }
    const context = attachmentCryptoContext({
      conversationId,
      sessionId,
      messageCounter,
      attachmentId: validated.id,
      chunkIndex: index,
      byteCount: bytes.byteLength
    });
    derived = await crypto.hkdfSha256({
      ikm: key,
      salt: ATTACHMENT_SALT,
      info: encoder.encode(`ATTACH:${validated.id}:${index}`),
      length: 32
    });
    nonce = crypto.randomBytes(NONCE_BYTES);
    encrypted = await crypto.aesGcmEncrypt({
      key: derived,
      nonce,
      plaintext: bytes,
      additionalData: context
    });
    if (!(encrypted instanceof Uint8Array) || encrypted.byteLength !== bytes.byteLength + TAG_BYTES) {
      throw new Error("Attachment encryption returned an invalid payload.");
    }
    const payload = Object.freeze({
      nonce: base64(nonce),
      ciphertext: base64(encrypted.subarray(0, -TAG_BYTES)),
      tag: base64(encrypted.subarray(-TAG_BYTES))
    });
    return Object.freeze({
      attachmentId: validated.id,
      chunkIndex: index,
      payload,
      ttlSeconds: validated.relayTTLSeconds,
      idempotencyKey: base64(await crypto.sha256(canonicalJsonBytes({
        domain: "org.noctweave.js/direct-attachment-upload/v1",
        attachmentId: validated.id,
        eventId: canonicalUUID(eventId, "Attachment event ID"),
        chunkIndex: index
      })))
    });
  } finally {
    bytes.fill(0);
    key.fill(0);
    wipe(derived);
    wipe(encrypted);
    wipe(nonce);
  }
}

export async function decryptDirectAttachmentChunkV1({
  crypto,
  descriptor,
  messageKey,
  conversationId,
  sessionId,
  messageCounter,
  chunk
}) {
  requireAttachmentCrypto(crypto);
  const validated = validateDirectAttachmentDescriptorV1(descriptor);
  const record = validateDirectAttachmentRelayChunkV1(chunk, validated);
  const key = copyBytes(messageKey, "Attachment message key");
  let derived;
  let nonce;
  let ciphertext;
  let tag;
  let combined;
  try {
    if (key.byteLength !== 32) throw new TypeError("Attachment message key is invalid.");
    nonce = decodeBase64(record.payload.nonce, NONCE_BYTES, "Attachment nonce");
    ciphertext = decodeBase64(
      record.payload.ciphertext,
      expectedChunkBytes(validated, record.chunkIndex),
      "Attachment ciphertext"
    );
    tag = decodeBase64(record.payload.tag, TAG_BYTES, "Attachment tag");
    combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.byteLength);
    derived = await crypto.hkdfSha256({
      ikm: key,
      salt: ATTACHMENT_SALT,
      info: encoder.encode(`ATTACH:${validated.id}:${record.chunkIndex}`),
      length: 32
    });
    const plaintext = await crypto.aesGcmDecrypt({
      key: derived,
      nonce,
      ciphertext: combined,
      additionalData: attachmentCryptoContext({
        conversationId,
        sessionId,
        messageCounter,
        attachmentId: validated.id,
        chunkIndex: record.chunkIndex,
        byteCount: ciphertext.byteLength
      })
    });
    if (!(plaintext instanceof Uint8Array) || plaintext.byteLength !== ciphertext.byteLength) {
      wipe(plaintext);
      throw new Error("Attachment decryption returned an invalid payload.");
    }
    return plaintext;
  } finally {
    key.fill(0);
    wipe(derived);
    wipe(nonce);
    wipe(ciphertext);
    wipe(tag);
    wipe(combined);
  }
}

export function validateDirectAttachmentRelayChunkV1(value, descriptor) {
  const validated = validateDirectAttachmentDescriptorV1(descriptor);
  exact(value, ["attachmentId", "chunkIndex", "payload"], "Attachment relay chunk");
  const index = attachmentChunkIndex(validated, value.chunkIndex);
  if (canonicalUUID(value.attachmentId, "Attachment chunk ID") !== validated.id) {
    throw new TypeError("Attachment relay chunk belongs to another attachment.");
  }
  exact(value.payload, ["nonce", "ciphertext", "tag"], "Encrypted attachment payload");
  canonicalBase64(value.payload.nonce, NONCE_BYTES, "Attachment nonce");
  canonicalBase64(
    value.payload.ciphertext,
    expectedChunkBytes(validated, index),
    "Attachment ciphertext"
  );
  canonicalBase64(value.payload.tag, TAG_BYTES, "Attachment tag");
  return Object.freeze({
    attachmentId: validated.id,
    chunkIndex: index,
    payload: Object.freeze({ ...value.payload })
  });
}

export function attachmentFallbackText(descriptor) {
  const mimeType = validateDirectAttachmentDescriptorV1(descriptor).mimeType.toLowerCase();
  if (mimeType.startsWith("audio/")) return "Voice message";
  if (mimeType.startsWith("image/")) return "Image";
  return "Attachment";
}

function attachmentCryptoContext({
  conversationId,
  sessionId,
  messageCounter,
  attachmentId,
  chunkIndex,
  byteCount
}) {
  for (const [label, value] of [["conversation ID", conversationId], ["session ID", sessionId]]) {
    if (typeof value !== "string" || value.length === 0 || value.trim() !== value ||
        encoder.encode(value).byteLength > 256) {
      throw new TypeError(`Attachment ${label} is invalid.`);
    }
  }
  integer(messageCounter, "Attachment message counter", 0, Number.MAX_SAFE_INTEGER);
  return encoder.encode(
    `${conversationId}:${sessionId}:${messageCounter}:${attachmentId}:${chunkIndex}:${byteCount}`
  );
}

function expectedChunkBytes(descriptor, chunkIndex) {
  return Math.min(
    descriptor.chunkSize,
    descriptor.byteCount - chunkIndex * descriptor.chunkSize
  );
}

function attachmentChunkIndex(descriptor, value) {
  return integer(value, "Attachment chunk index", 0, descriptor.chunkCount - 1);
}

function canonicalMIME(value) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value ||
      encoder.encode(value).byteLength > 128 || !/^[\x20-\x3a\x3c-\x7e]+$/u.test(value)) {
    throw new TypeError("Attachment MIME type is invalid.");
  }
  return value;
}

function canonicalUUID(value, label) {
  if (typeof value !== "string" ||
      !/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/u.test(value)) {
    throw new TypeError(`${label} must be a canonical Swift UUID.`);
  }
  return value;
}

function canonicalBase64(value, byteLength, label) {
  const decoded = decodeBase64(value, byteLength, label);
  try {
    return value;
  } finally {
    decoded.fill(0);
  }
}

function decodeBase64(value, byteLength, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} is invalid.`);
  }
  let decoded;
  try {
    const raw = atob(value);
    decoded = Uint8Array.from(raw, (character) => character.charCodeAt(0));
  } catch {
    throw new TypeError(`${label} is invalid.`);
  }
  if (decoded.byteLength !== byteLength || base64(decoded) !== value) {
    decoded.fill(0);
    throw new TypeError(`${label} is invalid.`);
  }
  return decoded;
}

function copyBytes(value, label) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  throw new TypeError(`${label} must be bytes.`);
}

function requireAttachmentCrypto(crypto) {
  for (const method of ["randomBytes", "sha256", "hkdfSha256", "aesGcmEncrypt", "aesGcmDecrypt"]) {
    if (typeof crypto?.[method] !== "function") {
      throw new TypeError(`Attachment cryptography requires ${method}(...).`);
    }
  }
}

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== [...fields].sort().join(",")) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}

function integer(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function wipe(value) {
  if (value instanceof Uint8Array) value.fill(0);
}
