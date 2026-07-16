import { base64, canonicalJsonBytes, swiftISODate } from "./crypto/swift-canonical.js";
import { bytes } from "./crypto/webcrypto.js";

const canonicalTimestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

export function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
  return value;
}

export function requireInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} must be an integer from ${minimum} through ${maximum}.`);
  }
  return value;
}

export function requireCanonicalTimestamp(value, label = "timestamp") {
  const encoded = value instanceof Date ? swiftISODate(value) : value;
  if (typeof encoded !== "string" || !canonicalTimestampPattern.test(encoded)) {
    throw new TypeError(`${label} must be a whole-second UTC timestamp.`);
  }
  const parsed = new Date(encoded);
  if (!Number.isFinite(parsed.getTime()) || swiftISODate(parsed) !== encoded || parsed.getTime() < 0) {
    throw new TypeError(`${label} is invalid.`);
  }
  return encoded;
}

export function timestampMilliseconds(value, label = "timestamp") {
  return new Date(requireCanonicalTimestamp(value, label)).getTime();
}

export function requireBase64(value, expectedLength, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be base64.`);
  }
  let decoded;
  try {
    const binary = atob(value);
    decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new TypeError(`${label} must be base64.`);
  }
  if (base64(decoded) !== value || (expectedLength !== undefined && decoded.byteLength !== expectedLength)) {
    throw new TypeError(`${label} has an invalid encoding or length.`);
  }
  return decoded;
}

export function encodeBase64(value, label = "value") {
  return base64(bytes(value, label));
}

export function requireNonzeroFixedBase64(value, length, label) {
  const decoded = requireBase64(value, length, label);
  if (!decoded.some((octet) => octet !== 0)) {
    throw new TypeError(`${label} must not be all zeroes.`);
  }
  return decoded;
}

export function equalBytes(leftValue, rightValue) {
  const left = bytes(leftValue, "left");
  const right = bytes(rightValue, "right");
  let difference = left.byteLength ^ right.byteLength;
  const length = Math.max(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function concatBytes(...values) {
  const inputs = values.map((value, index) => bytes(value, `value ${index}`));
  const output = new Uint8Array(inputs.reduce((total, input) => total + input.byteLength, 0));
  let offset = 0;
  for (const input of inputs) {
    output.set(input, offset);
    offset += input.byteLength;
  }
  return output;
}

export function uint16Bytes(value) {
  requireInteger(value, "UInt16", 0, 0xffff);
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

export function uint32Bytes(value) {
  requireInteger(value, "UInt32", 0, 0xffffffff);
  return Uint8Array.of(
    Math.floor(value / 0x1000000) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  );
}

export function uint64Bytes(value) {
  if ((typeof value !== "bigint" && !Number.isSafeInteger(value)) || BigInt(value) < 0n || BigInt(value) > 0xffffffffffffffffn) {
    throw new TypeError("UInt64 is out of range.");
  }
  let remaining = BigInt(value);
  const output = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

export function lengthPrefixed(value) {
  const data = bytes(value, "length-prefixed value");
  if (data.byteLength > 0xffffffff) {
    throw new TypeError("Length-prefixed value exceeds UInt32.");
  }
  return concatBytes(uint32Bytes(data.byteLength), data);
}

export function timestampBytes(value) {
  const milliseconds = timestampMilliseconds(value);
  return uint64Bytes(BigInt(milliseconds / 1_000));
}

export async function cryptoSha256(crypto, value) {
  if (typeof crypto?.sha256 !== "function") {
    throw new TypeError("A SHA-256 implementation is required.");
  }
  const digest = bytes(await crypto.sha256(bytes(value, "SHA-256 input")), "SHA-256 digest");
  if (digest.byteLength !== 32) {
    throw new Error("SHA-256 returned an invalid digest length.");
  }
  return new Uint8Array(digest);
}

export async function cryptoHmacSha256(crypto, { key, data }) {
  const implementation = typeof crypto?.hmacSha256 === "function"
    ? crypto
    : crypto?.webcrypto;
  if (typeof implementation?.hmacSha256 !== "function") {
    throw new TypeError("An HMAC-SHA-256 implementation is required.");
  }
  const mac = bytes(await implementation.hmacSha256({ key, data }), "HMAC-SHA-256 result");
  if (mac.byteLength !== 32) {
    throw new Error("HMAC-SHA-256 returned an invalid MAC length.");
  }
  return new Uint8Array(mac);
}

export async function cryptoHkdfSha256(crypto, input) {
  if (typeof crypto?.hkdfSha256 !== "function") {
    throw new TypeError("An HKDF-SHA-256 implementation is required.");
  }
  return new Uint8Array(await crypto.hkdfSha256(input));
}

export async function cryptoRandomBytes(crypto, length) {
  if (typeof crypto?.randomBytes !== "function") {
    throw new TypeError("A cryptographically secure random-byte implementation is required.");
  }
  const result = bytes(await crypto.randomBytes(length), "random bytes");
  if (result.byteLength !== length) {
    throw new Error("The random-byte implementation returned an invalid length.");
  }
  return new Uint8Array(result);
}

export function swiftCanonicalBytes(value) {
  return canonicalJsonBytes(value);
}

export function freezeWire(value) {
  if (Array.isArray(value)) {
    return Object.freeze(value.map(freezeWire));
  }
  if (value instanceof Uint8Array || value === null || typeof value !== "object") {
    return value;
  }
  return Object.freeze(Object.fromEntries(
    Object.entries(value).map(([key, child]) => [key, freezeWire(child)])
  ));
}
