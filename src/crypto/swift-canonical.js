export function canonicalJsonBytes(value) {
  return new TextEncoder().encode(canonicalJson(value));
}

export function canonicalJson(value) {
  return encodeCanonical(value, 0, new WeakSet());
}

const MAXIMUM_NESTING_DEPTH = 128;

function encodeCanonical(value, depth, ancestors) {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new TypeError("NCJ-1 permits only safe canonical integers.");
    }
    return String(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(normalizedUnicode(value));
  }
  if (Array.isArray(value)) {
    requireContainerDepth(depth);
    requireAcyclic(value, ancestors);
    try {
      return `[${value.map((child) => encodeCanonical(child, depth + 1, ancestors)).join(",")}]`;
    } finally {
      ancestors.delete(value);
    }
  }
  if (typeof value === "object") {
    requireContainerDepth(depth);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("NCJ-1 objects must be plain records.");
    }
    requireAcyclic(value, ancestors);
    try {
      const normalized = new Map();
      for (const [key, child] of Object.entries(value)) {
        const canonicalKey = normalizedUnicode(key);
        if (normalized.has(canonicalKey)) {
          throw new TypeError("NCJ-1 object keys collide after NFC normalization.");
        }
        normalized.set(canonicalKey, child);
      }
      const keys = [...normalized.keys()].sort(compareUTF8);
      return `{${keys.map((key) =>
        `${JSON.stringify(key)}:${encodeCanonical(normalized.get(key), depth + 1, ancestors)}`
      ).join(",")}}`;
    } finally {
      ancestors.delete(value);
    }
  }
  throw new TypeError("Value is outside the NCJ-1 protocol data model.");
}

function requireContainerDepth(depth) {
  if (depth >= MAXIMUM_NESTING_DEPTH) {
    throw new TypeError(`NCJ-1 nesting exceeds ${MAXIMUM_NESTING_DEPTH}.`);
  }
}

function requireAcyclic(value, ancestors) {
  if (ancestors.has(value)) {
    throw new TypeError("NCJ-1 cannot encode cyclic values.");
  }
  ancestors.add(value);
}

function normalizedUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xD800 && unit <= 0xDBFF) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) {
        throw new TypeError("NCJ-1 strings must contain valid Unicode scalars.");
      }
      index += 1;
    } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
      throw new TypeError("NCJ-1 strings must contain valid Unicode scalars.");
    }
  }
  return value.normalize("NFC");
}

function compareUTF8(left, right) {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const count = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < count; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) {
      return leftBytes[index] - rightBytes[index];
    }
  }
  return leftBytes.length - rightBytes.length;
}

export function base64(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function swiftISODate(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function swiftUUID() {
  return crypto.randomUUID().toUpperCase();
}
