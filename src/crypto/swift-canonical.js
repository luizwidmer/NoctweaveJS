export function canonicalJsonBytes(value) {
  return new TextEncoder().encode(canonicalJson(value));
}

export function canonicalJson(value) {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(",")}}`;
  }
  if (typeof value === "string") {
    return JSON.stringify(value).replaceAll("/", "\\/");
  }
  return JSON.stringify(value);
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
