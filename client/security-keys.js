// SPDX-License-Identifier: Apache-2.0
// Local FIDO2 verification and PRF wrapping. These credentials are never messaging identities.
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const fail = () => { throw new Error("Security key verification failed. The vault remains locked."); };
const ensure = (condition) => { if (!condition) fail(); };
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const join = (...parts) => new Uint8Array(parts.flatMap((part) => [...part]));
const random = (crypto, size) => crypto.getRandomValues(new Uint8Array(size));
const hash = async (crypto, bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

export function base64URL(bytes) {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function decodeBase64URL(value, maximum = 65_536) {
  ensure(typeof value === "string" && value.length <= Math.ceil(maximum * 4 / 3)
    && /^[A-Za-z0-9_-]*$/.test(value));
  const bytes = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), (v) => v.charCodeAt(0));
  ensure(bytes.length <= maximum && base64URL(bytes) === value);
  return bytes;
}

// Definite-length, bounded CBOR only. Reject duplicate keys and non-minimal encodings.
export function parseSecurityKeyCBOR(bytes, start = 0) {
  ensure(bytes instanceof Uint8Array && bytes.length <= 65_536);
  let offset = start;
  const read = (count) => { ensure(offset + count <= bytes.length); const value = bytes.slice(offset, offset + count); offset += count; return value; };
  const item = (depth) => {
    ensure(depth <= 8);
    const first = read(1)[0], major = first >> 5, additional = first & 31;
    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      fail();
    }
    ensure(major <= 5 && additional <= 26);
    let length = additional;
    if (additional >= 24) {
      const size = 2 ** (additional - 24);
      length = read(size).reduce((n, byte) => n * 256 + byte, 0);
      ensure(length >= (size === 1 ? 24 : 2 ** ((size / 2) * 8)));
    }
    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2) return read(length);
    if (major === 3) return decoder.decode(read(length));
    ensure(length <= 64);
    if (major === 4) return Array.from({ length }, () => item(depth + 1));
    const map = new Map();
    for (let i = 0; i < length; i++) {
      const key = item(depth + 1);
      ensure((typeof key === "string" || Number.isInteger(key)) && !map.has(key));
      map.set(key, item(depth + 1));
    }
    return map;
  };
  return { value: item(0), offset };
}

function finishData(authData, offset, flags) {
  if (flags & 0x80) {
    const extensions = parseSecurityKeyCBOR(authData, offset);
    ensure(extensions.value instanceof Map);
    offset = extensions.offset;
  }
  ensure(offset === authData.length);
}

async function verifyEnvelope(response, ceremony, type, crypto) {
  ensure(response && JSON.stringify(response).length <= 131_072
    && response.type === "public-key" && response.authenticatorAttachment === "cross-platform"
    && response.id === response.rawId && response.response);
  ensure(Date.now() < ceremony.expiresAt && ceremony.expiresAt - Date.now() <= 60_100);
  const clientData = decodeBase64URL(response.response.clientDataJSON, 8_192);
  const client = JSON.parse(decoder.decode(clientData));
  ensure(client.type === type && client.challenge === ceremony.challenge && client.origin === ceremony.origin
    && client.topOrigin === undefined && (client.crossOrigin === undefined || client.crossOrigin === false));
  let authData;
  if (type === "webauthn.create") {
    const attestation = decodeBase64URL(response.response.attestationObject);
    const parsed = parseSecurityKeyCBOR(attestation);
    ensure(parsed.offset === attestation.length && parsed.value instanceof Map);
    authData = parsed.value.get("authData");
  } else authData = decodeBase64URL(response.response.authenticatorData);
  ensure(authData instanceof Uint8Array && authData.length >= 37
    && equal(authData.slice(0, 32), await hash(crypto, encoder.encode(ceremony.rpID))));
  const flags = authData[32];
  ensure((flags & 5) === 5 && (flags & 0x3a) === 0 && Boolean(flags & 0x40) === (type === "webauthn.create"));
  const counter = new DataView(authData.buffer, authData.byteOffset).getUint32(33);
  return { authData, flags, counter, clientData };
}

export async function verifySecurityKeyRegistration(response, ceremony, crypto = globalThis.crypto) {
  const { authData, flags, counter } = await verifyEnvelope(response, ceremony, "webauthn.create", crypto);
  ensure(authData.length >= 55);
  const length = (authData[53] << 8) | authData[54];
  ensure(length > 0 && length <= 1_024 && equal(authData.slice(55, 55 + length), decodeBase64URL(response.rawId, 1_024)));
  const { value: cose, offset } = parseSecurityKeyCBOR(authData, 55 + length);
  ensure(cose instanceof Map && cose.get(1) === 2 && cose.get(3) === -7 && cose.get(-1) === 1);
  const x = cose.get(-2), y = cose.get(-3);
  ensure(x instanceof Uint8Array && x.length === 32 && y instanceof Uint8Array && y.length === 32);
  finishData(authData, offset, flags);
  const publicKey = join([4], x, y);
  await crypto.subtle.importKey("raw", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return { id: response.rawId, publicKey: base64URL(publicKey), counter };
}

function rawSignature(der) {
  ensure(der.length >= 8 && der.length <= 72 && der[0] === 0x30 && der[1] === der.length - 2);
  let offset = 2;
  const integer = () => {
    ensure(der[offset++] === 2);
    const size = der[offset++];
    ensure(size >= 1 && size <= 33 && offset + size <= der.length);
    let value = der.slice(offset, offset + size); offset += size;
    ensure((value[0] & 0x80) === 0);
    if (value[0] === 0 && value.length > 1) {
      ensure((value[1] & 0x80) !== 0); value = value.slice(1);
    }
    ensure(value.length <= 32);
    const padded = new Uint8Array(32); padded.set(value, 32 - value.length); return padded;
  };
  const signature = join(integer(), integer());
  ensure(offset === der.length);
  return signature;
}

export async function verifySecurityKeyAssertion(response, ceremony, keys, crypto = globalThis.crypto) {
  const { authData, flags, counter, clientData } = await verifyEnvelope(response, ceremony, "webauthn.get", crypto);
  const key = keys.find((key) => key.id === response.rawId);
  ensure(key && ((counter === 0 && key.counter === 0) || counter > key.counter));
  finishData(authData, 37, flags);
  const publicKey = await crypto.subtle.importKey("raw", decodeBase64URL(key.publicKey, 65),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  ensure(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey,
    rawSignature(decodeBase64URL(response.response.signature, 72)), join(authData, await hash(crypto, clientData))));
  return { ...key, counter };
}

export function validateSecurityKeyEntries(entries) {
  ensure(Array.isArray(entries) && entries.length <= 8 && new Set(entries.map((key) => key.id)).size === entries.length);
  const fields = ["version", "name", "id", "publicKey", "counter", "rpID", "origin", "prfSalt", "wrapSalt", "nonce", "wrappedPassphrase"].sort().join(",");
  for (const entry of entries) {
    ensure(entry && Object.keys(entry).sort().join(",") === fields && entry.version === 1
      && typeof entry.name === "string" && entry.name.trim() && encoder.encode(entry.name).length <= 128
      && Number.isInteger(entry.counter) && entry.counter >= 0 && entry.counter <= 0xffffffff
      && typeof entry.rpID === "string" && entry.rpID.length > 0 && entry.rpID.length <= 253
      && typeof entry.origin === "string" && entry.origin.length <= 512);
    ensure(decodeBase64URL(entry.id, 1_024).length > 0 && decodeBase64URL(entry.publicKey, 65).length === 65
      && decodeBase64URL(entry.prfSalt, 32).length === 32 && decodeBase64URL(entry.wrapSalt, 32).length === 32
      && decodeBase64URL(entry.nonce, 12).length === 12 && decodeBase64URL(entry.wrappedPassphrase, 4_112).length >= 28);
  }
  return entries;
}

function ceremony(authenticator, crypto) {
  const { rpID, origin } = authenticator;
  ensure(typeof rpID === "string" && rpID.length > 0 && rpID.length <= 253 && typeof origin === "string");
  return { rpID, origin, challenge: base64URL(random(crypto, 32)), expiresAt: Date.now() + 60_000 };
}

async function authenticate(keys, authenticator, signal, crypto) {
  signal?.throwIfAborted();
  const request = ceremony(authenticator, crypto);
  const eligible = keys.filter((key) => key.rpID === request.rpID && key.origin === request.origin);
  ensure(eligible.length > 0 && eligible.length <= 8);
  const response = await authenticator.get({ rpId: request.rpID, challenge: request.challenge,
    timeout: 55_000, userVerification: "required", hints: ["security-key"],
    allowCredentials: eligible.map(({ id }) => ({ type: "public-key", id })),
    extensions: { prf: { evalByCredential: Object.fromEntries(eligible.map(({ id, prfSalt }) => [id, { first: prfSalt }])) } }
  }, signal);
  signal?.throwIfAborted();
  const key = await verifySecurityKeyAssertion(response, request, eligible, crypto);
  const output = response.clientExtensionResults?.prf?.results?.first;
  if (!output) throw new Error("This key or browser does not provide FIDO2 PRF. Use your passphrase or a compatible key.");
  const secret = decodeBase64URL(output, 32); ensure(secret.length === 32);
  return { key, secret };
}

async function wrappingKey(secret, entry, scope, crypto) {
  const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: decodeBase64URL(entry.wrapSalt, 32),
    info: encoder.encode(JSON.stringify(["noctweavejs-vault-security-key-v1", scope, entry.rpID, entry.origin, entry.id])) },
  material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function wrappingParameters(entry, scope) {
  return { name: "AES-GCM", iv: decodeBase64URL(entry.nonce, 12), tagLength: 128,
    additionalData: encoder.encode(JSON.stringify([entry.version, scope, entry.rpID, entry.origin,
      entry.id, entry.publicKey, entry.prfSalt, entry.wrapSalt])) };
}

export async function createSecurityKeyEntry({ passphrase, name, keys, scope, authenticator, signal, crypto = globalThis.crypto }) {
  ensure(keys.length < 8 && typeof name === "string" && name.trim() && encoder.encode(name).length <= 128
    && typeof passphrase === "string" && passphrase.length >= 12 && encoder.encode(passphrase).length <= 4_096);
  signal?.throwIfAborted();
  const request = ceremony(authenticator, crypto);
  const response = await authenticator.create({ challenge: request.challenge, timeout: 55_000,
    rp: { id: request.rpID, name: "NoctweaveJS local vault" },
    user: { id: base64URL(random(crypto, 32)), name: "Local vault unlock", displayName: "Local vault unlock" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], attestation: "none",
    authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "discouraged", userVerification: "required" },
    excludeCredentials: keys.filter((key) => key.rpID === request.rpID).map(({ id }) => ({ type: "public-key", id })),
    extensions: { prf: {} }
  }, signal);
  signal?.throwIfAborted();
  const provisional = await verifySecurityKeyRegistration(response, request, crypto);
  ensure(!keys.some((key) => key.id === provisional.id));
  const entry = { ...provisional, version: 1, name: name.trim(), rpID: request.rpID, origin: request.origin,
    prfSalt: base64URL(random(crypto, 32)), wrapSalt: base64URL(random(crypto, 32)), nonce: base64URL(random(crypto, 12)) };
  const { key, secret } = await authenticate([entry], authenticator, signal, crypto);
  const plaintext = encoder.encode(passphrase);
  try {
    const wrapping = await wrappingKey(secret, key, scope, crypto);
    const wrapped = await crypto.subtle.encrypt(wrappingParameters(key, scope), wrapping, plaintext);
    signal?.throwIfAborted();
    return validateSecurityKeyEntries([{ ...key, wrappedPassphrase: base64URL(new Uint8Array(wrapped)) }])[0];
  } finally { secret.fill(0); plaintext.fill(0); }
}

export async function openWithSecurityKey({ keys, scope, authenticator, signal, crypto = globalThis.crypto }) {
  validateSecurityKeyEntries(keys);
  const { key, secret } = await authenticate(keys, authenticator, signal, crypto);
  let plaintext;
  try {
    const wrapping = await wrappingKey(secret, key, scope, crypto);
    plaintext = new Uint8Array(await crypto.subtle.decrypt(wrappingParameters(key, scope), wrapping,
      decodeBase64URL(key.wrappedPassphrase, 4_112)));
    signal?.throwIfAborted();
    return { key, passphrase: decoder.decode(plaintext) };
  } finally { secret.fill(0); plaintext?.fill(0); }
}

export function securityKeyAuthenticator({ pin = "" } = {}) {
  const desktop = globalThis.__noctweaveDesktopSecurityKeys;
  if (desktop?.available) {
    const perform = async (operation, options, signal) => {
      signal?.throwIfAborted();
      const cancel = () => { void desktop.cancel(); };
      signal?.addEventListener("abort", cancel, { once: true });
      let completed = false;
      try {
        const result = await desktop.request({ operation, options, pin });
        signal?.throwIfAborted();
        if (result.error) throw new Error(result.message || "Security key request failed.");
        completed = true;
        return result.credential;
      } finally {
        signal?.removeEventListener("abort", cancel);
        // Registration uses create + get; retain the PIN only between those two ceremonies.
        // Presence leases can outlive authentication and must never retain it.
        if (operation === "get" || !completed) pin = "";
      }
    };
    return { rpID: desktop.rpID, origin: desktop.origin,
      continuousPresence: desktop.continuousPresence === true,
      isPresent: async (id) => { const status = await desktop.presence(); return status.present && status.credentialID === id; },
      releasePresence: () => desktop.releasePresence(),
      clearPIN: () => { pin = ""; },
      create: (options, signal) => perform("create", options, signal),
      get: (options, signal) => perform("get", options, signal) };
  }
  if (desktop || !globalThis.isSecureContext || !globalThis.PublicKeyCredential || !globalThis.navigator?.credentials) return null;
  const convert = (value, key = "") => {
    if (typeof value === "string" && ["id", "challenge", "first", "second"].includes(key)) return decodeBase64URL(value);
    if (Array.isArray(value)) return value.map((item) => convert(item));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) =>
      [k, k === "rp" ? v : convert(v, k)]));
    return value;
  };
  const serialize = (value) => {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return base64URL(new Uint8Array(value.buffer ?? value, value.byteOffset ?? 0, value.byteLength));
    if (Array.isArray(value)) return value.map(serialize);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, serialize(v)]));
    return value;
  };
  const perform = async (operation, options, signal) => {
    const result = await navigator.credentials[operation]({ publicKey: convert(options), signal });
    if (!result) fail();
    const response = result.response;
    return { type: result.type, id: result.id, rawId: base64URL(new Uint8Array(result.rawId)),
      authenticatorAttachment: result.authenticatorAttachment,
      response: Object.fromEntries(["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]
        .filter((field) => response[field] != null).map((field) => [field, base64URL(new Uint8Array(response[field]))])),
      clientExtensionResults: serialize(result.getClientExtensionResults()) };
  };
  return { rpID: location.hostname, origin: location.origin,
    create: (options, signal) => perform("create", options, signal),
    get: (options, signal) => perform("get", options, signal) };
}
