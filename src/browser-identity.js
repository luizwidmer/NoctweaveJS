import { parseRelayEndpoint } from "./endpoint.js";
import { NoctweaveRelayClient } from "./relay-client.js";
import { relayRequests } from "./requests.js";
import { makeNativeContactOffer } from "./crypto/noctweave-native-message.js";
import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./crypto/swift-canonical.js";

const encoder = new TextEncoder();
const BECH32_CHARSET = Array.from("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

export class NoctweaveBrowserIdentityService {
  constructor({ pqc, crypto, relayClientFactory } = {}) {
    if (!pqc?.generateSigningKeypair || !pqc?.generateKemKeypair || !pqc?.sign) {
      throw new TypeError("A compatible Noctweave post-quantum adapter is required.");
    }
    if (!crypto?.sha256) {
      throw new TypeError("Compatible Noctweave WebCrypto primitives are required.");
    }
    this.pqc = pqc;
    this.crypto = crypto;
    this.relayClientFactory = relayClientFactory ?? ((endpoint, options) => (
      new NoctweaveRelayClient(endpoint, options)
    ));
  }

  async verifyRelay(endpoint, options = {}) {
    const parsed = parseBrowserRelayEndpoint(endpoint);
    const client = this.relayClientFactory(endpoint, {
      authToken: normalizedOptionalSecret(options.authToken),
      fetch: options.fetch,
      WebSocket: options.WebSocket,
      timeoutMs: options.timeoutMs
    });
    const [health, info] = await Promise.all([client.health(), client.info()]);
    if (!health || (health.type !== "ok" && health.type !== "health")) {
      throw new Error("The relay health check returned an incompatible response.");
    }
    if (info?.type !== "info" || !info.relayInfo || info.relayInfo.kind === "coordinator") {
      throw new Error("The address did not return a compatible client-facing Noctweave relay profile.");
    }
    return { endpoint: parsed, health, info };
  }

  async createAndRegister({ displayName, relay, authToken, fetch, WebSocket, timeoutMs } = {}) {
    const normalizedName = validateBrowserDisplayName(displayName);
    const verified = await this.verifyRelay(relay, { authToken, fetch, WebSocket, timeoutMs });
    const signing = this.pqc.generateSigningKeypair();
    const agreement = this.pqc.generateKemKeypair();
    const access = this.pqc.generateSigningKeypair();
    validateGeneratedKeypair(signing, "signing");
    validateGeneratedKeypair(agreement, "agreement");
    validateGeneratedKeypair(access, "inbox access");

    const accessDigest = await this.crypto.sha256(access.publicKey);
    const signingDigest = await this.crypto.sha256(signing.publicKey);
    const inboxId = bech32Encode("noctweave", accessDigest);
    const identity = {
      displayName: normalizedName,
      signing: serializeKeypair(signing),
      agreement: serializeKeypair(agreement),
      access: serializeKeypair(access),
      inboxId,
      accessFingerprint: base64(accessDigest),
      signingFingerprint: base64(signingDigest)
    };
    const contactOffer = makeNativeContactOffer({
      pqc: this.pqc,
      identity,
      relayEndpoint: relayEndpointForContactOffer(verified.endpoint)
    });
    const signedAt = swiftISODate();
    const nonce = swiftUUID();
    const payload = {
      accessPublicKey: base64(access.publicKey),
      contactOffer,
      inboxId,
      nonce,
      signedAt
    };
    const request = relayRequests.registerInbox({
      inboxId,
      accessPublicKey: base64(access.publicKey),
      contactOffer,
      accessProof: {
        fingerprint: identity.accessFingerprint,
        publicSigningKey: base64(access.publicKey),
        signedAt,
        nonce,
        signature: base64(this.pqc.sign(canonicalJsonBytes(payload), access.secretKey))
      }
    });
    const client = this.relayClientFactory(relay, {
      authToken: normalizedOptionalSecret(authToken),
      fetch,
      WebSocket,
      timeoutMs
    });
    const response = await client.send(request);
    if (response?.type !== "ok") {
      throw new Error("The relay rejected inbox registration.");
    }
    return {
      identity: { ...identity, contactOffer },
      relay: {
        address: String(relay).trim(),
        endpoint: verified.endpoint,
        relayInfo: verified.info.relayInfo,
        verifiedAt: new Date().toISOString()
      }
    };
  }
}

export function validateBrowserDisplayName(value) {
  if (typeof value !== "string") {
    throw new TypeError("Display name is required.");
  }
  const normalized = value.trim().replace(/\s+/gu, " ");
  const byteLength = encoder.encode(normalized).byteLength;
  if (normalized.length < 1 || byteLength > 128 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError("Display name must contain 1 to 128 UTF-8 bytes without control characters.");
  }
  return normalized;
}

export function parseBrowserRelayEndpoint(value) {
  const endpoint = parseRelayEndpoint(value);
  if (endpoint.transport === "tcp") {
    throw new TypeError("The browser client requires an HTTP, HTTPS, WS, or WSS relay URL.");
  }
  return endpoint;
}

function normalizedOptionalSecret(value) {
  if (value == null || value === "") {
    return null;
  }
  if (typeof value !== "string" || encoder.encode(value).byteLength > 4096) {
    throw new TypeError("Relay access password must not exceed 4096 UTF-8 bytes.");
  }
  return value;
}

function validateGeneratedKeypair(value, label) {
  if (!(value?.publicKey instanceof Uint8Array) || !(value?.secretKey instanceof Uint8Array) ||
      value.publicKey.byteLength === 0 || value.secretKey.byteLength === 0) {
    throw new Error(`Post-quantum ${label} key generation failed.`);
  }
}

function serializeKeypair(keypair) {
  return {
    publicKey: base64(keypair.publicKey),
    secretKey: base64(keypair.secretKey)
  };
}

function relayEndpointForContactOffer(endpoint) {
  return {
    host: endpoint.host,
    port: endpoint.port,
    useTLS: Boolean(endpoint.useTLS),
    transport: endpoint.transport
  };
}

function bech32Encode(hrp, data) {
  const words = convertBits(data, 8, 5, true);
  const checksum = createChecksum(hrp, words);
  return `${hrp}1${[...words, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
}

function createChecksum(hrp, data) {
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  return Array.from({ length: 6 }, (_, index) => (polymod >> (5 * (5 - index))) & 31);
}

function hrpExpand(hrp) {
  return [
    ...Array.from(hrp, (character) => character.charCodeAt(0) >> 5),
    0,
    ...Array.from(hrp, (character) => character.charCodeAt(0) & 31)
  ];
}

function bech32Polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) {
      if ((top >> index) & 1) {
        checksum ^= BECH32_GENERATOR[index];
      }
    }
  }
  return checksum;
}

function convertBits(data, from, to, pad) {
  let accumulator = 0;
  let bits = 0;
  const output = [];
  const maximum = (1 << to) - 1;
  for (const value of data) {
    accumulator = (accumulator << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      output.push((accumulator >> bits) & maximum);
    }
  }
  if (pad && bits > 0) {
    output.push((accumulator << (to - bits)) & maximum);
  }
  return output;
}
