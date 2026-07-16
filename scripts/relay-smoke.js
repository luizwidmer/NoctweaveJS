#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  relayRequests
} from "../src/index.js";

const BECH32_CHARSET = Array.from("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const options = parseArgs(process.argv.slice(2));
const endpoint = options.relay ?? "http://127.0.0.1:9339";
const crypto = new WebCryptoPrimitives();
const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
const client = new NoctweaveRelayClient(endpoint, {
  authToken: options.authToken,
  timeoutMs: Number(options.timeoutMs ?? 8000)
});

const access = pqc.generateSigningKeypair();
const inboxId = options.inbox ?? bech32Encode("noctweave", await crypto.sha256(access.publicKey));
const accessFingerprint = base64(await crypto.sha256(access.publicKey));
const messageText = options.text ?? `NoctweaveJS relay smoke ${swiftISODate()}`;
const encodedMessage = new TextEncoder().encode(messageText);
const ciphertext = await crypto.sha256(encodedMessage);
const nonce = crypto.randomBytes(12);
const tag = crypto.randomBytes(16);
const signature = crypto.randomBytes(3309);
const envelopeId = randomUUID();

console.log(`Relay: ${endpoint}`);
const health = await client.health();
console.log(`Health: ${JSON.stringify(health)}`);

const info = await client.info();
console.log(`Info: ${info.relayInfo?.relayName ?? info.type ?? "unknown"}`);

const registerSignedAt = swiftISODate();
const registerNonce = swiftUUID();
const registerProof = actorProof({
  keypair: access,
  fingerprint: accessFingerprint,
  signedAt: registerSignedAt,
  nonce: registerNonce,
  payload: registerProofPayload(inboxId, access.publicKey, registerSignedAt, registerNonce)
});

const registerRequest = relayRequests.registerInbox({
  inboxId,
  accessPublicKey: base64(access.publicKey),
  registrationVersion: 2,
  accessProof: registerProof
});

if (options.debugDir) {
  mkdirSync(options.debugDir, { recursive: true });
  writeFileSync(`${options.debugDir}/register-request.json`, JSON.stringify(registerRequest, null, 2));
  writeFileSync(
    `${options.debugDir}/register-signable-js.json`,
    canonicalJson(registerProofPayload(inboxId, access.publicKey, registerSignedAt, registerNonce))
  );
}

const registerResponse = await client.send(registerRequest);

if (registerResponse.type !== "ok") {
  console.error(`Relay did not register the inbox: ${JSON.stringify(registerResponse)}`);
  process.exit(1);
}
console.log("Registered: ok");

const envelope = {
  id: envelopeId,
  conversationId: options.conversationId ?? `js-smoke-${Date.now()}`,
  sessionId: options.sessionId ?? "js-smoke-session",
  senderFingerprint: options.senderFingerprint ?? "js-smoke-sender",
  sentAt: swiftISODate(),
  messageCounter: Number(options.messageCounter ?? 1),
  kemCiphertext: options.kemCiphertext ?? null,
  prekey: null,
  rootRatchet: null,
  authenticatedContext: null,
  payload: {
    nonce: base64(nonce),
    ciphertext: base64(ciphertext),
    tag: base64(tag)
  },
  signature: base64(signature)
};

const response = await client.send(
  relayRequests.deliver({
    inboxId,
    routingToken: options.routingToken,
    envelope
  })
);

if (response.type !== "delivered") {
  console.error(`Relay did not accept the message: ${JSON.stringify(response)}`);
  process.exit(1);
}

console.log(`Delivered: ${response.delivered?.storedCount ?? "accepted"}`);

const fetchSignedAt = swiftISODate();
const fetchNonce = swiftUUID();
const maxCount = 5;
const fetchProof = actorProof({
  keypair: access,
  fingerprint: accessFingerprint,
  signedAt: fetchSignedAt,
  nonce: fetchNonce,
  payload: {
    inboxId,
    maxCount,
    nonce: fetchNonce,
    signedAt: fetchSignedAt
  }
});

const fetchResponse = await client.send(
  relayRequests.fetch({
    inboxId,
    routingToken: null,
    maxCount,
    longPollTimeoutSeconds: null,
    accessProof: fetchProof
  })
);

if (fetchResponse.type !== "messages") {
  console.error(`Relay did not return messages: ${JSON.stringify(fetchResponse)}`);
  process.exit(1);
}

const fetched = fetchResponse.messages?.find((message) => message.id?.toLowerCase() === envelopeId.toLowerCase());
if (!fetched) {
  console.error(`Fetch did not include delivered envelope ${envelopeId}: ${JSON.stringify(fetchResponse)}`);
  process.exit(1);
}
if (fetched.payload?.ciphertext !== envelope.payload.ciphertext) {
  console.error("Fetched payload did not match delivered encoded ciphertext.");
  process.exit(1);
}
console.log(`Fetched: ${fetchResponse.messages.length} message(s), matched envelope ${envelopeId}`);
console.log(`Inbox: ${inboxId}`);
console.log(`Envelope: ${envelopeId}`);
console.log(`Encoded payload: nonce=${envelope.payload.nonce.length}b64 ciphertext=${envelope.payload.ciphertext.length}b64 tag=${envelope.payload.tag.length}b64`);

function actorProof({ keypair, fingerprint, signedAt, nonce, payload }) {
  return {
    fingerprint,
    publicSigningKey: base64(keypair.publicKey),
    signedAt,
    nonce,
    signature: base64(pqc.sign(canonicalJsonBytes(payload), keypair.secretKey))
  };
}

function registerProofPayload(inboxId, accessPublicKey, signedAt, nonce) {
  return {
    accessPublicKey: base64(accessPublicKey),
    inboxId,
    nonce,
    registrationVersion: 2,
    signedAt
  };
}

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!arg.startsWith("--")) {
      continue;
    }
    const key = arg.slice(2);
    const value = args[index + 1]?.startsWith("--") ? "true" : args[++index];
    parsed[toCamelCase(key)] = value;
  }
  return parsed;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
}

function base64(value) {
  return Buffer.from(value).toString("base64");
}

function canonicalJsonBytes(value) {
  return new TextEncoder().encode(canonicalJson(value));
}

function canonicalJson(value) {
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
    return swiftJSONString(value);
  }
  return JSON.stringify(value);
}

function swiftJSONString(value) {
  return JSON.stringify(value).replaceAll("/", "\\/");
}

function randomUUID() {
  return globalThis.crypto?.randomUUID?.() ?? crypto.randomBytes(16).reduce((id, byte) => id + byte.toString(16).padStart(2, "0"), "");
}

function swiftUUID() {
  return randomUUID().toUpperCase();
}

function swiftISODate(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function bech32Encode(hrp, data) {
  const data5 = convertBits(Array.from(data), 8, 5, true);
  const checksum = createChecksum(hrp.toLowerCase(), data5);
  return `${hrp.toLowerCase()}1${[...data5, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
}

function createChecksum(hrp, data) {
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const checksum = [];
  for (let index = 0; index < 6; index++) {
    checksum.push((polymod >> (5 * (5 - index))) & 0x1f);
  }
  return checksum;
}

function hrpExpand(hrp) {
  const bytes = Array.from(new TextEncoder().encode(hrp));
  return [...bytes.map((byte) => byte >> 5), 0, ...bytes.map((byte) => byte & 31)];
}

function bech32Polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index++) {
      if (((top >> index) & 1) !== 0) {
        checksum ^= BECH32_GENERATOR[index];
      }
    }
  }
  return checksum;
}

function convertBits(data, from, to, pad) {
  let accumulator = 0;
  let bits = 0;
  const maxValue = (1 << to) - 1;
  const result = [];
  for (const value of data) {
    if (value >> from !== 0) {
      throw new Error("Invalid Bech32 data value.");
    }
    accumulator = (accumulator << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      result.push((accumulator >> bits) & maxValue);
    }
  }
  if (pad && bits > 0) {
    result.push((accumulator << (to - bits)) & maxValue);
  }
  return result;
}
