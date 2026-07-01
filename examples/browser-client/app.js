import oqsFactory from "../../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  base64,
  canonicalJsonBytes,
  parseRelayEndpoint,
  relayRequests,
  swiftISODate,
  swiftUUID
} from "../../src/index.js";

const BECH32_CHARSET = Array.from("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const state = {
  crypto: new WebCryptoPrimitives(),
  pqc: null,
  identity: null,
  relayInfo: null
};

const elements = {
  status: document.querySelector("#status"),
  relay: document.querySelector("#relay"),
  connect: document.querySelector("#connect"),
  relayInfo: document.querySelector("#relayInfo"),
  createIdentity: document.querySelector("#createIdentity"),
  inbox: document.querySelector("#inbox"),
  fingerprint: document.querySelector("#fingerprint"),
  message: document.querySelector("#message"),
  send: document.querySelector("#send"),
  fetch: document.querySelector("#fetch"),
  messages: document.querySelector("#messages"),
  log: document.querySelector("#log")
};

elements.connect.addEventListener("click", () => runAction("Checking relay", checkRelay));
elements.createIdentity.addEventListener("click", () => runAction("Creating inbox", createIdentity));
elements.send.addEventListener("click", () => runAction("Sending", sendMessage));
elements.fetch.addEventListener("click", () => runAction("Fetching", fetchMessages));

runAction("Loading WASM", async () => {
  state.pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  log("WASM ready: " + JSON.stringify(state.pqc.profile()));
});

async function checkRelay() {
  const client = relayClient();
  const health = await client.health();
  const info = await client.info();
  state.relayInfo = info.relayInfo;
  elements.relayInfo.textContent = `${state.relayInfo?.relayName ?? "Relay"} | ${state.relayInfo?.softwareVersion ?? "unknown software"} | ${state.relayInfo?.transport ?? "unknown transport"}`;
  log(`health ${JSON.stringify(health)}`);
  log(`info ${JSON.stringify(info.relayInfo ?? info)}`);
}

async function createIdentity() {
  ensurePQC();
  const signing = state.pqc.generateSigningKeypair();
  const agreement = state.pqc.generateKemKeypair();
  const access = state.pqc.generateSigningKeypair();
  const inboxId = bech32Encode("noctweave", await state.crypto.sha256(access.publicKey));
  const accessFingerprint = base64(await state.crypto.sha256(access.publicKey));
  const signingFingerprint = base64(await state.crypto.sha256(signing.publicKey));
  const relayEndpoint = relayEndpointForContactOffer(parseRelayEndpoint(elements.relay.value));
  const unsignedContactOffer = {
    agreementPublicKey: base64(agreement.publicKey),
    displayName: "NoctweaveJS Browser",
    fingerprint: signingFingerprint,
    inboxAccessPublicKey: base64(access.publicKey),
    inboxId,
    relay: relayEndpoint,
    signingPublicKey: base64(signing.publicKey),
    version: 3
  };
  const contactOffer = {
    ...unsignedContactOffer,
    signature: base64(state.pqc.sign(canonicalJsonBytes(unsignedContactOffer), signing.secretKey))
  };
  const signedAt = swiftISODate();
  const nonce = swiftUUID();
  const registerRequest = relayRequests.registerInbox({
    inboxId,
    accessPublicKey: base64(access.publicKey),
    contactOffer,
    accessProof: actorProof({
      keypair: access,
      fingerprint: accessFingerprint,
      signedAt,
      nonce,
      payload: registerProofPayload(contactOffer, inboxId, access.publicKey, signedAt, nonce)
    })
  });
  const response = await relayClient().send(registerRequest);
  if (response.type !== "ok") {
    throw new Error(`Inbox registration failed: ${JSON.stringify(response)}`);
  }
  state.identity = { signing, agreement, access, inboxId, accessFingerprint, sent: [] };
  elements.inbox.textContent = inboxId;
  elements.fingerprint.textContent = accessFingerprint;
  log(`registered inbox ${inboxId}`);
}

async function sendMessage() {
  ensureIdentity();
  const plaintext = new TextEncoder().encode(elements.message.value);
  const ciphertext = await state.crypto.sha256(plaintext);
  const envelopeId = crypto.randomUUID();
  const envelope = {
    id: envelopeId,
    conversationId: `browser-${Date.now()}`,
    sessionId: "browser-session",
    senderFingerprint: "browser-smoke",
    sentAt: swiftISODate(),
    messageCounter: state.identity.sent.length + 1,
    kemCiphertext: null,
    prekey: null,
    rootRatchet: null,
    authenticatedContext: null,
    payload: {
      nonce: base64(state.crypto.randomBytes(12)),
      ciphertext: base64(ciphertext),
      tag: base64(state.crypto.randomBytes(16))
    },
    signature: base64(state.crypto.randomBytes(3309))
  };
  const response = await relayClient().send(relayRequests.deliver({ inboxId: state.identity.inboxId, envelope }));
  if (response.type !== "delivered") {
    throw new Error(`Deliver failed: ${JSON.stringify(response)}`);
  }
  state.identity.sent.push(envelope);
  log(`delivered ${envelopeId}`);
}

async function fetchMessages() {
  ensureIdentity();
  const maxCount = 20;
  const signedAt = swiftISODate();
  const nonce = swiftUUID();
  const response = await relayClient().send(relayRequests.fetch({
    inboxId: state.identity.inboxId,
    routingToken: null,
    maxCount,
    longPollTimeoutSeconds: null,
    accessProof: actorProof({
      keypair: state.identity.access,
      fingerprint: state.identity.accessFingerprint,
      signedAt,
      nonce,
      payload: {
        inboxId: state.identity.inboxId,
        maxCount,
        nonce,
        signedAt
      }
    })
  }));
  if (response.type !== "messages") {
    throw new Error(`Fetch failed: ${JSON.stringify(response)}`);
  }
  renderMessages(response.messages ?? []);
  log(`fetched ${(response.messages ?? []).length} message(s)`);
}

function relayClient() {
  const endpoint = elements.relay.value.trim();
  return new NoctweaveRelayClient(endpoint, {
    fetch: async (url, init) => {
      const path = new URL(url).pathname === "/health" ? "/proxy/health" : "/proxy/relay";
      return fetch(path, {
        ...init,
        headers: {
          ...(init?.headers ?? {}),
          "x-relay-endpoint": endpoint
        }
      });
    }
  });
}

function actorProof({ keypair, fingerprint, signedAt, nonce, payload }) {
  return {
    fingerprint,
    publicSigningKey: base64(keypair.publicKey),
    signedAt,
    nonce,
    signature: base64(state.pqc.sign(canonicalJsonBytes(payload), keypair.secretKey))
  };
}

function registerProofPayload(contactOffer, inboxId, accessPublicKey, signedAt, nonce) {
  return {
    accessPublicKey: base64(accessPublicKey),
    contactOffer,
    inboxId,
    nonce,
    signedAt
  };
}

function relayEndpointForContactOffer(endpoint) {
  return {
    host: endpoint.host,
    port: endpoint.port,
    useTLS: Boolean(endpoint.useTLS),
    transport: endpoint.transport ?? "http"
  };
}

function renderMessages(messages) {
  if (messages.length === 0) {
    elements.messages.textContent = "No messages fetched.";
    return;
  }
  elements.messages.innerHTML = "";
  for (const message of messages) {
    const item = document.createElement("div");
    item.className = "message";
    item.textContent = `${message.id} | ciphertext ${message.payload?.ciphertext?.length ?? 0} chars | ${message.sentAt}`;
    elements.messages.append(item);
  }
}

async function runAction(label, action) {
  setStatus(label);
  try {
    await action();
    setStatus("Ready");
  } catch (error) {
    setStatus("Error");
    log(error instanceof Error ? error.message : String(error));
    console.error(error);
  }
}

function ensurePQC() {
  if (!state.pqc) {
    throw new Error("WASM is still loading.");
  }
}

function ensureIdentity() {
  ensurePQC();
  if (!state.identity) {
    throw new Error("Create a test inbox first.");
  }
}

function setStatus(value) {
  elements.status.textContent = value;
}

function log(value) {
  elements.log.textContent = `${new Date().toLocaleTimeString()} ${value}\n${elements.log.textContent}`;
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
