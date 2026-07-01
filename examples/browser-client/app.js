import oqsFactory from "../../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  base64,
  canonicalJsonBytes,
  createNativeInboundSession,
  createNativeOutboundSession,
  decodeNativeContactCode,
  decryptNativeEnvelope,
  encodeNativeContactCode,
  encryptNativeTextEnvelope,
  makeNativeContactOffer,
  nativeConversationKey,
  parseRelayEndpoint,
  relayRequests,
  swiftISODate,
  swiftUUID,
  verifyNativeContactOffer
} from "../../src/index.js";

const BECH32_CHARSET = Array.from("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const encoder = new TextEncoder();
const profile = new URL(location.href).searchParams.get("profile") || "default";
const storageKey = `noctweave-js-browser-client:${profile}`;

const state = {
  crypto: new WebCryptoPrimitives(),
  pqc: null,
  identity: null,
  contacts: [],
  conversations: {},
  messages: [],
  seenEnvelopeIds: new Set()
};

const elements = {
  status: document.querySelector("#status"),
  relay: document.querySelector("#relay"),
  connect: document.querySelector("#connect"),
  relayInfo: document.querySelector("#relayInfo"),
  createIdentity: document.querySelector("#createIdentity"),
  resetProfile: document.querySelector("#resetProfile"),
  profile: document.querySelector("#profile"),
  inbox: document.querySelector("#inbox"),
  fingerprint: document.querySelector("#fingerprint"),
  contactCode: document.querySelector("#contactCode"),
  copyCode: document.querySelector("#copyCode"),
  peerCode: document.querySelector("#peerCode"),
  importContact: document.querySelector("#importContact"),
  contacts: document.querySelector("#contacts"),
  message: document.querySelector("#message"),
  send: document.querySelector("#send"),
  fetch: document.querySelector("#fetch"),
  chat: document.querySelector("#chat"),
  log: document.querySelector("#log")
};

elements.connect.addEventListener("click", () => runAction("Checking relay", checkRelay));
elements.createIdentity.addEventListener("click", () => runAction("Creating inbox", createIdentity));
elements.resetProfile.addEventListener("click", () => runAction("Resetting", resetProfile));
elements.copyCode.addEventListener("click", () => runAction("Copying", copyContactCode));
elements.importContact.addEventListener("click", () => runAction("Importing", importContactCode));
elements.contacts.addEventListener("change", renderChat);
elements.send.addEventListener("click", () => runAction("Sending", sendMessage));
elements.fetch.addEventListener("click", () => runAction("Fetching", fetchMessages));
elements.message.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
    event.preventDefault();
    runAction("Sending", sendMessage);
  }
});

runAction("Loading WASM", async () => {
  state.pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  loadState();
  renderAll();
  log(`profile ${profile}`);
  log("WASM ready");
});

async function checkRelay() {
  const client = relayClient();
  const health = await client.health();
  const info = await client.info();
  elements.relayInfo.textContent = `${info.relayInfo?.relayName ?? "Relay"} | ${info.relayInfo?.softwareVersion ?? "unknown software"} | ${info.relayInfo?.transport ?? "unknown transport"}`;
  log(`health ${JSON.stringify(health)}`);
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
  const identity = {
    displayName: `JS ${profile}`,
    signing: serializeKeypair(signing),
    agreement: serializeKeypair(agreement),
    access: serializeKeypair(access),
    inboxId,
    accessFingerprint,
    signingFingerprint
  };
  const contactOffer = makeNativeContactOffer({ pqc: state.pqc, identity, relayEndpoint });
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
  state.identity = { ...identity, contactOffer };
  saveState();
  renderAll();
  log(`registered inbox ${inboxId}`);
}

async function copyContactCode() {
  ensureIdentity();
  await navigator.clipboard.writeText(elements.contactCode.value);
  log("contact code copied");
}

async function importContactCode() {
  ensureIdentity();
  const code = elements.peerCode.value.trim();
  if (!code) {
    throw new Error("Paste a peer contact code first.");
  }
  const offer = decodeNativeContactCode(code);
  await verifyNativeContactOffer({ crypto: state.crypto, pqc: state.pqc, offer });
  if (offer.fingerprint === state.identity.signingFingerprint) {
    throw new Error("That contact code belongs to this profile.");
  }
  const existing = state.contacts.find((contact) => contact.fingerprint === offer.fingerprint);
  if (existing) {
    Object.assign(existing, contactFromOffer(offer));
  } else {
    state.contacts.push(contactFromOffer(offer));
  }
  elements.peerCode.value = "";
  saveState();
  renderAll();
  log(`paired ${offer.displayName}`);
}

async function sendMessage() {
  ensureIdentity();
  const contact = selectedContact();
  const text = elements.message.value.trim();
  if (!text) {
    throw new Error("Type a message first.");
  }
  const conversationKey = nativeConversationKey(contact);
  let conversation = state.conversations[conversationKey];
  let kemCiphertext = null;
  if (!conversation) {
    const created = await createNativeOutboundSession({
      crypto: state.crypto,
      pqc: state.pqc,
      identity: state.identity,
      contact
    });
    conversation = created.conversation;
    kemCiphertext = created.kemCiphertext;
    state.conversations[conversationKey] = conversation;
  }
  const sentAt = swiftISODate();
  const envelope = await encryptNativeTextEnvelope({
    crypto: state.crypto,
    pqc: state.pqc,
    identity: state.identity,
    contact,
    conversation,
    text,
    sentAt,
    kemCiphertext
  });
  const response = await relayClient(contact.relay).send(relayRequests.deliver({
    inboxId: contact.inboxId,
    envelope
  }));
  if (response.type !== "delivered") {
    throw new Error(`Deliver failed: ${JSON.stringify(response)}`);
  }
  state.messages.push({
    id: envelope.id,
    direction: "out",
    contactFingerprint: contact.fingerprint,
    text,
    sentAt
  });
  elements.message.value = "";
  saveState();
  renderChat();
  log(`sent to ${contact.displayName}`);
}

async function fetchMessages() {
  ensureIdentity();
  const ownAccess = deserializeKeypair(state.identity.access);
  const maxCount = 50;
  const signedAt = swiftISODate();
  const nonce = swiftUUID();
  const response = await relayClient().send(relayRequests.fetch({
    inboxId: state.identity.inboxId,
    routingToken: null,
    maxCount,
    longPollTimeoutSeconds: null,
    accessProof: actorProof({
      keypair: ownAccess,
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
  let decodedCount = 0;
  for (const envelope of response.messages ?? []) {
    if (state.seenEnvelopeIds.has(envelope.id?.toLowerCase())) {
      continue;
    }
    state.seenEnvelopeIds.add(envelope.id?.toLowerCase());
    const decoded = await decodeEnvelope(envelope);
    if (decoded) {
      state.messages.push(decoded);
      decodedCount++;
    }
  }
  saveState();
  renderChat();
  log(`fetch complete: ${decodedCount} new message(s)`);
}

async function decodeEnvelope(envelope) {
  const contact = state.contacts.find((candidate) => candidate.fingerprint === envelope.senderFingerprint);
  if (!contact) {
    log(`ignored unknown sender ${envelope.senderFingerprint}`);
    return null;
  }
  const conversationKey = nativeConversationKey(contact);
  let conversation = state.conversations[conversationKey];
  if (!conversation) {
    if (!envelope.kemCiphertext) {
      log(`ignored ${contact.displayName}: no session has been established`);
      return null;
    }
    conversation = await createNativeInboundSession({
      crypto: state.crypto,
      pqc: state.pqc,
      identity: state.identity,
      contact,
      kemCiphertext: envelope.kemCiphertext
    });
    state.conversations[conversationKey] = conversation;
  }
  const text = await decryptNativeEnvelope({
    crypto: state.crypto,
    pqc: state.pqc,
    identity: state.identity,
    contact,
    conversation,
    envelope
  });
  return {
    id: envelope.id,
    direction: "in",
    contactFingerprint: contact.fingerprint,
    text,
    sentAt: envelope.sentAt
  };
}

function relayClient(endpointOverride = undefined) {
  const endpoint = endpointOverride ? relayURLFromEndpoint(endpointOverride) : elements.relay.value.trim();
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

function contactFromOffer(offer) {
  return {
    displayName: offer.displayName,
    inboxId: offer.inboxId,
    relay: offer.relay,
    fingerprint: offer.fingerprint,
    signingPublicKey: offer.signingPublicKey,
    agreementPublicKey: offer.agreementPublicKey
  };
}

function selectedContact() {
  ensureIdentity();
  const fingerprint = elements.contacts.value;
  const contact = state.contacts.find((candidate) => candidate.fingerprint === fingerprint);
  if (!contact) {
    throw new Error("Pair with a contact first.");
  }
  return contact;
}

function renderAll() {
  elements.profile.textContent = profile;
  elements.inbox.textContent = state.identity?.inboxId ?? "Not created";
  elements.fingerprint.textContent = state.identity?.signingFingerprint ?? "Not created";
  elements.contactCode.value = state.identity ? encodeNativeContactCode(state.identity.contactOffer) : "";
  elements.copyCode.disabled = !state.identity;
  elements.send.disabled = !state.identity || state.contacts.length === 0;
  elements.fetch.disabled = !state.identity;
  renderContacts();
  renderChat();
}

function renderContacts() {
  const previous = elements.contacts.value;
  elements.contacts.innerHTML = "";
  if (state.contacts.length === 0) {
    const option = document.createElement("option");
    option.textContent = "No contacts paired";
    option.value = "";
    elements.contacts.append(option);
    return;
  }
  for (const contact of state.contacts) {
    const option = document.createElement("option");
    option.value = contact.fingerprint;
    option.textContent = contact.displayName;
    elements.contacts.append(option);
  }
  if (state.contacts.some((contact) => contact.fingerprint === previous)) {
    elements.contacts.value = previous;
  }
}

function renderChat() {
  const fingerprint = elements.contacts.value;
  const rows = state.messages.filter((message) => message.contactFingerprint === fingerprint);
  if (!fingerprint) {
    elements.chat.textContent = "Pair with a contact to start.";
    return;
  }
  if (rows.length === 0) {
    elements.chat.textContent = "No messages in this chat.";
    return;
  }
  elements.chat.innerHTML = "";
  for (const message of rows) {
    const bubble = document.createElement("div");
    bubble.className = `bubble ${message.direction}`;
    bubble.textContent = message.text;
    const meta = document.createElement("span");
    meta.textContent = `${message.direction === "out" ? "Sent" : "Received"} ${message.sentAt}`;
    bubble.append(meta);
    elements.chat.append(bubble);
  }
  elements.chat.scrollTop = elements.chat.scrollHeight;
}

function saveState() {
  localStorage.setItem(storageKey, JSON.stringify({
    identity: state.identity,
    contacts: state.contacts,
    conversations: state.conversations,
    messages: state.messages,
    seenEnvelopeIds: [...state.seenEnvelopeIds],
    relay: elements.relay.value
  }));
}

function loadState() {
  const saved = JSON.parse(localStorage.getItem(storageKey) || "{}");
  state.identity = saved.identity ?? null;
  state.contacts = saved.contacts ?? [];
  state.conversations = saved.conversations ?? {};
  state.messages = saved.messages ?? [];
  state.seenEnvelopeIds = new Set(saved.seenEnvelopeIds ?? []);
  if (saved.relay) {
    elements.relay.value = saved.relay;
  }
}

function resetProfile() {
  localStorage.removeItem(storageKey);
  state.identity = null;
  state.contacts = [];
  state.conversations = {};
  state.messages = [];
  state.seenEnvelopeIds = new Set();
  renderAll();
  log("profile reset");
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
    transport: endpoint.transport ?? "http"
  };
}

function relayURLFromEndpoint(endpoint) {
  const scheme = endpoint.transport === "websocket"
    ? endpoint.useTLS ? "wss" : "ws"
    : endpoint.useTLS ? "https" : "http";
  const defaultPort = endpoint.useTLS ? 443 : 80;
  const port = Number(endpoint.port);
  return `${scheme}://${endpoint.host}${port && port !== defaultPort ? `:${port}` : ""}`;
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
  const bytes = Array.from(encoder.encode(hrp));
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
