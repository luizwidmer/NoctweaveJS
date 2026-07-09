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
  seenEnvelopeIds: new Set(),
  selectedContactFingerprint: "",
  isContactCodeVisible: false,
  autoFetchEnabled: false,
  autoFetchTimer: null,
  isFetching: false
};

const elements = {
  status: document.querySelector("#status"),
  relay: document.querySelector("#relay"),
  connect: document.querySelector("#connect"),
  relayInfo: document.querySelector("#relayInfo"),
  createIdentity: document.querySelector("#createIdentity"),
  resetProfile: document.querySelector("#resetProfile"),
  exportProfile: document.querySelector("#exportProfile"),
  importProfile: document.querySelector("#importProfile"),
  identityDot: document.querySelector("#identityDot"),
  profile: document.querySelector("#profile"),
  inbox: document.querySelector("#inbox"),
  fingerprint: document.querySelector("#fingerprint"),
  contactCode: document.querySelector("#contactCode"),
  toggleCode: document.querySelector("#toggleCode"),
  copyCode: document.querySelector("#copyCode"),
  peerCode: document.querySelector("#peerCode"),
  importContact: document.querySelector("#importContact"),
  contactList: document.querySelector("#contactList"),
  contactCount: document.querySelector("#contactCount"),
  contacts: document.querySelector("#contacts"),
  deleteContact: document.querySelector("#deleteContact"),
  message: document.querySelector("#message"),
  messageCount: document.querySelector("#messageCount"),
  send: document.querySelector("#send"),
  fetch: document.querySelector("#fetch"),
  autoFetch: document.querySelector("#autoFetch"),
  chatTitle: document.querySelector("#chatTitle"),
  chat: document.querySelector("#chat"),
  log: document.querySelector("#log"),
  clearLog: document.querySelector("#clearLog")
};

elements.connect.addEventListener("click", () => runAction("Checking relay", checkRelay));
elements.createIdentity.addEventListener("click", () => runAction("Creating inbox", createIdentity));
elements.resetProfile.addEventListener("click", () => runAction("Resetting", resetProfile));
elements.exportProfile.addEventListener("click", () => runAction("Exporting", exportProfile));
elements.importProfile.addEventListener("change", () => runAction("Importing profile", importProfile));
elements.relay.addEventListener("change", saveState);
elements.toggleCode.addEventListener("click", toggleContactCode);
elements.copyCode.addEventListener("click", () => runAction("Copying", copyContactCode));
elements.importContact.addEventListener("click", () => runAction("Importing", importContactCode));
elements.contacts.addEventListener("change", () => selectContact(elements.contacts.value));
elements.deleteContact.addEventListener("click", () => runAction("Deleting", deleteSelectedContact));
elements.send.addEventListener("click", () => runAction("Sending", sendMessage));
elements.fetch.addEventListener("click", () => runAction("Fetching", fetchMessages));
elements.autoFetch.addEventListener("change", toggleAutoFetch);
elements.clearLog.addEventListener("click", () => {
  elements.log.textContent = "";
});
elements.message.addEventListener("input", renderMessageCount);
elements.message.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
    event.preventDefault();
    runAction("Sending", sendMessage);
  }
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && state.identity) {
    runAction("Fetching", fetchMessages);
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
  renderRelayInfo({ health, info });
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
  await navigator.clipboard.writeText(currentContactCode());
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
  state.selectedContactFingerprint = offer.fingerprint;
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
  renderMessageCount();
  saveState();
  renderChat();
  log(`sent to ${contact.displayName}`);
}

async function fetchMessages() {
  ensureIdentity();
  if (state.isFetching) {
    return;
  }
  state.isFetching = true;
  try {
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
  } finally {
    state.isFetching = false;
  }
}

function toggleContactCode() {
  state.isContactCodeVisible = !state.isContactCodeVisible;
  renderContactCode();
}

function toggleAutoFetch() {
  state.autoFetchEnabled = elements.autoFetch.checked;
  configureAutoFetch();
  saveState();
  log(state.autoFetchEnabled ? "auto-fetch enabled" : "auto-fetch disabled");
}

function configureAutoFetch() {
  if (state.autoFetchTimer) {
    clearInterval(state.autoFetchTimer);
    state.autoFetchTimer = null;
  }
  if (!state.autoFetchEnabled || !state.identity) {
    return;
  }
  state.autoFetchTimer = setInterval(() => {
    if (document.visibilityState === "visible") {
      runAction("Fetching", fetchMessages);
    }
  }, 4000);
}

function deleteSelectedContact() {
  const contact = selectedContact();
  if (!confirm(`Delete ${contact.displayName} from this browser profile?`)) {
    return;
  }
  state.contacts = state.contacts.filter((candidate) => candidate.fingerprint !== contact.fingerprint);
  state.messages = state.messages.filter((message) => message.contactFingerprint !== contact.fingerprint);
  delete state.conversations[nativeConversationKey(contact)];
  state.selectedContactFingerprint = state.contacts[0]?.fingerprint ?? "";
  saveState();
  renderAll();
  log(`deleted ${contact.displayName}`);
}

function exportProfile() {
  const payload = JSON.stringify({
    version: 1,
    exportedAt: new Date().toISOString(),
    profile,
    identity: state.identity,
    contacts: state.contacts,
    conversations: state.conversations,
    messages: state.messages,
    seenEnvelopeIds: [...state.seenEnvelopeIds],
    relay: elements.relay.value
  }, null, 2);
  const url = URL.createObjectURL(new Blob([payload], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `noctweave-${profile}.json`;
  link.click();
  URL.revokeObjectURL(url);
  log("profile exported");
}

async function importProfile() {
  const [file] = elements.importProfile.files ?? [];
  elements.importProfile.value = "";
  if (!file) {
    return;
  }
  const payload = JSON.parse(await file.text());
  if (payload.version !== 1) {
    throw new Error("Unsupported profile export.");
  }
  state.identity = payload.identity ?? null;
  state.contacts = payload.contacts ?? [];
  state.conversations = payload.conversations ?? {};
  state.messages = payload.messages ?? [];
  state.seenEnvelopeIds = new Set(payload.seenEnvelopeIds ?? []);
  state.selectedContactFingerprint = state.contacts[0]?.fingerprint ?? "";
  if (payload.relay) {
    elements.relay.value = payload.relay;
  }
  saveState();
  renderAll();
  log(`profile imported from ${file.name}`);
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
  elements.identityDot.classList.toggle("ready", Boolean(state.identity));
  renderContactCode();
  elements.copyCode.disabled = !state.identity;
  elements.toggleCode.disabled = !state.identity;
  elements.exportProfile.disabled = !state.identity;
  elements.send.disabled = !state.identity || state.contacts.length === 0;
  elements.fetch.disabled = !state.identity;
  elements.autoFetch.disabled = !state.identity;
  elements.autoFetch.checked = state.autoFetchEnabled;
  elements.deleteContact.disabled = !state.identity || state.contacts.length === 0;
  renderContacts();
  renderChat();
  renderMessageCount();
  configureAutoFetch();
}

function renderContactCode() {
  elements.toggleCode.textContent = state.isContactCodeVisible ? "Hide" : "Show";
  if (!state.identity) {
    elements.contactCode.value = "";
    elements.contactCode.placeholder = "Create an inbox first.";
    return;
  }
  if (state.isContactCodeVisible) {
    elements.contactCode.value = currentContactCode();
    return;
  }
  elements.contactCode.value = "Contact code hidden. Use Copy Code or Show.";
}

function currentContactCode() {
  ensureIdentity();
  return encodeNativeContactCode(state.identity.contactOffer);
}

function renderContacts() {
  const previous = state.selectedContactFingerprint || elements.contacts.value;
  elements.contacts.innerHTML = "";
  elements.contactList.innerHTML = "";
  elements.contactCount.textContent = String(state.contacts.length);
  if (state.contacts.length === 0) {
    const option = document.createElement("option");
    option.textContent = "No contacts paired";
    option.value = "";
    elements.contacts.append(option);
    state.selectedContactFingerprint = "";
    elements.deleteContact.disabled = true;
    return;
  }
  for (const contact of state.contacts) {
    const option = document.createElement("option");
    option.value = contact.fingerprint;
    option.textContent = contact.displayName;
    elements.contacts.append(option);

    const card = document.createElement("button");
    card.type = "button";
    card.className = "contactCard";
    card.dataset.fingerprint = contact.fingerprint;
    card.innerHTML = `<strong></strong><span></span>`;
    card.querySelector("strong").textContent = contact.displayName;
    card.querySelector("span").textContent = `${shortFingerprint(contact.fingerprint)} · ${contact.relay?.host ?? "relay"}`;
    card.addEventListener("click", () => selectContact(contact.fingerprint));
    elements.contactList.append(card);
  }
  if (state.contacts.some((contact) => contact.fingerprint === previous)) {
    state.selectedContactFingerprint = previous;
  } else {
    state.selectedContactFingerprint = state.contacts[0].fingerprint;
  }
  elements.contacts.value = state.selectedContactFingerprint;
  elements.deleteContact.disabled = false;
  syncContactCardSelection();
}

function selectContact(fingerprint) {
  state.selectedContactFingerprint = fingerprint;
  elements.contacts.value = fingerprint;
  saveState();
  syncContactCardSelection();
  renderChat();
}

function syncContactCardSelection() {
  for (const card of elements.contactList.querySelectorAll(".contactCard")) {
    card.classList.toggle("active", card.dataset.fingerprint === state.selectedContactFingerprint);
  }
}

function renderChat() {
  const fingerprint = state.selectedContactFingerprint || elements.contacts.value;
  const rows = state.messages.filter((message) => message.contactFingerprint === fingerprint);
  const contact = state.contacts.find((candidate) => candidate.fingerprint === fingerprint);
  elements.chatTitle.textContent = contact?.displayName ?? "No contact selected";
  if (!fingerprint) {
    renderEmptyChat("Pair with a contact to start.");
    return;
  }
  if (rows.length === 0) {
    renderEmptyChat("No messages in this chat yet.");
    return;
  }
  elements.chat.innerHTML = "";
  for (const message of rows) {
    const bubble = document.createElement("div");
    bubble.className = `bubble ${message.direction}`;
    bubble.textContent = message.text;
    const meta = document.createElement("span");
    meta.textContent = `${message.direction === "out" ? "Sent" : "Received"} ${formatDate(message.sentAt)}`;
    bubble.append(meta);
    elements.chat.append(bubble);
  }
  elements.chat.scrollTop = elements.chat.scrollHeight;
}

function renderEmptyChat(text) {
  elements.chat.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "emptyState";
  empty.textContent = text;
  elements.chat.append(empty);
}

function renderMessageCount() {
  const count = elements.message.value.length;
  elements.messageCount.textContent = `${count} character${count === 1 ? "" : "s"}`;
}

function renderRelayInfo({ health, info }) {
  const relayInfo = info.relayInfo ?? {};
  const chips = [
    ["Name", relayInfo.relayName ?? "Relay"],
    ["Software", relayInfo.softwareVersion ?? "Unknown"],
    ["Transport", relayInfo.transport ?? "HTTP"],
    ["Health", health?.status ?? "OK"]
  ];
  elements.relayInfo.innerHTML = "";
  const grid = document.createElement("div");
  grid.className = "infoGrid";
  for (const [title, value] of chips) {
    const chip = document.createElement("div");
    chip.className = "infoChip";
    const strong = document.createElement("strong");
    strong.textContent = title;
    const span = document.createElement("span");
    span.textContent = String(value);
    chip.append(strong, span);
    grid.append(chip);
  }
  elements.relayInfo.append(grid);
}

function saveState() {
  localStorage.setItem(storageKey, JSON.stringify({
    identity: state.identity,
    contacts: state.contacts,
    conversations: state.conversations,
    messages: state.messages,
    seenEnvelopeIds: [...state.seenEnvelopeIds],
    relay: elements.relay.value,
    selectedContactFingerprint: state.selectedContactFingerprint,
    autoFetchEnabled: state.autoFetchEnabled
  }));
}

function loadState() {
  const saved = JSON.parse(localStorage.getItem(storageKey) || "{}");
  state.identity = saved.identity ?? null;
  state.contacts = saved.contacts ?? [];
  state.conversations = saved.conversations ?? {};
  state.messages = saved.messages ?? [];
  state.seenEnvelopeIds = new Set(saved.seenEnvelopeIds ?? []);
  state.selectedContactFingerprint = saved.selectedContactFingerprint ?? state.contacts[0]?.fingerprint ?? "";
  state.autoFetchEnabled = Boolean(saved.autoFetchEnabled);
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
  state.selectedContactFingerprint = "";
  state.isContactCodeVisible = false;
  state.autoFetchEnabled = false;
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

function deserializeKeypair(keypair) {
  return {
    publicKey: fromBase64(keypair.publicKey),
    secretKey: fromBase64(keypair.secretKey)
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

function fromBase64(value) {
  const binary = atob(value);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    output[index] = binary.charCodeAt(index);
  }
  return output;
}

function shortFingerprint(value) {
  if (!value || value.length <= 14) {
    return value ?? "";
  }
  return `${value.slice(0, 7)}…${value.slice(-6)}`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(date);
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
