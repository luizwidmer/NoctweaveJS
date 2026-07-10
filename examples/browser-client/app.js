import oqsFactory from "../../wasm/dist/noctweave_oqs.js";
import {
  BrowserLocalStorageStore,
  EncryptedNoctweaveStore,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  NoctweaveStateRepository,
  WebCryptoPrimitives,
  base64,
  canonicalJsonBytes,
  createNativeInboundSession,
  createNativeOutboundSession,
  decodeNativeContactCode,
  decryptNativeEnvelope,
  decryptPortableProfile,
  encodeNativeContactCode,
  encryptPortableProfile,
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
const legacyStorageKey = `noctweave-js-browser-client:${profile}`;
const vaultNamespace = `${legacyStorageKey}:vault`;
const vaultSaltKey = `${vaultNamespace}:salt`;
const vaultStateStorageKey = `${vaultNamespace}:state`;
const vaultStateKey = "state";
const maximumProfileFileBytes = 2 * 1024 * 1024;
let pendingSecretRequest = null;

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
  isFetching: false,
  repository: null
};

const elements = {
  appShell: document.querySelector("#appShell"),
  vaultGate: document.querySelector("#vaultGate"),
  vaultTitle: document.querySelector("#vaultTitle"),
  vaultDescription: document.querySelector("#vaultDescription"),
  vaultPassphrase: document.querySelector("#vaultPassphrase"),
  vaultConfirmation: document.querySelector("#vaultConfirmation"),
  vaultConfirmationRow: document.querySelector("#vaultConfirmationRow"),
  vaultHint: document.querySelector("#vaultHint"),
  vaultError: document.querySelector("#vaultError"),
  unlockVault: document.querySelector("#unlockVault"),
  forgetVault: document.querySelector("#forgetVault"),
  status: document.querySelector("#status"),
  relay: document.querySelector("#relay"),
  connect: document.querySelector("#connect"),
  relayInfo: document.querySelector("#relayInfo"),
  createIdentity: document.querySelector("#createIdentity"),
  lockProfile: document.querySelector("#lockProfile"),
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
  clearLog: document.querySelector("#clearLog"),
  secretDialog: document.querySelector("#secretDialog"),
  secretForm: document.querySelector("#secretForm"),
  secretTitle: document.querySelector("#secretTitle"),
  secretDescription: document.querySelector("#secretDescription"),
  secretPassphrase: document.querySelector("#secretPassphrase"),
  secretConfirmation: document.querySelector("#secretConfirmation"),
  secretConfirmationRow: document.querySelector("#secretConfirmationRow"),
  secretError: document.querySelector("#secretError"),
  secretCancel: document.querySelector("#secretCancel")
};

elements.unlockVault.addEventListener("click", unlockOrCreateVault);
elements.forgetVault.addEventListener("click", forgetLocalVault);
elements.vaultPassphrase.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    unlockOrCreateVault();
  }
});
elements.connect.addEventListener("click", () => runAction("Checking relay", checkRelay));
elements.createIdentity.addEventListener("click", () => runAction("Creating inbox", createIdentity));
elements.lockProfile.addEventListener("click", lockProfile);
elements.resetProfile.addEventListener("click", () => runAction("Resetting", resetProfile));
elements.exportProfile.addEventListener("click", () => runAction("Exporting", exportProfile));
elements.importProfile.addEventListener("change", () => runAction("Importing profile", importProfile));
elements.relay.addEventListener("change", scheduleSave);
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
elements.secretForm.addEventListener("submit", submitSecretDialog);
elements.secretCancel.addEventListener("click", cancelSecretDialog);
elements.secretDialog.addEventListener("cancel", (event) => {
  event.preventDefault();
  cancelSecretDialog();
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && state.identity) {
    runAction("Fetching", fetchMessages);
  }
});

runAction("Loading WASM", async () => {
  state.pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  configureVaultGate();
  setStatus("Locked");
});

function configureVaultGate() {
  const hasEncryptedState = localStorage.getItem(vaultStateStorageKey) !== null;
  const hasSalt = localStorage.getItem(vaultSaltKey) !== null;
  const hasVault = hasEncryptedState || hasSalt;
  elements.vaultTitle.textContent = hasVault ? `Unlock ${profile}` : `Create ${profile}`;
  elements.vaultDescription.textContent = hasVault
    ? "Enter this browser profile’s passphrase. Identity keys remain encrypted at rest."
    : "Create a local passphrase to encrypt identity keys, sessions, contacts, and message history.";
  elements.vaultConfirmationRow.hidden = hasVault;
  elements.vaultPassphrase.autocomplete = hasVault ? "current-password" : "new-password";
  elements.vaultHint.textContent = hasVault
    ? "The passphrase is never sent to the relay and cannot be recovered."
    : "Use at least 12 characters. This passphrase cannot be recovered.";
  elements.unlockVault.textContent = hasVault ? "Unlock profile" : "Create encrypted profile";
  elements.unlockVault.dataset.mode = hasVault ? "unlock" : "create";
  elements.forgetVault.hidden = !hasVault;
  elements.vaultError.textContent = hasEncryptedState === hasSalt
    ? ""
    : "The local vault is incomplete. Reset this browser profile from site storage before continuing.";
  elements.vaultPassphrase.value = "";
  elements.vaultConfirmation.value = "";
  elements.vaultGate.hidden = false;
  elements.appShell.inert = true;
  elements.appShell.setAttribute("aria-hidden", "true");
  document.body.classList.add("vault-locked");
  queueMicrotask(() => elements.vaultPassphrase.focus());
}

async function unlockOrCreateVault() {
  ensurePQC();
  const mode = elements.unlockVault.dataset.mode;
  const passphrase = elements.vaultPassphrase.value;
  elements.vaultError.textContent = "";
  elements.unlockVault.disabled = true;
  elements.unlockVault.textContent = mode === "unlock" ? "Unlocking…" : "Creating…";
  try {
    if (mode === "create") {
      if (passphrase.length < 12) {
        throw new Error("Use a profile passphrase containing at least 12 characters.");
      }
      if (passphrase !== elements.vaultConfirmation.value) {
        throw new Error("The profile passphrases do not match.");
      }
      await createVault(passphrase);
    } else {
      await openVault(passphrase);
    }
    elements.vaultPassphrase.value = "";
    elements.vaultConfirmation.value = "";
    elements.vaultGate.hidden = true;
    elements.appShell.inert = false;
    elements.appShell.setAttribute("aria-hidden", "false");
    document.body.classList.remove("vault-locked");
    renderAll();
    log(`profile ${profile}`);
    log("encrypted vault unlocked");
    setStatus("Ready");
  } catch (error) {
    elements.vaultError.textContent = safeVaultError(error);
  } finally {
    elements.unlockVault.disabled = false;
    elements.unlockVault.textContent = mode === "unlock" ? "Unlock profile" : "Create encrypted profile";
  }
}

async function createVault(passphrase) {
  if (localStorage.getItem(vaultStateStorageKey) !== null || localStorage.getItem(vaultSaltKey) !== null) {
    throw new Error("An encrypted profile already exists in this browser.");
  }
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const repository = makeVaultRepository(passphrase, salt);
  try {
    const initial = legacyStateForMigration() ?? snapshotState();
    await validatePersistedState(initial);
    localStorage.setItem(vaultSaltKey, base64(salt));
    await repository.save(initial);
    localStorage.removeItem(legacyStorageKey);
    state.repository = repository;
    applyPersistedState(initial);
  } catch (error) {
    localStorage.removeItem(vaultSaltKey);
    localStorage.removeItem(vaultStateStorageKey);
    throw error;
  } finally {
    salt.fill(0);
  }
}

async function openVault(passphrase) {
  if (!passphrase) {
    throw new Error("Enter the profile passphrase.");
  }
  const encodedSalt = localStorage.getItem(vaultSaltKey);
  if (!encodedSalt || localStorage.getItem(vaultStateStorageKey) === null) {
    throw new Error("The encrypted browser profile is incomplete.");
  }
  const salt = fromBase64(encodedSalt);
  try {
    if (salt.byteLength !== 16) {
      throw new Error("The encrypted browser profile is malformed.");
    }
    const repository = makeVaultRepository(passphrase, salt);
    let persisted;
    try {
      persisted = await repository.load();
    } catch {
      throw new Error("The profile could not be unlocked. Check the passphrase and local profile data.");
    }
    if (!persisted) {
      throw new Error("The encrypted browser profile contains no state.");
    }
    await validatePersistedState(persisted);
    state.repository = repository;
    applyPersistedState(persisted);
  } finally {
    salt.fill(0);
  }
}

function makeVaultRepository(passphrase, salt) {
  const backend = new BrowserLocalStorageStore({ namespace: vaultNamespace });
  const encrypted = new EncryptedNoctweaveStore(backend, {
    passphrase,
    salt,
    iterations: 310_000
  });
  return new NoctweaveStateRepository(encrypted, { key: vaultStateKey });
}

function legacyStateForMigration() {
  const raw = localStorage.getItem(legacyStorageKey);
  if (!raw) {
    return null;
  }
  let legacy;
  try {
    legacy = JSON.parse(raw);
  } catch {
    throw new Error("Legacy plaintext profile data is malformed and was not migrated.");
  }
  return {
    version: 2,
    identity: legacy.identity ?? null,
    contacts: legacy.contacts ?? [],
    conversations: legacy.conversations ?? {},
    messages: legacy.messages ?? [],
    seenEnvelopeIds: legacy.seenEnvelopeIds ?? [],
    relay: legacy.relay ?? elements.relay.value,
    selectedContactFingerprint: legacy.selectedContactFingerprint ?? "",
    autoFetchEnabled: Boolean(legacy.autoFetchEnabled)
  };
}

function lockProfile() {
  stopAutoFetch();
  clearLiveState();
  configureVaultGate();
  setStatus("Locked");
}

function forgetLocalVault() {
  if (!confirm(`Forget ${profile}? This permanently deletes its local identity keys and message history.`)) {
    return;
  }
  stopAutoFetch();
  localStorage.removeItem(vaultStateStorageKey);
  localStorage.removeItem(vaultSaltKey);
  localStorage.removeItem(legacyStorageKey);
  clearLiveState();
  configureVaultGate();
}

function stopAutoFetch() {
  if (state.autoFetchTimer) {
    clearInterval(state.autoFetchTimer);
    state.autoFetchTimer = null;
  }
}

function clearLiveState() {
  state.identity = null;
  state.contacts = [];
  state.conversations = {};
  state.messages = [];
  state.seenEnvelopeIds = new Set();
  state.selectedContactFingerprint = "";
  state.isContactCodeVisible = false;
  state.autoFetchEnabled = false;
  state.repository = null;
}

function safeVaultError(error) {
  if (!(error instanceof Error)) {
    return "The encrypted profile operation failed.";
  }
  const allowed = [
    "passphrase", "profile", "vault", "encrypted", "malformed", "incomplete",
    "already exists", "do not match", "state", "contact", "message", "relay"
  ];
  return allowed.some((fragment) => error.message.toLowerCase().includes(fragment))
    ? error.message
    : "The encrypted profile operation failed.";
}

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
  await saveState();
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
  await saveState();
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
  await saveState();
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
    await saveState();
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
  scheduleSave();
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

async function deleteSelectedContact() {
  const contact = selectedContact();
  if (!confirm(`Delete ${contact.displayName} from this browser profile?`)) {
    return;
  }
  state.contacts = state.contacts.filter((candidate) => candidate.fingerprint !== contact.fingerprint);
  state.messages = state.messages.filter((message) => message.contactFingerprint !== contact.fingerprint);
  delete state.conversations[nativeConversationKey(contact)];
  state.selectedContactFingerprint = state.contacts[0]?.fingerprint ?? "";
  await saveState();
  renderAll();
  log(`deleted ${contact.displayName}`);
}

async function exportProfile() {
  ensureIdentity();
  const passphrase = await requestSecret({
    title: "Protect profile export",
    description: "Choose a separate passphrase for this file. It contains identity private keys and message state.",
    confirmation: true
  });
  if (passphrase === null) {
    return;
  }
  const packageData = await encryptPortableProfile({
    ...snapshotState(),
    exportedAt: new Date().toISOString(),
    profile
  }, passphrase);
  const payload = JSON.stringify(packageData, null, 2);
  const url = URL.createObjectURL(new Blob([payload], { type: "application/vnd.noctweave.profile+json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `noctweave-${profile}.noctweave.json`;
  link.click();
  URL.revokeObjectURL(url);
  log("encrypted profile exported");
}

async function importProfile() {
  const [file] = elements.importProfile.files ?? [];
  elements.importProfile.value = "";
  if (!file) {
    return;
  }
  if (file.size <= 0 || file.size > maximumProfileFileBytes) {
    throw new Error("Encrypted profile file must be between 1 byte and 2 MB.");
  }
  let packageData;
  try {
    packageData = JSON.parse(await file.text());
  } catch {
    throw new Error("Encrypted profile file is not valid JSON.");
  }
  const passphrase = await requestSecret({
    title: "Unlock profile export",
    description: "Enter the passphrase used when this encrypted profile file was created.",
    confirmation: false
  });
  if (passphrase === null) {
    return;
  }
  const payload = await decryptPortableProfile(packageData, passphrase);
  await validatePersistedState(payload);
  applyPersistedState(payload);
  await saveState();
  renderAll();
  log(`encrypted profile imported from ${file.name}`);
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
  elements.contacts.replaceChildren();
  elements.contactList.replaceChildren();
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
    const name = document.createElement("strong");
    const detail = document.createElement("span");
    name.textContent = contact.displayName;
    detail.textContent = `${shortFingerprint(contact.fingerprint)} · ${contact.relay?.host ?? "relay"}`;
    card.append(name, detail);
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
  scheduleSave();
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
  elements.chat.replaceChildren();
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
  elements.chat.replaceChildren();
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
  elements.relayInfo.replaceChildren();
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

function snapshotState() {
  return {
    version: 2,
    identity: state.identity,
    contacts: state.contacts,
    conversations: state.conversations,
    messages: state.messages,
    seenEnvelopeIds: [...state.seenEnvelopeIds],
    relay: elements.relay.value,
    selectedContactFingerprint: state.selectedContactFingerprint,
    autoFetchEnabled: state.autoFetchEnabled
  };
}

async function saveState() {
  if (!state.repository) {
    throw new Error("Unlock the encrypted browser profile before saving.");
  }
  await state.repository.save(snapshotState());
}

function scheduleSave() {
  void saveState().catch((error) => {
    log(safeVaultError(error));
    setStatus("Save failed");
  });
}

function applyPersistedState(saved) {
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

async function resetProfile() {
  if (!confirm(`Reset ${profile}? This permanently deletes its local identity keys and message history.`)) {
    return;
  }
  stopAutoFetch();
  if (state.repository) {
    await state.repository.clear();
  }
  localStorage.removeItem(vaultStateStorageKey);
  localStorage.removeItem(vaultSaltKey);
  localStorage.removeItem(legacyStorageKey);
  clearLiveState();
  configureVaultGate();
  setStatus("Locked");
}

async function validatePersistedState(saved) {
  if (!saved || typeof saved !== "object" || Array.isArray(saved) || saved.version !== 2) {
    throw new Error("Unsupported encrypted profile state.");
  }
  const encodedLength = encoder.encode(JSON.stringify(saved)).byteLength;
  if (encodedLength > maximumProfileFileBytes) {
    throw new Error("Encrypted profile state exceeds the 2 MB limit.");
  }
  if (!Array.isArray(saved.contacts) || saved.contacts.length > 256 ||
      !Array.isArray(saved.messages) || saved.messages.length > 10_000 ||
      !Array.isArray(saved.seenEnvelopeIds) || saved.seenEnvelopeIds.length > 20_000 ||
      !saved.conversations || typeof saved.conversations !== "object" || Array.isArray(saved.conversations) ||
      Object.keys(saved.conversations).length > 512) {
    throw new Error("Encrypted profile collections exceed supported limits.");
  }
  parseRelayEndpoint(String(saved.relay ?? ""));

  if (saved.identity !== null && saved.identity !== undefined) {
    validateBoundedString(saved.identity.displayName, "identity display name", 1, 128);
    validateBoundedString(saved.identity.inboxId, "identity inbox", 1, 160);
    validateBoundedString(saved.identity.signingFingerprint, "identity fingerprint", 1, 160);
    validateBoundedString(saved.identity.accessFingerprint, "inbox access fingerprint", 1, 160);
    validateSerializedKeypair(saved.identity.signing, "identity signing key");
    validateSerializedKeypair(saved.identity.agreement, "identity agreement key");
    validateSerializedKeypair(saved.identity.access, "inbox access key");
    if (!saved.identity.contactOffer) {
      throw new Error("Encrypted profile identity is missing its signed contact offer.");
    }
    await verifyNativeContactOffer({
      crypto: state.crypto,
      pqc: state.pqc,
      offer: saved.identity.contactOffer
    });
    if (saved.identity.contactOffer.fingerprint !== saved.identity.signingFingerprint ||
        saved.identity.contactOffer.inboxId !== saved.identity.inboxId) {
      throw new Error("Encrypted profile identity binding is invalid.");
    }
  }

  const fingerprints = new Set();
  for (const contact of saved.contacts) {
    validateBoundedString(contact?.displayName, "contact display name", 1, 128);
    validateBoundedString(contact?.inboxId, "contact inbox", 1, 160);
    validateBoundedString(contact?.fingerprint, "contact fingerprint", 1, 160);
    if (fingerprints.has(contact.fingerprint)) {
      throw new Error("Encrypted profile contains duplicate contacts.");
    }
    fingerprints.add(contact.fingerprint);
    const signingKey = validatedBase64Bytes(contact.signingPublicKey, "contact signing key", 16_384);
    const agreementKey = validatedBase64Bytes(contact.agreementPublicKey, "contact agreement key", 16_384);
    try {
      if (base64(await state.crypto.sha256(signingKey)) !== contact.fingerprint) {
        throw new Error("Encrypted profile contact fingerprint is invalid.");
      }
    } finally {
      signingKey.fill(0);
      agreementKey.fill(0);
    }
    parseRelayEndpoint(relayURLFromEndpoint(contact.relay));
  }

  for (const message of saved.messages) {
    validateBoundedString(message?.id, "message identifier", 1, 160);
    validateBoundedString(message?.contactFingerprint, "message contact", 1, 160);
    validateBoundedString(message?.text, "message text", 0, 32_768);
    if (message.direction !== "in" && message.direction !== "out") {
      throw new Error("Encrypted profile contains an invalid message direction.");
    }
  }
  for (const id of saved.seenEnvelopeIds) {
    validateBoundedString(id, "seen envelope identifier", 1, 160);
  }
}

function validateSerializedKeypair(value, label) {
  if (!value || typeof value !== "object") {
    throw new Error(`Encrypted profile ${label} is missing.`);
  }
  const publicKey = validatedBase64Bytes(value.publicKey, `${label} public material`, 16_384);
  const secretKey = validatedBase64Bytes(value.secretKey, `${label} private material`, 32_768);
  publicKey.fill(0);
  secretKey.fill(0);
}

function validatedBase64Bytes(value, label, maximumBytes) {
  validateBoundedString(value, label, 4, Math.ceil(maximumBytes * 4 / 3) + 4);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Encrypted profile ${label} is malformed.`);
  }
  let bytes;
  try {
    bytes = fromBase64(value);
  } catch {
    throw new Error(`Encrypted profile ${label} is malformed.`);
  }
  if (bytes.byteLength === 0 || bytes.byteLength > maximumBytes || base64(bytes) !== value) {
    bytes.fill(0);
    throw new Error(`Encrypted profile ${label} is malformed.`);
  }
  return bytes;
}

function validateBoundedString(value, label, minimum, maximum) {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum) {
    throw new Error(`Encrypted profile ${label} is invalid.`);
  }
}

function requestSecret({ title, description, confirmation }) {
  if (pendingSecretRequest) {
    throw new Error("Another encrypted profile operation is already open.");
  }
  elements.secretTitle.textContent = title;
  elements.secretDescription.textContent = description;
  elements.secretConfirmationRow.hidden = !confirmation;
  elements.secretPassphrase.autocomplete = confirmation ? "new-password" : "current-password";
  elements.secretPassphrase.value = "";
  elements.secretConfirmation.value = "";
  elements.secretError.textContent = "";
  elements.secretDialog.showModal();
  queueMicrotask(() => elements.secretPassphrase.focus());
  return new Promise((resolve) => {
    pendingSecretRequest = { resolve, confirmation };
  });
}

function submitSecretDialog(event) {
  event.preventDefault();
  if (!pendingSecretRequest) {
    elements.secretDialog.close();
    return;
  }
  const passphrase = elements.secretPassphrase.value;
  if (!passphrase) {
    elements.secretError.textContent = "Enter the profile passphrase.";
    return;
  }
  if (pendingSecretRequest.confirmation && passphrase.length < 12) {
    elements.secretError.textContent = "Use at least 12 characters.";
    return;
  }
  if (pendingSecretRequest.confirmation && passphrase !== elements.secretConfirmation.value) {
    elements.secretError.textContent = "The passphrases do not match.";
    return;
  }
  const { resolve } = pendingSecretRequest;
  pendingSecretRequest = null;
  elements.secretPassphrase.value = "";
  elements.secretConfirmation.value = "";
  elements.secretDialog.close();
  resolve(passphrase);
}

function cancelSecretDialog() {
  if (!pendingSecretRequest) {
    elements.secretDialog.close();
    return;
  }
  const { resolve } = pendingSecretRequest;
  pendingSecretRequest = null;
  elements.secretPassphrase.value = "";
  elements.secretConfirmation.value = "";
  elements.secretDialog.close();
  resolve(null);
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
