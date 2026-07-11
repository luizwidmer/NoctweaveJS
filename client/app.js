import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  BrowserLocalStorageStore,
  EncryptedNoctweaveStore,
  NoctweaveBrowserIdentityService,
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
  encryptNativeTextEnvelope,
  encryptPortableProfile,
  nativeConversationKey,
  parseBrowserRelayEndpoint,
  relayRequests,
  swiftISODate,
  swiftUUID,
  verifyNativeContactOffer
} from "../src/index.js";

const profileName = new URL(location.href).searchParams.get("profile") || "default";
const namespace = `noctweave-js-client:${profileName}`;
const saltStorageKey = `${namespace}:salt`;
const encryptedStorageKey = `${namespace}:vault:profile`;
const stateKey = "profile";
const steps = ["welcome", "storage", "relay", "identity"];
const maximumProfileFileBytes = 2 * 1024 * 1024;
const autoFetchIntervalMs = 5_000;

const runtime = {
  pqc: null,
  crypto: new WebCryptoPrimitives(),
  identityService: null,
  repository: null,
  profile: null,
  verifiedRelay: null,
  currentStep: "welcome",
  currentView: "chats",
  codeVisible: false,
  autoFetchTimer: null,
  syncing: false,
  sendingContacts: new Set(),
  pendingSecret: null
};

const $ = (selector) => document.querySelector(selector);
const elements = {
  startup: $("#startup"), app: $("#app"), setupTitle: $("#setupTitle"), setupProgress: $("#setupProgress"),
  setupError: $("#setupError"), busy: $("#busy"), busyLabel: $("#busyLabel"), acceptNotice: $("#acceptNotice"),
  unlockPassphrase: $("#unlockPassphrase"), storagePassphrase: $("#storagePassphrase"), storageConfirmation: $("#storageConfirmation"),
  relayAddress: $("#relayAddress"), relayPassword: $("#relayPassword"), relayResult: $("#relayResult"), displayName: $("#displayName"),
  navigation: $("#navigation"), viewTitle: $("#viewTitle"), viewEyebrow: $("#viewEyebrow"), headerIdentity: $("#headerIdentity"),
  railRelay: $("#railRelay"), relayDot: $("#relayDot"), contactCode: $("#contactCode"), identityName: $("#identityName"),
  identityInbox: $("#identityInbox"), identityFingerprint: $("#identityFingerprint"), identityRelay: $("#identityRelay"),
  toast: $("#toast"), navUnread: $("#navUnread"), conversationItems: $("#conversationItems"), noConversations: $("#noConversations"),
  chatSearch: $("#chatSearch"), chatPlaceholder: $("#chatPlaceholder"), activeChat: $("#activeChat"), chatContactName: $("#chatContactName"),
  chatContactStatus: $("#chatContactStatus"), messageList: $("#messageList"), composer: $("#composer"), messageInput: $("#messageInput"),
  contactSearch: $("#contactSearch"), contactList: $("#contactList"), noContacts: $("#noContacts"), addContactCard: $("#addContactCard"),
  contactAlias: $("#contactAlias"), importContactCode: $("#importContactCode"), relayList: $("#relayList"), addRelayCard: $("#addRelayCard"),
  newRelayAddress: $("#newRelayAddress"), newRelayPassword: $("#newRelayPassword"), autoFetch: $("#autoFetch"),
  lastSync: $("#lastSync"), storedMessages: $("#storedMessages"), secretDialog: $("#secretDialog"), secretForm: $("#secretForm"),
  secretTitle: $("#secretTitle"), secretDescription: $("#secretDescription"), secretPassphrase: $("#secretPassphrase"),
  secretConfirmation: $("#secretConfirmation"), secretConfirmationRow: $("#secretConfirmationRow"), secretError: $("#secretError")
};

bindEvents();
boot();

function bindEvents() {
  elements.acceptNotice.addEventListener("change", () => {
    $("[data-step='welcome'] .next").disabled = !elements.acceptNotice.checked;
  });
  $("[data-step='welcome'] .next").addEventListener("click", () => showStep("storage"));
  $("#createStorage").addEventListener("click", () => run("Creating encrypted profile", createEncryptedProfile));
  $("#unlockProfile").addEventListener("click", () => run("Unlocking profile", unlockProfile));
  $("#resetLockedProfile").addEventListener("click", resetInstallation);
  $("#verifyRelay").addEventListener("click", () => run("Verifying relay", verifyRelay));
  $("#createIdentity").addEventListener("click", () => run("Creating post-quantum identity", createIdentity));
  $("#lockClient").addEventListener("click", lockClient);
  $("#resetClient").addEventListener("click", resetInstallation);
  $("#syncNow").addEventListener("click", () => run("Fetching messages", syncMessages));
  $("#revealCode").addEventListener("click", toggleCode);
  $("#copyCode").addEventListener("click", copyCode);
  $("#downloadCode").addEventListener("click", downloadCode);
  $("#showAddContact").addEventListener("click", () => { elements.addContactCard.hidden = false; elements.importContactCode.focus(); });
  $("#hideAddContact").addEventListener("click", () => { elements.addContactCard.hidden = true; });
  $("#importContact").addEventListener("click", () => run("Verifying contact", importContact));
  $("#contactFile").addEventListener("change", loadContactFile);
  $("#showAddRelay").addEventListener("click", () => { elements.addRelayCard.hidden = false; elements.newRelayAddress.focus(); });
  $("#hideAddRelay").addEventListener("click", () => { elements.addRelayCard.hidden = true; });
  $("#addRelay").addEventListener("click", () => run("Checking relay", addRelay));
  $("#clearConversation").addEventListener("click", clearConversation);
  $("#closeMobileChat").addEventListener("click", closeMobileChat);
  $("#exportProfile").addEventListener("click", () => run("Exporting encrypted profile", exportProfile));
  $("#importProfile").addEventListener("change", () => run("Importing encrypted profile", importProfile));
  elements.autoFetch.addEventListener("change", updateAutoFetch);
  elements.chatSearch.addEventListener("input", renderConversationList);
  elements.contactSearch.addEventListener("input", renderContacts);
  elements.composer.addEventListener("submit", (event) => { event.preventDefault(); run("Sending message", sendMessage); });
  elements.messageInput.addEventListener("input", resizeComposer);
  elements.messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); elements.composer.requestSubmit(); }
  });
  elements.navigation.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-view]");
    if (button) openView(button.dataset.view);
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-open-view]");
    if (button) openView(button.dataset.openView);
  });
  elements.unlockPassphrase.addEventListener("keydown", (event) => {
    if (event.key === "Enter") run("Unlocking profile", unlockProfile);
  });
  elements.secretForm.addEventListener("submit", submitSecretDialog);
  $("#secretCancel").addEventListener("click", cancelSecretDialog);
  elements.secretDialog.addEventListener("cancel", (event) => { event.preventDefault(); cancelSecretDialog(); });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && runtime.profile?.identity) run("Fetching messages", syncMessages, { quiet: true });
  });
}

async function boot() {
  await run("Loading post-quantum runtime", async () => {
    runtime.pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
    runtime.identityService = new NoctweaveBrowserIdentityService({
      pqc: runtime.pqc,
      crypto: runtime.crypto,
      relayClientFactory: makeRelayClient
    });
    if (localStorage.getItem(encryptedStorageKey) !== null || localStorage.getItem(saltStorageKey) !== null) showStep("unlock");
    else showStep("welcome");
  });
}

function makeRelayClient(endpoint, options = {}) {
  const parsed = parseBrowserRelayEndpoint(String(endpoint));
  const customFetch = parsed.transport === "http" ? proxyFetch(String(endpoint)) : options.fetch;
  return new NoctweaveRelayClient(endpoint, { ...options, fetch: customFetch });
}

function proxyFetch(endpoint) {
  return async (url, init) => {
    const path = new URL(url).pathname === "/health" ? "/proxy/health" : "/proxy/relay";
    return fetch(path, { ...init, headers: { ...(init?.headers ?? {}), "x-relay-endpoint": endpoint } });
  };
}

async function createEncryptedProfile() {
  const passphrase = elements.storagePassphrase.value;
  if (passphrase.length < 12) throw new Error("Use a profile passphrase containing at least 12 characters.");
  if (passphrase !== elements.storageConfirmation.value) throw new Error("Profile passphrases do not match.");
  if (localStorage.getItem(encryptedStorageKey) !== null || localStorage.getItem(saltStorageKey) !== null) throw new Error("An encrypted profile already exists in this browser.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const repository = makeRepository(passphrase, salt);
  const profile = newProfileState();
  try {
    localStorage.setItem(saltStorageKey, base64(salt));
    await repository.save(profile);
    runtime.repository = repository;
    runtime.profile = profile;
    elements.storagePassphrase.value = "";
    elements.storageConfirmation.value = "";
    showStep("relay");
  } catch (error) {
    localStorage.removeItem(saltStorageKey);
    localStorage.removeItem(encryptedStorageKey);
    throw error;
  } finally { salt.fill(0); }
}

async function unlockProfile() {
  const encodedSalt = localStorage.getItem(saltStorageKey);
  if (!encodedSalt || localStorage.getItem(encryptedStorageKey) === null) throw new Error("The encrypted browser profile is incomplete.");
  const salt = fromBase64(encodedSalt);
  try {
    if (salt.byteLength !== 16) throw new Error("The encrypted browser profile is malformed.");
    const repository = makeRepository(elements.unlockPassphrase.value, salt);
    let profile;
    try { profile = await repository.load(); } catch { throw new Error("The profile could not be unlocked. Check the passphrase."); }
    profile = migrateProfile(profile);
    validateProfile(profile);
    runtime.repository = repository;
    runtime.profile = profile;
    await saveProfile();
    elements.unlockPassphrase.value = "";
    routeAfterUnlock();
  } finally { salt.fill(0); }
}

function makeRepository(passphrase, salt) {
  const backend = new BrowserLocalStorageStore({ namespace: `${namespace}:vault` });
  const encrypted = new EncryptedNoctweaveStore(backend, { passphrase, salt, iterations: 310_000 });
  return new NoctweaveStateRepository(encrypted, { key: stateKey });
}

function newProfileState() {
  return {
    version: 2, onboardingComplete: false, identity: null, relay: null, relays: [], contacts: [],
    conversations: {}, messages: [], seenEnvelopeIds: [], selectedContactFingerprint: "",
    settings: { autoFetch: true }, lastSyncAt: null
  };
}

function migrateProfile(profile) {
  if (!profile || typeof profile !== "object") throw new Error("The encrypted browser profile has an unsupported format.");
  if (profile.version === 2) {
    const relay = profile.relay?.address
      ? { ...profile.relay, id: relayId(profile.relay.address), preferred: true }
      : null;
    const relays = (profile.relays ?? []).map((item) => ({
      ...item,
      id: relayId(item.address),
      preferred: relay?.id === relayId(item.address)
    }));
    if (relay && !relays.some((item) => item.id === relay.id)) relays.unshift(relay);
    return { ...newProfileState(), ...profile, relay, relays, settings: { autoFetch: true, ...(profile.settings ?? {}) } };
  }
  if (profile.version !== 1) throw new Error("The encrypted browser profile has an unsupported format.");
  const homeRelay = profile.relay?.address
    ? { ...profile.relay, id: relayId(profile.relay.address), preferred: true }
    : null;
  return {
    ...newProfileState(), ...profile, version: 2, relay: homeRelay,
    relays: homeRelay ? [homeRelay] : [],
    seenEnvelopeIds: [], settings: { autoFetch: true }, lastSyncAt: null
  };
}

function validateProfile(profile) {
  if (!profile || profile.version !== 2 || !Array.isArray(profile.contacts) || !Array.isArray(profile.messages) ||
      !Array.isArray(profile.relays) || !Array.isArray(profile.seenEnvelopeIds) || !profile.conversations || typeof profile.conversations !== "object") {
    throw new Error("The encrypted browser profile has an unsupported format.");
  }
  if (profile.contacts.length > 512 || profile.messages.length > 20_000 || profile.relays.length > 32 || profile.seenEnvelopeIds.length > 40_000) {
    throw new Error("The encrypted browser profile exceeds supported collection limits.");
  }
}

function routeAfterUnlock() {
  if (runtime.profile?.onboardingComplete && runtime.profile.identity && runtime.profile.relay) showApplication();
  else if (runtime.profile?.relay) { elements.relayAddress.value = runtime.profile.relay.address ?? ""; showStep("identity"); }
  else showStep("relay");
}

async function verifyRelay() {
  const address = elements.relayAddress.value.trim();
  parseBrowserRelayEndpoint(address);
  const authToken = elements.relayPassword.value || null;
  const verified = await runtime.identityService.verifyRelay(address, { authToken });
  runtime.verifiedRelay = relayRecord(address, authToken, verified.info.relayInfo);
  runtime.profile.relay = runtime.verifiedRelay;
  runtime.profile.relays = [runtime.verifiedRelay];
  await saveProfile();
  elements.relayResult.textContent = `${relayDisplayName(verified.info.relayInfo)} is reachable and compatible.`;
  elements.relayResult.classList.add("good");
  setTimeout(() => showStep("identity"), 350);
}

async function createIdentity() {
  const relay = runtime.verifiedRelay ?? runtime.profile?.relay;
  if (!relay?.address) throw new Error("Verify a relay before creating an identity.");
  const created = await runtime.identityService.createAndRegister({
    displayName: elements.displayName.value, relay: relay.address, authToken: relay.authToken
  });
  runtime.profile.identity = created.identity;
  runtime.profile.relay = { ...relay, ...created.relay, id: relayId(relay.address), preferred: true, authToken: relay.authToken };
  runtime.profile.relays = [runtime.profile.relay];
  runtime.profile.onboardingComplete = true;
  await saveProfile();
  showApplication();
  notify("Identity created and registered");
}

async function addRelay() {
  const address = elements.newRelayAddress.value.trim();
  parseBrowserRelayEndpoint(address);
  const authToken = elements.newRelayPassword.value || null;
  const verified = await runtime.identityService.verifyRelay(address, { authToken });
  const record = relayRecord(address, authToken, verified.info.relayInfo);
  const index = runtime.profile.relays.findIndex((item) => item.id === record.id);
  if (index >= 0) runtime.profile.relays[index] = { ...runtime.profile.relays[index], ...record };
  else runtime.profile.relays.push(record);
  await saveProfile();
  elements.newRelayAddress.value = "";
  elements.newRelayPassword.value = "";
  elements.addRelayCard.hidden = true;
  renderRelays();
  notify("Relay verified and saved");
}

async function checkRelay(id) {
  const relay = runtime.profile.relays.find((item) => item.id === id);
  if (!relay) return;
  const verified = await runtime.identityService.verifyRelay(relay.address, { authToken: relay.authToken });
  Object.assign(relay, { relayInfo: verified.info.relayInfo, verifiedAt: new Date().toISOString(), reachable: true });
  if (runtime.profile.relay?.id === id) runtime.profile.relay = { ...relay };
  await saveProfile();
  renderRelays();
  notify("Relay is reachable");
}

async function deleteRelay(id) {
  const relay = runtime.profile.relays.find((item) => item.id === id);
  if (!relay || relay.preferred || runtime.profile.relay?.id === id) {
    notify("The active identity’s home relay cannot be removed.", true);
    return;
  }
  runtime.profile.relays = runtime.profile.relays.filter((item) => item.id !== id);
  await saveProfile();
  renderRelays();
}

async function importContact() {
  const code = elements.importContactCode.value.trim();
  if (!code) throw new Error("Paste a signed contact code first.");
  const offer = decodeNativeContactCode(code);
  await verifyNativeContactOffer({ crypto: runtime.crypto, pqc: runtime.pqc, offer });
  if (offer.fingerprint === runtime.profile.identity.signingFingerprint) throw new Error("That contact code belongs to this identity.");
  const alias = elements.contactAlias.value.trim();
  const contact = contactFromOffer(offer, alias);
  const existing = runtime.profile.contacts.findIndex((item) => item.fingerprint === offer.fingerprint);
  if (existing >= 0) runtime.profile.contacts[existing] = { ...runtime.profile.contacts[existing], ...contact };
  else runtime.profile.contacts.push(contact);
  runtime.profile.selectedContactFingerprint = contact.fingerprint;
  await saveProfile();
  elements.importContactCode.value = "";
  elements.contactAlias.value = "";
  elements.addContactCard.hidden = true;
  renderApplication();
  openChat(contact.fingerprint);
  notify(existing >= 0 ? "Contact updated" : "Contact verified and added");
}

async function loadContactFile(event) {
  const input = event.currentTarget;
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;
  if (file.size < 1 || file.size > 100_000) { notify("Contact files must be no larger than 100 KB.", true); return; }
  try {
    elements.importContactCode.value = (await file.text()).trim();
    elements.addContactCard.hidden = false;
    elements.importContactCode.focus();
    notify("Contact file loaded; verify it before saving");
  } catch { notify("The contact file could not be read.", true); }
}

async function deleteContact(fingerprint) {
  const contact = contactByFingerprint(fingerprint);
  if (!contact || !confirm(`Delete ${contactName(contact)} and its local conversation history?`)) return;
  runtime.profile.contacts = runtime.profile.contacts.filter((item) => item.fingerprint !== fingerprint);
  runtime.profile.messages = runtime.profile.messages.filter((item) => item.contactFingerprint !== fingerprint);
  delete runtime.profile.conversations[nativeConversationKey(contact)];
  if (runtime.profile.selectedContactFingerprint === fingerprint) runtime.profile.selectedContactFingerprint = "";
  await saveProfile();
  renderApplication();
}

async function sendMessage() {
  const contact = selectedContact();
  const text = elements.messageInput.value.trim();
  if (!contact) throw new Error("Select a contact before sending.");
  if (!text) return;
  if (runtime.sendingContacts.has(contact.fingerprint)) throw new Error("The previous message is still being prepared.");
  runtime.sendingContacts.add(contact.fingerprint);
  try {
    const conversationKey = nativeConversationKey(contact);
    let conversation = runtime.profile.conversations[conversationKey];
    let kemCiphertext = null;
    if (!conversation) {
      const created = await createNativeOutboundSession({ crypto: runtime.crypto, pqc: runtime.pqc, identity: runtime.profile.identity, contact });
      conversation = created.conversation;
      kemCiphertext = created.kemCiphertext;
      runtime.profile.conversations[conversationKey] = conversation;
    }
    const sentAt = swiftISODate();
    const envelope = await encryptNativeTextEnvelope({
      crypto: runtime.crypto, pqc: runtime.pqc, identity: runtime.profile.identity, contact, conversation, text, sentAt, kemCiphertext
    });
    const message = { id: envelope.id, direction: "out", contactFingerprint: contact.fingerprint, text, sentAt, status: "sending", envelope };
    runtime.profile.messages.push(message);
    elements.messageInput.value = "";
    resizeComposer();
    await saveProfile();
    renderChat();
    try {
      await deliverStoredMessage(message, contact);
      message.status = "sent";
      delete message.envelope;
      await saveProfile();
      renderChat();
    } catch (error) {
      message.status = "failed";
      await saveProfile();
      renderChat();
      throw error;
    }
  } finally {
    runtime.sendingContacts.delete(contact.fingerprint);
  }
}

async function retryMessage(id) {
  const message = runtime.profile.messages.find((item) => item.id === id && item.direction === "out");
  const contact = message && contactByFingerprint(message.contactFingerprint);
  if (!message?.envelope || !contact) throw new Error("This message no longer has a retry envelope.");
  if (runtime.sendingContacts.has(contact.fingerprint)) throw new Error("Another message is still being delivered.");
  runtime.sendingContacts.add(contact.fingerprint);
  message.status = "sending";
  renderChat();
  try {
    await deliverStoredMessage(message, contact);
    message.status = "sent";
    delete message.envelope;
    await saveProfile();
    renderChat();
  } catch (error) {
    message.status = "failed";
    await saveProfile();
    renderChat();
    throw error;
  } finally {
    runtime.sendingContacts.delete(contact.fingerprint);
  }
}

async function deliverStoredMessage(message, contact) {
  const response = await makeRelayClient(relayURLFromEndpoint(contact.relay)).send(relayRequests.deliver({ inboxId: contact.inboxId, envelope: message.envelope }));
  if (!["delivered", "ok"].includes(response?.type)) throw new Error("The relay did not accept the encrypted message.");
}

async function syncMessages() {
  if (runtime.syncing || !runtime.profile?.identity) return;
  runtime.syncing = true;
  let accessKey = null;
  $("#syncNow").classList.add("spinning");
  try {
    const identity = runtime.profile.identity;
    const maxCount = 100;
    const signedAt = swiftISODate();
    const nonce = swiftUUID();
    accessKey = deserializeKeypair(identity.access);
    const response = await makeRelayClient(runtime.profile.relay.address, { authToken: runtime.profile.relay.authToken }).send(relayRequests.fetch({
      inboxId: identity.inboxId,
      routingToken: null,
      maxCount,
      longPollTimeoutSeconds: null,
      accessProof: actorProof(accessKey, identity.accessFingerprint, { inboxId: identity.inboxId, maxCount, nonce, signedAt }, signedAt, nonce)
    }));
    if (response?.type !== "messages") throw new Error("The relay returned an incompatible inbox response.");
    const acknowledged = [];
    let received = 0;
    for (const envelope of response.messages ?? []) {
      const normalizedId = String(envelope.id ?? "").toLowerCase();
      if (!normalizedId) continue;
      if (runtime.profile.seenEnvelopeIds.includes(normalizedId)) { acknowledged.push(envelope.id); continue; }
      try {
        const decoded = await decodeEnvelope(envelope);
        if (!decoded) continue;
        runtime.profile.messages.push(decoded);
        runtime.profile.seenEnvelopeIds.push(normalizedId);
        if (runtime.profile.seenEnvelopeIds.length > 40_000) runtime.profile.seenEnvelopeIds.splice(0, 5_000);
        acknowledged.push(envelope.id);
        received += 1;
      } catch (error) {
        console.warn("Noctweave envelope retained for retry:", safeError(error));
      }
    }
    runtime.profile.lastSyncAt = new Date().toISOString();
    await saveProfile();
    renderApplication();
    if (acknowledged.length > 0) await acknowledgeMessages(acknowledged, accessKey);
    if (received > 0) notify(`${received} new encrypted message${received === 1 ? "" : "s"}`);
  } finally {
    accessKey?.secretKey?.fill(0);
    accessKey?.publicKey?.fill(0);
    runtime.syncing = false;
    $("#syncNow").classList.remove("spinning");
  }
}

async function acknowledgeMessages(messageIds, accessKey) {
  const identity = runtime.profile.identity;
  const signedAt = swiftISODate();
  const nonce = swiftUUID();
  const payload = { inboxId: identity.inboxId, messageIds, signedAt, nonce };
  const response = await makeRelayClient(runtime.profile.relay.address, { authToken: runtime.profile.relay.authToken }).send(relayRequests.acknowledgeMessages({
    inboxId: identity.inboxId,
    messageIds,
    accessProof: actorProof(accessKey, identity.accessFingerprint, payload, signedAt, nonce)
  }));
  if (response?.type !== "ok") throw new Error("Messages were saved locally but relay acknowledgement failed; sync will retry safely.");
}

async function decodeEnvelope(envelope) {
  const contact = contactByFingerprint(envelope.senderFingerprint);
  if (!contact) return null;
  const key = nativeConversationKey(contact);
  let conversation = runtime.profile.conversations[key];
  if (!conversation) {
    if (!envelope.kemCiphertext) return null;
    conversation = await createNativeInboundSession({
      crypto: runtime.crypto, pqc: runtime.pqc, identity: runtime.profile.identity, contact, kemCiphertext: envelope.kemCiphertext
    });
    runtime.profile.conversations[key] = conversation;
  }
  const text = await decryptNativeEnvelope({ crypto: runtime.crypto, pqc: runtime.pqc, identity: runtime.profile.identity, contact, conversation, envelope });
  return { id: envelope.id, direction: "in", contactFingerprint: contact.fingerprint, text, sentAt: envelope.sentAt, read: false, status: "received" };
}

function actorProof(keypair, fingerprint, payload, signedAt, nonce) {
  return { fingerprint, publicSigningKey: base64(keypair.publicKey), signedAt, nonce, signature: base64(runtime.pqc.sign(canonicalJsonBytes(payload), keypair.secretKey)) };
}

async function clearConversation() {
  const contact = selectedContact();
  if (!contact || !confirm(`Clear local history with ${contactName(contact)}? The cryptographic session remains active.`)) return;
  runtime.profile.messages = runtime.profile.messages.filter((item) => item.contactFingerprint !== contact.fingerprint);
  await saveProfile();
  renderApplication();
}

function openChat(fingerprint) {
  runtime.profile.selectedContactFingerprint = fingerprint;
  for (const message of runtime.profile.messages) if (message.contactFingerprint === fingerprint && message.direction === "in") message.read = true;
  void saveProfile();
  openView("chats");
  renderApplication();
}

function closeMobileChat() {
  runtime.profile.selectedContactFingerprint = "";
  void saveProfile();
  renderConversationList();
  renderChat();
}

function selectedContact() { return contactByFingerprint(runtime.profile?.selectedContactFingerprint); }
function contactByFingerprint(fingerprint) { return runtime.profile?.contacts.find((item) => item.fingerprint === fingerprint) ?? null; }
function contactName(contact) { return contact.alias || contact.displayName; }

function contactFromOffer(offer, alias = "") {
  return {
    alias: alias || undefined, displayName: offer.displayName, inboxId: offer.inboxId, relay: offer.relay,
    fingerprint: offer.fingerprint, signingPublicKey: offer.signingPublicKey, agreementPublicKey: offer.agreementPublicKey,
    inboxAccessPublicKey: offer.inboxAccessPublicKey, verifiedAt: new Date().toISOString()
  };
}

function relayRecord(address, authToken, relayInfo) {
  return { id: relayId(address), address, authToken, endpoint: parseBrowserRelayEndpoint(address), relayInfo, verifiedAt: new Date().toISOString(), reachable: true, preferred: false };
}

function relayId(address) { return String(address).trim().toLowerCase().replace(/\/$/, ""); }

function showApplication() {
  elements.startup.hidden = true;
  elements.app.hidden = false;
  renderApplication();
  openView(runtime.currentView || "chats");
  configureAutoFetch();
  run("Fetching messages", syncMessages, { quiet: true });
}

function renderApplication() {
  if (!runtime.profile?.identity) return;
  const identity = runtime.profile.identity;
  const relay = runtime.profile.relay;
  elements.headerIdentity.textContent = identity.displayName;
  elements.identityName.textContent = identity.displayName;
  elements.identityInbox.textContent = identity.inboxId;
  elements.identityFingerprint.textContent = short(identity.signingFingerprint, 30);
  elements.identityRelay.textContent = relayDisplayName(relay?.relayInfo);
  elements.railRelay.textContent = relayDisplayName(relay?.relayInfo);
  elements.relayDot.classList.toggle("offline", relay?.reachable === false);
  elements.lastSync.textContent = formatDate(runtime.profile.lastSyncAt);
  elements.storedMessages.textContent = String(runtime.profile.messages.length);
  elements.autoFetch.checked = runtime.profile.settings?.autoFetch !== false;
  renderCode();
  renderContacts();
  renderConversationList();
  renderChat();
  renderRelays();
  renderUnread();
}

function renderContacts() {
  const query = elements.contactSearch.value.trim().toLowerCase();
  const contacts = runtime.profile.contacts.filter((contact) => `${contactName(contact)} ${contact.displayName}`.toLowerCase().includes(query));
  elements.contactList.replaceChildren();
  for (const contact of contacts) {
    const card = document.createElement("article");
    card.className = "contactCard";
    const glyph = document.createElement("div"); glyph.className = "contactGlyph"; glyph.textContent = initials(contactName(contact));
    const info = document.createElement("div");
    const name = document.createElement("strong"); name.textContent = contactName(contact);
    const details = document.createElement("span"); details.textContent = `${short(contact.fingerprint, 18)} · ${contact.relay?.host ?? "relay"}`;
    info.append(name, details);
    const actions = document.createElement("div"); actions.className = "cardActions";
    const message = document.createElement("button"); message.textContent = "Message"; message.addEventListener("click", () => openChat(contact.fingerprint));
    const remove = document.createElement("button"); remove.className = "iconButton danger"; remove.textContent = "×"; remove.title = "Delete contact"; remove.addEventListener("click", () => deleteContact(contact.fingerprint));
    actions.append(message, remove); card.append(glyph, info, actions); elements.contactList.append(card);
  }
  elements.noContacts.hidden = runtime.profile.contacts.length !== 0;
}

function renderConversationList() {
  const query = elements.chatSearch.value.trim().toLowerCase();
  const contacts = runtime.profile.contacts.filter((contact) => {
    const messages = messagesFor(contact.fingerprint);
    return messages.length > 0 && (!query || contactName(contact).toLowerCase().includes(query) || messages.some((message) => message.text.toLowerCase().includes(query)));
  }).sort((a, b) => latestTimestamp(b.fingerprint) - latestTimestamp(a.fingerprint));
  elements.conversationItems.replaceChildren();
  for (const contact of contacts) {
    const messages = messagesFor(contact.fingerprint);
    const last = messages.at(-1);
    const unread = messages.filter((message) => message.direction === "in" && !message.read).length;
    const button = document.createElement("button");
    button.className = "conversationItem";
    button.classList.toggle("active", runtime.profile.selectedContactFingerprint === contact.fingerprint);
    const glyph = document.createElement("span"); glyph.className = "contactGlyph"; glyph.textContent = initials(contactName(contact));
    const body = document.createElement("span"); body.className = "conversationBody";
    const top = document.createElement("span"); top.className = "conversationTop";
    const name = document.createElement("strong"); name.textContent = contactName(contact);
    const time = document.createElement("time"); time.textContent = compactTime(last.sentAt);
    top.append(name, time);
    const preview = document.createElement("span"); preview.className = "preview"; preview.textContent = last.direction === "out" ? `You: ${last.text}` : last.text;
    body.append(top, preview); button.append(glyph, body);
    if (unread) { const badge = document.createElement("b"); badge.className = "unreadBadge"; badge.textContent = String(unread); button.append(badge); }
    button.addEventListener("click", () => openChat(contact.fingerprint));
    elements.conversationItems.append(button);
  }
  elements.noConversations.hidden = contacts.length !== 0 || Boolean(query);
}

function renderChat() {
  const contact = selectedContact();
  elements.chatPlaceholder.hidden = Boolean(contact);
  elements.activeChat.hidden = !contact;
  if (!contact) return;
  elements.chatContactName.textContent = contactName(contact);
  elements.chatContactStatus.textContent = `Verified · ${contact.relay?.host ?? "Noctweave relay"}`;
  elements.messageList.replaceChildren();
  const rows = messagesFor(contact.fingerprint);
  if (rows.length === 0) {
    const empty = document.createElement("div"); empty.className = "chatWelcome"; empty.innerHTML = "<strong>Encrypted conversation ready</strong><span>Your first message establishes a post-quantum session.</span>"; elements.messageList.append(empty);
  }
  for (const message of rows) {
    const row = document.createElement("div"); row.className = `messageRow ${message.direction}`;
    const bubble = document.createElement("div"); bubble.className = "messageBubble";
    const text = document.createElement("p"); text.textContent = message.text;
    const meta = document.createElement("span"); meta.className = "messageMeta"; meta.textContent = `${compactTime(message.sentAt)}${message.status === "sending" ? " · sending" : message.status === "failed" ? " · not delivered" : ""}`;
    bubble.append(text, meta);
    if (message.status === "failed" && message.envelope) { const retry = document.createElement("button"); retry.className = "retryButton"; retry.textContent = "Retry"; retry.addEventListener("click", () => run("Retrying message", () => retryMessage(message.id))); bubble.append(retry); }
    row.append(bubble); elements.messageList.append(row);
  }
  requestAnimationFrame(() => { elements.messageList.scrollTop = elements.messageList.scrollHeight; });
}

function renderRelays() {
  elements.relayList.replaceChildren();
  for (const relay of runtime.profile.relays) {
    const card = document.createElement("article"); card.className = "relayCard";
    const main = document.createElement("div");
    const title = document.createElement("div"); title.className = "relayTitle";
    const name = document.createElement("strong"); name.textContent = relayDisplayName(relay.relayInfo);
    const badge = document.createElement("span"); badge.className = `badge ${relay.reachable === false ? "bad" : "good"}`; badge.textContent = relay.reachable === false ? "Unavailable" : "Verified";
    title.append(name, badge);
    const address = document.createElement("span"); address.textContent = relay.address;
    const detail = document.createElement("small"); detail.textContent = `${relay.relayInfo?.federationMode ?? "solo"} · checked ${formatDate(relay.verifiedAt)}`;
    main.append(title, address, detail);
    const actions = document.createElement("div"); actions.className = "cardActions";
    const check = document.createElement("button"); check.textContent = "Check"; check.addEventListener("click", () => run("Checking relay", () => checkRelay(relay.id)));
    actions.append(check);
    if (!relay.preferred && runtime.profile.relay?.id !== relay.id) { const remove = document.createElement("button"); remove.className = "iconButton danger"; remove.textContent = "×"; remove.addEventListener("click", () => deleteRelay(relay.id)); actions.append(remove); }
    card.append(main, actions); elements.relayList.append(card);
  }
}

function renderUnread() {
  const count = runtime.profile.messages.filter((message) => message.direction === "in" && !message.read).length;
  elements.navUnread.textContent = String(count);
  elements.navUnread.hidden = count === 0;
  document.title = count ? `(${count}) NoctweaveJS` : "NoctweaveJS Client";
}

function messagesFor(fingerprint) {
  return runtime.profile.messages.filter((message) => message.contactFingerprint === fingerprint).sort((a, b) => new Date(a.sentAt) - new Date(b.sentAt));
}
function latestTimestamp(fingerprint) { return new Date(messagesFor(fingerprint).at(-1)?.sentAt ?? 0).getTime(); }

function openView(view) {
  const titles = { chats: ["Messages", "Chats"], contacts: ["People", "Contact Book"], code: ["Pairing", "My Code"], relays: ["Network", "Relays"], identity: ["Profile", "Identity"], settings: ["Application", "Settings"] };
  if (!titles[view]) return;
  runtime.currentView = view;
  document.querySelectorAll("[data-view-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.viewPanel === view));
  elements.navigation.querySelectorAll("button").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  elements.viewEyebrow.textContent = titles[view][0]; elements.viewTitle.textContent = titles[view][1];
}

function toggleCode() { runtime.codeVisible = !runtime.codeVisible; renderCode(); }
function renderCode() {
  elements.contactCode.textContent = runtime.codeVisible ? encodeNativeContactCode(runtime.profile.identity.contactOffer) : "Contact code hidden";
  $("#revealCode").textContent = runtime.codeVisible ? "Hide" : "Reveal";
}
async function copyCode() { await navigator.clipboard.writeText(encodeNativeContactCode(runtime.profile.identity.contactOffer)); notify("Contact code copied"); }
function downloadCode() {
  const blob = new Blob([encodeNativeContactCode(runtime.profile.identity.contactOffer)], { type: "text/plain" });
  downloadBlob(blob, `${safeFilename(runtime.profile.identity.displayName)}.noctweave-contact.txt`);
}

async function exportProfile() {
  const passphrase = await requestSecret("Protect profile backup", "Choose a separate passphrase. This file contains private keys, sessions, contacts, and history.", true);
  if (passphrase === null) return;
  const packageData = await encryptPortableProfile({ ...runtime.profile, exportedAt: new Date().toISOString() }, passphrase);
  downloadBlob(new Blob([JSON.stringify(packageData, null, 2)], { type: "application/vnd.noctweave.profile+json" }), `noctweave-${safeFilename(profileName)}.noctweave.json`);
}

async function importProfile() {
  const input = $("#importProfile");
  const file = input.files?.[0]; input.value = "";
  if (!file) return;
  if (file.size < 1 || file.size > maximumProfileFileBytes) throw new Error("The profile backup must be no larger than 2 MB.");
  const passphrase = await requestSecret("Unlock profile backup", "Enter the passphrase used for this encrypted backup.", false);
  if (passphrase === null) return;
  let packageData;
  try { packageData = JSON.parse(await file.text()); } catch { throw new Error("The profile backup is not valid JSON."); }
  const profile = migrateProfile(await decryptPortableProfile(packageData, passphrase));
  validateProfile(profile);
  runtime.profile = profile;
  await saveProfile();
  renderApplication();
  notify("Encrypted profile imported");
}

function requestSecret(title, description, confirmation) {
  if (runtime.pendingSecret) return Promise.reject(new Error("A passphrase request is already open."));
  elements.secretTitle.textContent = title; elements.secretDescription.textContent = description;
  elements.secretConfirmationRow.hidden = !confirmation; elements.secretPassphrase.value = ""; elements.secretConfirmation.value = ""; elements.secretError.textContent = "";
  elements.secretDialog.showModal(); elements.secretPassphrase.focus();
  return new Promise((resolve) => { runtime.pendingSecret = { resolve, confirmation }; });
}
function submitSecretDialog(event) {
  event.preventDefault();
  if (!runtime.pendingSecret) return;
  const passphrase = elements.secretPassphrase.value;
  if (runtime.pendingSecret.confirmation && passphrase.length < 12) { elements.secretError.textContent = "Use at least 12 characters."; return; }
  if (runtime.pendingSecret.confirmation && passphrase !== elements.secretConfirmation.value) { elements.secretError.textContent = "Passphrases do not match."; return; }
  const resolve = runtime.pendingSecret.resolve; runtime.pendingSecret = null; elements.secretDialog.close(); resolve(passphrase);
}
function cancelSecretDialog() { if (!runtime.pendingSecret) return; const resolve = runtime.pendingSecret.resolve; runtime.pendingSecret = null; elements.secretDialog.close(); resolve(null); }

function updateAutoFetch() { runtime.profile.settings.autoFetch = elements.autoFetch.checked; void saveProfile(); configureAutoFetch(); }
function configureAutoFetch() {
  clearInterval(runtime.autoFetchTimer); runtime.autoFetchTimer = null;
  if (runtime.profile?.settings?.autoFetch === false || !runtime.profile?.identity) return;
  runtime.autoFetchTimer = setInterval(() => { if (document.visibilityState === "visible") run("Fetching messages", syncMessages, { quiet: true }); }, autoFetchIntervalMs);
}

function lockClient() {
  clearInterval(runtime.autoFetchTimer); runtime.autoFetchTimer = null;
  runtime.repository = null; runtime.profile = null; runtime.verifiedRelay = null; runtime.codeVisible = false;
  showStep("unlock");
}

async function resetInstallation() {
  if (!confirm("Reset this browser installation? Private keys, sessions, contacts, and local history will be permanently deleted.")) return;
  clearInterval(runtime.autoFetchTimer);
  if (runtime.repository) await runtime.repository.clear();
  localStorage.removeItem(saltStorageKey); localStorage.removeItem(encryptedStorageKey);
  runtime.repository = null; runtime.profile = null; runtime.verifiedRelay = null;
  elements.acceptNotice.checked = false; $("[data-step='welcome'] .next").disabled = true; showStep("welcome");
}

async function saveProfile() {
  if (!runtime.repository || !runtime.profile) throw new Error("Unlock the encrypted profile first.");
  validateProfile(runtime.profile);
  await runtime.repository.save(runtime.profile);
}

function showStep(step) {
  runtime.currentStep = step; elements.startup.hidden = false; elements.app.hidden = true;
  document.querySelectorAll(".setupStep").forEach((section) => section.classList.toggle("active", section.dataset.step === step));
  const effectiveIndex = step === "unlock" ? 0 : Math.max(0, steps.indexOf(step));
  [...elements.setupProgress.children].forEach((item, index) => item.classList.toggle("active", index <= effectiveIndex));
  const titles = { welcome: "Private messaging starts here.", unlock: "Welcome back.", storage: "Protect this browser profile.", relay: "Choose where you connect.", identity: "Create your identity." };
  elements.setupTitle.textContent = titles[step]; elements.setupError.textContent = "";
}

async function run(label, operation, { quiet = false } = {}) {
  if (!quiet) setBusy(true, label);
  elements.setupError.textContent = "";
  try { await operation(); }
  catch (error) { const message = safeError(error); if (!elements.startup.hidden) elements.setupError.textContent = message; else if (!quiet) notify(message, true); else console.warn(message); }
  finally { if (!quiet) setBusy(false); }
}

function setBusy(active, label = "Working…") {
  elements.busy.hidden = !active; elements.busyLabel.textContent = label;
  if (!elements.startup.hidden) elements.startup.classList.toggle("working", active);
}

function safeError(error) {
  if (!(error instanceof Error)) return "The operation failed.";
  const blocked = /secret.?key|private.?key|ciphertext|signature.{40,}|[A-Za-z0-9+/]{80,}/i;
  return blocked.test(error.message) ? "The operation failed safely without exposing cryptographic material." : error.message.slice(0, 240);
}

function notify(message, error = false) {
  elements.toast.textContent = message; elements.toast.classList.toggle("error", error); elements.toast.hidden = false;
  clearTimeout(notify.timer); notify.timer = setTimeout(() => { elements.toast.hidden = true; }, 3000);
}

function relayURLFromEndpoint(endpoint) {
  const scheme = endpoint.transport === "websocket" ? (endpoint.useTLS ? "wss" : "ws") : (endpoint.useTLS ? "https" : "http");
  const defaultPort = endpoint.useTLS ? 443 : 80;
  const port = Number(endpoint.port);
  const host = String(endpoint.host).includes(":") ? `[${endpoint.host}]` : endpoint.host;
  return `${scheme}://${host}${port && port !== defaultPort ? `:${port}` : ""}`;
}

function deserializeKeypair(keypair) { return { publicKey: fromBase64(keypair.publicKey), secretKey: fromBase64(keypair.secretKey) }; }
function fromBase64(value) { const binary = atob(value); return Uint8Array.from(binary, (character) => character.charCodeAt(0)); }
function relayDisplayName(info) { return info?.relayName || info?.name || "Noctweave Relay"; }
function formatDate(value) { if (!value) return "Never"; const date = new Date(value); return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString(); }
function compactTime(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
function short(value, length) { return value?.length > length ? `${value.slice(0, Math.floor(length / 2))}…${value.slice(-Math.floor(length / 2))}` : value ?? ""; }
function initials(value) { return value.trim().split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "◇"; }
function safeFilename(value) { return String(value).replace(/[^a-z0-9._-]+/gi, "-").replace(/^-|-$/g, "") || "profile"; }
function downloadBlob(blob, filename) { const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 0); }
function resizeComposer() { elements.messageInput.style.height = "auto"; elements.messageInput.style.height = `${Math.min(elements.messageInput.scrollHeight, 140)}px`; }
