import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  BrowserLocalStorageStore,
  EncryptedNoctweaveStore,
  NoctweaveBrowserIdentityService,
  NoctweaveRemoteEnvelopeError,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  NoctweaveStateRepository,
  WebCryptoPrimitives,
  base64,
  canonicalJsonBytes,
  browserMailboxRouteKey,
  buildCommitMailboxCursorRequest,
  buildRetireInboxRequest,
  buildSyncMailboxRequest,
  contactFromNativeOffer,
  createNativeInboundSession,
  createNativeOutboundSession,
  decodeNativeContactCode,
  decryptNativeApplicationEnvelope,
  encodeNativeContactCode,
  encryptNativeTextEnvelope,
  findNativeContactForEnvelope,
  isCertifiedNativeContact,
  nativeConversationKey,
  parseBrowserRelayEndpoint,
  relayRequests,
  swiftISODate,
  swiftUUID,
  validateMailboxSyncContinuity,
  validateBrowserIdentityState,
  validateRetireInboxRequest,
  verifyNativeContactOffer,
  verifyNativeEnvelope
} from "../src/index.js";

const profileName = new URL(location.href).searchParams.get("profile") || "default";
const namespace = `noctweave-js-client:${profileName}`;
const saltStorageKey = `${namespace}:salt`;
const encryptedStorageKey = `${namespace}:vault:profile`;
const stateKey = "profile";
const steps = ["welcome", "storage", "relay", "identity"];
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
  sendingContacts: new Set()
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
  lastSync: $("#lastSync"), storedMessages: $("#storedMessages")
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
  $("#resetLockedProfile").addEventListener("click", resetLockedProfile);
  $("#verifyRelay").addEventListener("click", () => run("Verifying relay", verifyRelay));
  $("#createIdentity").addEventListener("click", () => run("Creating post-quantum identity", createIdentity));
  $("#lockClient").addEventListener("click", lockClient);
  $("#resetClient").addEventListener("click", () => run("Retiring old inbox routes", retireAndDeleteIdentity));
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
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && runtime.profile?.identity) run("Fetching messages", syncMessages, { quiet: true });
  });
}

async function boot() {
  await run("Loading post-quantum runtime", async () => {
    const wasmBinary = globalThis.__noctweaveDesktopWasmBinary;
    const wasmOptions = wasmBinary instanceof Uint8Array ? { wasmBinary } : {};
    runtime.pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory, wasmOptions);
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
    if (typeof globalThis.__noctweaveDesktopRelayFetch === "function") {
      const body = init?.body;
      if (body !== undefined && typeof body !== "string") {
        throw new TypeError("Desktop relay requests require a text body.");
      }
      return globalThis.__noctweaveDesktopRelayFetch({
        endpoint,
        route: path === "/proxy/health" ? "health" : "relay",
        body
      });
    }
    return fetch(path, { ...init, headers: { ...(init?.headers ?? {}), "x-relay-endpoint": endpoint } });
  };
}

async function createEncryptedProfile() {
  const passphrase = elements.storagePassphrase.value;
  if (passphrase.length < 12) throw new Error("Use a profile passphrase containing at least 12 characters.");
  if (passphrase !== elements.storageConfirmation.value) throw new Error("Profile passphrases do not match.");
  if (localStorage.getItem(encryptedStorageKey) !== null || localStorage.getItem(saltStorageKey) !== null) throw new Error("An encrypted local profile already exists.");
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
  if (!encodedSalt || localStorage.getItem(encryptedStorageKey) === null) throw new Error("The encrypted local profile is incomplete.");
  const salt = fromBase64(encodedSalt);
  try {
    if (salt.byteLength !== 16) throw new Error("The encrypted local profile is malformed.");
    const repository = makeRepository(elements.unlockPassphrase.value, salt);
    let profile;
    try { profile = await repository.load(); } catch { throw new Error("The profile could not be unlocked. Check the passphrase."); }
    validateProfile(profile);
    if (profile.identity) {
      await verifyNativeContactOffer({
        crypto: runtime.crypto,
        pqc: runtime.pqc,
        offer: profile.identity.contactOffer
      });
      if (profile.identity.contactOffer.fingerprint !== profile.identity.signingFingerprint ||
          profile.identity.contactOffer.inboxId !== profile.identity.inboxId ||
          profile.identity.contactOffer.identityGenerationId !== profile.identity.identityGenerationId) {
        throw new Error("The encrypted browser profile identity binding is invalid.");
      }
    }
    if (profile.identityDeletionPending) {
      if (profile.pendingInboxRetirements.length > 0) {
        await resumePendingInboxRetirements(profile, repository);
      }
      await finishLocalReset(repository);
      notify("Old inbox routes retired; local identity state deleted");
      return;
    }
    for (const message of profile.messages) {
      if (message.direction === "out" && message.status === "sending" && message.envelope) {
        message.status = "failed";
      }
    }
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
    stateSchema: "nw.browser-profile.v1", version: 1,
    onboardingComplete: false, identity: null, relay: null, relays: [], contacts: [],
    conversations: {}, messages: [], seenEnvelopeIds: [], seenEnvelopeReceipts: {}, selectedContactFingerprint: "",
    quarantinedTransportEnvelopes: [], pendingInboxRetirements: [], identityDeletionPending: false,
    settings: { autoFetch: true }, lastSyncAt: null
  };
}

function envelopeReceiptKey(sourceScope, logicalId) {
  return `${sourceScope}|${logicalId}`;
}

function validateProfile(profile) {
  if (!profile || profile.stateSchema !== "nw.browser-profile.v1" || profile.version !== 1 ||
      !Array.isArray(profile.contacts) || !Array.isArray(profile.messages) ||
      !Array.isArray(profile.relays) || !Array.isArray(profile.seenEnvelopeIds) ||
      !Array.isArray(profile.quarantinedTransportEnvelopes) ||
      !Array.isArray(profile.pendingInboxRetirements) ||
      typeof profile.onboardingComplete !== "boolean" ||
      typeof profile.identityDeletionPending !== "boolean" ||
      typeof profile.selectedContactFingerprint !== "string" ||
      !profile.settings || typeof profile.settings !== "object" ||
      typeof profile.settings.autoFetch !== "boolean" ||
      (profile.lastSyncAt !== null && !Number.isFinite(Date.parse(profile.lastSyncAt))) ||
      !profile.seenEnvelopeReceipts || typeof profile.seenEnvelopeReceipts !== "object" ||
      Array.isArray(profile.seenEnvelopeReceipts) || !profile.conversations || typeof profile.conversations !== "object") {
    throw new Error("The encrypted browser profile has an unsupported format.");
  }
  if (profile.contacts.length > 512 || profile.messages.length > 20_000 || profile.relays.length > 32 ||
      profile.seenEnvelopeIds.length > 40_000 || Object.keys(profile.seenEnvelopeReceipts).length > 40_000 ||
      profile.quarantinedTransportEnvelopes.length > 512 || profile.pendingInboxRetirements.length > 32) {
    throw new Error("The encrypted browser profile exceeds supported collection limits.");
  }
  const contactFingerprints = new Set();
  for (const contact of profile.contacts) {
    if (!isCertifiedNativeContact(contact) || typeof contact.fingerprint !== "string" ||
        contactFingerprints.has(contact.fingerprint)) {
      throw new Error("The encrypted browser profile contains an unsupported contact record.");
    }
    contactFingerprints.add(contact.fingerprint);
  }
  for (const [key, conversation] of Object.entries(profile.conversations)) {
    if (!key.startsWith("direct-v4:") || !conversation || typeof conversation !== "object" ||
        Array.isArray(conversation) || !conversation.endpointSession ||
        typeof conversation.endpointSession !== "object") {
      throw new Error("The encrypted browser profile contains an unsupported session record.");
    }
  }
  const messageIds = new Set();
  for (const message of profile.messages) {
    const scopedMessageId = `${message?.contactFingerprint ?? ""}|${message?.direction ?? ""}|${message?.id ?? ""}`;
    if (!message || typeof message !== "object" || Array.isArray(message) ||
        typeof message.id !== "string" || message.id.length < 1 || message.id.length > 160 ||
        messageIds.has(scopedMessageId) || typeof message.contactFingerprint !== "string" ||
        message.contactFingerprint.length < 1 || message.contactFingerprint.length > 160 ||
        typeof message.text !== "string" || message.text.length > 32_768 ||
        !Number.isFinite(Date.parse(message.sentAt)) ||
        !["in", "out"].includes(message.direction) ||
        (message.direction === "out" && message.status != null &&
          !["sending", "sent", "failed"].includes(message.status))) {
      throw new Error("The encrypted browser profile contains an invalid message record.");
    }
    if (message.envelope != null) {
      if (message.direction !== "out" || !message.envelope ||
          typeof message.envelope !== "object" || Array.isArray(message.envelope) ||
          message.status === "sent" || typeof message.envelopeId !== "string" ||
          message.envelopeId.length < 1 || message.envelopeId.length > 160 ||
          typeof message.clientTransactionId !== "string" ||
          message.clientTransactionId.length < 1 || message.clientTransactionId.length > 160 ||
          message.envelope.id !== message.envelopeId ||
          JSON.stringify(message.envelope).length > 512 * 1024) {
        throw new Error("The encrypted browser profile contains an invalid retry envelope.");
      }
    }
    messageIds.add(scopedMessageId);
  }
  const receiptEnvelopeIds = new Set();
  for (const [key, receipt] of Object.entries(profile.seenEnvelopeReceipts)) {
    const logicalId = receipt?.logicalId;
    const sourceScope = receipt?.sourceScope;
    if (!/^[0-9a-f-]{36}$/u.test(logicalId) ||
        typeof sourceScope !== "string" || sourceScope.length < 1 || sourceScope.length > 160 ||
        key !== envelopeReceiptKey(sourceScope, logicalId) || !receipt || typeof receipt !== "object" ||
        !/^[0-9a-f-]{36}$/u.test(receipt.envelopeId) ||
        typeof receipt.digest !== "string" || receipt.digest.length !== 44 ||
        receiptEnvelopeIds.has(receipt.envelopeId)) {
      throw new Error("The encrypted browser profile contains an invalid envelope receipt.");
    }
    receiptEnvelopeIds.add(receipt.envelopeId);
  }
  const quarantinePositions = new Set();
  for (const item of profile.quarantinedTransportEnvelopes) {
    const position = `${item?.streamDigest ?? ""}:${item?.sequence ?? ""}`;
    if (!item || typeof item !== "object" || typeof item.streamDigest !== "string" ||
        item.streamDigest.length !== 44 || !Number.isSafeInteger(item.sequence) || item.sequence < 1 ||
        !/^[0-9a-f-]{36}$/u.test(item.envelopeId) ||
        typeof item.envelopeDigest !== "string" || item.envelopeDigest.length !== 44 ||
        !["unknownSender", "invalidAttribution", "replayConflict", "unsupportedPayload"].includes(item.reason) ||
        !Number.isFinite(Date.parse(item.quarantinedAt)) || quarantinePositions.has(position)) {
      throw new Error("The encrypted browser profile contains an invalid transport quarantine receipt.");
    }
    quarantinePositions.add(position);
  }
  const retirementRelays = new Set();
  for (const item of profile.pendingInboxRetirements) {
    if (!item || typeof item !== "object" || Array.isArray(item) ||
        typeof item.relayAddress !== "string" || retirementRelays.has(item.relayAddress)) {
      throw new Error("The encrypted browser profile contains an invalid inbox-retirement journal.");
    }
    parseBrowserRelayEndpoint(item.relayAddress);
    validateRetireInboxRequest(item.request);
    retirementRelays.add(item.relayAddress);
  }
  if (profile.pendingInboxRetirements.length > 0 && !profile.identityDeletionPending) {
    throw new Error("The encrypted browser profile contains an unbound inbox-retirement journal.");
  }
  if (profile.identity != null) {
    validateBrowserIdentityState(profile.identity);
    if (Object.values(profile.identity.localEndpoint.mailboxRoutes).some((route) =>
      route.mode !== "v2" || route.registration?.state !== "active")) {
      throw new Error("The encrypted browser profile identity has an inactive mailbox route.");
    }
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
    notify("The active identity generation’s current relay route cannot be removed.", true);
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
    const previousConversation = runtime.profile.conversations[conversationKey] ?? null;
    let conversation = previousConversation ? structuredClone(previousConversation) : null;
    let kemCiphertext = null;
    let prekey = null;
    if (!conversation) {
      const created = await createNativeOutboundSession({ crypto: runtime.crypto, pqc: runtime.pqc, identity: runtime.profile.identity, contact });
      conversation = created.conversation;
      kemCiphertext = created.kemCiphertext;
      prekey = created.prekey ?? null;
    }
    const sentAt = swiftISODate();
    const eventId = swiftUUID();
    const clientTransactionId = swiftUUID();
    const envelope = await encryptNativeTextEnvelope({
      crypto: runtime.crypto, pqc: runtime.pqc, identity: runtime.profile.identity,
      contact, conversation, text, sentAt, eventId, clientTransactionId,
      kemCiphertext, prekey
    });
    const message = {
      id: envelope.authenticatedContext?.directV4?.eventId ?? eventId,
      envelopeId: envelope.id,
      clientTransactionId,
      direction: "out",
      contactFingerprint: contact.fingerprint,
      text,
      sentAt,
      status: "sending",
      envelope
    };
    runtime.profile.conversations[conversationKey] = conversation;
    runtime.profile.messages.push(message);
    try {
      await saveProfile();
    } catch (error) {
      runtime.profile.messages.pop();
      if (previousConversation) runtime.profile.conversations[conversationKey] = previousConversation;
      else delete runtime.profile.conversations[conversationKey];
      throw error;
    }
    elements.messageInput.value = "";
    resizeComposer();
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
  let consumerKey = null;
  $("#syncNow").classList.add("spinning");
  try {
    const identity = runtime.profile.identity;
    const localEndpoint = identity.localEndpoint;
    if (identity.architectureVersion !== 2 || !localEndpoint) {
      throw new Error("The identity does not use the current mailbox-v2 endpoint state.");
    }
    const relay = runtime.profile.relay;
    const routeKey = browserMailboxRouteKey(relay.address, identity.inboxId);
    const route = localEndpoint.mailboxRoutes?.[routeKey];
    if (route?.mode !== "v2" || route.registration?.state !== "active") {
      throw new Error("Mailbox v2 registration is not active.");
    }
    consumerKey = deserializeKeypair(route.signing);
    const client = makeRelayClient(relay.address, { authToken: relay.authToken });
    if (route.pendingCommit) {
      await commitMailboxCursor(client, identity, route, consumerKey);
    }
    const maxCount = 100;
    const request = await buildSyncMailboxRequest({
      inboxId: identity.inboxId,
      consumerId: route.consumerId,
      cursor: route.cursor,
      maxCount,
      consumerSigningKey: consumerKey,
      consumerFingerprint: route.signingFingerprint,
      pqc: runtime.pqc,
      crypto: runtime.crypto
    });
    const response = await client.syncMailbox(request);
    const batch = validateMailboxSyncContinuity(
      response.mailboxSync,
      route.committedSequence
    );
    const envelopeReceiptOwners = new Map(
      Object.entries(runtime.profile.seenEnvelopeReceipts).map(([receiptKey, receipt]) => [
        receipt.envelopeId,
        receiptKey
      ])
    );
    let received = 0;
    for (const event of batch.events) {
      const envelope = event.envelope;
      const normalizedId = String(envelope.id ?? "").toLowerCase();
      if (!normalizedId) throw new Error("The relay returned an envelope without an ID.");
      const logicalId = String(
        envelope.authenticatedContext?.directV4?.eventId ?? envelope.id ?? ""
      ).toLowerCase();
      if (!logicalId) throw new Error("The relay returned an envelope without a logical event ID.");
      const sourceScope = String(envelope.senderFingerprint ?? "");
      if (sourceScope.length < 1 || sourceScope.length > 160) {
        throw new Error("The relay returned an envelope without a bounded relationship source.");
      }
      const receiptKey = envelopeReceiptKey(sourceScope, logicalId);
      const digest = base64(await runtime.crypto.sha256(canonicalJsonBytes(envelope)));
      const priorReceipt = runtime.profile.seenEnvelopeReceipts[receiptKey]
        ?? runtime.profile.seenEnvelopeReceipts[logicalId];
      if (priorReceipt) {
        if (priorReceipt.envelopeId !== normalizedId || priorReceipt.digest !== digest) {
          await verifyEnvelopeAttribution(envelope);
          await recordTransportQuarantine(event, digest, "replayConflict", routeKey);
        }
        continue;
      }
      const priorLogicalOwner = envelopeReceiptOwners.get(normalizedId);
      if (priorLogicalOwner && priorLogicalOwner !== receiptKey) {
        await verifyEnvelopeAttribution(envelope);
        await recordTransportQuarantine(event, digest, "replayConflict", routeKey);
        continue;
      }
      try {
        const mutationSnapshot = {
          conversations: runtime.profile.conversations,
          messages: runtime.profile.messages,
          seenEnvelopeReceipts: runtime.profile.seenEnvelopeReceipts,
          seenEnvelopeIds: runtime.profile.seenEnvelopeIds
        };
        runtime.profile.conversations = { ...mutationSnapshot.conversations };
        runtime.profile.messages = [...mutationSnapshot.messages];
        runtime.profile.seenEnvelopeReceipts = { ...mutationSnapshot.seenEnvelopeReceipts };
        runtime.profile.seenEnvelopeIds = [...mutationSnapshot.seenEnvelopeIds];
        const decoded = await decodeEnvelope(envelope);
        if (!decoded) {
          throw new NoctweaveRemoteEnvelopeError(
            "unknownSender",
            "The envelope cannot be attributed to a verified contact."
          );
        }
        if (!decoded.silent) runtime.profile.messages.push(decoded);
        runtime.profile.seenEnvelopeReceipts[receiptKey] = {
          sourceScope,
          logicalId,
          envelopeId: normalizedId,
          digest
        };
        envelopeReceiptOwners.set(normalizedId, logicalId);
        runtime.profile.seenEnvelopeIds.push(normalizedId);
        if (runtime.profile.seenEnvelopeIds.length > 40_000) {
          runtime.profile.seenEnvelopeIds.splice(0, 5_000);
        }
        const receiptIds = Object.keys(runtime.profile.seenEnvelopeReceipts);
        if (receiptIds.length > 40_000) {
          for (const id of receiptIds.slice(0, 5_000)) {
            envelopeReceiptOwners.delete(runtime.profile.seenEnvelopeReceipts[id].envelopeId);
            delete runtime.profile.seenEnvelopeReceipts[id];
          }
        }
        received += 1;
        // Persist every ratchet transition and decoded event before allowing the
        // local endpoint cursor to advance over the containing batch.
        try {
          await saveProfile();
        } catch (error) {
          runtime.profile.conversations = mutationSnapshot.conversations;
          runtime.profile.messages = mutationSnapshot.messages;
          runtime.profile.seenEnvelopeReceipts = mutationSnapshot.seenEnvelopeReceipts;
          runtime.profile.seenEnvelopeIds = mutationSnapshot.seenEnvelopeIds;
          envelopeReceiptOwners.clear();
          for (const [ownerId, receipt] of Object.entries(runtime.profile.seenEnvelopeReceipts)) {
            envelopeReceiptOwners.set(receipt.envelopeId, ownerId);
          }
          throw error;
        }
      } catch (error) {
        if (error instanceof NoctweaveRemoteEnvelopeError) {
          await recordTransportQuarantine(event, digest, error.reason, routeKey);
          console.warn("Noctweave envelope quarantined:", safeError(error));
          continue;
        }
        console.warn("Noctweave envelope retained for retry:", safeError(error));
        throw error;
      }
    }
    route.cursor = batch.nextCursor;
    route.pendingCommit = {
      cursor: batch.nextCursor,
      sequence: batch.nextSequence,
      preparedAt: swiftISODate()
    };
    runtime.profile.lastSyncAt = new Date().toISOString();
    await saveProfile();
    await commitMailboxCursor(client, identity, route, consumerKey);
    renderApplication();
    if (received > 0) notify(`${received} new encrypted message${received === 1 ? "" : "s"}`);
  } finally {
    consumerKey?.secretKey?.fill(0);
    consumerKey?.publicKey?.fill(0);
    runtime.syncing = false;
    $("#syncNow").classList.remove("spinning");
  }
}

async function recordTransportQuarantine(event, envelopeDigest, reason, routeKey) {
  const sequence = event?.sequence;
  const envelopeId = String(event?.envelope?.id ?? "").toLowerCase();
  if (!Number.isSafeInteger(sequence) || sequence < 1 ||
      !/^[0-9a-f-]{36}$/u.test(envelopeId) ||
      typeof envelopeDigest !== "string" || envelopeDigest.length !== 44 ||
      !["unknownSender", "invalidAttribution", "replayConflict", "unsupportedPayload"].includes(reason)) {
    throw new Error("A transport quarantine receipt cannot be constructed safely.");
  }
  const streamDigest = base64(await runtime.crypto.sha256(new TextEncoder().encode(routeKey)));
  const existing = runtime.profile.quarantinedTransportEnvelopes.find(
    (item) => item.streamDigest === streamDigest && item.sequence === sequence
  );
  if (existing) {
    if (existing.envelopeId !== envelopeId || existing.envelopeDigest !== envelopeDigest ||
        existing.reason !== reason) {
      throw new Error("The relay changed an already quarantined mailbox position.");
    }
    return;
  }
  if (runtime.profile.quarantinedTransportEnvelopes.length >= 512) {
    runtime.profile.quarantinedTransportEnvelopes.splice(0, 64);
  }
  runtime.profile.quarantinedTransportEnvelopes.push({
    streamDigest,
    sequence,
    envelopeId,
    envelopeDigest,
    reason,
    quarantinedAt: swiftISODate()
  });
  await saveProfile();
}

async function commitMailboxCursor(client, identity, route, consumerKey) {
  const pending = route.pendingCommit;
  if (!pending) return;
  if (!Number.isSafeInteger(route.committedSequence) || route.committedSequence < 0 ||
      !Number.isSafeInteger(pending.sequence) || pending.sequence < route.committedSequence) {
    throw new Error("The persisted mailbox sequence state is invalid.");
  }
  const request = await buildCommitMailboxCursorRequest({
    inboxId: identity.inboxId,
    consumerId: route.consumerId,
    cursor: pending.cursor,
    sequence: pending.sequence,
    consumerSigningKey: consumerKey,
    consumerFingerprint: route.signingFingerprint,
    pqc: runtime.pqc,
    crypto: runtime.crypto
  });
  const response = await client.commitMailboxCursor(request);
  const registration = response.mailboxConsumer;
  if (registration?.state !== "active" ||
      registration.consumerId !== route.consumerId ||
      registration.consumerSigningPublicKey !== route.signing.publicKey ||
      registration.committedSequence !== pending.sequence) {
    throw new Error("The relay returned a mismatched committed mailbox sequence.");
  }
  route.registration = registration;
  route.cursor = pending.cursor;
  route.committedSequence = pending.sequence;
  route.pendingCommit = null;
  await saveProfile();
}

async function decodeEnvelope(envelope) {
  const contact = await findNativeContactForEnvelope({
    crypto: runtime.crypto,
    identity: runtime.profile.identity,
    contacts: runtime.profile.contacts,
    envelope
  });
  if (!contact) return null;
  const key = nativeConversationKey(contact);
  const storedConversation = runtime.profile.conversations[key];
  let conversation = storedConversation ? structuredClone(storedConversation) : null;
  if (!conversation) {
    if (!envelope.kemCiphertext) return null;
    conversation = await createNativeInboundSession({
      crypto: runtime.crypto, pqc: runtime.pqc, identity: runtime.profile.identity, contact,
      kemCiphertext: envelope.kemCiphertext, prekey: envelope.prekey ?? null
    });
  }
  const decryptOptions = {
    crypto: runtime.crypto,
    pqc: runtime.pqc,
    identity: runtime.profile.identity,
    contact,
    conversation,
    envelope
  };
  const decoded = await decryptNativeApplicationEnvelope(decryptOptions);
  const silent = decoded.projection.disposition === "silent";
  const text = decoded.projection.kind === "text"
    ? decoded.projection.text
    : decoded.projection.fallbackText;
  runtime.profile.conversations[key] = conversation;
  return {
    id: envelope.authenticatedContext?.directV4?.eventId ?? envelope.id,
    direction: "in", contactFingerprint: contact.fingerprint, text, silent,
    sentAt: envelope.sentAt, read: false, status: "received"
  };
}

async function verifyEnvelopeAttribution(envelope) {
  const contact = await findNativeContactForEnvelope({
    crypto: runtime.crypto,
    identity: runtime.profile.identity,
    contacts: runtime.profile.contacts,
    envelope
  });
  if (!contact) throw new Error("The envelope cannot be attributed to a verified contact.");
  const key = nativeConversationKey(contact);
  let conversation = runtime.profile.conversations[key];
  if (!conversation) {
    if (!envelope.kemCiphertext) {
      throw new Error("The signed envelope cannot establish an authenticated session.");
    }
    conversation = await createNativeInboundSession({
      crypto: runtime.crypto,
      pqc: runtime.pqc,
      identity: runtime.profile.identity,
      contact,
      kemCiphertext: envelope.kemCiphertext,
      prekey: envelope.prekey ?? null
    });
  }
  await verifyNativeEnvelope({
    crypto: runtime.crypto,
    pqc: runtime.pqc,
    contact,
    conversation,
    envelope
  });
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
  return { ...contactFromNativeOffer(offer, alias), verifiedAt: new Date().toISOString() };
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

async function resetLockedProfile() {
  const runtimeName = document.documentElement.dataset.runtime === "desktop" ? "desktop application" : "browser profile";
  if (!confirm(`Forget this locked ${runtimeName}? The encrypted local data will be deleted, but the inbox cannot be cryptographically retired while its key is locked. Unlock first to retire and delete the identity generation completely.`)) return;
  clearInterval(runtime.autoFetchTimer);
  await finishLocalReset(null);
}

async function retireAndDeleteIdentity() {
  const runtimeName = document.documentElement.dataset.runtime === "desktop" ? "desktop application" : "browser endpoint";
  if (!confirm(`Retire and delete this ${runtimeName} identity generation? Every known inbox route will be retired before private keys, sessions, contacts, and local history are permanently deleted. This deletes the generation; it does not create or link a replacement.`)) return;
  if (!runtime.repository || !runtime.profile?.identity) {
    throw new Error("Unlock the identity before performing complete retirement and deletion.");
  }
  clearInterval(runtime.autoFetchTimer);
  if (!runtime.profile.identityDeletionPending) {
    const accessKey = deserializeKeypair(runtime.profile.identity.access);
    try {
      const request = await buildRetireInboxRequest({
        inboxId: runtime.profile.identity.inboxId,
        accessSigningKey: accessKey,
        accessFingerprint: runtime.profile.identity.accessFingerprint,
        pqc: runtime.pqc,
        crypto: runtime.crypto
      });
      const relays = new Map();
      for (const relay of [runtime.profile.relay, ...runtime.profile.relays].filter(Boolean)) {
        if (relay?.address) relays.set(relay.address, relay);
      }
      if (relays.size === 0 || relays.size > 32) {
        throw new Error("The identity has no bounded set of known inbox relays to retire.");
      }
      runtime.profile.pendingInboxRetirements = [...relays.values()].map((relay) => ({
        relayAddress: relay.address,
        request
      }));
      runtime.profile.identityDeletionPending = true;
      // Persist the exact private-key-free requests before any key deletion or
      // network call. Exact relay retries are intentionally idempotent.
      await saveProfile();
    } finally {
      accessKey.secretKey.fill(0);
      accessKey.publicKey.fill(0);
    }
  }
  if (runtime.profile.pendingInboxRetirements.length > 0) {
    await resumePendingInboxRetirements(runtime.profile, runtime.repository);
  }
  await finishLocalReset(runtime.repository);
}

async function resumePendingInboxRetirements(profile, repository) {
  while (profile.pendingInboxRetirements.length > 0) {
    const pending = profile.pendingInboxRetirements[0];
    const relay = [profile.relay, ...profile.relays].find(
      (candidate) => candidate?.address === pending.relayAddress
    );
    const client = new NoctweaveRelayClient(pending.relayAddress, {
      authToken: relay?.authToken ?? null
    });
    await client.retireInbox(pending.request);
    profile.pendingInboxRetirements.shift();
    await repository.save(profile);
  }
}

async function finishLocalReset(repository) {
  if (repository) await repository.clear();
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
  const titles = { welcome: "Private messaging starts here.", unlock: "Welcome back.", storage: "Protect this local profile.", relay: "Choose where you connect.", identity: "Create your identity." };
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
