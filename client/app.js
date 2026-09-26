import { securityKeyAuthenticator } from "./security-keys.js";
import { unlockFailureMessage } from "./unlock-visibility.js";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  EncryptedNoctweaveStore,
  NoctweaveBrowserPairingService,
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  PairingLobbyHostSessionV1,
  PairingLobbyRequesterSessionV1,
  WebCryptoPrimitives,
  createRendezvousRelayAdapterV2,
  decodeContactPairingInvitationV2,
  decodeNoctweavePairingLinkV1,
  encodeContactPairingInvitationV2,
  encodeNoctweavePairingLinkV1,
  parseBrowserRelayEndpoint,
  relayEndpointURL,
  swiftISODate,
  validateBrowserPersonaState,
  verifyPairingLobbyListingV1
} from "../src/index.js";
import {
  browserSecurityStorageCapabilityV2,
  browserSecurityStorageProfileV2,
  createIndexedDBBrowserAnchorStoreFactoryV2
} from "./browser-security-profile.js";
import {
  HostAnchoredBrowserApplicationVaultV2,
  NoctweaveBrowserMessagingServiceV2,
  browserMessagingAttachmentMaximumBytes,
  browserMessagingAttachmentStatus,
  browserRollbackAnchorRequirement,
  executeAnchoredBrowserLocalBurnV2
} from "./messaging-service.js";
import { initializeAppearanceControl } from "./theme.js";

initializeAppearanceControl();

const state = {
  pqc: null,
  crypto: null,
  pairing: null,
  messaging: null,
  vault: null,
  vaultStatus: "unavailable",
  encryptedStore: null,
  repository: null,
  persona: null,
  invitation: null,
  invitationPairingID: null,
  selectedRelationshipID: null,
  messageSnapshot: null,
  messageSyncStatus: "Select a relationship to begin.",
  securityProfile: null,
  anchorFactory: null,
  relayVerifiedEndpoint: null,
  relayVerifiedSummary: null,
  safetyNumber: null,
  pairingBusy: new Set(),
  relayPairing: null,
  relayPairingBusy: false,
  messageBusy: false,
  lastMaintenanceAt: 0,
  pumpTimer: null,
  messagePumpTimer: null,
  keyController: null,
  keyPresenceRequired: false,
  hiddenUnlockMethods: [],
  keyDetectedForAttempt: false,
  attachedKeys: [],
  attachmentTimer: null,
  attachmentGeneration: 0,
  keyUIRevision: 0,
  activeView: "chats"
};
const RELAY_PREFERENCE_KEY = "application:relay-preference:v1";
const ACTIVE_PAIRING_POLL_MS = 1_000;
const PAIRING_INVITATION_MAX_CHARACTERS = 32_768;

const $ = (selector) => document.querySelector(selector);
const elements = {
  gate: $("#vaultGate"),
  app: $("#appShell"),
  passphrase: $("#vaultPassphrase"),
  confirmation: $("#vaultConfirmation"),
  confirmationRow: $("#vaultConfirmationRow"),
  vaultTitle: $("#vaultTitle"),
  vaultIntro: $("#vaultIntro"),
  unlock: $("#unlockVault"),
  forget: $("#forgetVault"),
  error: $("#vaultError"),
  securityAcknowledgment: $("#securityAcknowledgment"),
  securityAcknowledgmentText: $("#securityAcknowledgmentText"),
  securityProfileWarning: $("#securityProfileWarning"),
  securityProfileInfo: $("#securityProfileInfo"),
  creationFields: $("#personaCreationFields"),
  onboardingRelay: $("#onboardingRelay"),
  onboardingRelayCheck: $("#onboardingRelayCheck"),
  onboardingRelayInfo: $("#onboardingRelayInfo"),
  displayName: $("#displayName"),
  relay: $("#relay"),
  relayInfo: $("#relayInfo"),
  status: $("#status"),
  personaName: $("#personaName"),
  relationshipCount: $("#relationshipCount"),
  relationshipList: $("#relationshipList"),
  relationshipSectionLabel: $("#relationshipSectionLabel"),
  selectedRelationshipName: $("#selectedRelationshipName"),
  selectedRelationshipState: $("#selectedRelationshipState"),
  messageList: $("#messageList"),
  messageText: $("#messageText"),
  sendMessage: $("#sendMessage"),
  resumeOutbox: $("#resumeOutbox"),
  syncMessages: $("#syncMessages"),
  retryRouteTeardown: $("#retryRouteTeardown"),
  relationshipConsent: $("#relationshipConsent"),
  muteRelationship: $("#muteRelationship"),
  deliveryReceiptsEnabled: $("#deliveryReceiptsEnabled"),
  readReceiptsEnabled: $("#readReceiptsEnabled"),
  safetyNumber: $("#safetyNumber"),
  attachmentFile: $("#attachmentFile"),
  attachmentStatus: $("#attachmentStatus"),
  outboxStatus: $("#outboxStatus"),
  invitation: $("#pairingInvitation"),
  peerInvitation: $("#peerInvitation"),
  relationshipPseudonym: $("#relationshipPseudonym"),
  invitationResult: $("#invitationResult"),
  pairingStatus: $("#pairingStatus"),
  pendingPairingList: $("#pendingPairingList"),
  relayPairingStatus: $("#relayPairingStatus"),
  relayPairingResults: $("#relayPairingResults"),
  startRelayVisibility: $("#startRelayVisibility"),
  findRelayPeers: $("#findRelayPeers"),
  stopRelayPairing: $("#stopRelayPairing"),
  viewTitle: $("#viewTitle"),
  viewSubtitle: $("#viewSubtitle"),
  openPairingView: $("#openPairingView"),
  openAttachment: $("#openAttachment")
};

const clientViews = [...document.querySelectorAll("[data-client-view]")];
const clientViewNavigation = [...document.querySelectorAll("[data-client-view-target]")];
const clientViewCopy = {
  chats: ["Chats", "Private conversations and groups"],
  people: ["People", "Add contacts with relay pairing or a one-use invitation"],
  you: ["You", "Persona, relays, and app settings"],
  relays: ["Relays", "Verify and choose this persona's transport"],
  identity: ["Identity Management", "Local labels and relationship-scoped authority"],
  settings: ["Settings", "Appearance and protected local state"]
};

elements.unlock.addEventListener("click", () => run(hasVault() ? unlockVault : createVault));
$("#unlockWithKey").addEventListener("click", () => void performSecurityKeyAction("unlock"));
$("#registerSecurityKey").addEventListener("click", () => void performSecurityKeyAction("register"));
$("#saveKeyPresence").addEventListener("click", () => void performSecurityKeyAction("presence"));
$("#saveUnlockVisibility").addEventListener("click", () => void performSecurityKeyAction("visibility"));
for (const id of ["#cancelKeyUnlock", "#cancelKeySetup", "#cancelUnlockPrivacy"]) $(id).addEventListener("click", cancelSecurityKeyAction);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    if (state.persona) lockProfile();
    else { cancelSecurityKeyAction(); stopKeyAttachmentWatch(); }
  }
  else startKeyAttachmentWatch();
});
elements.forget.addEventListener("click", () => run(forgetVault));
elements.onboardingRelayCheck.addEventListener("click", () => run(verifyOnboardingRelay));
elements.onboardingRelay.addEventListener("input", () => {
  if (elements.onboardingRelay.value.trim() === state.relayVerifiedEndpoint) return;
  state.relayVerifiedEndpoint = null;
  state.relayVerifiedSummary = null;
  elements.onboardingRelayInfo.textContent = "The relay will be verified before this persona is created.";
});
$("#verifyRelay").addEventListener("click", () => run(verifyRelay));
$("#createInvitation").addEventListener("click", () => run(createInvitation));
$("#shareInvitation").addEventListener("click", () => run(shareInvitation));
$("#copyInvitation").addEventListener("click", () => run(copyInvitation));
$("#pasteAndPair").addEventListener("click", () => run(pasteAndPair));
$("#inspectInvitation").addEventListener("click", () => run(inspectInvitation));
$("#acceptInvitation").addEventListener("click", () => run(acceptInvitation));
$("#resumePairings").addEventListener("click", () => run(resumeAllPairings));
elements.startRelayVisibility.addEventListener("click", () => run(startRelayVisibility));
elements.findRelayPeers.addEventListener("click", () => run(findRelayPeers));
elements.stopRelayPairing.addEventListener("click", () => run(stopRelayPairing));
elements.openPairingView.addEventListener("click", () => activateClientView("people"));
for (const control of clientViewNavigation) {
  control.addEventListener("click", () => activateClientView(
    control.dataset.clientViewTarget,
    control
  ));
}
elements.sendMessage.addEventListener("click", () => runMessaging(sendMessage));
elements.resumeOutbox.addEventListener("click", () => runMessaging(resumeSelectedOutbox));
elements.syncMessages.addEventListener("click", () => runMessaging(syncSelectedMessages));
elements.retryRouteTeardown.addEventListener("click", () => runMessaging(retrySelectedRouteTeardown));
elements.relationshipConsent.addEventListener("change", () => runMessaging(updateSelectedConsent));
elements.muteRelationship.addEventListener("click", () => runMessaging(toggleSelectedRelationshipMute));
elements.deliveryReceiptsEnabled.addEventListener("change", () => runMessaging(updateReceiptPreferences));
elements.readReceiptsEnabled.addEventListener("change", () => runMessaging(updateReceiptPreferences));
elements.attachmentFile.addEventListener("change", () => runMessaging(sendSelectedAttachment));
elements.openAttachment.addEventListener("click", () => elements.attachmentFile.click());
$("#lockProfile").addEventListener("click", lockProfile);
$("#burnProfile").addEventListener("click", () => runMessaging(burnLocalPersona));
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") void resumeAfterKeyPresenceCheck();
});

async function resumeAfterKeyPresenceCheck() {
  if (await state.vault?.checkSecurityKeyPresence() === false) return;
  await foregroundMessagingMaintenance();
}

boot();

async function boot() {
  await run(async () => {
    const wasmBinary = globalThis.__noctweaveDesktopWasmBinary;
    const wasmOptions = wasmBinary instanceof Uint8Array ? { wasmBinary } : {};
    state.pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory, wasmOptions);
    const webcrypto = new WebCryptoPrimitives();
    state.crypto = new NoctweaveCryptoSuite({ pqc: state.pqc, webcrypto });
    state.pairing = new NoctweaveBrowserPairingService({
      pqc: state.pqc,
      crypto: state.crypto,
      relayClientFactory: makeRelayClient
    });
    const desktopAnchorFactory = typeof globalThis.noctweaveRelationshipStateAnchorStoreFactory ===
      "function"
      ? globalThis.noctweaveRelationshipStateAnchorStoreFactory
      : null;
    const desktopMode = document.documentElement.dataset.runtime === "desktop";
    if (desktopAnchorFactory !== null) {
      state.anchorFactory = desktopAnchorFactory;
      state.securityProfile = globalThis.noctweaveDesktopAnchorCapability ?? {
        id: "electrobun-host-anchor-v3",
        label: "Electrobun hardened host anchor",
        hardwareRollbackResistance: true,
        warning: null,
        available: true,
        reason: null
      };
      state.vault = new HostAnchoredBrowserApplicationVaultV2({
        crypto: state.crypto,
        storageCrypto: globalThis.crypto,
        stateAnchorStoreFactory: state.anchorFactory
      });
      state.vaultStatus = (await state.vault.inspect()).status;
    } else if (!desktopMode) {
      state.securityProfile = browserSecurityStorageCapabilityV2();
      state.anchorFactory = createIndexedDBBrowserAnchorStoreFactoryV2();
      if (state.anchorFactory !== null) {
        state.vault = new HostAnchoredBrowserApplicationVaultV2({
          crypto: state.crypto,
          storageCrypto: globalThis.crypto,
          stateAnchorStoreFactory: state.anchorFactory
        });
        try {
          state.vaultStatus = (await state.vault.inspect()).status;
        } catch (error) {
          const detail = displayError(error);
          state.securityProfile = {
            ...state.securityProfile,
            available: false,
            reason: detail.startsWith("Legacy plaintext IndexedDB")
              ? detail
              : "Encrypted browser storage could not be opened. Preserve this profile for review before clearing its IndexedDB data."
          };
          state.vault = null;
          state.anchorFactory = null;
        }
      } else {
        state.messageSyncStatus = state.securityProfile.reason;
      }
    } else {
      state.securityProfile = globalThis.noctweaveDesktopAnchorCapability ?? {
        available: false,
        reason: "The hardened Electrobun host anchor is unavailable on this platform."
      };
      state.messageSyncStatus = state.securityProfile.reason;
    }
    renderGate();
  });
}

function makeRelayClient(endpoint, options = {}) {
  const parsed = typeof endpoint === "string" ? parseBrowserRelayEndpoint(endpoint) : endpoint;
  const endpointURL = typeof endpoint === "string" ? endpoint : relayEndpointURL(parsed, "/");
  const customFetch = parsed.transport === "http" ? proxyFetch(endpointURL) : options.fetch;
  return new NoctweaveRelayClient(parsed, {
    crypto: state.crypto,
    ...options,
    fetch: customFetch
  });
}

function proxyFetch(endpoint) {
  return async (url, init) => {
    if (new URL(url).pathname !== "/relay" || init?.method !== "POST") {
      throw new Error("The Noctweave proxy accepts only modular relay requests.");
    }
    if (typeof globalThis.__noctweaveDesktopRelayFetch === "function") {
      return globalThis.__noctweaveDesktopRelayFetch({
        endpoint,
        body: typeof init?.body === "string" ? init.body : ""
      });
    }
    return fetch("/proxy/relay", {
      ...init,
      headers: { ...(init?.headers ?? {}), "x-relay-endpoint": endpoint }
    });
  };
}

function hasVault() {
  return state.vaultStatus === "active" || state.vaultStatus === "burning";
}

function renderGate() {
  $("#vaultCard").hidden = true;
  $("#vaultLoading").hidden = false;
  const existing = hasVault();
  elements.vaultTitle.textContent = existing ? "Unlock NoctweaveJS" : "Create your local persona";
  elements.vaultIntro.textContent = existing
    ? "Decrypt this installation's local persona to resume its independent pairwise relationships."
    : "Choose a label for this installation. Every peer relationship receives fresh post-quantum keys, endpoint state, and an opaque route.";
  elements.passphrase.autocomplete = existing ? "current-password" : "new-password";
  elements.creationFields.hidden = existing;
  elements.confirmationRow.hidden = existing;
  elements.unlock.textContent = state.vaultStatus === "burning"
    ? "Finish local burn"
    : existing ? "Unlock encrypted persona" : "Create secure persona";
  // Destructive persona removal requires an unlocked session so live routes
  // can be torn down. The in-app burn action owns that flow.
  elements.forget.hidden = true;
  elements.error.textContent = "";
  const profile = state.securityProfile ?? browserSecurityStorageProfileV2;
  const available = profile.available !== false && state.vault !== null;
  elements.unlock.disabled = !available;
  elements.onboardingRelayCheck.disabled = !available;
  elements.securityAcknowledgment.disabled = !available;
  elements.securityProfileInfo.textContent = available
    ? profile.label ?? "Encrypted local storage"
    : profile.reason ?? browserRollbackAnchorRequirement;
  const profileWarning = typeof profile.warning === "string"
    ? profile.warning.trim()
    : "";
  elements.securityProfileWarning.textContent = profileWarning;
  elements.securityProfileWarning.hidden = profileWarning.length === 0;
  elements.securityAcknowledgmentText.textContent = profile.hardwareRollbackResistance === true
    ? "I understand this encrypted persona is local to this installation and has no account recovery."
    : "I understand this browser profile is best-effort and may be rolled back from an older device or browser backup.";
  if (state.relayVerifiedEndpoint === null) {
    elements.onboardingRelayInfo.textContent = "The relay will be verified before this persona is created.";
  }
  void refreshSecurityKeyUI();
}

async function createVault() {
  if (state.vault === null) throw new Error(browserRollbackAnchorRequirement);
  if (!elements.securityAcknowledgment.checked) {
    throw new Error("Acknowledge the selected storage/security profile before creating a persona.");
  }
  const requestedRelay = elements.onboardingRelay.value.trim();
  if (state.relayVerifiedEndpoint !== requestedRelay) {
    elements.onboardingRelayInfo.textContent = "Verifying relay identity and capabilities…";
    await verifyOnboardingRelay();
  }
  const passphrase = validatePassphrase();
  if (passphrase !== elements.confirmation.value) throw new Error("Passphrases do not match.");
  const displayName = elements.displayName.value.trim();
  try {
    const opened = await state.vault.initialize({
      passphrase,
      persona: state.pairing.createPersona({ displayName })
    });
    elements.relay.value = state.relayVerifiedEndpoint;
    elements.relayInfo.textContent = state.relayVerifiedSummary ?? "Relay verified during onboarding.";
    activateVaultSession(opened);
    await persistRelayPreference(state.relayVerifiedEndpoint);
    showApp();
  } finally {
    elements.passphrase.value = "";
    elements.confirmation.value = "";
  }
}

async function unlockVault() {
  if (state.keyController) { state.keyController.abort(); }
  // Browsers mediate hardware access; an empty, user-initiated Unlock starts WebAuthn.
  if (!globalThis.__noctweaveDesktopSecurityKeys?.attachments && !elements.passphrase.value && state.hasSecurityKeys) {
    state.keyDetectedForAttempt = true;
    renderUnlockVisibility();
    await performSecurityKeyAction("unlock");
    return;
  }
  if (state.keyController) throw new Error("Finish or cancel the security key request first.");
  if (state.vault === null) throw new Error(browserRollbackAnchorRequirement);
  const passphrase = validatePassphrase();
  try {
    if (state.vaultStatus === "burning") {
      const recovered = await state.vault.unlockBurnRecovery({ passphrase });
      await completeLocalBurn({
        persona: validateBrowserPersonaState(recovered.persona),
        messaging: createMessagingService(recovered.encryptedStore)
      });
      return;
    }
    const opened = await state.vault.unlock({ passphrase });
    activateVaultSession({
      ...opened,
      persona: validateBrowserPersonaState(opened.persona)
    });
    await restoreRelayPreference();
    showApp();
  } finally {
    elements.passphrase.value = "";
  }
}

async function verifyOnboardingRelay() {
  const endpoint = elements.onboardingRelay.value.trim();
  const result = await state.pairing.verifyRelay(endpoint);
  state.relayVerifiedEndpoint = endpoint;
  state.relayVerifiedSummary = `${result.endpoint.transport.toUpperCase()} route transport verified`;
  elements.onboardingRelayInfo.textContent = `${state.relayVerifiedSummary}. You can now create the local persona.`;
}

function activateVaultSession({ persona, encryptedStore }) {
  if (!(encryptedStore instanceof EncryptedNoctweaveStore)) {
    throw new Error("The host-anchored application vault returned an invalid encryption boundary.");
  }
  state.encryptedStore = encryptedStore;
  state.repository = state.vault;
  state.persona = validateBrowserPersonaState(persona);
  state.vaultStatus = "active";
  state.messaging = createMessagingService(encryptedStore);
}

function createMessagingService(encryptedStore) {
  return new NoctweaveBrowserMessagingServiceV2({
    crypto: state.crypto,
    pqc: state.pqc,
    store: encryptedStore,
    relayClientFactory: makeRelayClient,
    stateAnchorStoreFactory: globalThis.noctweaveRelationshipStateAnchorStoreFactory
      ?? state.anchorFactory
  });
}

function showApp() {
  if (document.hidden) {
    lockProfile();
    return;
  }
  state.keyDetectedForAttempt = false;
  stopKeyAttachmentWatch();
  void refreshSecurityKeyUI();
  elements.gate.hidden = true;
  elements.app.hidden = false;
  elements.app.inert = false;
  globalThis.scrollTo?.({ top: 0, left: 0, behavior: "auto" });
  activateClientView("chats");
  selectInitialRelationship();
  renderPersona();
  startPairingPump();
  startMessagePump();
}

function activateClientView(view, selectedControl = null) {
  if (!Object.hasOwn(clientViewCopy, view)) return;
  state.activeView = view;
  for (const section of clientViews) {
    section.hidden = section.dataset.clientView !== view;
  }
  const primaryView = ["relays", "identity", "settings"].includes(view) ? "you" : view;
  for (const control of clientViewNavigation) {
    const selected = control.closest(".nativeNavigation") !== null &&
      control.dataset.clientViewTarget === primaryView;
    control.setAttribute("aria-current", selected ? "page" : "false");
  }
  const [defaultTitle, defaultSubtitle] = clientViewCopy[view];
  const title = selectedControl?.dataset.viewTitle ?? defaultTitle;
  const subtitle = selectedControl?.dataset.viewSubtitle ?? defaultSubtitle;
  elements.viewTitle.textContent = title;
  elements.viewSubtitle.textContent = subtitle;
}

function lockProfile() {
  const discardedDraft = elements.messageText.value.trim().length > 0;
  cancelSecurityKeyAction();
  for (const id of ["#keyVaultPassphrase", "#registerKeyPIN", "#unlockKeyPIN", "#visibilityPassphrase", "#visibilityKeyPIN"]) $(id).value = "";
  void closeRelayPairing({ bestEffort: true });
  stopPairingPump();
  stopMessagePump();
  state.repository = null;
  state.vault?.lock();
  state.encryptedStore = null;
  state.messaging = null;
  state.persona = null;
  state.invitation = null;
  state.invitationPairingID = null;
  state.selectedRelationshipID = null;
  state.messageSnapshot = null;
  state.messageSyncStatus = "Select a relationship to begin.";
  state.safetyNumber = null;
  state.relayVerifiedEndpoint = null;
  state.relayVerifiedSummary = null;
  elements.relayInfo.textContent = "Not checked yet.";
  state.messageBusy = false;
  state.lastMaintenanceAt = 0;
  state.pairingBusy.clear();
  state.relayPairing = null;
  state.relayPairingBusy = false;
  elements.invitation.value = "";
  elements.peerInvitation.value = "";
  elements.messageText.value = "";
  elements.attachmentFile.value = "";
  for (const input of [elements.displayName, elements.relay, elements.onboardingRelay,
    elements.relationshipPseudonym]) input.value = "";
  for (const output of [elements.relationshipList, elements.messageList,
    elements.pendingPairingList, elements.relayPairingResults]) output.replaceChildren();
  for (const output of [elements.personaName, elements.relationshipCount,
    elements.selectedRelationshipName, elements.selectedRelationshipState,
    elements.safetyNumber, elements.attachmentStatus, elements.outboxStatus,
    elements.invitationResult, elements.pairingStatus, elements.relayPairingStatus]) {
    output.textContent = "";
  }
  elements.app.hidden = true;
  elements.app.inert = true;
  elements.gate.hidden = false;
  globalThis.scrollTo?.({ top: 0, left: 0, behavior: "auto" });
  renderGate();
  if (discardedDraft) elements.error.textContent = "Unsent draft discarded when the profile locked.";
}

function cancelSecurityKeyAction() {
  state.keyController?.abort();
  state.keyDetectedForAttempt = false;
  $("#unlockKeyPIN").value = "";
  elements.passphrase.value = "";
  $("#keyUnlockStatus").textContent = "";
  renderUnlockVisibility();
}

function renderUnlockVisibility() {
  const keyFlowActive = state.vaultStatus === "active" && state.hasSecurityKeys && state.keyDetectedForAttempt;
  $("#passphraseUnlock").hidden = keyFlowActive;
  $("#passphraseUnlock").inert = keyFlowActive;
  if (keyFlowActive) {
    elements.passphrase.blur();
    elements.passphrase.value = "";
  }
  const keyVisible = state.vaultStatus === "active" && state.hasSecurityKeys &&
    (!state.hiddenUnlockMethods.includes("securityKey") || state.keyDetectedForAttempt);
  $("#securityKeyUnlock").hidden = !keyVisible;
  $("#keyUnlockHint").textContent = state.keyDetectedForAttempt
    ? "Authenticate with the connected key."
    : state.keyPresenceRequired ? "Connect your registered USB key to unlock this vault."
    : "Or unlock with a registered security key.";
}

function stopKeyAttachmentWatch() {
  state.attachmentGeneration++;
  if (state.attachmentTimer) clearTimeout(state.attachmentTimer);
  state.attachmentTimer = null;
  state.attachedKeys = [];
  void globalThis.__noctweaveDesktopSecurityKeys?.stopAttachments?.();
}

function startKeyAttachmentWatch() {
  const host = globalThis.__noctweaveDesktopSecurityKeys;
  if (!host?.attachments || state.persona || !hasVault() || document.hidden || state.attachmentTimer) return;
  const generation = state.attachmentGeneration;
  const poll = async () => {
    if (generation !== state.attachmentGeneration || state.persona || document.hidden) return;
    try {
      const status = await host.attachments();
      if (generation !== state.attachmentGeneration || state.persona || document.hidden) return;
      if (status.known) {
        const inserted = status.devices.some((token) => !state.attachedKeys.includes(token));
        state.attachedKeys = status.devices;
        if (!status.devices.length && state.keyDetectedForAttempt) {
          state.keyController?.abort();
          state.keyDetectedForAttempt = false;
          $("#unlockKeyPIN").value = "";
          renderUnlockVisibility();
        }
        if (inserted && state.hasSecurityKeys && !state.keyController) {
          state.keyDetectedForAttempt = true;
          renderUnlockVisibility();
          void performSecurityKeyAction("unlock");
        }
      }
    } catch { /* Discovery is never an authentication result. */ }
    if (generation === state.attachmentGeneration && !state.persona && !document.hidden) {
      state.attachmentTimer = setTimeout(poll, 1_000);
    }
  };
  state.attachmentTimer = setTimeout(poll, 0);
}

async function refreshSecurityKeyUI() {
  const revision = ++state.keyUIRevision;
  const authenticator = securityKeyAuthenticator();
  if (state.vault) state.vault.onSecurityKeyDisconnected = () => {
    const message = unlockFailureMessage("The security key was disconnected. Reconnect it and unlock again.", state.hiddenUnlockMethods);
    lockProfile();
    $("#keyUnlockStatus").textContent = message;
  };
  const busy = state.keyController !== null;
  for (const field of document.querySelectorAll("[data-key-pin-field]")) {
    field.hidden = !globalThis.__noctweaveDesktopSecurityKeys?.available;
  }
  $("#registerSecurityKey").disabled = busy || !authenticator;
  $("#unlockWithKey").disabled = busy || !authenticator;
  $("#cancelKeyUnlock").hidden = !busy && !state.keyDetectedForAttempt;
  $("#cancelKeySetup").hidden = !busy;
  $("#cancelUnlockPrivacy").hidden = !busy;
  for (const id of ["#keyVaultPassphrase", "#securityKeyName", "#registerKeyPIN", "#unlockKeyPIN", "#visibilityPassphrase", "#visibilityKeyPIN"]) $(id).disabled = busy;
  try {
    const protection = state.vault ? await state.vault.securityKeyProtection()
      : { keys: [], required: false, hiddenMethods: [] };
    if (revision !== state.keyUIRevision) return;
    const keys = protection.keys;
    state.hasSecurityKeys = keys.length > 0;
    state.keyPresenceRequired = protection.required;
    state.hiddenUnlockMethods = protection.hiddenMethods;
    $("#continuousKeyPresence").hidden = !authenticator?.continuousPresence;
    if (!busy) {
      $("#keepSecurityKeyConnected").checked = protection.required;
      $("#hideSecurityKeyUnlock").checked = protection.hiddenMethods.includes("securityKey");
    }
    $("#keepSecurityKeyConnected").disabled = busy;
    $("#hideSecurityKeyUnlock").disabled = busy || !keys.length;
    $("#saveUnlockVisibility").disabled = busy;
    $("#visibilityKeyPINField").hidden = !protection.required || !globalThis.__noctweaveDesktopSecurityKeys?.available;
    $("#saveKeyPresence").disabled = busy || !keys.length;
    const discloseConnection = protection.required && !protection.hiddenMethods.includes("securityKey");
    elements.passphrase.disabled = false;
    elements.unlock.disabled = state.securityProfile?.available === false || !state.vault;
    if (discloseConnection && !protection.hiddenMethods.length && !state.persona && !busy) {
      $("#keyUnlockStatus").textContent = "This vault requires a connected registered USB key.";
    }
    $("#registerSecurityKey").disabled = busy || !authenticator || keys.length >= 8 || protection.required;
    const list = $("#registeredSecurityKeys");
    list.replaceChildren();
    for (const key of keys) {
      const row = document.createElement("div"); row.className = "registeredKey";
      const label = document.createElement("span"); label.textContent = key.name;
      const remove = document.createElement("button"); remove.className = "subtle"; remove.textContent = "Remove";
      remove.setAttribute("aria-label", `Remove ${key.name}`); remove.disabled = busy;
      remove.addEventListener("click", () => void performSecurityKeyAction("remove", key.id));
      row.append(label, remove); list.append(row);
    }
    if (!keys.length) list.textContent = "No security keys registered.";
    if (!authenticator) {
      const message = "Security keys are unavailable here. Use a compatible browser over HTTPS or localhost, or the macOS desktop app.";
      $("#keySetupStatus").textContent = message;
      $("#keyUnlockStatus").textContent = unlockFailureMessage(message, state.hiddenUnlockMethods);
    }
    renderUnlockVisibility();
    startKeyAttachmentWatch();
  } catch {
    if (revision !== state.keyUIRevision) return;
    // Unknown policy must not briefly reveal a configured unlock method.
    state.hiddenUnlockMethods = ["passphrase", "securityKey"];
    state.keyDetectedForAttempt = false;
    renderUnlockVisibility();
    $("#registerSecurityKey").disabled = true;
    $("#saveUnlockVisibility").disabled = true;
    $("#keySetupStatus").textContent = "The protected settings could not be read.";
    elements.error.textContent = "Unable to unlock. Try again.";
  } finally {
    if (revision === state.keyUIRevision) {
      $("#vaultLoading").hidden = true;
      $("#vaultCard").hidden = false;
    }
  }
}

async function performSecurityKeyAction(operation, id = null) {
  if (state.keyController || !state.vault) return;
  if (operation === "unlock") {
    state.keyDetectedForAttempt = true;
    renderUnlockVisibility();
  }
  const required = $("#keepSecurityKeyConnected").checked;
  const hiddenMethods = [
    ...($("#hideSecurityKeyUnlock").checked ? ["securityKey"] : [])
  ];
  const controller = new AbortController();
  state.keyController = controller;
  const status = $(operation === "unlock" ? "#keyUnlockStatus"
    : operation === "visibility" ? "#unlockPrivacyStatus" : "#keySetupStatus");
  const pinField = $(operation === "unlock" ? "#unlockKeyPIN"
    : operation === "visibility" ? "#visibilityKeyPIN" : "#registerKeyPIN");
  const authenticator = securityKeyAuthenticator({ pin: pinField.value });
  pinField.value = "";
  const passphraseField = $(operation === "visibility" ? "#visibilityPassphrase" : "#keyVaultPassphrase");
  let passphrase = passphraseField.value;
  passphraseField.value = "";
  status.textContent = operation === "unlock" && state.hiddenUnlockMethods.length ? "Verifying…"
    : operation === "remove" || operation === "visibility" ? "Verifying your protection…"
    : "Follow the prompt and touch your security key. You can cancel at any time.";
  void refreshSecurityKeyUI();
  try {
    if (!authenticator && !["remove", "visibility"].includes(operation)) throw new Error("Security keys are unavailable here.");
    if (operation === "unlock") {
      const opened = await state.vault.unlockWithSecurityKey({ authenticator, signal: controller.signal });
      controller.signal.throwIfAborted();
      await activateVaultSession(opened);
      controller.signal.throwIfAborted();
      await restoreRelayPreference();
      controller.signal.throwIfAborted();
      showApp();
    } else {
      requireUnlocked();
      if (passphrase.length < 12) throw new Error(operation === "visibility"
        ? "Enter your vault passphrase to save lock-screen privacy." : "Enter your vault passphrase to change registered keys.");
      if (operation === "remove") await state.vault.removeSecurityKey({ id, passphrase, signal: controller.signal });
      else if (operation === "visibility") await state.vault.setUnlockMethodVisibility({ hiddenMethods, passphrase,
        authenticator, signal: controller.signal });
      else if (operation === "presence") await state.vault.setSecurityKeyPresenceRequired({ required, passphrase,
        authenticator, signal: controller.signal });
      else await state.vault.addSecurityKey({ passphrase, name: $("#securityKeyName").value,
        authenticator, signal: controller.signal });
      controller.signal.throwIfAborted();
    }
    status.textContent = operation === "register" ? "Key registered and verified. Your passphrase remains available for recovery."
      : operation === "visibility" ? "Lock-screen privacy saved."
      : operation === "remove" ? "Key removed from this vault."
      : operation === "presence" ? (required ? "Keep key connected is enabled. Removing the key locks this app." : "Connection requirement disabled.")
      : "Security key verified.";
  } catch (error) {
    if (operation === "unlock") {
      state.vault.lock();
      if (state.persona) lockProfile();
    }
    const message = controller.signal.aborted ? "Request cancelled." : displayError(error);
    status.textContent = operation === "unlock" ? unlockFailureMessage(message, state.hiddenUnlockMethods) : message;
  } finally {
    passphrase = "";
    authenticator?.clearPIN?.();
    if (!state.keyPresenceRequired) {
      try { await authenticator?.releasePresence?.(); } catch { /* No continuous lease is active. */ }
    }
    if (state.keyController === controller) state.keyController = null;
    elements.unlock.disabled = state.securityProfile?.available === false || state.vault === null;
    void refreshSecurityKeyUI();
  }
}

async function forgetVault() {
  if (!state.persona || !state.messaging) {
    throw new Error("Unlock the encrypted persona before deletion so live receive routes can be torn down.");
  }
  await burnLocalPersona();
}

async function verifyRelay() {
  const result = await state.pairing.verifyRelay(elements.relay.value);
  state.relayVerifiedEndpoint = elements.relay.value.trim();
  state.relayVerifiedSummary = `${result.endpoint.transport.toUpperCase()} route transport verified`;
  elements.relayInfo.textContent = state.relayVerifiedSummary;
  await persistRelayPreference(state.relayVerifiedEndpoint);
}

async function persistRelayPreference(endpoint) {
  if (!(state.encryptedStore instanceof EncryptedNoctweaveStore)) return;
  const normalized = endpoint.trim();
  parseBrowserRelayEndpoint(normalized);
  await state.encryptedStore.set(RELAY_PREFERENCE_KEY, {
    version: 1,
    endpoint: normalized
  });
}

async function restoreRelayPreference() {
  if (!(state.encryptedStore instanceof EncryptedNoctweaveStore)) return;
  const saved = await state.encryptedStore.get(RELAY_PREFERENCE_KEY);
  if (saved === null) return;
  if (!saved || typeof saved !== "object" || Array.isArray(saved) ||
      saved.version !== 1 || typeof saved.endpoint !== "string" ||
      Object.keys(saved).sort().join(",") !== "endpoint,version") {
    throw new Error("The encrypted relay preference is invalid.");
  }
  parseBrowserRelayEndpoint(saved.endpoint);
  elements.relay.value = saved.endpoint;
  state.relayVerifiedEndpoint = saved.endpoint;
  state.relayVerifiedSummary = "Encrypted relay preference restored; verify before changing it.";
  elements.relayInfo.textContent = state.relayVerifiedSummary;
}

async function createInvitation() {
  requireUnlocked();
  const prepared = await prepareOffererInvitation();
  state.invitation = prepared.encoded;
  state.invitationPairingID = prepared.pairingID;
  elements.invitation.value = prepared.encoded;
  $("#shareInvitation").hidden = false;
  $("#copyInvitation").hidden = false;
  elements.invitationResult.textContent = "Invitation ready for ten minutes. Share it privately; this client is already waiting.";
  await pumpPairing(prepared.pairingID);
}

async function prepareOffererInvitation() {
  const relationshipPseudonym = requireRelationshipPseudonym();
  await verifyRelay();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 10 * 60 * 1_000);
  const createdAtValue = swiftISODate(createdAt);
  const expiresAtValue = swiftISODate(expiresAt);
  const prepared = await state.pairing.prepareOffererPairing({
    persona: state.persona,
    relay: elements.relay.value,
    relationshipPseudonym,
    createdAt: createdAtValue,
    expiresAt: expiresAtValue
  });
  const encoded = await encodeNoctweavePairingLinkV1({
    crypto: state.crypto,
    relay: parseBrowserRelayEndpoint(elements.relay.value),
    invitation: prepared.invitation
  });
  await persistPersona(prepared.persona);
  return { encoded, pairingID: prepared.pairingID };
}

async function startRelayVisibility() {
  requireUnlocked();
  requireRelationshipPseudonym();
  await closeRelayPairing({ bestEffort: true });
  const client = await pairingLobbyClient();
  const host = await PairingLobbyHostSessionV1.create({ crypto: state.crypto });
  try {
    await client.createRealtimeRouteV1(host.requestRouteCreateRequest);
    const lease = await client.acquirePairingLobbyV1(host.leaseAcquireRequest);
    const subscription = await client.subscribeRealtimeRouteV1(
      host.requestRouteSubscribeRequest()
    );
    state.relayPairing = {
      role: "host",
      client,
      host,
      lease,
      subscription,
      cursor: 0,
      pending: []
    };
    elements.relayPairingStatus.textContent =
      `Visible as ${host.badge.displayText} for two minutes. Compare the entire badge before approving.`;
    renderRelayPairing();
    await pollRelayPairing();
  } catch (error) {
    host.dispose();
    throw error;
  }
}

async function findRelayPeers() {
  requireUnlocked();
  requireRelationshipPseudonym();
  await closeRelayPairing({ bestEffort: true });
  const client = await pairingLobbyClient();
  const leases = await client.listPairingLobbyV1();
  const listings = [];
  for (const lease of leases) {
    try {
      const listing = await verifyPairingLobbyListingV1(state.crypto, lease);
      listings.push({ lease, listing });
    } catch {
      // Omit malformed or expired public entries; they never become pairing authorities.
    }
  }
  state.relayPairing = { role: "finder", client, listings };
  elements.relayPairingStatus.textContent = listings.length === 0
    ? "No one is visible on this relay right now."
    : "Choose the badge shown on the other device, then compare it in full.";
  renderRelayPairing();
}

async function requestRelayPairing(lease) {
  const current = state.relayPairing;
  if (current?.role !== "finder") throw new Error("Refresh the same-relay list first.");
  const requester = await PairingLobbyRequesterSessionV1.create({
    crypto: state.crypto,
    listing: lease
  });
  try {
    await current.client.createRealtimeRouteV1(requester.responseRouteCreateRequest);
    const subscription = await current.client.subscribeRealtimeRouteV1(
      requester.responseRouteSubscribeRequest()
    );
    await current.client.appendRealtimeRouteV1(requester.requestAppendRequest);
    state.relayPairing = {
      role: "requester",
      client: current.client,
      requester,
      subscription,
      cursor: 0
    };
    elements.relayPairingStatus.textContent =
      `Request sent to ${requester.hostBadge.displayText}. Waiting for approval on that device.`;
    renderRelayPairing();
  } catch (error) {
    requester.dispose();
    throw error;
  }
}

async function acceptRelayPairingRequest(requestID) {
  const current = state.relayPairing;
  if (current?.role !== "host") throw new Error("The visibility window is no longer active.");
  const pending = current.pending.find(({ id }) => id === requestID);
  if (!pending) throw new Error("The pairing request expired or was already handled.");
  const prepared = await prepareOffererInvitation();
  state.invitation = prepared.encoded;
  state.invitationPairingID = prepared.pairingID;
  elements.invitation.value = prepared.encoded;
  try {
    const append = await current.host.decisionAppendRequest({
      pending,
      decision: "accepted",
      pairingLink: prepared.encoded
    });
    await current.client.appendRealtimeRouteV1(append);
    await closeRelayPairing({ bestEffort: true });
    clearSharedInvitation();
    elements.relayPairingStatus.textContent = "Approved. The encrypted invitation was delivered through the relay; pairing is finishing automatically.";
    await pumpPairing(prepared.pairingID);
  } catch (error) {
    $("#shareInvitation").hidden = false;
    $("#copyInvitation").hidden = false;
    elements.invitationResult.textContent = "Relay delivery failed. The same one-use invitation is available below as a private fallback.";
    throw error;
  }
}

async function rejectRelayPairingRequest(requestID) {
  const current = state.relayPairing;
  if (current?.role !== "host") throw new Error("The visibility window is no longer active.");
  const pending = current.pending.find(({ id }) => id === requestID);
  if (!pending) throw new Error("The pairing request expired or was already handled.");
  await current.client.appendRealtimeRouteV1(
    await current.host.decisionAppendRequest({ pending, decision: "rejected" })
  );
  current.pending = current.pending.filter(({ id }) => id !== requestID);
  elements.relayPairingStatus.textContent = "Request declined. You remain visible until the two-minute window ends.";
  renderRelayPairing();
}

async function pairingLobbyClient() {
  await verifyRelay();
  const client = makeRelayClient(elements.relay.value);
  const { relayInfo } = await client.info();
  const modules = relayInfo.protocolCapabilities?.modules ?? [];
  const pairing = modules.some(({ module, versions }) =>
    module === "nw.pairing-lobby" && versions.includes(1));
  const realtime = modules.some(({ module, versions }) =>
    module === "nw.realtime-route" && versions.includes(1));
  if (!pairing || !realtime) {
    throw new Error("This relay has not enabled its default-off same-relay pairing lobby.");
  }
  return client;
}

async function shareInvitation() {
  if (!state.invitation) throw new Error("Create a fresh invitation first.");
  if (typeof navigator.share !== "function") {
    await copyInvitation();
    elements.invitationResult.textContent = "System sharing is unavailable, so the one-use invitation was copied.";
    return;
  }
  await navigator.share({
    title: "Noctweave one-use invitation",
    text: `Open Noctweave, choose I received an invitation, and paste this one-use link:\n\n${state.invitation}`
  });
  elements.invitationResult.textContent = "Invitation shared. Keep this client open while the other client accepts it.";
}

async function copyInvitation() {
  if (!state.invitation) throw new Error("Create a fresh invitation first.");
  await navigator.clipboard.writeText(state.invitation);
  elements.invitationResult.textContent = "One-use invitation copied.";
}

async function inspectInvitation() {
  const { invitation, relay } = await decodePairingInput(
    normalizedPairingInput(elements.peerInvitation.value)
  );
  elements.relay.value = relayEndpointURL(relay, "/").replace(/\/$/u, "");
  elements.invitationResult.textContent = `Valid one-use rendezvous; expires ${invitation.offer.expiresAt}. No identity or route was disclosed.`;
}

async function pasteAndPair() {
  requireUnlocked();
  if (!navigator.clipboard || typeof navigator.clipboard.readText !== "function") {
    throw new Error("Clipboard reading is unavailable here. Open Enter invitation manually instead.");
  }
  const encoded = normalizedPairingInput(await navigator.clipboard.readText());
  elements.peerInvitation.value = encoded;
  await acceptInvitation();
}

async function acceptInvitation() {
  requireUnlocked();
  const relationshipPseudonym = requireRelationshipPseudonym();
  const encoded = normalizedPairingInput(elements.peerInvitation.value);
  const { invitation, relay } = await decodePairingInput(encoded);
  const relayURL = relayEndpointURL(relay, "/").replace(/\/$/u, "");
  elements.relay.value = relayURL;
  const readiness = await state.pairing.verifyRelay(relayURL);
  state.relayVerifiedEndpoint = relayURL;
  state.relayVerifiedSummary = `${readiness.endpoint.transport.toUpperCase()} rendezvous verified`;
  elements.relayInfo.textContent = state.relayVerifiedSummary;
  await persistRelayPreference(relayURL);
  const prepared = await state.pairing.prepareResponderPairing({
    persona: state.persona,
    invitation,
    relay,
    relationshipPseudonym,
    at: swiftISODate()
  });
  await persistPersona(prepared.persona);
  elements.peerInvitation.value = "";
  elements.invitationResult.textContent = "Invitation accepted. Its secret was removed from the form; pairing will finish automatically.";
  await pumpPairing(prepared.pairingID);
}

async function decodePairingInput(encoded) {
  if (encoded.startsWith("noctweave-pair-v1:")) {
    return decodeNoctweavePairingLinkV1({ crypto: state.crypto, encoded });
  }
  const invitation = await decodeContactPairingInvitationV2({
    crypto: state.crypto,
    encoded
  });
  return {
    invitation,
    relay: parseBrowserRelayEndpoint(elements.relay.value)
  };
}

async function resumeAllPairings() {
  requireUnlocked();
  const pairingIDs = state.persona.pendingPairings.map(({ pairingID }) => pairingID);
  if (pairingIDs.length === 0) {
    elements.pairingStatus.textContent = "No pending rendezvous.";
    return;
  }
  for (const pairingID of pairingIDs) await pumpPairing(pairingID);
}

async function pumpPairing(pairingID) {
  requireUnlocked();
  if (state.pairingBusy.has(pairingID)) return;
  state.pairingBusy.add(pairingID);
  renderPendingPairings();
  try {
    for (let round = 0; round < 16; round += 1) {
      const current = pendingPairing(pairingID);
      if (!current) return;
      const endpoint = current.participant.localReceiveRoute.relay;
      const relayClient = makeRelayClient(endpoint);
      const adapter = await createRendezvousRelayAdapterV2({
        crypto: state.crypto,
        offer: current.offer
      });
      const resumed = await state.pairing.resumePairing({ persona: state.persona, pairingID });
      let progressed = false;

      for (const outbound of resumed.outboundTransportFrames) {
        await relayClient.appendRendezvousTransportV2(outbound);
        const acknowledged = await state.pairing.acknowledgePairingOutbound({
          persona: state.persona,
          pairingID,
          frameIDs: [outbound.frame.frameId.rawValue]
        });
        await persistPersona(acknowledged.persona);
        progressed = true;
      }

      const receiving = pendingPairing(pairingID);
      if (!receiving || receiving.phase === "ready") break;
      const request = adapter.syncRequest({
        receivingAs: receiving.role,
        afterSequence: receiving.nextInboundTransportSequence - 1,
        maxCount: 32
      });
      const batch = await relayClient.syncRendezvousTransportV2(request);
      for (const inbound of batch.frames) {
        const processed = await state.pairing.processPairingFrame({
          persona: state.persona,
          pairingID,
          transportFrame: inbound,
          at: swiftISODate()
        });
        await persistPersona(processed.persona);
        progressed = true;
      }
      if (!progressed || (!batch.hasMore && batch.frames.length === 0)) break;
    }
    const pairing = pendingPairing(pairingID);
    if (pairing?.phase === "ready" && pairing.outboundTransportFrames.length === 0) {
      elements.pairingStatus.textContent = "Relationship verified. Finishing securely…";
      await finalizePairing(pairingID, { alreadyBusy: true });
      return;
    }
    elements.pairingStatus.textContent = "Pairing is active. Waiting for the other client; retry is safe after a restart.";
  } finally {
    state.pairingBusy.delete(pairingID);
    renderPendingPairings();
  }
}

async function finalizePairing(pairingID, { alreadyBusy = false } = {}) {
  if (!alreadyBusy && state.pairingBusy.has(pairingID)) {
    throw new Error("Pairing synchronization is still running.");
  }
  if (!alreadyBusy) {
    state.pairingBusy.add(pairingID);
    renderPendingPairings();
  }
  try {
    const pending = requirePendingPairing(pairingID);
    const finalized = await state.pairing.finalizePairing({
      persona: state.persona,
      pairingID,
      at: swiftISODate()
    });
    await deleteRendezvousLanes(pending, finalized.rendezvousDeletionRequests);
    await persistPersona(finalized.persona);
    if (state.invitationPairingID === pairingID) clearSharedInvitation();
    state.selectedRelationshipID = finalized.relationship.relationshipID;
    await refreshSelectedMessages({ resumeOutbound: true, synchronize: true });
    elements.pairingStatus.textContent = "Fresh pairwise relationship stored; the one-use rendezvous lanes were deleted.";
  } finally {
    if (!alreadyBusy) {
      state.pairingBusy.delete(pairingID);
      renderPendingPairings();
    }
  }
}

async function cancelPairing(pairingID) {
  if (state.pairingBusy.has(pairingID)) throw new Error("Pairing synchronization is still running.");
  state.pairingBusy.add(pairingID);
  renderPendingPairings();
  try {
    const pending = requirePendingPairing(pairingID);
    const cancelled = await state.pairing.cancelPairing({
      persona: state.persona,
      pairingID,
      at: swiftISODate()
    });
    await deleteRendezvousLanes(pending, cancelled.rendezvousDeletionRequests, {
      allowAlreadyExpired: true
    });
    await persistPersona(cancelled.persona);
    if (state.invitationPairingID === pairingID || state.persona.pendingPairings.length === 0) {
      clearSharedInvitation();
    }
    elements.pairingStatus.textContent = "Pairing cancelled; private pending state and one-use rendezvous lanes were deleted.";
  } finally {
    state.pairingBusy.delete(pairingID);
    renderPendingPairings();
  }
}

async function deleteRendezvousLanes(pairing, requests, { allowAlreadyExpired = false } = {}) {
  const relayClient = makeRelayClient(pairing.participant.localReceiveRoute.relay);
  try {
    for (const request of requests) await relayClient.deleteRendezvousTransportV2(request);
  } catch (error) {
    if (!allowAlreadyExpired || Date.parse(pairing.offer.expiresAt) > Date.now()) throw error;
    // The relay lease has ended, so no live lane remains to delete. Local
    // cancellation still erases the encrypted pending participant state.
  }
}

async function pollRelayPairing() {
  if (state.relayPairingBusy || !state.relayPairing) return;
  state.relayPairingBusy = true;
  renderRelayPairing();
  try {
    const current = state.relayPairing;
    if (current.role === "host") {
      const batch = await current.client.syncRealtimeRouteV1({
        routeCapability: current.host.announcement.requestRouteCapability,
        subscriptionCapability: current.subscription.subscriptionCapability,
        afterSequence: current.cursor,
        maxRecords: 32
      });
      current.cursor = batch.nextSequence;
      for (const record of batch.records) {
        try {
          const pending = await current.host.openRequest(record.payload);
          if (!current.pending.some(({ id }) => id === pending.id)) current.pending.push(pending);
        } catch {
          // Advance past invalid public input so one bad request cannot pin the approval screen.
        }
      }
      if (current.pending.length > 0) {
        elements.relayPairingStatus.textContent =
          "Pairing request received. Compare the entire badge shown on both devices before approving.";
      }
    } else if (current.role === "requester") {
      const batch = await current.client.syncRealtimeRouteV1({
        routeCapability: current.requester.request.responseRouteCapability,
        subscriptionCapability: current.subscription.subscriptionCapability,
        afterSequence: current.cursor,
        maxRecords: 8
      });
      current.cursor = batch.nextSequence;
      for (const record of batch.records) {
        const response = await current.requester.openResponse(record.payload);
        if (response.decision === "rejected") {
          await closeRelayPairing({ bestEffort: true });
          elements.relayPairingStatus.textContent = "The other device declined this request.";
          return;
        }
        const invitation = response.pairingLink;
        await closeRelayPairing({ bestEffort: true });
        elements.peerInvitation.value = invitation;
        elements.relayPairingStatus.textContent = "Approved. Starting the encrypted one-use rendezvous…";
        await acceptInvitation();
        return;
      }
    }
  } catch (error) {
    if (Date.now() >= relayPairingExpiry(state.relayPairing)) {
      await closeRelayPairing({ bestEffort: true });
      elements.relayPairingStatus.textContent = "The two-minute pairing window expired. Start a fresh one to continue.";
      return;
    }
    throw error;
  } finally {
    state.relayPairingBusy = false;
    renderRelayPairing();
  }
}

async function stopRelayPairing() {
  await closeRelayPairing({ bestEffort: false });
  elements.relayPairingStatus.textContent = "Same-relay pairing stopped. Disposable routes will expire automatically.";
}

async function closeRelayPairing({ bestEffort }) {
  const current = state.relayPairing;
  if (!current) return;
  state.relayPairing = null;
  renderRelayPairing();
  const operations = [];
  if (current.role === "host") {
    operations.push(() => current.client.releasePairingLobbyV1(current.host.leaseReleaseRequest));
    operations.push(() => current.client.unsubscribeRealtimeRouteV1({
      routeCapability: current.host.announcement.requestRouteCapability,
      subscriptionCapability: current.subscription.subscriptionCapability
    }));
  } else if (current.role === "requester") {
    operations.push(() => current.client.unsubscribeRealtimeRouteV1({
      routeCapability: current.requester.request.responseRouteCapability,
      subscriptionCapability: current.subscription.subscriptionCapability
    }));
  }
  let failure = null;
  for (const operation of operations) {
    try { await operation(); } catch (error) { failure ??= error; }
  }
  current.host?.dispose();
  current.requester?.dispose();
  if (failure && !bestEffort) throw failure;
}

function relayPairingExpiry(current) {
  if (current?.role === "host") return Date.parse(current.host.announcement.expiresAt);
  if (current?.role === "requester") return Date.parse(current.requester.request.expiresAt);
  return Number.POSITIVE_INFINITY;
}

function renderRelayPairing() {
  const current = state.relayPairing;
  const busy = state.relayPairingBusy;
  elements.startRelayVisibility.disabled = busy || current !== null;
  elements.findRelayPeers.disabled = busy || current !== null;
  elements.stopRelayPairing.hidden = current === null;
  elements.stopRelayPairing.disabled = busy;
  if (!current) {
    elements.relayPairingResults.replaceChildren();
    return;
  }
  if (current.role === "finder") {
    elements.relayPairingResults.replaceChildren(...current.listings.map(({ lease, listing }) =>
      relayPairingResult(
        listing.badge.displayText,
        `Visible until ${listing.expiresAt}`,
        pairingButton("Request pairing", () => run(() => requestRelayPairing(lease)))
      )
    ));
    return;
  }
  if (current.role === "requester") {
    elements.relayPairingResults.replaceChildren(relayPairingResult(
      current.requester.hostBadge.displayText,
      `Your badge: ${current.requester.requesterBadge.displayText}`
    ));
    return;
  }
  const own = relayPairingResult(
    current.host.badge.displayText,
    "Your temporary badge · visible for this window only"
  );
  const requests = current.pending.map((pending) => {
    const actions = document.createElement("div");
    actions.className = "buttonRow";
    const accept = pairingButton("Approve", () => run(() => acceptRelayPairingRequest(pending.id)));
    const reject = pairingButton("Decline", () => run(() => rejectRelayPairingRequest(pending.id)), "subtle");
    accept.disabled = busy;
    reject.disabled = busy;
    actions.append(accept, reject);
    return relayPairingResult(
      pending.requesterBadge.displayText,
      "Pairing request · compare the full badge",
      actions
    );
  });
  elements.relayPairingResults.replaceChildren(own, ...requests);
}

function relayPairingResult(titleText, detailText, action = null) {
  const item = document.createElement("article");
  const copy = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = titleText;
  const detail = document.createElement("span");
  detail.textContent = detailText;
  copy.append(title, detail);
  item.append(copy);
  if (action) item.append(action);
  return item;
}

async function persistPersona(persona) {
  const validated = validateBrowserPersonaState(persona);
  await state.repository.save(validated);
  state.persona = validated;
  renderPersona();
}

function pendingPairing(pairingID) {
  return state.persona?.pendingPairings.find((pairing) => pairing.pairingID === pairingID) ?? null;
}

function requirePendingPairing(pairingID) {
  const pairing = pendingPairing(pairingID);
  if (!pairing) throw new Error("Pending pairwise pairing was not found.");
  return pairing;
}

function startPairingPump() {
  stopPairingPump();
  void backgroundResume();
  state.pumpTimer = setInterval(backgroundResume, ACTIVE_PAIRING_POLL_MS);
}

function stopPairingPump() {
  if (state.pumpTimer !== null) clearInterval(state.pumpTimer);
  state.pumpTimer = null;
}

async function backgroundResume() {
  if (!state.persona || !state.repository) return;
  try {
    if (state.relayPairing) await pollRelayPairing();
    if (state.persona.pendingPairings.length > 0) await resumeAllPairings();
  } catch (error) {
    if (state.relayPairing) {
      elements.relayPairingStatus.textContent = `Same-relay pairing paused: ${displayError(error)}`;
    } else {
      elements.pairingStatus.textContent = `Rendezvous paused: ${displayError(error)} Use Resume all to retry.`;
    }
  }
}

function selectInitialRelationship() {
  const relationships = state.persona?.relationships ?? [];
  if (!relationships.some(({ relationshipID }) => relationshipID === state.selectedRelationshipID)) {
    state.selectedRelationshipID = relationships[0]?.relationshipID ?? null;
  }
  state.messageSnapshot = null;
}

function selectedRelationship() {
  return state.persona?.relationships.find(({ relationshipID }) =>
    relationshipID === state.selectedRelationshipID) ?? null;
}

function selectRelationship(relationshipID) {
  if (state.messageBusy) return;
  if (!state.persona.relationships.some((relationship) =>
    relationship.relationshipID === relationshipID)) {
    throw new Error("Pairwise relationship was not found.");
  }
  state.selectedRelationshipID = relationshipID;
  state.messageSnapshot = null;
  state.safetyNumber = null;
  state.messageSyncStatus = "Opening encrypted relationship state…";
  activateClientView("chats");
  renderPersona();
  void runMessaging(() => refreshSelectedMessages({ resumeOutbound: true, synchronize: true }));
}

function startMessagePump() {
  stopMessagePump();
  void backgroundMessageResume(true);
  state.messagePumpTimer = setInterval(() => backgroundMessageResume(false), 5_000);
}

function stopMessagePump() {
  if (state.messagePumpTimer !== null) clearInterval(state.messagePumpTimer);
  state.messagePumpTimer = null;
}

async function backgroundMessageResume(resumeOutbound) {
  if (!state.persona || !state.messaging || !selectedRelationship() || state.messageBusy) return;
  try {
    if (resumeOutbound) await resumeAllMessagingOutboxes();
    if (resumeOutbound || Date.now() - state.lastMaintenanceAt >= 5 * 60 * 1_000) {
      await maintainAllBrowserRelationships();
    }
    await refreshSelectedMessages({ synchronize: true });
  } catch (error) {
    state.messageSyncStatus = `Messaging paused: ${displayError(error)}`;
    renderSelectedMessages();
  }
}

async function foregroundMessagingMaintenance() {
  if (!state.persona || !state.messaging || state.messageBusy) return;
  try {
    await maintainAllBrowserRelationships();
    await refreshSelectedMessages({ synchronize: true });
  } catch (error) {
    state.messageSyncStatus = `Foreground maintenance paused: ${displayError(error)}`;
    renderSelectedMessages();
  }
}

async function maintainAllBrowserRelationships() {
  if (state.messageBusy) return;
  state.messageBusy = true;
  renderSelectedMessages();
  const reports = [];
  try {
    for (const relationship of state.persona.relationships) {
      try {
        reports.push(await state.messaging.maintainRelationship(relationship, {
          persistAppliedRelationship: persistRuntimeRelationship
        }));
      } catch (error) {
        reports.push({ prekey: "failed", routes: "failed", routeBlocker: displayError(error) });
      }
    }
    state.lastMaintenanceAt = Date.now();
    const pending = reports.filter(({ prekey, routeBlocker }) =>
      prekey === "publicationPending" || prekey === "failed" || routeBlocker !== null);
    if (pending.length > 0) {
      state.messageSyncStatus = `${pending.length} relationship maintenance operation${pending.length === 1 ? "" : "s"} need attention.`;
    }
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function resumeAllMessagingOutboxes() {
  state.messageBusy = true;
  renderSelectedMessages();
  const failures = [];
  try {
    const teardowns = await state.messaging.resumeRouteTeardowns({
      relationships: state.persona.relationships
    });
    failures.push(...teardowns.failures);
    for (const relationship of state.persona.relationships) {
      try {
        let snapshot = await state.messaging.open(relationship, {
          persistAppliedRelationship: persistRuntimeRelationship
        });
        if (snapshot.availability.consent !== "blocked" &&
            snapshot.availability.routeTeardownState === null) {
          snapshot = (await state.messaging.resumeOutbound(relationship)).snapshot;
        }
        if (relationship.relationshipID === state.selectedRelationshipID) {
          state.messageSnapshot = snapshot;
          state.safetyNumber = (await state.messaging.safetyNumber(relationship)).display;
        }
      } catch (error) {
        failures.push(displayError(error));
      }
    }
    state.messageSyncStatus = failures.length === 0
      ? "Encrypted outboxes reopened and resumed after unlock."
      : `${failures.length} durable maintenance operation${failures.length === 1 ? "" : "s"} remain retryable.`;
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function refreshSelectedMessages({ resumeOutbound = false, synchronize = false } = {}) {
  requireUnlocked();
  const relationship = selectedRelationship();
  if (!relationship) {
    state.messageSnapshot = null;
    state.messageSyncStatus = "Select a relationship to begin.";
    renderSelectedMessages();
    return;
  }
  if (state.messageBusy) return;
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    let snapshot = await state.messaging.open(relationship, {
      persistAppliedRelationship: persistRuntimeRelationship
    });
    state.safetyNumber = (await state.messaging.safetyNumber(relationship)).display;
    if (resumeOutbound && snapshot.availability.consent !== "blocked") {
      const resumed = await state.messaging.resumeOutbound(relationship);
      snapshot = resumed.snapshot;
    }
    if (synchronize && snapshot.availability.canReceive) {
      const synchronized = await state.messaging.syncReceiveRoutes(requireSelectedRelationship(), {
        persistAppliedRelationship: persistRuntimeRelationship
      });
      snapshot = synchronized.snapshot;
      const failures = synchronized.outcomes.filter(({ status }) =>
        status === "failed" || status === "continuityGap" || status === "expired");
      const receivedCount = synchronized.outcomes.reduce((sum, item) => sum + item.received, 0);
      state.messageSyncStatus = synchronized.routeControlStatus.startsWith("pending:")
        ? "Inbound events are durable; authenticated route maintenance still needs retry."
        : synchronized.receiptStatus.startsWith("pending:")
        ? "Inbound events are durable; an enabled delivery receipt still needs retry."
        : failures.length > 0
        ? `${failures.length} receive route${failures.length === 1 ? "" : "s"} need attention.`
        : receivedCount > 0
          ? `${receivedCount} new event${receivedCount === 1 ? "" : "s"} stored locally before relay cleanup.`
          : "All active receive routes synchronized.";
    } else {
      state.messageSyncStatus = snapshot.availability.message;
    }
    state.messageSnapshot = snapshot;
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function sendMessage() {
  requireUnlocked();
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    const sent = await state.messaging.sendText({
      relationship,
      text: elements.messageText.value
    });
    state.messageSnapshot = sent.snapshot;
    elements.messageText.value = "";
    const accepted = sent.intent.status === "relayAccepted" ||
      sent.resumed.intents.some(({ id, status }) => id === sent.intent.id && status === "relayAccepted");
    state.messageSyncStatus = accepted
      ? "Message is encrypted, durably stored, and accepted by a peer route relay."
      : "Message is encrypted in the local outbox; relay retry is pending.";
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function resumeSelectedOutbox() {
  requireUnlocked();
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    const resumed = await state.messaging.resumeOutbound(relationship);
    state.messageSnapshot = resumed.snapshot;
    state.messageSyncStatus = resumed.resumed.completed > 0
      ? `${resumed.resumed.completed} pending message${resumed.resumed.completed === 1 ? "" : "s"} reached relay acceptance.`
      : "No pending message reached relay acceptance. Review the route and failure state below.";
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function syncSelectedMessages() {
  await refreshSelectedMessages({ synchronize: true });
}

async function retrySelectedRouteTeardown() {
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    const teardown = await state.messaging.resumeRouteTeardowns({
      relationship,
      relationshipID: relationship.relationshipID
    });
    state.messageSnapshot = await state.messaging.snapshot(relationship);
    state.messageSyncStatus = teardown.complete
      ? "All local receive routes are now torn down. Fresh pairing is required."
      : `${teardown.failures.length} route teardown${teardown.failures.length === 1 ? "" : "s"} remain retryable.`;
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function discardOutbound(clientTransactionId) {
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    const discarded = await state.messaging.discard(relationship, clientTransactionId);
    state.messageSnapshot = discarded.snapshot;
    state.messageSyncStatus = "Unaccepted local outbox entry discarded.";
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function markMessageRead(eventID) {
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    const marked = await state.messaging.markRead(relationship, eventID);
    state.messageSnapshot = marked.snapshot;
    state.messageSyncStatus = marked.resumed.completed > 0
      ? "Relationship-scoped read receipt reached relay acceptance."
      : "Read receipt is durable locally and awaits relay retry.";
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function updateSelectedConsent() {
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  const consent = elements.relationshipConsent.value;
  if (!new Set(["accepted", "pendingRequest", "blocked"]).has(consent)) {
    throw new Error("Local relationship consent is invalid.");
  }
  if (relationship.localPolicy.consent === "blocked" && consent !== "blocked") {
    throw new Error("A blocked relationship cannot be resurrected. Create a fresh pairing.");
  }
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    await persistRelationshipPolicy(relationship, { ...relationship.localPolicy, consent });
    if (consent === "blocked") {
      const teardown = await state.messaging.teardownRelationshipRoutes(
        requireSelectedRelationship(),
        "blocked"
      );
      state.messageSyncStatus = teardown.complete
        ? "Blocked locally and all live receive routes were torn down. Fresh pairing is required."
        : "Blocked locally. Route teardown remains encrypted, retryable, and pending.";
    }
    state.messageSnapshot = await state.messaging.snapshot(requireSelectedRelationship());
    if (consent !== "blocked") state.messageSyncStatus = state.messageSnapshot.availability.message;
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function toggleSelectedRelationshipMute() {
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    const muted = state.messageSnapshot?.availability.muted ?? false;
    const mutedUntil = muted ? null : swiftISODate(new Date(Date.now() + 8 * 60 * 60 * 1_000));
    await persistRelationshipPolicy(relationship, { ...relationship.localPolicy, mutedUntil });
    state.messageSnapshot = await state.messaging.snapshot(requireSelectedRelationship());
    state.messageSyncStatus = state.messageSnapshot.availability.message;
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function updateReceiptPreferences() {
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  try {
    await persistRelationshipPolicy(relationship, {
      ...relationship.localPolicy,
      deliveryReceiptsEnabled: elements.deliveryReceiptsEnabled.checked,
      readReceiptsEnabled: elements.readReceiptsEnabled.checked
    });
    state.messageSnapshot = await state.messaging.snapshot(requireSelectedRelationship());
    state.messageSyncStatus = "Relationship-scoped receipt preferences saved only in this encrypted vault.";
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function persistRelationshipPolicy(relationship, policy) {
  return state.messaging.updateRelationshipLocalPolicy(relationship, policy, {
    persistAppliedRelationship: persistRuntimeRelationship
  });
}

async function persistRuntimeRelationship({ relationship }) {
  const persona = structuredClone(validateBrowserPersonaState(state.persona));
  const index = persona.relationships.findIndex(({ relationshipID }) =>
    relationshipID === relationship.relationshipID);
  if (index < 0) throw new Error("Durable relationship state is not part of this local persona.");
  persona.relationships[index] = relationship;
  const validated = validateBrowserPersonaState(persona);
  await state.repository.save(validated);
  state.persona = validated;
}

async function burnLocalPersona() {
  requireUnlocked();
  if (!confirm("Burn this local persona, tear down every live receive route, and erase all local relationship state? There is no recovery.")) return;
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  let began = false;
  try {
    await state.vault.beginBurn();
    state.vaultStatus = "burning";
    began = true;
    await completeLocalBurn({ persona: state.persona, messaging: state.messaging });
  } catch (error) {
    if (began) lockProfile();
    throw error;
  } finally {
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function completeLocalBurn({ persona, messaging }) {
  const burnedRelationships = [...persona.relationships];
  const result = await executeAnchoredBrowserLocalBurnV2({
    vault: state.vault,
    messaging,
    relationships: burnedRelationships
  });
  state.vaultStatus = "burned";

  // Relay teardown is intentionally after every local authority boundary is
  // terminal. Failure or a crash here cannot resurrect any relationship.
  if (result.failures.length > 0) console.warn(
    `${result.failures.length} best-effort relay route teardown${result.failures.length === 1 ? "" : "s"} failed after local burn.`
  );
  lockProfile();
}

async function sendSelectedAttachment() {
  requireUnlocked();
  const relationship = requireSelectedRelationship();
  const file = elements.attachmentFile.files?.[0];
  if (!file) return;
  if (state.messageBusy) throw new Error("Messaging is already working.");
  if (!Number.isSafeInteger(file.size) || file.size <= 0 ||
      file.size > browserMessagingAttachmentMaximumBytes) {
    elements.attachmentFile.value = "";
    throw new Error(
      `Attachments must contain 1 to ${browserMessagingAttachmentMaximumBytes} bytes.`
    );
  }
  state.messageBusy = true;
  renderSelectedMessages();
  let bytes;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
    const sent = await state.messaging.sendAttachment({
      relationship,
      bytes,
      mimeType: canonicalAttachmentMIME(file.type)
    });
    state.messageSnapshot = sent.snapshot;
    const accepted = sent.intent.status === "relayAccepted" ||
      sent.resumed.intents.some(({ id, status }) =>
        id === sent.intent.id && status === "relayAccepted");
    state.messageSyncStatus = accepted
      ? "Attachment chunks and descriptor are encrypted, durable, and accepted by a peer route relay."
      : "Attachment is encrypted in the local outbox; relay retry is pending.";
  } finally {
    bytes?.fill(0);
    elements.attachmentFile.value = "";
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

async function downloadReceivedAttachment(eventID) {
  const relationship = requireSelectedRelationship();
  if (state.messageBusy) throw new Error("Messaging is already working.");
  state.messageBusy = true;
  renderSelectedMessages();
  let bytes;
  let objectURL;
  try {
    const result = await state.messaging.downloadAttachment({ relationship, eventID });
    state.messageSnapshot = result.snapshot;
    bytes = result.downloaded.bytes;
    const descriptor = result.downloaded.descriptor;
    const desktopExport = globalThis.__noctweaveDesktopExportAttachment;
    if (typeof desktopExport === "function") {
      const exported = await desktopExport({
        bytes,
        mimeType: descriptor.mimeType,
        sha256: descriptor.sha256
      });
      state.messageSyncStatus = exported.saved
        ? `Attachment verified and saved as ${exported.fileName} (${exported.byteCount} bytes).`
        : `Attachment verified (${exported.byteCount} bytes); save canceled.`;
    } else {
      objectURL = URL.createObjectURL(new Blob([bytes], { type: descriptor.mimeType }));
      const link = document.createElement("a");
      link.href = objectURL;
      link.download = attachmentDownloadName(descriptor.mimeType);
      link.click();
      state.messageSyncStatus =
        `Attachment verified (${bytes.byteLength} bytes) and handed to the system download flow.`;
    }
  } finally {
    if (objectURL) setTimeout(() => URL.revokeObjectURL(objectURL), 30_000);
    bytes?.fill(0);
    state.messageBusy = false;
    renderSelectedMessages();
  }
}

function requireSelectedRelationship() {
  const relationship = selectedRelationship();
  if (!relationship) throw new Error("Select a completed pairwise relationship first.");
  return relationship;
}

function renderPersona() {
  elements.personaName.textContent = state.persona.displayName;
  elements.relationshipCount.textContent = String(state.persona.relationships.length);
  elements.relationshipList.replaceChildren(...state.persona.relationships.map((relationship) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "relationshipChoice";
    item.disabled = state.messageBusy;
    item.setAttribute("aria-pressed", String(relationship.relationshipID === state.selectedRelationshipID));
    const name = document.createElement("strong");
    name.textContent = relationship.peerIdentity.relationshipPseudonym;
    const detail = document.createElement("span");
    detail.textContent = relationship.localPolicy.consent === "blocked"
      ? "Blocked locally"
      : "Pairwise-only relationship";
    item.append(name, detail);
    item.addEventListener("click", () => selectRelationship(relationship.relationshipID));
    return item;
  }));
  if (state.persona.relationships.length === 0) {
    elements.relationshipList.hidden = true;
    elements.relationshipSectionLabel.hidden = true;
  } else {
    elements.relationshipList.hidden = false;
    elements.relationshipSectionLabel.hidden = false;
  }
  renderPendingPairings();
  renderSelectedMessages();
}

function renderSelectedMessages() {
  if (!state.persona) {
    state.messageSnapshot = null;
    state.safetyNumber = null;
    elements.messageList.replaceChildren();
    elements.safetyNumber.textContent = "";
    return;
  }
  const relationship = selectedRelationship();
  const snapshot = state.messageSnapshot;
  const availability = snapshot?.availability ?? null;
  for (const choice of elements.relationshipList.querySelectorAll(".relationshipChoice")) {
    choice.disabled = state.messageBusy;
  }
  elements.selectedRelationshipName.textContent = relationship
    ? relationship.peerIdentity.relationshipPseudonym
    : "No relationship selected";
  elements.selectedRelationshipState.textContent = availability?.message ??
    (relationship ? state.messageSyncStatus : "Complete a fresh pairing to begin messaging.");
  elements.selectedRelationshipState.dataset.state = availability?.maintenanceState ?? "unavailable";
  elements.outboxStatus.textContent = state.messageSyncStatus;
  elements.attachmentStatus.textContent = browserMessagingAttachmentStatus;
  elements.attachmentFile.disabled = !availability?.canSend || state.messageBusy;
  elements.openAttachment.disabled = !availability?.canSend || state.messageBusy;
  elements.messageText.disabled = !availability?.canSend || state.messageBusy;
  elements.sendMessage.disabled = !availability?.canSend || state.messageBusy;
  elements.resumeOutbox.disabled = !relationship || availability?.consent === "blocked" ||
    availability?.routeTeardownState !== null || state.messageBusy;
  elements.syncMessages.disabled = !availability?.canReceive || state.messageBusy;
  elements.syncMessages.hidden = !relationship || !/(paused|failed|error)/i.test(state.messageSyncStatus);
  elements.syncMessages.textContent = "Retry sync";
  elements.resumeOutbox.hidden = !relationship;
  const teardownPending = availability?.routeTeardownState === "pending";
  elements.retryRouteTeardown.hidden = !teardownPending;
  elements.retryRouteTeardown.disabled = !teardownPending || state.messageBusy;
  const policyLocked = !relationship || availability?.consent === "blocked" ||
    availability?.routeTeardownState !== null || state.messageBusy;
  elements.relationshipConsent.disabled = policyLocked;
  elements.relationshipConsent.value = relationship?.localPolicy.consent ?? "accepted";
  elements.muteRelationship.disabled = policyLocked;
  elements.muteRelationship.hidden = !relationship;
  elements.muteRelationship.textContent = availability?.muted ? "Unmute" : "Mute 8 hours";
  elements.deliveryReceiptsEnabled.disabled = policyLocked;
  elements.readReceiptsEnabled.disabled = policyLocked;
  elements.deliveryReceiptsEnabled.checked = relationship?.localPolicy.deliveryReceiptsEnabled ?? false;
  elements.readReceiptsEnabled.checked = relationship?.localPolicy.readReceiptsEnabled ?? false;
  elements.safetyNumber.textContent = state.safetyNumber ??
    "Unavailable until a relationship is selected.";

  if (!snapshot || snapshot.timeline.length === 0) {
    elements.messageList.dataset.empty = "true";
    const empty = document.createElement("div");
    empty.className = "conversationEmpty";
    if (!relationship) {
      const mark = document.createElement("img");
      mark.src = "./assets/noctweave-mark.svg";
      mark.alt = "";
      const title = document.createElement("h2");
      title.textContent = "Welcome to Noctweave";
      const explanation = document.createElement("p");
      explanation.textContent = "Start with a one-use invitation. Every conversation receives independent secure relationship authority and encryption state.";
      const add = document.createElement("button");
      add.type = "button";
      add.textContent = "Add Contact";
      add.addEventListener("click", () => activateClientView("people"));
      empty.append(mark, title, explanation, add);
    } else {
      const title = document.createElement("h2");
      title.textContent = "No messages yet";
      const explanation = document.createElement("p");
      explanation.textContent = "Messages in this disposable relationship will appear here.";
      empty.append(title, explanation);
    }
    elements.messageList.replaceChildren(empty);
    return;
  }
  delete elements.messageList.dataset.empty;
  elements.messageList.replaceChildren(...snapshot.timeline.map((message) => {
    const item = document.createElement("article");
    item.className = `messageBubble ${message.direction}`;
    const text = document.createElement("p");
    text.textContent = message.text;
    const metadata = document.createElement("span");
    metadata.textContent = [
      message.direction === "outbound" ? "You" : "Peer",
      message.relationLabel,
      message.deliveryLabel,
      message.failureCode
    ].filter(Boolean).join(" · ");
    item.append(text, metadata);
    if (message.direction === "inbound" && message.contentKind === "attachment") {
      const download = pairingButton(
        document.documentElement.dataset.runtime === "desktop"
          ? "Save verified attachment…"
          : "Download verified attachment",
        () => runMessaging(() => downloadReceivedAttachment(message.eventID)),
        "subtle"
      );
      download.disabled = state.messageBusy;
      item.append(download);
    }
    if (message.direction === "inbound" &&
        relationship?.localPolicy.readReceiptsEnabled && availability?.canSend) {
      const markRead = pairingButton("Send read receipt", () =>
        runMessaging(() => markMessageRead(message.eventID)), "subtle");
      markRead.disabled = state.messageBusy;
      item.append(markRead);
    }
    if (message.direction === "outbound" &&
        ["retryableFailure", "permanentFailure"].includes(message.intentStatus)) {
      const discard = pairingButton("Discard unsent copy", () =>
        runMessaging(() => discardOutbound(message.clientTransactionId)), "danger");
      discard.disabled = state.messageBusy;
      item.append(discard);
    }
    return item;
  }));
}

function canonicalAttachmentMIME(value) {
  const normalized = typeof value === "string"
    ? value.split(";", 1)[0].trim().toLowerCase()
    : "";
  return normalized.length > 0 && normalized.length <= 128 &&
    /^[\x20-\x3a\x3c-\x7e]+$/u.test(normalized)
    ? normalized
    : "application/octet-stream";
}

function attachmentDownloadName(mimeType) {
  const suffix = ({
    "text/plain": "txt",
    "application/pdf": "pdf",
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "audio/mpeg": "mp3",
    "audio/mp4": "m4a"
  })[mimeType.toLowerCase()] ?? "bin";
  return `noctweave-attachment.${suffix}`;
}

function renderPendingPairings() {
  if (!state.persona) return;
  const pairings = state.persona.pendingPairings;
  if (pairings.length === 0) {
    elements.pendingPairingList.textContent = "No pending rendezvous.";
    return;
  }
  elements.pendingPairingList.replaceChildren(...pairings.map((pairing) => {
    const item = document.createElement("article");
    const summary = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = pairing.role === "offerer" ? "Invitation you created" : "Invitation you accepted";
    const detail = document.createElement("span");
    detail.textContent = `${pairingPhaseLabel(pairing.phase)} · expires ${pairing.offer.expiresAt}`;
    summary.append(title, detail);

    const actions = document.createElement("div");
    actions.className = "buttonRow";
    const busy = state.pairingBusy.has(pairing.pairingID);
    const resume = pairingButton(busy ? "Syncing…" : "Resume", () => run(() => pumpPairing(pairing.pairingID)));
    resume.disabled = busy;
    actions.append(resume);
    if (pairing.phase === "ready" && pairing.outboundTransportFrames.length === 0) {
      actions.append(pairingButton("Finalize", () => run(() => finalizePairing(pairing.pairingID))));
    }
    const cancel = pairingButton("Cancel", () => run(() => cancelPairing(pairing.pairingID)), "danger");
    cancel.disabled = busy;
    actions.append(cancel);
    item.append(summary, actions);
    return item;
  }));
}

function pairingButton(label, operation, className = "subtle") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", operation);
  return button;
}

function pairingPhaseLabel(phase) {
  return ({
    awaitingOpen: "Waiting for peer to redeem",
    awaitingAcceptance: "Peer connected",
    awaitingIntroduction: "Waiting for peer introduction",
    awaitingConfirmation: "Verifying relationship",
    awaitingAcknowledgement: "Waiting for final acknowledgement",
    ready: "Finishing verified relationship"
  })[phase] ?? "Pairing in progress";
}

function requireRelationshipPseudonym() {
  const value = elements.relationshipPseudonym.value.trim();
  if (!value) throw new Error("Enter the name the other person should see for you.");
  return value;
}

function normalizedPairingInput(value) {
  if (typeof value !== "string") throw new Error("Paste a one-use invitation first.");
  const normalized = value.trim();
  if (!normalized) throw new Error("Paste a one-use invitation first.");
  if (normalized.length > PAIRING_INVITATION_MAX_CHARACTERS) {
    throw new Error("The invitation exceeds the 32 KiB safety limit.");
  }
  return normalized;
}

function clearSharedInvitation() {
  state.invitation = null;
  state.invitationPairingID = null;
  elements.invitation.value = "";
  $("#shareInvitation").hidden = true;
  $("#copyInvitation").hidden = true;
}

function requireUnlocked() {
  if (!state.persona || !state.repository) throw new Error("Unlock the encrypted persona first.");
}

function validatePassphrase() {
  const value = elements.passphrase.value;
  if (value.length < 12) throw new Error("Use at least 12 characters.");
  return value;
}

async function run(operation) {
  elements.status.textContent = "Working";
  elements.error.textContent = "";
  try {
    await operation();
    elements.status.textContent = "Ready";
  } catch (error) {
    elements.status.textContent = "Error";
    elements.error.textContent = state.persona ? displayError(error)
      : unlockFailureMessage(displayError(error), state.hiddenUnlockMethods);
    if ($("#vaultCard").hidden) $("#vaultLoading").textContent = "Unable to open Noctweave. Reload to try again.";
    if (state.persona) elements.pairingStatus.textContent = elements.error.textContent;
  }
}

async function runMessaging(operation) {
  elements.status.textContent = "Working";
  elements.error.textContent = "";
  try {
    await operation();
    elements.status.textContent = "Ready";
  } catch (error) {
    elements.status.textContent = "Error";
    const message = displayError(error);
    elements.error.textContent = message;
    state.messageSyncStatus = message;
    renderSelectedMessages();
  }
}

function displayError(error) {
  const message = error instanceof Error ? error.message : String(error);
  const described = error && typeof error === "object" && typeof error.code === "string"
    ? `${message} (${error.code})`
    : message;
  const cause = error && typeof error === "object" ? error.cause : null;
  return cause instanceof Error && cause.message !== message
    ? `${described}: ${displayError(cause)}`
    : described;
}
