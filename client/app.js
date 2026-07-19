import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  EncryptedNoctweaveStore,
  NoctweaveBrowserPairingService,
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  createRendezvousRelayAdapterV2,
  decodeContactPairingInvitationV2,
  encodeContactPairingInvitationV2,
  parseBrowserRelayEndpoint,
  relayEndpointURL,
  swiftISODate,
  validateBrowserPersonaState
} from "../src/index.js";
import {
  HostAnchoredBrowserApplicationVaultV2,
  NoctweaveBrowserMessagingServiceV2,
  browserMessagingAttachmentBlocker,
  browserRollbackAnchorRequirement,
  executeAnchoredBrowserLocalBurnV2
} from "./messaging-service.js";

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
  selectedRelationshipID: null,
  messageSnapshot: null,
  messageSyncStatus: "Select a relationship to begin.",
  safetyNumber: null,
  pairingBusy: new Set(),
  messageBusy: false,
  lastMaintenanceAt: 0,
  pumpTimer: null,
  messagePumpTimer: null
};

const $ = (selector) => document.querySelector(selector);
const elements = {
  gate: $("#vaultGate"),
  app: $("#appShell"),
  passphrase: $("#vaultPassphrase"),
  confirmation: $("#vaultConfirmation"),
  confirmationRow: $("#vaultConfirmationRow"),
  unlock: $("#unlockVault"),
  forget: $("#forgetVault"),
  error: $("#vaultError"),
  displayName: $("#displayName"),
  relay: $("#relay"),
  relayInfo: $("#relayInfo"),
  status: $("#status"),
  personaName: $("#personaName"),
  relationshipCount: $("#relationshipCount"),
  relationshipList: $("#relationshipList"),
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
  pendingPairingList: $("#pendingPairingList")
};

elements.unlock.addEventListener("click", () => run(hasVault() ? unlockVault : createVault));
elements.forget.addEventListener("click", () => run(forgetVault));
$("#verifyRelay").addEventListener("click", () => run(verifyRelay));
$("#createInvitation").addEventListener("click", () => run(createInvitation));
$("#copyInvitation").addEventListener("click", () => run(copyInvitation));
$("#inspectInvitation").addEventListener("click", () => run(inspectInvitation));
$("#acceptInvitation").addEventListener("click", () => run(acceptInvitation));
$("#resumePairings").addEventListener("click", () => run(resumeAllPairings));
elements.sendMessage.addEventListener("click", () => runMessaging(sendMessage));
elements.resumeOutbox.addEventListener("click", () => runMessaging(resumeSelectedOutbox));
elements.syncMessages.addEventListener("click", () => runMessaging(syncSelectedMessages));
elements.retryRouteTeardown.addEventListener("click", () => runMessaging(retrySelectedRouteTeardown));
elements.relationshipConsent.addEventListener("change", () => runMessaging(updateSelectedConsent));
elements.muteRelationship.addEventListener("click", () => runMessaging(toggleSelectedRelationshipMute));
elements.deliveryReceiptsEnabled.addEventListener("change", () => runMessaging(updateReceiptPreferences));
elements.readReceiptsEnabled.addEventListener("change", () => runMessaging(updateReceiptPreferences));
elements.attachmentFile.addEventListener("change", () => runMessaging(rejectAttachmentSelection));
$("#lockProfile").addEventListener("click", lockProfile);
$("#burnProfile").addEventListener("click", () => runMessaging(burnLocalPersona));
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") void foregroundMessagingMaintenance();
});

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
    const anchorFactory = typeof globalThis.noctweaveRelationshipStateAnchorStoreFactory ===
      "function"
      ? globalThis.noctweaveRelationshipStateAnchorStoreFactory
      : null;
    if (anchorFactory !== null) {
      state.vault = new HostAnchoredBrowserApplicationVaultV2({
        crypto: state.crypto,
        storageCrypto: globalThis.crypto,
        stateAnchorStoreFactory: anchorFactory
      });
      state.vaultStatus = (await state.vault.inspect()).status;
    } else {
      state.messageSyncStatus = browserRollbackAnchorRequirement;
    }
    renderGate();
  });
}

function makeRelayClient(endpoint, options = {}) {
  const parsed = typeof endpoint === "string" ? parseBrowserRelayEndpoint(endpoint) : endpoint;
  const endpointURL = typeof endpoint === "string" ? endpoint : relayEndpointURL(parsed, "/");
  const customFetch = parsed.transport === "http" ? proxyFetch(endpointURL) : options.fetch;
  return new NoctweaveRelayClient(parsed, { ...options, fetch: customFetch });
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
  const existing = hasVault();
  elements.confirmationRow.hidden = existing;
  elements.unlock.textContent = state.vaultStatus === "burning"
    ? "Finish local burn"
    : existing ? "Unlock encrypted persona" : "Create encrypted persona";
  elements.forget.hidden = !existing;
  elements.error.textContent = "";
}

async function createVault() {
  if (state.vault === null) throw new Error(browserRollbackAnchorRequirement);
  const passphrase = validatePassphrase();
  if (passphrase !== elements.confirmation.value) throw new Error("Passphrases do not match.");
  const displayName = elements.displayName.value.trim();
  try {
    const opened = await state.vault.initialize({
      passphrase,
      persona: state.pairing.createPersona({ displayName })
    });
    activateVaultSession(opened);
    showApp();
  } finally {
    elements.passphrase.value = "";
    elements.confirmation.value = "";
  }
}

async function unlockVault() {
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
    showApp();
  } finally {
    elements.passphrase.value = "";
  }
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
  });
}

function showApp() {
  elements.gate.hidden = true;
  elements.app.hidden = false;
  elements.app.inert = false;
  selectInitialRelationship();
  renderPersona();
  startPairingPump();
  startMessagePump();
}

function lockProfile() {
  stopPairingPump();
  stopMessagePump();
  state.repository = null;
  state.vault?.lock();
  state.encryptedStore = null;
  state.messaging = null;
  state.persona = null;
  state.invitation = null;
  state.selectedRelationshipID = null;
  state.messageSnapshot = null;
  state.messageSyncStatus = "Select a relationship to begin.";
  state.safetyNumber = null;
  state.messageBusy = false;
  state.lastMaintenanceAt = 0;
  state.pairingBusy.clear();
  elements.invitation.value = "";
  elements.peerInvitation.value = "";
  elements.messageText.value = "";
  elements.app.hidden = true;
  elements.app.inert = true;
  elements.gate.hidden = false;
  renderGate();
}

async function forgetVault() {
  if (!state.persona || !state.messaging) {
    throw new Error("Unlock the encrypted persona before deletion so live receive routes can be torn down.");
  }
  await burnLocalPersona();
}

async function verifyRelay() {
  const result = await state.pairing.verifyRelay(elements.relay.value);
  elements.relayInfo.textContent = `${result.endpoint.transport} route transport verified`;
}

async function createInvitation() {
  requireUnlocked();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 10 * 60 * 1_000);
  const createdAtValue = swiftISODate(createdAt);
  const expiresAtValue = swiftISODate(expiresAt);
  const prepared = await state.pairing.prepareOffererPairing({
    persona: state.persona,
    relay: elements.relay.value,
    relationshipPseudonym: elements.relationshipPseudonym.value,
    createdAt: createdAtValue,
    expiresAt: expiresAtValue
  });
  const encoded = await encodeContactPairingInvitationV2({
    crypto: state.crypto,
    invitation: prepared.invitation
  });
  await persistPersona(prepared.persona);
  state.invitation = encoded;
  elements.invitation.value = encoded;
  elements.invitationResult.textContent = "Fresh invitation ready. Share it privately; it expires in ten minutes and can be redeemed once.";
  await pumpPairing(prepared.pairingID);
}

async function copyInvitation() {
  if (!state.invitation) throw new Error("Create a fresh invitation first.");
  await navigator.clipboard.writeText(state.invitation);
  elements.invitationResult.textContent = "One-use invitation copied.";
}

async function inspectInvitation() {
  const invitation = await decodeContactPairingInvitationV2({
    crypto: state.crypto,
    encoded: elements.peerInvitation.value.trim()
  });
  elements.invitationResult.textContent = `Valid one-use rendezvous; expires ${invitation.offer.expiresAt}. No identity or route was disclosed.`;
}

async function acceptInvitation() {
  requireUnlocked();
  const encoded = elements.peerInvitation.value.trim();
  if (!encoded) throw new Error("Paste a one-use invitation first.");
  const invitation = await decodeContactPairingInvitationV2({ crypto: state.crypto, encoded });
  const prepared = await state.pairing.prepareResponderPairing({
    persona: state.persona,
    invitation,
    relay: elements.relay.value,
    relationshipPseudonym: elements.relationshipPseudonym.value,
    at: swiftISODate()
  });
  await persistPersona(prepared.persona);
  elements.peerInvitation.value = "";
  elements.invitationResult.textContent = "Invitation accepted. Its secret was removed from the form; the encrypted rendezvous will resume until ready.";
  await pumpPairing(prepared.pairingID);
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
    elements.pairingStatus.textContent = pairing?.phase === "ready"
      ? "Pairing is verified and ready for your explicit final approval."
      : "Rendezvous synchronized. Waiting for the peer; retry is safe after a restart.";
  } finally {
    state.pairingBusy.delete(pairingID);
    renderPendingPairings();
  }
}

async function finalizePairing(pairingID) {
  if (state.pairingBusy.has(pairingID)) throw new Error("Pairing synchronization is still running.");
  state.pairingBusy.add(pairingID);
  renderPendingPairings();
  try {
    const pending = requirePendingPairing(pairingID);
    const finalized = await state.pairing.finalizePairing({
      persona: state.persona,
      pairingID,
      at: swiftISODate()
    });
    await deleteRendezvousLanes(pending, finalized.rendezvousDeletionRequests);
    await persistPersona(finalized.persona);
    state.selectedRelationshipID = finalized.relationship.relationshipID;
    await refreshSelectedMessages({ resumeOutbound: true, synchronize: true });
    elements.pairingStatus.textContent = "Fresh pairwise relationship stored; the one-use rendezvous lanes were deleted.";
  } finally {
    state.pairingBusy.delete(pairingID);
    renderPendingPairings();
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
    if (state.persona.pendingPairings.length === 0) {
      state.invitation = null;
      elements.invitation.value = "";
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
  state.pumpTimer = setInterval(backgroundResume, 3_000);
}

function stopPairingPump() {
  if (state.pumpTimer !== null) clearInterval(state.pumpTimer);
  state.pumpTimer = null;
}

async function backgroundResume() {
  if (!state.persona || !state.repository || state.persona.pendingPairings.length === 0) return;
  try {
    await resumeAllPairings();
  } catch (error) {
    elements.pairingStatus.textContent = `Rendezvous paused: ${error instanceof Error ? error.message : String(error)} Use Resume all to retry.`;
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

async function rejectAttachmentSelection() {
  elements.attachmentFile.value = "";
  await state.messaging.prepareFile();
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
    elements.relationshipList.textContent = "No completed pairwise relationships yet.";
  }
  renderPendingPairings();
  renderSelectedMessages();
}

function renderSelectedMessages() {
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
  elements.attachmentStatus.textContent = browserMessagingAttachmentBlocker;
  elements.attachmentFile.disabled = true;
  elements.messageText.disabled = !availability?.canSend || state.messageBusy;
  elements.sendMessage.disabled = !availability?.canSend || state.messageBusy;
  elements.resumeOutbox.disabled = !relationship || availability?.consent === "blocked" ||
    availability?.routeTeardownState !== null || state.messageBusy;
  elements.syncMessages.disabled = !availability?.canReceive || state.messageBusy;
  const teardownPending = availability?.routeTeardownState === "pending";
  elements.retryRouteTeardown.hidden = !teardownPending;
  elements.retryRouteTeardown.disabled = !teardownPending || state.messageBusy;
  const policyLocked = !relationship || availability?.consent === "blocked" ||
    availability?.routeTeardownState !== null || state.messageBusy;
  elements.relationshipConsent.disabled = policyLocked;
  elements.relationshipConsent.value = relationship?.localPolicy.consent ?? "accepted";
  elements.muteRelationship.disabled = policyLocked;
  elements.muteRelationship.textContent = availability?.muted ? "Unmute" : "Mute 8 hours";
  elements.deliveryReceiptsEnabled.disabled = policyLocked;
  elements.readReceiptsEnabled.disabled = policyLocked;
  elements.deliveryReceiptsEnabled.checked = relationship?.localPolicy.deliveryReceiptsEnabled ?? false;
  elements.readReceiptsEnabled.checked = relationship?.localPolicy.readReceiptsEnabled ?? false;
  elements.safetyNumber.textContent = state.safetyNumber ??
    "Unavailable until a relationship is selected.";

  if (!snapshot || snapshot.timeline.length === 0) {
    elements.messageList.textContent = relationship
      ? "No visible messages stored for this relationship."
      : "Select a relationship to view its encrypted local history.";
    return;
  }
  elements.messageList.replaceChildren(...snapshot.timeline.map((message) => {
    const item = document.createElement("article");
    item.className = `messageBubble ${message.direction}`;
    const text = document.createElement("p");
    text.textContent = message.text;
    const metadata = document.createElement("span");
    metadata.textContent = [
      message.direction === "outbound" ? "You" : "Peer",
      message.relationLabel,
      message.deliveryLabel
    ].filter(Boolean).join(" · ");
    item.append(text, metadata);
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
    ready: "Ready to finalize"
  })[phase] ?? "Pairing in progress";
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
    elements.error.textContent = error instanceof Error ? error.message : String(error);
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
  return error instanceof Error ? error.message : String(error);
}
