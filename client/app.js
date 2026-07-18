import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  BrowserLocalStorageStore,
  EncryptedNoctweaveStore,
  NoctweaveBrowserPairingService,
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  NoctweaveStateRepository,
  WebCryptoPrimitives,
  base64,
  createRendezvousRelayAdapterV2,
  decodeContactPairingInvitationV2,
  encodeContactPairingInvitationV2,
  parseBrowserRelayEndpoint,
  relayEndpointURL,
  swiftISODate,
  validateBrowserPersonaState
} from "../src/index.js";

const profileName = new URL(location.href).searchParams.get("profile") || "default";
const namespace = `noctweave-js-client:${profileName}`;
const saltKey = `${namespace}:salt`;
const vaultNamespace = `${namespace}:vault`;
const stateKey = "persona";

const state = {
  pqc: null,
  crypto: null,
  pairing: null,
  repository: null,
  persona: null,
  invitation: null,
  pairingBusy: new Set(),
  pumpTimer: null
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
$("#lockProfile").addEventListener("click", lockProfile);

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
  return localStorage.getItem(saltKey) !== null;
}

function renderGate() {
  const existing = hasVault();
  elements.confirmationRow.hidden = existing;
  elements.unlock.textContent = existing ? "Unlock encrypted persona" : "Create encrypted persona";
  elements.forget.hidden = !existing;
  elements.error.textContent = "";
}

async function createVault() {
  const passphrase = validatePassphrase();
  if (passphrase !== elements.confirmation.value) throw new Error("Passphrases do not match.");
  const displayName = elements.displayName.value.trim();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(saltKey, base64(salt));
  try {
    state.repository = repository(passphrase, salt);
    state.persona = state.pairing.createPersona({ displayName });
    await state.repository.save(state.persona);
    showApp();
  } catch (error) {
    localStorage.removeItem(saltKey);
    throw error;
  } finally {
    salt.fill(0);
    elements.passphrase.value = "";
    elements.confirmation.value = "";
  }
}

async function unlockVault() {
  const passphrase = validatePassphrase();
  const salt = decodeBase64(localStorage.getItem(saltKey));
  try {
    state.repository = repository(passphrase, salt);
    state.persona = validateBrowserPersonaState(await state.repository.load());
    showApp();
  } finally {
    salt.fill(0);
    elements.passphrase.value = "";
  }
}

function repository(passphrase, salt) {
  const raw = new BrowserLocalStorageStore({ namespace: vaultNamespace });
  const encrypted = new EncryptedNoctweaveStore(raw, {
    passphrase,
    salt,
    iterations: 310_000
  });
  return new NoctweaveStateRepository(encrypted, { key: stateKey });
}

function showApp() {
  elements.gate.hidden = true;
  elements.app.hidden = false;
  elements.app.inert = false;
  renderPersona();
  startPairingPump();
}

function lockProfile() {
  stopPairingPump();
  state.repository = null;
  state.persona = null;
  state.invitation = null;
  state.pairingBusy.clear();
  elements.invitation.value = "";
  elements.peerInvitation.value = "";
  elements.app.hidden = true;
  elements.app.inert = true;
  elements.gate.hidden = false;
  renderGate();
}

async function forgetVault() {
  if (!confirm("Delete this encrypted local persona and all pairwise relationships?")) return;
  const raw = new BrowserLocalStorageStore({ namespace: vaultNamespace });
  await raw.clear();
  localStorage.removeItem(saltKey);
  lockProfile();
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

function renderPersona() {
  elements.personaName.textContent = state.persona.displayName;
  elements.relationshipCount.textContent = String(state.persona.relationships.length);
  elements.relationshipList.replaceChildren(...state.persona.relationships.map((relationship) => {
    const item = document.createElement("article");
    const name = document.createElement("strong");
    name.textContent = relationship.peerIdentity.relationshipPseudonym;
    const detail = document.createElement("span");
    detail.textContent = "Pairwise-only relationship";
    item.append(name, detail);
    return item;
  }));
  if (state.persona.relationships.length === 0) {
    elements.relationshipList.textContent = "No completed pairwise relationships yet.";
  }
  renderPendingPairings();
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

function decodeBase64(value) {
  if (typeof value !== "string" || !value) throw new Error("Encrypted persona salt is missing.");
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
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
