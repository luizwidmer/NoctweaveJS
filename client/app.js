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
  decodeContactPairingInvitationV2,
  encodeContactPairingInvitationV2,
  parseBrowserRelayEndpoint,
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
  invitation: null
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
  invitationResult: $("#invitationResult")
};

elements.unlock.addEventListener("click", () => run(hasVault() ? unlockVault : createVault));
elements.forget.addEventListener("click", () => run(forgetVault));
$("#verifyRelay").addEventListener("click", () => run(verifyRelay));
$("#createInvitation").addEventListener("click", () => run(createInvitation));
$("#copyInvitation").addEventListener("click", () => run(copyInvitation));
$("#inspectInvitation").addEventListener("click", () => run(inspectInvitation));
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
  const parsed = parseBrowserRelayEndpoint(String(endpoint));
  const customFetch = parsed.transport === "http" ? proxyFetch(String(endpoint)) : options.fetch;
  return new NoctweaveRelayClient(endpoint, { ...options, fetch: customFetch });
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
}

function lockProfile() {
  state.repository = null;
  state.persona = null;
  state.invitation = null;
  elements.invitation.value = "";
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
    createdAt: createdAtValue,
    expiresAt: expiresAtValue
  });
  const encoded = await encodeContactPairingInvitationV2({
    crypto: state.crypto,
    invitation: prepared.invitation
  });
  await state.repository.save(prepared.persona);
  state.persona = prepared.persona;
  state.invitation = encoded;
  elements.invitation.value = encoded;
  elements.invitationResult.textContent = "Fresh invitation ready. It expires in ten minutes and can be redeemed once.";
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
  }
}
