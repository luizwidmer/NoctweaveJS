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
  encodeNativeContactCode,
  parseBrowserRelayEndpoint
} from "../src/index.js";

const profileName = new URL(location.href).searchParams.get("profile") || "default";
const namespace = `noctweave-js-client:${profileName}`;
const saltStorageKey = `${namespace}:salt`;
const encryptedStorageKey = `${namespace}:vault:profile`;
const stateKey = "profile";
const steps = ["welcome", "storage", "relay", "identity"];

const runtime = {
  pqc: null,
  crypto: new WebCryptoPrimitives(),
  identityService: null,
  repository: null,
  profile: null,
  verifiedRelay: null,
  currentStep: "welcome",
  codeVisible: false
};

const $ = (selector) => document.querySelector(selector);
const elements = {
  startup: $("#startup"), app: $("#app"), setupTitle: $("#setupTitle"), setupProgress: $("#setupProgress"),
  setupError: $("#setupError"), busy: $("#busy"), busyLabel: $("#busyLabel"), acceptNotice: $("#acceptNotice"),
  unlockPassphrase: $("#unlockPassphrase"), storagePassphrase: $("#storagePassphrase"), storageConfirmation: $("#storageConfirmation"),
  relayAddress: $("#relayAddress"), relayPassword: $("#relayPassword"), relayResult: $("#relayResult"), displayName: $("#displayName"),
  navigation: $("#navigation"), viewTitle: $("#viewTitle"), viewEyebrow: $("#viewEyebrow"), headerIdentity: $("#headerIdentity"),
  railRelay: $("#railRelay"), contactCode: $("#contactCode"), identityName: $("#identityName"), identityInbox: $("#identityInbox"),
  identityFingerprint: $("#identityFingerprint"), identityRelay: $("#identityRelay"), relayName: $("#relayName"),
  savedRelayAddress: $("#savedRelayAddress"), relaySoftware: $("#relaySoftware"), relayFederation: $("#relayFederation"),
  relayChecked: $("#relayChecked"), toast: $("#toast")
};

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
$("#recheckRelay").addEventListener("click", () => run("Checking relay", recheckRelay));
$("#revealCode").addEventListener("click", toggleCode);
$("#copyCode").addEventListener("click", copyCode);
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

boot();

async function boot() {
  await run("Loading post-quantum runtime", async () => {
    runtime.pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
    runtime.identityService = new NoctweaveBrowserIdentityService({
      pqc: runtime.pqc,
      crypto: runtime.crypto,
      relayClientFactory: makeRelayClient
    });
    if (localStorage.getItem(encryptedStorageKey) !== null || localStorage.getItem(saltStorageKey) !== null) {
      showStep("unlock");
    } else {
      showStep("welcome");
    }
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
    return fetch(path, {
      ...init,
      headers: { ...(init?.headers ?? {}), "x-relay-endpoint": endpoint }
    });
  };
}

async function createEncryptedProfile() {
  const passphrase = elements.storagePassphrase.value;
  if (passphrase.length < 12) throw new Error("Use a profile passphrase containing at least 12 characters.");
  if (passphrase !== elements.storageConfirmation.value) throw new Error("Profile passphrases do not match.");
  if (localStorage.getItem(encryptedStorageKey) !== null || localStorage.getItem(saltStorageKey) !== null) {
    throw new Error("An encrypted profile already exists in this browser.");
  }
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
  } finally {
    salt.fill(0);
  }
}

async function unlockProfile() {
  const encodedSalt = localStorage.getItem(saltStorageKey);
  if (!encodedSalt || localStorage.getItem(encryptedStorageKey) === null) throw new Error("The encrypted browser profile is incomplete.");
  const salt = fromBase64(encodedSalt);
  try {
    if (salt.byteLength !== 16) throw new Error("The encrypted browser profile is malformed.");
    const repository = makeRepository(elements.unlockPassphrase.value, salt);
    let profile;
    try {
      profile = await repository.load();
    } catch {
      throw new Error("The profile could not be unlocked. Check the passphrase.");
    }
    validateProfile(profile);
    runtime.repository = repository;
    runtime.profile = profile;
    elements.unlockPassphrase.value = "";
    routeAfterUnlock();
  } finally {
    salt.fill(0);
  }
}

function makeRepository(passphrase, salt) {
  const backend = new BrowserLocalStorageStore({ namespace: `${namespace}:vault` });
  const encrypted = new EncryptedNoctweaveStore(backend, { passphrase, salt, iterations: 310_000 });
  return new NoctweaveStateRepository(encrypted, { key: stateKey });
}

function newProfileState() {
  return { version: 1, onboardingComplete: false, identity: null, relay: null, contacts: [], conversations: {}, messages: [] };
}

function validateProfile(profile) {
  if (!profile || profile.version !== 1 || !Array.isArray(profile.contacts) || !Array.isArray(profile.messages)) {
    throw new Error("The encrypted browser profile has an unsupported format.");
  }
}

function routeAfterUnlock() {
  if (runtime.profile?.onboardingComplete && runtime.profile.identity && runtime.profile.relay) {
    showApplication();
  } else if (runtime.profile?.relay) {
    elements.relayAddress.value = runtime.profile.relay.address ?? "";
    showStep("identity");
  } else {
    showStep("relay");
  }
}

async function verifyRelay() {
  const address = elements.relayAddress.value.trim();
  parseBrowserRelayEndpoint(address);
  const authToken = elements.relayPassword.value || null;
  const verified = await runtime.identityService.verifyRelay(address, { authToken });
  runtime.verifiedRelay = { address, authToken, endpoint: verified.endpoint, relayInfo: verified.info.relayInfo, verifiedAt: new Date().toISOString() };
  runtime.profile.relay = runtime.verifiedRelay;
  await saveProfile();
  const name = relayDisplayName(verified.info.relayInfo);
  elements.relayResult.textContent = `${name} responded with a compatible client relay profile.`;
  elements.relayResult.classList.add("good");
  setTimeout(() => showStep("identity"), 450);
}

async function createIdentity() {
  const relay = runtime.verifiedRelay ?? runtime.profile?.relay;
  if (!relay?.address) throw new Error("Verify a relay before creating an identity.");
  const created = await runtime.identityService.createAndRegister({
    displayName: elements.displayName.value,
    relay: relay.address,
    authToken: relay.authToken
  });
  runtime.profile.identity = created.identity;
  runtime.profile.relay = { ...relay, ...created.relay, authToken: relay.authToken };
  runtime.profile.onboardingComplete = true;
  await saveProfile();
  showApplication();
  notify("Identity created and registered");
}

async function recheckRelay() {
  const relay = runtime.profile.relay;
  const checked = await runtime.identityService.verifyRelay(relay.address, { authToken: relay.authToken });
  runtime.profile.relay = { ...relay, relayInfo: checked.info.relayInfo, verifiedAt: new Date().toISOString() };
  await saveProfile();
  renderApplication();
  notify("Relay is reachable");
}

async function saveProfile() {
  if (!runtime.repository || !runtime.profile) throw new Error("Unlock the encrypted profile first.");
  await runtime.repository.save(runtime.profile);
}

function showStep(step) {
  runtime.currentStep = step;
  elements.startup.hidden = false;
  elements.app.hidden = true;
  document.querySelectorAll(".setupStep").forEach((section) => section.classList.toggle("active", section.dataset.step === step));
  const effectiveIndex = step === "unlock" ? 0 : Math.max(0, steps.indexOf(step));
  [...elements.setupProgress.children].forEach((item, index) => item.classList.toggle("active", index <= effectiveIndex));
  const titles = {
    welcome: "Private messaging starts here.", unlock: "Welcome back.", storage: "Protect this browser profile.",
    relay: "Choose where you connect.", identity: "Create your identity."
  };
  elements.setupTitle.textContent = titles[step];
  elements.setupError.textContent = "";
}

function showApplication() {
  elements.startup.hidden = true;
  elements.app.hidden = false;
  renderApplication();
  openView("chats");
}

function renderApplication() {
  const identity = runtime.profile.identity;
  const relay = runtime.profile.relay;
  const info = relay.relayInfo ?? {};
  elements.headerIdentity.textContent = identity.displayName;
  elements.identityName.textContent = identity.displayName;
  elements.identityInbox.textContent = identity.inboxId;
  elements.identityFingerprint.textContent = short(identity.signingFingerprint, 22);
  elements.identityRelay.textContent = relayDisplayName(info);
  elements.railRelay.textContent = relayDisplayName(info);
  elements.relayName.textContent = relayDisplayName(info);
  elements.savedRelayAddress.textContent = relay.address;
  elements.relaySoftware.textContent = info.softwareVersion ?? info.software ?? "Not reported";
  elements.relayFederation.textContent = info.federationName ?? info.federationMode ?? "Solo / not reported";
  elements.relayChecked.textContent = formatDate(relay.verifiedAt);
  renderCode();
}

function openView(view) {
  const titles = { chats: ["Messages", "Chats"], contacts: ["People", "Contacts"], code: ["Pairing", "My Code"], relays: ["Network", "Relays"], identity: ["Profile", "Identity"], settings: ["Application", "Settings"] };
  document.querySelectorAll("[data-view-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.viewPanel === view));
  elements.navigation.querySelectorAll("button").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  elements.viewEyebrow.textContent = titles[view][0];
  elements.viewTitle.textContent = titles[view][1];
}

function toggleCode() {
  runtime.codeVisible = !runtime.codeVisible;
  renderCode();
}

function renderCode() {
  elements.contactCode.textContent = runtime.codeVisible
    ? encodeNativeContactCode(runtime.profile.identity.contactOffer)
    : "Contact code hidden";
  $("#revealCode").textContent = runtime.codeVisible ? "Hide" : "Reveal";
}

async function copyCode() {
  await navigator.clipboard.writeText(encodeNativeContactCode(runtime.profile.identity.contactOffer));
  notify("Contact code copied");
}

function lockClient() {
  runtime.repository = null;
  runtime.profile = null;
  runtime.verifiedRelay = null;
  runtime.codeVisible = false;
  showStep("unlock");
}

async function resetInstallation() {
  if (!confirm("Reset this browser installation? Identity keys and local client data will be permanently deleted.")) return;
  if (runtime.repository) await runtime.repository.clear();
  localStorage.removeItem(saltStorageKey);
  localStorage.removeItem(encryptedStorageKey);
  runtime.repository = null;
  runtime.profile = null;
  runtime.verifiedRelay = null;
  elements.acceptNotice.checked = false;
  $("[data-step='welcome'] .next").disabled = true;
  showStep("welcome");
}

async function run(label, operation) {
  setBusy(true, label);
  elements.setupError.textContent = "";
  try {
    await operation();
  } catch (error) {
    const message = safeError(error);
    if (!elements.startup.hidden) elements.setupError.textContent = message;
    else notify(message, true);
  } finally {
    setBusy(false);
  }
}

function setBusy(active, label = "Working…") {
  elements.busy.hidden = !active;
  elements.busyLabel.textContent = label;
  document.querySelectorAll("button").forEach((button) => {
    if (button.id === "resetLockedProfile") return;
    if (active) {
      button.dataset.disabledBeforeBusy = button.disabled ? "1" : "0";
      button.disabled = true;
    } else {
      button.disabled = button.dataset.disabledBeforeBusy === "1";
      delete button.dataset.disabledBeforeBusy;
      if (button.matches("[data-step='welcome'] .next")) {
        button.disabled = !elements.acceptNotice.checked;
      }
    }
  });
}

function safeError(error) {
  if (!(error instanceof Error)) return "The operation failed.";
  const allowed = ["relay", "profile", "passphrase", "display name", "browser", "identity", "inbox", "http", "websocket", "post-quantum"];
  return allowed.some((word) => error.message.toLowerCase().includes(word)) ? error.message : "The operation failed safely. Review the supplied information and try again.";
}

function notify(message, error = false) {
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", error);
  elements.toast.hidden = false;
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => { elements.toast.hidden = true; }, 2600);
}

function relayDisplayName(info) { return info?.relayName || info?.name || "Noctweave Relay"; }
function formatDate(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? "Not checked" : date.toLocaleString(); }
function short(value, length) { return value?.length > length ? `${value.slice(0, Math.floor(length / 2))}…${value.slice(-Math.floor(length / 2))}` : value ?? ""; }
function fromBase64(value) { const binary = atob(value); return Uint8Array.from(binary, (character) => character.charCodeAt(0)); }
