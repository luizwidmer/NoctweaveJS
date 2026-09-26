import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createProtocolCapabilityManifest } from "../src/index.js";
import { SecurityKeyFixture } from "./helpers/security-key-fixture.js";

// This is an executable DOM-level production-shell test. It deliberately uses
// a small IndexedDB/DOM harness instead of source-text assertions: the test
// imports client/index.js, drives the same buttons as a browser, and proves
// that a first-run persona reaches the client shell. A real browser runner can
// replace this harness without changing the production entry point.
if (!process.env.NOCTWEAVE_PRODUCTION_DOM_SMOKE_CHILD) {
  test("production browser client acknowledges IndexedDB limits and creates a persona", async () => {
    const result = await runChildSmoke();
    assert.equal(result.code, 0, result.stderr || result.stdout);
  });
  test("key attachment replaces the waiting passphrase; removal and cancellation restore it", async () => {
    const result = await runChildSmoke("key-stages");
    assert.equal(result.code, 0, result.stderr || result.stdout);
  });
  test("production client blocks and preserves legacy plaintext IndexedDB state", async () => {
    const result = await runChildSmoke("legacy-anchor");
    assert.equal(result.code, 0, result.stderr || result.stdout);
  });
}

async function runProductionBrowserSmoke() {
  const html = await readFile(new URL("../client/index.html", import.meta.url), "utf8");
  const dom = new TestDocument([...html.matchAll(/id="([^"]+)"/gu)].map((match) => match[1]));
  const previous = installBrowserHarness(dom);
  const mode = process.env.NOCTWEAVE_PRODUCTION_DOM_SMOKE_CHILD;
  const keyStages = mode === "key-stages";
  if (mode === "legacy-anchor") {
    const database = new TestDatabase();
    database.createObjectStore("anchors");
    database.createObjectStore("encryptedStates");
    database.stores.get("anchors").set("legacy", {
      id: "legacy", value: { relationshipID: "PRIVATE_LEGACY_CANARY" }
    });
    globalThis.indexedDB.databases.set("NoctweaveJS-Browser-v2", database);
  }
  const key = new SecurityKeyFixture();
  let attached = [];
  if (keyStages) {
    globalThis.__noctweaveDesktopSecurityKeys = {
      available: true, rpID: key.rpID, origin: key.origin,
      attachments: async () => ({ known: true, devices: attached }),
      stopAttachments: async () => {}, cancel: async () => {}, releasePresence: async () => {},
      request: async ({ operation, options }) => ({ credential: await key[operation](options) })
    };
  }
  try {
    await import(`../client/index.js?dom-smoke=${Date.now()}`);
    if (mode === "legacy-anchor") {
      await waitFor(() => /Legacy plaintext IndexedDB/u.test(dom.get("securityProfileInfo").textContent));
      assert.equal(dom.get("unlockVault").disabled, true);
      assert.equal(globalThis.indexedDB.databases.get("NoctweaveJS-Browser-v2")
        .stores.get("anchors").get("legacy").value.relationshipID, "PRIVATE_LEGACY_CANARY");
      return;
    }
    await waitFor(() => /browser|desktop/i.test(dom.get("securityProfileInfo").textContent));
    assert.match(dom.get("securityProfileInfo").textContent, /browser|desktop/i);
    assert.match(dom.get("onboardingRelayInfo").textContent, /verified before/i);
    assert.match(dom.get("securityProfileWarning").textContent, /rollbackable|hardened/i);
    dom.get("securityAcknowledgment").checked = true;
    dom.get("onboardingRelay").value = "http://127.0.0.1:9340";
    dom.get("displayName").value = "Browser smoke persona";
    dom.get("vaultPassphrase").value = "correct horse battery staple";
    dom.get("vaultConfirmation").value = "correct horse battery staple";
    await dom.get("unlockVault").click();
    await settle();
    assert.match(dom.get("onboardingRelayInfo").textContent, /verified/i, dom.get("vaultError").textContent);
    assert.equal(dom.get("appShell").hidden, false);
    assert.equal(dom.get("personaName").textContent, "Browser smoke persona", dom.get("vaultError").textContent);
    assert.match(dom.get("relayInfo").textContent, /transport verified/i);
    assert.equal(dom.get("vaultGate").hidden, true);
    if (keyStages) {
      dom.get("keyVaultPassphrase").value = "correct horse battery staple";
      dom.get("securityKeyName").value = "Test key";
      await dom.get("registerSecurityKey").click();
      await waitFor(() => dom.get("keySetupStatus").textContent.startsWith("Key registered"));
      await waitFor(() => !dom.get("saveUnlockVisibility").disabled);
      dom.get("hideSecurityKeyUnlock").checked = true;
      dom.get("visibilityPassphrase").value = "correct horse battery staple";
      await dom.get("saveUnlockVisibility").click();
      await waitFor(() => dom.get("unlockPrivacyStatus").textContent === "Lock-screen privacy saved.");
      await dom.get("lockProfile").click();
      await waitFor(() => !dom.get("vaultGate").hidden && dom.get("securityKeyUnlock").hidden);
      assert.equal(dom.get("passphraseUnlock").hidden, false);
      dom.get("vaultPassphrase").value = "partially entered waiting password";
      key.beforeGet = async () => { throw new Error("Test key needs another attempt"); };
      attached = ["test-key"];
      await waitFor(() => !dom.get("securityKeyUnlock").hidden);
      await waitFor(() => dom.get("keyUnlockStatus").textContent === "Unable to unlock. Try again.");
      assert.equal(dom.get("passphraseUnlock").hidden, true);
      assert.equal(dom.get("passphraseUnlock").inert, true);
      assert.equal(dom.get("vaultPassphrase").value, "");
      assert.ok(dom.get("vaultPassphrase").blurred);
      assert.equal(dom.get("appShell").hidden, true);
      attached = [];
      await waitFor(() => !dom.get("passphraseUnlock").hidden);
      assert.equal(dom.get("passphraseUnlock").inert, false);
      assert.equal(dom.get("securityKeyUnlock").hidden, true);
      attached = ["test-key"];
      await waitFor(() => !dom.get("securityKeyUnlock").hidden);
      await dom.get("cancelKeyUnlock").click();
      assert.equal(dom.get("passphraseUnlock").hidden, false);
      assert.equal(dom.get("passphraseUnlock").inert, false);
      assert.equal(dom.get("securityKeyUnlock").hidden, true);
      assert.equal(dom.get("appShell").hidden, true);
      await waitFor(() => !dom.get("unlockWithKey").disabled);
    }
  } finally {
    dom.hidden = true;
    dom.visibilityState = "hidden";
    dom.dispatch("visibilitychange");
    await settle();
    restoreBrowserHarness(previous);
  }
}

function runChildSmoke(scenario = "1") {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url)], {
      env: { ...process.env, NOCTWEAVE_PRODUCTION_DOM_SMOKE_CHILD: scenario },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

class TestElement {
  constructor(id = null) {
    this.id = id;
    this.hidden = false;
    this.inert = false;
    this.disabled = false;
    this.checked = false;
    this.value = "";
    this.textContent = "";
    this.dataset = {};
    this.children = [];
    this.listeners = new Map();
    this.attributes = new Map();
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  blur() { this.blurred = true; }

  async click() {
    if (this.disabled) throw new Error(`Test element ${this.id} is disabled.`);
    return this.listeners.get("click")?.({ target: this });
  }

  replaceChildren(...children) {
    this.children = children;
  }

  append(...children) {
    this.children.push(...children);
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  querySelectorAll(selector) {
    if (selector === ".relationshipChoice") return this.children.filter((child) => child.className === selector.slice(1));
    return [];
  }
}

class TestDocument {
  constructor(ids) {
    this.elements = new Map(ids.map((id) => [id, new TestElement(id)]));
    this.documentElement = new TestElement("documentElement");
    this.visibilityState = "visible";
    this.listeners = new Map();
  }

  get(id) {
    const element = this.elements.get(id);
    if (!element) throw new Error(`Missing production DOM element: ${id}`);
    return element;
  }

  querySelector(selector) {
    if (!selector.startsWith("#")) throw new Error(`Unsupported test selector: ${selector}`);
    return this.get(selector.slice(1));
  }

  querySelectorAll(selector) {
    if (selector === "[data-appearance-select]") {
      return [
        this.get("appAppearancePreference")
      ];
    }
    return [];
  }

  createElement() {
    return new TestElement();
  }

  addEventListener(type, listener) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  dispatch(type) { for (const listener of this.listeners.get(type) ?? []) listener(); }
}

function installBrowserHarness(document) {
  const saved = {
    document: globalThis.document,
    fetch: globalThis.fetch,
    indexedDB: globalThis.indexedDB,
    confirm: globalThis.confirm,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    navigator: globalThis.navigator,
    __noctweaveDesktopSecurityKeys: globalThis.__noctweaveDesktopSecurityKeys
  };
  globalThis.document = document;
  globalThis.indexedDB = new TestIndexedDB();
  globalThis.confirm = () => true;
  globalThis.setInterval = () => 1;
  globalThis.clearInterval = () => {};
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { clipboard: { writeText: async () => {} } }
  });
  globalThis.fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    const body = request.method === "info"
      ? { relayInfo: relayInfo() }
      : {};
    return new Response(JSON.stringify({
      requestID: request.requestID,
      module: request.module,
      version: request.version,
      method: request.method,
      status: "success",
      body,
      error: null
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  return saved;
}

function restoreBrowserHarness(saved) {
  for (const [key, value] of Object.entries(saved)) {
    if (key === "navigator") Object.defineProperty(globalThis, key, { configurable: true, value });
    else globalThis[key] = value;
  }
}

function relayInfo() {
  const capabilities = createProtocolCapabilityManifest();
  return {
    kind: "standard",
    federation: { mode: "solo", name: null, description: null },
    temporalBucketSeconds: 300,
    temporalBucketScheduleSeconds: null,
    attachmentDefaultTTLSeconds: null,
    attachmentMaxTTLSeconds: null,
    attachmentsEnabled: null,
    attachmentStorageBackend: null,
    hiddenRetrieval: null,
    onionTransport: null,
    mixnetTransport: null,
    wakeSupport: null,
    iceService: null,
    relayName: null,
    operatorNote: null,
    softwareVersion: null,
    protocolCapabilities: {
      architectureVersion: capabilities.architectureVersion,
      modules: [
        ...capabilities.modules,
        { module: "nw.opaque-route", versions: [2], status: "stable", limits: {} },
        { module: "nw.rendezvous-transport", versions: [2], status: "provisional", limits: {} }
      ]
    },
    requiresPassword: null,
    tlsEnabled: null,
    transport: null,
    federationCoordinatorEndpoints: null,
    coordinatorReportedRelayCount: null,
    coordinatorRegistrationAuthRequired: null,
    curatedStrictPolicyEnabled: null,
    curatedCoordinatorQuorum: null,
    curatedRequireSignedDirectory: null,
    federationDirectoryPublicKey: null,
    knownOpenPeers: null,
    openFederationDiscovery: null,
    relayIdentity: null,
    advertisedAt: "2026-07-18T12:00:00Z"
  };
}

class TestIndexedDB {
  constructor() { this.databases = new Map(); }
  open(name) {
    const request = new TestRequest();
    queueMicrotask(() => {
      let database = this.databases.get(name);
      const fresh = !database;
      database ??= new TestDatabase();
      this.databases.set(name, database);
      request.result = database;
      if (fresh) request.onupgradeneeded?.();
      request.onsuccess?.();
    });
    return request;
  }
}

class TestDatabase {
  constructor() { this.stores = new Map(); this.objectStoreNames = { contains: (name) => this.stores.has(name) }; }
  createObjectStore(name) { const store = new Map(); this.stores.set(name, store); return new TestObjectStore(store); }
  transaction(names) { return new TestTransaction(this, Array.isArray(names) ? names : [names]); }
}

class TestTransaction {
  constructor(database, names) {
    this.database = database;
    this.names = names;
    this.oncomplete = null;
    this.onerror = null;
    this.error = null;
    setTimeout(() => this.oncomplete?.(), 10);
  }
  objectStore(name) {
    const store = this.database.stores.get(name);
    if (!store) throw new Error(`Missing fake IndexedDB object store ${name}.`);
    return new TestObjectStore(store, this);
  }
}

class TestObjectStore {
  constructor(store, transaction) { this.store = store; this.transaction = transaction; }
  get(key) { return this.request(this.store.get(key)); }
  count() { return this.request(this.store.size); }
  add(value) { if (this.store.has(value.id)) throw new Error("ConstraintError"); this.store.set(value.id, value); return this.request(value); }
  put(value) { this.store.set(value.id, value); return this.request(value); }
  delete(key) { this.store.delete(key); return this.request(undefined); }
  request(result) {
    const request = new TestRequest();
    queueMicrotask(() => { request.result = structuredClone(result); request.onsuccess?.(); });
    return request;
  }
}

class TestRequest {
  constructor() { this.result = undefined; this.onsuccess = null; this.onerror = null; this.onupgradeneeded = null; }
}

async function settle() {
  await new Promise((resolve) => setTimeout(resolve, 100));
}

async function waitFor(predicate) {
  const deadline = Date.now() + 10_000;
  while (!predicate() && Date.now() < deadline) await settle();
  assert.ok(predicate(), "Expected production UI transition did not occur.");
}

if (process.env.NOCTWEAVE_PRODUCTION_DOM_SMOKE_CHILD) {
  await runProductionBrowserSmoke();
}
