import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createProtocolCapabilityManifest } from "../src/index.js";

// This is an executable DOM-level production-shell test. It deliberately uses
// a small IndexedDB/DOM harness instead of source-text assertions: the test
// imports client/index.js, drives the same buttons as a browser, and proves
// that a first-run persona reaches the client shell. A real browser runner can
// replace this harness without changing the production entry point.
if (process.env.NOCTWEAVE_PRODUCTION_DOM_SMOKE_CHILD !== "1") {
  test("production browser client acknowledges IndexedDB limits and creates a persona", async () => {
    const result = await runChildSmoke();
    assert.equal(result.code, 0, result.stderr || result.stdout);
  });
}

async function runProductionBrowserSmoke() {
  const html = await readFile(new URL("../client/index.html", import.meta.url), "utf8");
  const dom = new TestDocument([...html.matchAll(/id="([^"]+)"/gu)].map((match) => match[1]));
  const previous = installBrowserHarness(dom);
  try {
    await import(`../client/index.js?dom-smoke=${Date.now()}`);
    await settle();
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
  } finally {
    restoreBrowserHarness(previous);
  }
}

function runChildSmoke() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url)], {
      env: { ...process.env, NOCTWEAVE_PRODUCTION_DOM_SMOKE_CHILD: "1" },
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
        this.get("onboardingAppearancePreference"),
        this.get("appAppearancePreference")
      ];
    }
    return [];
  }

  createElement() {
    return new TestElement();
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }
}

function installBrowserHarness(document) {
  const saved = {
    document: globalThis.document,
    fetch: globalThis.fetch,
    indexedDB: globalThis.indexedDB,
    confirm: globalThis.confirm,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    navigator: globalThis.navigator
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

if (process.env.NOCTWEAVE_PRODUCTION_DOM_SMOKE_CHILD === "1") {
  await runProductionBrowserSmoke();
}
