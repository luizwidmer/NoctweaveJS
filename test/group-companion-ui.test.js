import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("Groups connects with an in-memory token and recovers from a rejected token", async () => {
  const html = await readFile(new URL("../client/groups.html", import.meta.url), "utf8");
  const elements = new Map([...html.matchAll(/id="([^"]+)"/gu)]
    .map((match) => [match[1], new TestElement(match[1])]));
  const get = (id) => {
    const element = elements.get(id);
    if (!element) throw new Error(`Missing Groups element: ${id}`);
    return element;
  };
  get("setupPanel").hidden = true;
  const buttons = [...html.matchAll(/<button[^>]*id="([^"]+)"/gu)].map((match) => get(match[1]));
  const requests = [];
  const documentListeners = new Map();
  let revoked = false;
  const previous = {
    document: globalThis.document,
    fetch: globalThis.fetch,
    setInterval: globalThis.setInterval
  };
  const priorLocalStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  globalThis.document = {
    documentElement: { dataset: {} },
    querySelector: (selector) => get(selector.slice(1)),
    querySelectorAll: (selector) => selector === "button" ? buttons : [],
    visibilityState: "visible",
    hidden: false,
    addEventListener: (name, listener) => documentListeners.set(name, listener)
  };
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: () => null, setItem: () => {
      throw new Error("The access token must not enter localStorage.");
    } }
  });
  globalThis.setInterval = () => 1;
  globalThis.fetch = async (url, init) => {
    requests.push({ url, authorization: init.headers.authorization });
    if (revoked || init.headers.authorization !== `Bearer ${"a".repeat(64)}`) {
      return new Response(JSON.stringify({ error: "Rejected" }), { status: 401 });
    }
    return new Response(JSON.stringify({
      available: true, encryptedState: true, initialized: false, groups: []
    }), { status: 200 });
  };
  try {
    await import("../client/groups.js?companion-auth-test");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(requests.length, 0, "Opening Groups must not request private state before authorization.");
    assert.equal(get("setupPanel").hidden, true);
    assert.equal(get("companionAccessPanel").hidden, false);

    get("companionAccessToken").value = "b".repeat(64);
    await get("unlockCompanion").click();
    assert.equal(requests.length, 1);
    assert.equal(get("companionAccessToken").value, "");
    assert.equal(get("companionAccessPanel").hidden, false);
    assert.match(get("companionStatus").textContent, /Access token rejected/u);

    get("companionAccessToken").value = "a".repeat(64);
    await get("unlockCompanion").click();
    assert.equal(requests.length, 2);
    assert.equal(get("companionAccessToken").value, "");
    assert.equal(get("companionAccessPanel").hidden, true);
    assert.equal(get("setupPanel").hidden, false);
    assert.equal(get("companionStatus").textContent, "Setup required");
    assert.deepEqual(requests.map(({ url }) => url), [
      "/api/group-companion/status", "/api/group-companion/status"
    ]);

    get("admissionResponse").value = "PENDING_ONE_USE_WELCOME";
    globalThis.document.hidden = true;
    documentListeners.get("visibilitychange")();
    assert.equal(get("admissionResponse").value, "PENDING_ONE_USE_WELCOME");
    assert.equal(get("companionAccessPanel").hidden, true);
    globalThis.document.hidden = false;
    get("clearAdmissionResponse").click();
    assert.equal(get("admissionResponse").value, "");

    get("groupMessage").value = "UNSENT_GROUP_MESSAGE_CANARY";
    get("admissionRequest").value = "UNSENT_ADMISSION_CANARY";
    globalThis.document.hidden = true;
    documentListeners.get("visibilitychange")();
    assert.equal(get("groupMessage").value, "");
    assert.equal(get("admissionRequest").value, "");
    assert.equal(get("companionAccessPanel").hidden, false);
    globalThis.document.hidden = false;

    get("companionAccessToken").value = "a".repeat(64);
    await get("unlockCompanion").click();

    revoked = true;
    await get("setupCompanion").click();
    assert.equal(get("companionAccessPanel").hidden, false);
    assert.equal(get("setupPanel").hidden, true);
    assert.equal(get("groupConversationPanel").hidden, true);
    assert.equal(get("companionAccessToken").value, "");
  } finally {
    for (const [key, value] of Object.entries(previous)) globalThis[key] = value;
    if (priorLocalStorage) Object.defineProperty(globalThis, "localStorage", priorLocalStorage);
    else delete globalThis.localStorage;
  }
});

class TestElement {
  constructor(id) {
    this.id = id;
    this.value = "";
    this.textContent = "";
    this.hidden = false;
    this.disabled = false;
    this.listeners = new Map();
  }

  addEventListener(type, listener) { this.listeners.set(type, listener); }
  click() { return this.listeners.get("click")?.(); }
  replaceChildren() {}
}
