import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Execute the production shell with dummy DOM/storage/network boundaries and
// a controlled clock. No relay, browser profile, or wall-clock timer is used.
async function clientHarness() {
  const source = await readFile(new URL("../client/app.js", import.meta.url), "utf8");
  const elements = new Map();
  const element = () => ({
    value: "", textContent: "", hidden: false, disabled: false, checked: false,
    dataset: {}, children: [], addEventListener() {}, setAttribute() {},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    querySelectorAll() { return []; }
  });
  const timers = new Map();
  let now = 2_000_000;
  class Clock extends Date {
    static now() { return now; }
  }
  const context = vm.createContext({
    console, Date: Clock,
    document: {
      hidden: false, visibilityState: "visible", documentElement: { dataset: {} },
      querySelector(selector) {
        if (!elements.has(selector)) elements.set(selector, element());
        return elements.get(selector);
      },
      querySelectorAll: () => [], createElement: element, addEventListener() {}
    },
    initializeAppearanceControl() {},
    browserMessagingAttachmentStatus: "Dummy attachment policy",
    browserMessagingAttachmentMaximumBytes: 16 * 1024 * 1024,
    setInterval(callback, milliseconds) {
      const id = timers.size + 1;
      timers.set(id, { callback, milliseconds });
      return id;
    },
    clearInterval(id) { timers.delete(id); }
  });
  vm.runInContext(source.replace(/^import\b[\s\S]*?;\n/gmu, "")
    .replace(/^boot\(\);$/mu, "") +
    "\nglobalThis.harness = { state, startMessagePump, stopMessagePump, lockProfile, resumeAllMessagingOutboxes, updateReceiptPreferences, updateSelectedConsent, sendSelectedAttachment };", context);
  const { state, startMessagePump, stopMessagePump, lockProfile,
    resumeAllMessagingOutboxes, updateReceiptPreferences,
    updateSelectedConsent, sendSelectedAttachment } = context.harness;
  const relationship = {
    relationshipID: "dummy-relationship",
    peerIdentity: { relationshipPseudonym: "Dummy peer" },
    localPolicy: { consent: "accepted" }
  };
  const snapshot = {
    availability: { canSend: true, canReceive: true, consent: "accepted", routeTeardownState: null },
    timeline: []
  };
  const calls = { retries: 0, maintenance: 0, syncs: 0 };
  const messaging = {
    async resumeRouteTeardowns() { return { failures: [] }; },
    async open() { return snapshot; },
    async safetyNumber() { return { display: "dummy safety number" }; },
    async resumeOutbound() { calls.retries++; return { snapshot }; },
    async maintainRelationship() {
      calls.maintenance++;
      return { prekey: "current", routeBlocker: null };
    },
    async syncReceiveRoutes() {
      calls.syncs++;
      return { snapshot, outcomes: [], receiptStatus: "current", routeControlStatus: "current" };
    }
  };
  Object.assign(state, {
    persona: { relationships: [relationship] }, repository: {}, messaging,
    vault: { lock() {} },
    selectedRelationshipID: relationship.relationshipID
  });
  async function settle() {
    // All boundaries above return promises; drain their finite async chain.
    for (let i = 0; i < 100; i++) await Promise.resolve();
    assert.equal(state.messageBusy, false);
  }
  return { state, calls, timers, messaging, relationship, elements,
    document: context.document,
    startMessagePump, stopMessagePump, lockProfile,
    resumeAllMessagingOutboxes, updateReceiptPreferences,
    updateSelectedConsent, sendSelectedAttachment, settle,
    lockSession() {
      state.repository = null;
      state.messaging = null;
      state.persona = null;
      state.messageSnapshot = null;
      state.messageBusy = false;
      elements.get("#appShell").hidden = true;
    },
    advance(milliseconds) { now += milliseconds; } };
}

test("the periodic message pump retries durable outboxes without waiting for another unlock", async () => {
  const app = await clientHarness();
  app.startMessagePump();
  await app.settle();
  assert.equal(app.calls.retries, 1);
  assert.equal(app.calls.maintenance, 1);
  const timer = [...app.timers.values()][0];
  assert.equal(timer.milliseconds, 5_000);
  app.advance(5_000);
  await timer.callback();
  await app.settle();
  assert.equal(app.calls.retries, 2, "retry-eligible outboxes must be revisited every poll");
  assert.equal(app.calls.syncs, 2);
  assert.equal(app.calls.maintenance, 1, "route maintenance keeps its five-minute cadence");
  app.advance(5 * 60_000);
  await timer.callback();
  await app.settle();
  assert.equal(app.calls.retries, 3);
  assert.equal(app.calls.maintenance, 2);
  app.stopMessagePump();
  assert.equal(app.timers.size, 0);
});

test("the periodic message pump leaves busy or locked sessions alone", async () => {
  const app = await clientHarness();
  app.startMessagePump();
  await app.settle();
  const timer = [...app.timers.values()][0];
  app.state.messageBusy = true;
  await timer.callback();
  assert.equal(app.calls.retries, 1);
  app.state.messageBusy = false;
  app.state.persona = null;
  app.state.messaging = null;
  await timer.callback();
  assert.equal(app.calls.retries, 1);
  assert.equal(app.calls.syncs, 1);
});

test("an unlocked background tab continues encrypted outbox and route maintenance", async () => {
  const app = await clientHarness();
  app.document.hidden = true;
  app.startMessagePump();
  await app.settle();
  assert.equal(app.calls.retries, 1);
  assert.equal(app.calls.maintenance, 1);
  assert.equal(app.calls.syncs, 1);
});

test("an old outbox resume cannot install its snapshot in a reopened conversation", async () => {
  const app = await clientHarness();
  let resolveTeardowns;
  app.messaging.resumeRouteTeardowns = () => new Promise((resolve) => {
    resolveTeardowns = resolve;
  });
  const pending = app.resumeAllMessagingOutboxes();
  app.lockSession();
  const nextRelationship = { ...app.relationship, relationshipID: "next-conversation" };
  app.state.persona = { relationships: [nextRelationship] };
  app.state.repository = {};
  app.state.messaging = {};
  app.state.selectedRelationshipID = nextRelationship.relationshipID;
  app.state.messageBusy = true;
  app.elements.get("#appShell").hidden = false;
  resolveTeardowns({ failures: [] });
  await pending;
  assert.equal(app.state.messageSnapshot, null);
  assert.equal(app.state.messageBusy, true);
  assert.equal(app.calls.retries, 0);
});

test("an old receipt update cannot snapshot the newly selected conversation", async () => {
  const app = await clientHarness();
  let resolvePolicy;
  app.messaging.updateRelationshipLocalPolicy = () => new Promise((resolve) => {
    resolvePolicy = resolve;
  });
  const pending = app.updateReceiptPreferences();
  app.lockSession();
  const nextRelationship = { ...app.relationship, relationshipID: "next-conversation" };
  let newSnapshotCalls = 0;
  app.state.persona = { relationships: [nextRelationship] };
  app.state.repository = {};
  app.state.messaging = { snapshot() { newSnapshotCalls++; } };
  app.state.selectedRelationshipID = nextRelationship.relationshipID;
  app.state.messageBusy = true;
  app.elements.get("#appShell").hidden = false;
  resolvePolicy();
  await pending;
  assert.equal(newSnapshotCalls, 0);
  assert.equal(app.state.messageSnapshot, null);
  assert.equal(app.state.messageBusy, true);
});

test("a delayed file read cannot send an old attachment through a reopened session", async () => {
  const app = await clientHarness();
  let resolveFileRead;
  app.elements.get("#attachmentFile").files = [{
    size: 3, type: "application/octet-stream",
    arrayBuffer: () => new Promise((resolve) => { resolveFileRead = resolve; })
  }];
  const pending = app.sendSelectedAttachment();
  app.lockSession();
  const nextRelationship = { ...app.relationship, relationshipID: "next-conversation" };
  let newSendCalls = 0;
  app.state.persona = { relationships: [nextRelationship] };
  app.state.repository = {};
  app.state.messaging = { sendAttachment() { newSendCalls++; } };
  app.state.selectedRelationshipID = nextRelationship.relationshipID;
  app.state.messageBusy = true;
  app.elements.get("#appShell").hidden = false;
  resolveFileRead(new Uint8Array([65, 66, 67]).buffer);
  await pending;
  assert.equal(newSendCalls, 0);
  assert.equal(app.state.messageBusy, true);
});

test("an old block action cannot tear down newly selected relationship routes", async () => {
  const app = await clientHarness();
  let resolvePolicy;
  app.messaging.updateRelationshipLocalPolicy = () => new Promise((resolve) => {
    resolvePolicy = resolve;
  });
  app.elements.get("#relationshipConsent").value = "blocked";
  const pending = app.updateSelectedConsent();
  app.lockSession();
  const nextRelationship = { ...app.relationship, relationshipID: "next-conversation" };
  let newTeardownCalls = 0;
  app.state.persona = { relationships: [nextRelationship] };
  app.state.repository = {};
  app.state.messaging = { teardownRelationshipRoutes() { newTeardownCalls++; } };
  app.state.selectedRelationshipID = nextRelationship.relationshipID;
  app.state.messageBusy = true;
  app.elements.get("#appShell").hidden = false;
  resolvePolicy();
  await pending;
  assert.equal(newTeardownCalls, 0);
  assert.equal(app.state.messageBusy, true);
});
