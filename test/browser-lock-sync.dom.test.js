import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";

const source = readFileSync(new URL("../client/app.js", import.meta.url), "utf8");

function productionFunction(start, next) {
  const from = source.indexOf(start);
  const to = source.indexOf(next, from);
  assert.ok(from >= 0 && to > from, `Missing production function ${start}`);
  return source.slice(from, to);
}

test("a delayed old-session sync cannot display its conversation in a new session", async () => {
  const relationshipA = { relationshipID: "A" };
  const relationshipB = { relationshipID: "B" };
  let resolveSync;
  let signalSyncStarted;
  const delayedSync = new Promise((resolve) => { resolveSync = resolve; });
  const syncStarted = new Promise((resolve) => { signalSyncStarted = resolve; });
  const oldMessaging = {
    open: async () => ({
      availability: { consent: "accepted", canReceive: true, message: "Ready" },
      timeline: []
    }),
    safetyNumber: async () => ({ display: "A safety number" }),
    syncReceiveRoutes: async () => {
      signalSyncStarted();
      return delayedSync;
    }
  };
  const state = {
    persona: { relationships: [relationshipA, relationshipB] },
    repository: {}, vault: { lock() {} },
    messaging: oldMessaging,
    selectedRelationshipID: "A",
    messageBusy: false,
    pairingBusy: new Set()
  };
  const element = () => ({ value: "", textContent: "", hidden: false, inert: false, replaceChildren() {} });
  const elements = new Proxy({}, {
    get(target, key) { return target[key] ??= element(); }
  });
  const context = {
    state, elements, document: { hidden: false }, $: () => element(),
    cancelSecurityKeyAction() {}, closeRelayPairing() {},
    stopPairingPump() {}, stopMessagePump() {}, renderGate() {},
    renderSelectedMessages() {},
    requireUnlocked() {
      if (!state.persona || !state.repository) throw new Error("Locked");
    },
    selectedRelationship() {
      return state.persona?.relationships.find(({ relationshipID }) =>
        relationshipID === state.selectedRelationshipID) ?? null;
    },
    requireSelectedRelationship() {
      return state.persona?.relationships.find(({ relationshipID }) =>
        relationshipID === state.selectedRelationshipID) ?? null;
    },
    persistRuntimeRelationship() {}
  };
  context.globalThis = context;
  const { lockProfile, refreshSelectedMessages } = vm.runInNewContext(
    `${productionFunction("function lockProfile()", "function cancelSecurityKeyAction()")}
${productionFunction("async function refreshSelectedMessages(", "async function sendMessage()")}
({ lockProfile, refreshSelectedMessages })`,
    context
  );

  const pending = refreshSelectedMessages({ synchronize: true });
  await syncStarted;
  lockProfile();
  state.persona = { relationships: [relationshipA, relationshipB] };
  state.repository = {};
  state.messaging = {};
  state.selectedRelationshipID = "B";
  state.messageBusy = true;
  elements.app.hidden = false;
  elements.app.inert = false;
  elements.gate.hidden = true;
  resolveSync({
    snapshot: {
      availability: { consent: "accepted", canReceive: true, message: "Ready" },
      timeline: [{ text: "A private message" }]
    },
    outcomes: [], routeControlStatus: "ok", receiptStatus: "ok"
  });
  await pending;

  assert.equal(state.selectedRelationshipID, "B");
  assert.equal(state.messageSnapshot, null);
  assert.equal(state.messageBusy, true);
});

test("a relationship save cannot install the old persona after lock and reopen", async () => {
  let resolveSave;
  let signalSaveStarted;
  const delayedSave = new Promise((resolve) => { resolveSave = resolve; });
  const saveStarted = new Promise((resolve) => { signalSaveStarted = resolve; });
  const oldMessaging = {};
  const oldRepository = {
    save: async () => {
      signalSaveStarted();
      await delayedSave;
    }
  };
  const newPersona = { relationships: [{ relationshipID: "B" }] };
  const state = {
    messaging: oldMessaging,
    repository: oldRepository,
    persona: { relationships: [{ relationshipID: "A", label: "old" }] }
  };
  const persist = vm.runInNewContext(
    `${productionFunction("async function persistRuntimeRelationship(", "async function burnLocalPersona()")}
persistRuntimeRelationship`,
    { state, structuredClone, validateBrowserPersonaState: (value) => value }
  );
  const pending = persist(
    { relationship: { relationshipID: "A", label: "updated old" } },
    oldMessaging,
    oldRepository
  );
  await saveStarted;
  state.messaging = {};
  state.repository = {};
  state.persona = newPersona;
  resolveSave();
  await assert.rejects(pending, /messaging session changed/i);
  assert.equal(state.persona, newPersona);
});

test("a relationship save still updates its current session", async () => {
  const messaging = {};
  const repository = { save: async () => {} };
  const state = {
    messaging, repository,
    persona: { relationships: [{ relationshipID: "A", label: "old" }] }
  };
  const persist = vm.runInNewContext(
    `${productionFunction("async function persistRuntimeRelationship(", "async function burnLocalPersona()")}
persistRuntimeRelationship`,
    { state, structuredClone, validateBrowserPersonaState: (value) => value }
  );
  await persist(
    { relationship: { relationshipID: "A", label: "updated" } },
    messaging,
    repository
  );
  assert.equal(state.persona.relationships[0].label, "updated");
});
