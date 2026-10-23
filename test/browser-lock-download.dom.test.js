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

function attachmentDownloadFixture() {
  const element = () => ({
    value: "", textContent: "", hidden: false, inert: false,
    replaceChildren() {}
  });
  const elements = new Proxy({}, {
    get(target, key) { return target[key] ??= element(); }
  });
  let resolveDownload;
  const delayedDownload = new Promise((resolve) => { resolveDownload = resolve; });
  const exported = [];
  const state = {
    persona: { relationships: [] },
    repository: {},
    selectedRelationshipID: "fixture",
    vault: { lock() {} },
    pairingBusy: new Set(),
    messaging: { downloadAttachment: () => delayedDownload },
    messageBusy: false
  };
  const context = {
    state, elements, document: { hidden: false },
    $: () => element(),
    cancelSecurityKeyAction() {},
    closeRelayPairing() {},
    stopPairingPump() {},
    stopMessagePump() {},
    renderGate() {},
    renderSelectedMessages() {},
    requireSelectedRelationship: () => ({ relationshipID: "fixture" }),
    attachmentDownloadName: () => "fixture.bin",
    Blob, URL, setTimeout
  };
  context.globalThis = context;
  context.__noctweaveDesktopExportAttachment = async ({ bytes }) => {
    exported.push([...bytes]);
    return { saved: true, fileName: "fixture.bin", byteCount: bytes.length };
  };
  const functions = vm.runInNewContext(
    `${productionFunction("function lockProfile()", "function cancelSecurityKeyAction()")}
${productionFunction("function messageOperationSession(", "async function backgroundMessageResume(")}
${productionFunction("async function downloadReceivedAttachment(eventID)", "function requireSelectedRelationship()")}
({ lockProfile, downloadReceivedAttachment })`,
    context
  );
  return { ...functions, state, elements, document: context.document,
    exported, resolveDownload };
}

test("a delayed attachment cannot export plaintext after profile lock", async () => {
  const fixture = attachmentDownloadFixture();
  const bytes = new Uint8Array([65, 66, 67]);
  const pending = fixture.downloadReceivedAttachment("fixture-event");
  fixture.lockProfile();
  fixture.resolveDownload({
    snapshot: { timeline: [] },
    downloaded: { bytes, descriptor: { mimeType: "application/octet-stream", sha256: "fixture" } }
  });
  await pending;
  assert.equal(fixture.elements.app.hidden, true);
  assert.equal(fixture.elements.gate.hidden, false);
  assert.deepEqual(fixture.exported, []);
  assert.deepEqual([...bytes], [0, 0, 0]);
});

test("an unlocked attachment still exports and clears its plaintext buffer", async () => {
  const fixture = attachmentDownloadFixture();
  const bytes = new Uint8Array([65, 66, 67]);
  const pending = fixture.downloadReceivedAttachment("fixture-event");
  fixture.resolveDownload({
    snapshot: { timeline: [] },
    downloaded: { bytes, descriptor: { mimeType: "application/octet-stream", sha256: "fixture" } }
  });
  await pending;
  assert.deepEqual(fixture.exported, [[65, 66, 67]]);
  assert.deepEqual([...bytes], [0, 0, 0]);
});

test("an old download cannot clear a newly unlocked session's busy state", async () => {
  const fixture = attachmentDownloadFixture();
  const bytes = new Uint8Array([65, 66, 67]);
  const pending = fixture.downloadReceivedAttachment("fixture-event");
  fixture.lockProfile();
  fixture.state.messaging = { downloadAttachment() {} };
  fixture.state.persona = { relationships: [] };
  fixture.state.messageBusy = true;
  fixture.resolveDownload({
    snapshot: { timeline: [] },
    downloaded: { bytes, descriptor: { mimeType: "application/octet-stream", sha256: "fixture" } }
  });
  await pending;
  assert.equal(fixture.state.messageBusy, true);
  assert.deepEqual(fixture.exported, []);
  assert.deepEqual([...bytes], [0, 0, 0]);
});

test("a hidden but still unlocked tab cannot hand plaintext to an exporter", async () => {
  const fixture = attachmentDownloadFixture();
  const bytes = new Uint8Array([65, 66, 67]);
  const pending = fixture.downloadReceivedAttachment("fixture-event");
  fixture.document.hidden = true;
  fixture.resolveDownload({
    snapshot: { timeline: [] },
    downloaded: { bytes, descriptor: { mimeType: "application/octet-stream", sha256: "fixture" } }
  });
  await pending;
  assert.deepEqual(fixture.exported, []);
  assert.deepEqual([...bytes], [0, 0, 0]);
});
