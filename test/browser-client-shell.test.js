import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("production browser client binds only present one-use pairing controls", async () => {
  const [html, script] = await Promise.all([
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../client/app.js", import.meta.url), "utf8")
  ]);
  const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map((match) => match[1]));
  const referenced = [...script.matchAll(/\$\("#([A-Za-z0-9_-]+)"\)/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(referenced.filter((id) => !ids.has(id)))], []);
  for (const id of [
    "pairingInvitation",
    "peerInvitation",
    "relationshipPseudonym",
    "relationshipList",
    "pendingPairingList",
    "pairingStatus",
    "acceptInvitation",
    "resumePairings",
    "verifyRelay",
    "selectedRelationshipName",
    "selectedRelationshipState",
    "messageList",
    "messageText",
    "sendMessage",
    "resumeOutbox",
    "syncMessages",
    "relationshipConsent",
    "muteRelationship",
    "deliveryReceiptsEnabled",
    "readReceiptsEnabled",
    "safetyNumber",
    "retryRouteTeardown",
    "attachmentFile"
  ]) {
    assert.equal(ids.has(id), true, id);
  }
  assert.match(html, /One-use pairing/);
  assert.match(html, /no protocol key or routable identifier/i);
  assert.match(html, /Durable pairwise messaging/);
});

test("browser shell drives both persisted rendezvous roles through relay transport", async () => {
  const script = await readFile(new URL("../client/app.js", import.meta.url), "utf8");
  for (const operation of [
    "prepareOffererPairing",
    "prepareResponderPairing",
    "resumePairing",
    "appendRendezvousTransportV2",
    "acknowledgePairingOutbound",
    "syncRendezvousTransportV2",
    "processPairingFrame",
    "finalizePairing",
    "cancelPairing",
    "deleteRendezvousTransportV2"
  ]) {
    assert.match(script, new RegExp(`\\b${operation}\\b`), operation);
  }
  assert.match(script, /startPairingPump\(\)/);
  assert.match(script, /setInterval\(backgroundResume/);
  assert.match(script, /elements\.peerInvitation\.value = ""/);
});

test("pairing relay effects are persisted in crash-safe order and terminal lanes are cleaned", async () => {
  const script = await readFile(new URL("../client/app.js", import.meta.url), "utf8");
  const pumpStart = script.indexOf("async function pumpPairing");
  const pumpEnd = script.indexOf("async function finalizePairing", pumpStart);
  const pump = script.slice(pumpStart, pumpEnd);
  assert.ok(pumpStart >= 0 && pumpEnd > pumpStart);
  assert.ok(pump.indexOf("appendRendezvousTransportV2") < pump.indexOf("acknowledgePairingOutbound"));
  assert.ok(pump.indexOf("acknowledgePairingOutbound") < pump.indexOf("persistPersona(acknowledged.persona)"));
  assert.ok(pump.indexOf("processPairingFrame") < pump.indexOf("persistPersona(processed.persona)"));

  for (const terminal of ["finalizePairing", "cancelPairing"]) {
    const start = script.indexOf(`async function ${terminal}`);
    const end = script.indexOf("\nasync function ", start + 1);
    const body = script.slice(start, end);
    assert.match(body, /deleteRendezvousLanes/);
    assert.match(body, /persistPersona/);
    assert.ok(body.indexOf("deleteRendezvousLanes") < body.indexOf("persistPersona"));
  }
  assert.doesNotMatch(script, /textContent\s*=.*(?:routeCapability|publishCapability|readCapability|deleteCapability|pairingID)/);
});

test("browser secret state stays encrypted and old global schemas are rejected", async () => {
  const [script, identityService] = await Promise.all([
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../src/browser-pairing-service.js", import.meta.url), "utf8")
  ]);
  assert.match(script, /EncryptedNoctweaveStore/);
  assert.match(script, /HostAnchoredBrowserApplicationVaultV2/);
  assert.match(script, /state\.vault\.initialize/);
  assert.doesNotMatch(script, /localStorage|searchParams/);
  assert.match(script, /validateBrowserPersonaState/);
  assert.match(script, /prepareOffererPairing/);
  assert.doesNotMatch(script, /pendingPairings\.push/);
  assert.match(identityService, /stateSchema !== browserPersonaStateSchema/);
  assert.match(identityService, /scope !== "pairwise"/);
  assert.doesNotMatch(script, /migrate|backfill|compatibility/i);
});

test("browser shell binds completed relationships to durable send, retry, and local-first receive", async () => {
  const [script, service] = await Promise.all([
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../client/messaging-service.js", import.meta.url), "utf8")
  ]);
  for (const operation of [
    "DurablePairwiseMessagingRuntimeV2",
    "prepareText",
    "resumeOutbound",
    "syncReceive",
    "listOutbound",
    "listReceived",
    "discard",
    "NoctweaveWebClient"
  ]) {
    assert.match(service, new RegExp(`\\b${operation}\\b`), operation);
  }
  assert.ok(service.indexOf("runtime.prepareText") < service.indexOf("runtime.resumeOutbound"));
  assert.match(service, /for \(const localRoute of current\.localReceiveRoutes\)/);
  assert.match(service, /EncryptedNoctweaveStore/);
  assert.match(script, /startMessagePump\(\)/);
  assert.match(script, /backgroundMessageResume\(true\)/);
  assert.match(script, /visibilitychange/);
  assert.match(script, /maintainAllBrowserRelationships/);
  assert.match(script, /5 \* 60 \* 1_000/);
  assert.match(service, /prepareEndpointPrekeyUpdate/);
  assert.match(service, /persistAppliedRelationship/);
  assert.match(service, /relationshipSnapshot/);
  assert.match(script, /text\.textContent = message\.text/);
  assert.doesNotMatch(script, /innerHTML\s*=/);
  assert.doesNotMatch(script, /textContent\s*=.*(?:sendCapability|readCredential|payloadKey|privateKey)/);
});

test("browser shell exposes route and block state while attachment transport stays honestly disabled", async () => {
  const [html, script, service] = await Promise.all([
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../client/messaging-service.js", import.meta.url), "utf8")
  ]);
  assert.match(service, /maintenanceState = "blocked"/);
  assert.match(service, /maintenanceState = "routeExpired"/);
  assert.match(service, /maintenanceState = "expiresSoon"/);
  assert.match(service, /addTestingPairwiseRouteV2/);
  assert.match(service, /promoteProbedPairwiseRouteV2/);
  assert.match(service, /revokeDrainedPairwiseRouteV2/);
  assert.match(service, /finalizeLocalRouteRetirement/);
  assert.match(service, /rollbackAnchorUnavailable/);
  assert.match(html, /Ordinary browser storage is not hardware rollback-resistant/);
  assert.match(script, /globalThis\.noctweaveRelationshipStateAnchorStoreFactory/);
  assert.match(html, /id="attachmentFile"[^>]*disabled/);
  assert.match(html, /Encrypted attachment upload is not yet exposed by the durable browser runtime/);
  assert.doesNotMatch(service, /installationId|selfSync|globalIdentity/);
  for (const phrase of [
    "Message request",
    "Permit delivery receipts",
    "Permit read receipts",
    "Relationship safety number",
    "Compare out of band"
  ]) {
    assert.match(html, new RegExp(phrase));
  }
  const blockStart = script.indexOf("async function updateSelectedConsent");
  const blockEnd = script.indexOf("async function toggleSelectedRelationshipMute", blockStart);
  const block = script.slice(blockStart, blockEnd);
  assert.ok(block.indexOf("persistRelationshipPolicy") < block.indexOf("teardownRelationshipRoutes"));
  assert.match(block, /cannot be resurrected/);
  const burnStart = script.indexOf("async function burnLocalPersona");
  const burnEnd = script.indexOf("async function rejectAttachmentSelection", burnStart);
  const burn = script.slice(burnStart, burnEnd);
  assert.ok(burn.indexOf("beginBurn") < burn.indexOf("executeAnchoredBrowserLocalBurnV2"));
  const aggregateBurn = service.slice(
    service.indexOf("export async function executeAnchoredBrowserLocalBurnV2"),
    service.indexOf("/**", service.indexOf("export async function executeAnchoredBrowserLocalBurnV2") + 10)
  );
  const beginCall = aggregateBurn.indexOf("await vault.beginBurn");
  const blockCall = aggregateBurn.indexOf("await messaging.anchorRelationshipsForBurn");
  const destroyCall = aggregateBurn.indexOf("await messaging.destroyRollbackAnchors");
  const finishCall = aggregateBurn.indexOf("await vault.finishBurn");
  const relayCall = aggregateBurn.indexOf("await messaging.teardownRelationshipRoutes");
  assert.ok(beginCall < blockCall);
  assert.ok(blockCall < destroyCall);
  assert.ok(destroyCall < finishCall);
  assert.ok(finishCall < relayCall);
  assert.doesNotMatch(service, /browser-route-(?:teardown|maintenance)-v2"\s*\}/);
  assert.match(service, /makeOpaqueRouteTeardownRequestV2/);
  assert.match(service, /resumeRouteTeardowns/);
});

test("every browser invitation persists a valid offerer state machine", async () => {
  const script = await readFile(new URL("../client/app.js", import.meta.url), "utf8");
  const start = script.indexOf("async function createInvitation");
  const end = script.indexOf("async function copyInvitation", start);
  assert.ok(start >= 0 && end > start);
  const body = script.slice(start, end);
  assert.match(body, /prepareOffererPairing/);
  assert.match(body, /persona:\s*state\.persona/);
  assert.match(body, /persistPersona\(prepared\.persona\)/);
  assert.ok(body.indexOf("prepareOffererPairing") < body.indexOf("persistPersona"));
  const persistStart = script.indexOf("async function persistPersona");
  const persistEnd = script.indexOf("\nfunction pendingPairing", persistStart);
  const persistBody = script.slice(persistStart, persistEnd);
  assert.ok(persistBody.indexOf("repository.save") < persistBody.indexOf("state.persona = validated"));
  assert.match(body, /expiresAt/);
});

test("reference browser example runs the production protocol surface", async () => {
  const [exampleScript, productionHTML, exampleHTML] = await Promise.all([
    readFile(new URL("../examples/browser-client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/index.html", import.meta.url), "utf8")
  ]);
  assert.match(exampleScript, /import "\.\.\/\.\.\/client\/app\.js"/);
  for (const html of [productionHTML, exampleHTML]) {
    assert.match(html, /no account recovery|no protocol key/i);
    assert.match(html, /one-use/i);
    assert.doesNotMatch(html, /signed public code|reusable compatibility/i);
  }
  const productionIDs = [...productionHTML.matchAll(/id="([^"]+)"/g)].map((match) => match[1]).sort();
  const exampleIDs = [...exampleHTML.matchAll(/id="([^"]+)"/g)].map((match) => match[1]).sort();
  assert.deepEqual(exampleIDs, productionIDs);
});

test("browser surfaces package the canonical Noctweave mark", async () => {
  const files = await Promise.all([
    readFile(new URL("../client/assets/noctweave-mark.svg", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/assets/noctweave-mark.svg", import.meta.url), "utf8")
  ]);
  for (const svg of files) {
    assert.match(svg, /<svg/);
    assert.match(svg, /viewBox=/);
    assert.match(svg, /#FAF3EA/);
    assert.match(svg, /#C96A61/);
    assert.match(svg, /M96 32H224V176L140 134V110L96 88Z/);
  }
  assert.equal(files[0], files[1]);
});

test("development server serves SVG branding with a non-sniffed image type", async () => {
  const server = await readFile(new URL("../examples/browser-client/server.js", import.meta.url), "utf8");
  assert.match(server, /"\.svg":\s*"image\/svg\+xml"/);
  assert.match(server, /x-content-type-options/);
});
