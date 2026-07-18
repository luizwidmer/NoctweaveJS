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
    "verifyRelay"
  ]) {
    assert.equal(ids.has(id), true, id);
  }
  assert.match(html, /One-use pairing/);
  assert.match(html, /no protocol key or routable identifier/i);
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
  assert.match(script, /iterations:\s*310_000/);
  assert.match(script, /validateBrowserPersonaState/);
  assert.match(script, /prepareOffererPairing/);
  assert.doesNotMatch(script, /pendingPairings\.push/);
  assert.match(identityService, /stateSchema !== browserPersonaStateSchema/);
  assert.match(identityService, /scope !== "pairwise"/);
  assert.doesNotMatch(script, /migrate|backfill|compatibility/i);
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
});

test("browser surfaces package the canonical Noctweave mark", async () => {
  const files = await Promise.all([
    readFile(new URL("../client/assets/noctweave-mark.svg", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/assets/noctweave-mark.svg", import.meta.url), "utf8")
  ]);
  for (const svg of files) {
    assert.match(svg, /<svg/);
    assert.match(svg, /viewBox=/);
  }
});

test("development server serves SVG branding with a non-sniffed image type", async () => {
  const server = await readFile(new URL("../examples/browser-client/server.js", import.meta.url), "utf8");
  assert.match(server, /"\.svg":\s*"image\/svg\+xml"/);
  assert.match(server, /x-content-type-options/);
});
