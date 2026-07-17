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
  for (const id of ["pairingInvitation", "peerInvitation", "relationshipList", "verifyRelay"]) {
    assert.equal(ids.has(id), true, id);
  }
  assert.match(html, /One-use pairing/);
  assert.match(html, /no protocol key or routable identifier/i);
});

test("browser secret state stays encrypted and old global schemas are rejected", async () => {
  const [script, identityService] = await Promise.all([
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../src/browser-identity.js", import.meta.url), "utf8")
  ]);
  assert.match(script, /EncryptedNoctweaveStore/);
  assert.match(script, /iterations:\s*310_000/);
  assert.match(script, /validateBrowserPersonaState/);
  assert.match(script, /preparePairingParticipant/);
  assert.match(script, /pendingPairings\.push/);
  assert.match(identityService, /stateSchema !== browserPersonaStateSchema/);
  assert.match(identityService, /scope !== "pairwise"/);
  assert.doesNotMatch(script, /migrate|backfill|compatibility/i);
});

test("every browser invitation creates fresh participant state before persistence", async () => {
  const script = await readFile(new URL("../client/app.js", import.meta.url), "utf8");
  const start = script.indexOf("async function createInvitation");
  const end = script.indexOf("async function copyInvitation", start);
  assert.ok(start >= 0 && end > start);
  const body = script.slice(start, end);
  assert.match(body, /createPairingInvitation/);
  assert.match(body, /preparePairingParticipant/);
  assert.match(body, /state\.persona\.pendingPairings\.push/);
  assert.ok(body.indexOf("preparePairingParticipant") < body.indexOf("repository.save"));
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
