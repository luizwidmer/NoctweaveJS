import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("production browser client binds only existing UI elements", async () => {
  const [html, script] = await Promise.all([
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../client/app.js", import.meta.url), "utf8")
  ]);
  const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map((match) => match[1]));
  const referenced = [...script.matchAll(/\$\("#([A-Za-z0-9_-]+)"\)/g)].map((match) => match[1]);
  const missing = [...new Set(referenced.filter((id) => !ids.has(id)))];
  assert.deepEqual(missing, []);
  assert.match(html, /id="contactList"/);
  assert.match(html, /id="messageList"/);
  assert.match(html, /id="relayList"/);
  assert.doesNotMatch(html, /Contacts and full direct-chat UX are intentionally/);
});

test("production browser client keeps secret-bearing state behind encrypted storage", async () => {
  const script = await readFile(new URL("../client/app.js", import.meta.url), "utf8");
  assert.match(script, /EncryptedNoctweaveStore/);
  assert.match(script, /iterations:\s*310_000/);
  assert.match(script, /acknowledgeMessages/);
  assert.match(script, /await saveProfile\(\);\s*renderApplication\(\);\s*if \(acknowledged\.length/);
});

test("browser surfaces package the canonical Noctweave mark", async () => {
  const [clientHTML, demoHTML, clientMark, demoMark] = await Promise.all([
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../client/assets/noctweave-mark.svg", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/assets/noctweave-mark.svg", import.meta.url), "utf8")
  ]);
  assert.match(clientHTML, /assets\/noctweave-mark\.svg/);
  assert.match(demoHTML, /assets\/noctweave-mark\.svg/);
  assert.equal(clientMark, demoMark);
  assert.match(clientMark, /#7B61FF/);
  assert.match(clientMark, /#5B9CFA/);
  assert.match(clientMark, /#3DD5C5/);
});

test("development server serves SVG branding with a non-sniffed image type", async () => {
  const server = await readFile(new URL("../examples/browser-client/server.js", import.meta.url), "utf8");
  assert.match(server, /"\.svg": "image\/svg\+xml"/);
  assert.match(server, /"x-content-type-options": "nosniff"/);
});
