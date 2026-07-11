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
