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
  assert.match(script, /buildCommitMailboxCursorRequest/);
  assert.match(script, /route\.pendingCommit\s*=\s*\{/);
  assert.match(script, /validateMailboxSyncContinuity/);
  assert.match(script, /route\.committedSequence\s*=\s*pending\.sequence/);
  assert.match(script, /await saveProfile\(\);\s*await commitMailboxCursor/);
  assert.match(script, /deserializeKeypair\(route\.signing\)/);
  assert.match(script, /quarantinedTransportEnvelopes/);
  assert.match(script, /NoctweaveRemoteEnvelopeError/);
  assert.match(script, /envelopeReceiptKey\(sourceScope, logicalId\)/);
  assert.match(script, /const scopedMessageId/);
  assert.match(script, /stateSchema:\s*"nw\.browser-profile\.v1"/);
  assert.match(script, /validateBrowserIdentityState\(profile\.identity\)/);
  assert.doesNotMatch(script, /migrateProfile|migrateAndRegisterIdentity|legacyUnscoped/);
  assert.doesNotMatch(script, /relayRequests\.(?:fetch|acknowledgeMessages)/);
});

test("browser profiles reject old schemas instead of migrating or backfilling them", async () => {
  const [production, example] = await Promise.all([
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/app.js", import.meta.url), "utf8")
  ]);
  assert.match(production, /profile\.stateSchema !== "nw\.browser-profile\.v1"/);
  assert.match(example, /saved\.stateSchema !== "nw\.browser-example-profile\.v1"/);
  for (const script of [production, example]) {
    assert.doesNotMatch(script, /legacyStateForMigration|migrateProfile|migrateMessages|migrateEnvelopeReceipts/);
    assert.doesNotMatch(script, /contact\.version === 4/);
    assert.doesNotMatch(script, /decryptNativeEnvelope/);
  }
});

test("browser identity-deletion paths journal relay retirement before deleting identity keys", async () => {
  const [production, example, productionHTML, exampleHTML] = await Promise.all([
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/index.html", import.meta.url), "utf8")
  ]);
  for (const script of [production, example]) {
    assert.match(script, /buildRetireInboxRequest/);
    assert.match(script, /pendingInboxRetirements/);
    assert.match(script, /identityDeletionPending/);
    assert.match(script, /resumePendingInboxRetirements/);
    assert.match(script, /retireInbox\(pending\.request\)/);
    assert.match(script, /cannot retire its relay inbox while the access key is locked|cannot be cryptographically retired while its key is locked/);
  }
  assert.match(production, /if \(profile\.identityDeletionPending\)/);
  assert.match(example, /if \(state\.identityDeletionPending\)/);
  const productionRetirement = production.slice(
    production.indexOf("async function retireAndDeleteIdentity"),
    production.indexOf("async function resumePendingInboxRetirements")
  );
  const exampleRetirement = example.slice(
    example.indexOf("async function resetProfile"),
    example.indexOf("async function resumePendingInboxRetirements")
  );
  assert.ok(
    productionRetirement.indexOf("identityDeletionPending = true") <
      productionRetirement.indexOf("await saveProfile();")
  );
  assert.ok(
    exampleRetirement.indexOf("identityDeletionPending = true") <
      exampleRetirement.indexOf("await saveState();")
  );
  assert.ok(
    production.indexOf("await saveProfile();") < production.indexOf("await resumePendingInboxRetirements(runtime.profile"),
    "production deletion must persist its exact retirement request before network cleanup"
  );
  assert.ok(
    example.indexOf("await saveState();") < example.indexOf("await resumePendingInboxRetirements(state.repository)"),
    "example deletion must persist its exact retirement request before network cleanup"
  );
  for (const script of [production, example]) {
    assert.doesNotMatch(script, /complete identity burn|Burn this|Burn \$\{profile\}|Burn complete/);
    assert.match(script, /does not create or link a replacement|No replacement identity will be created or linked/);
  }
  for (const html of [productionHTML, exampleHTML]) {
    assert.match(html, /not a one-time unlinkable rendezvous/);
    assert.doesNotMatch(html, /home relay/i);
  }
});

test("browser send paths persist one exact retry envelope before relay submission", async () => {
  const [production, example] = await Promise.all([
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/app.js", import.meta.url), "utf8")
  ]);
  for (const [script, saveCall] of [
    [production, "await saveProfile();"],
    [example, "await saveState();"]
  ]) {
    const sendStart = script.indexOf("async function sendMessage()");
    const retryStart = script.indexOf("async function retryMessage", sendStart);
    const deliveryStart = script.indexOf("async function deliverStoredMessage", retryStart);
    assert.ok(sendStart >= 0 && retryStart > sendStart && deliveryStart > retryStart);
    const send = script.slice(sendStart, retryStart);
    const retry = script.slice(retryStart, deliveryStart);
    assert.match(send, /structuredClone\(previousConversation\)/);
    assert.match(send, /clientTransactionId/);
    assert.match(send, /envelopeId:\s*directEnvelope\.id/);
    assert.match(send, /validateProtocolEnvelopeV1\(\{ version: 1, directV4: directEnvelope \}\)/);
    assert.ok(send.indexOf(saveCall) < send.indexOf("await deliverStoredMessage"));
    assert.match(retry, /message\.envelope/);
    assert.doesNotMatch(retry, /encryptNative/);
  }
});

test("browser receive paths commit cloned ratchets only with durable event state", async () => {
  const [production, example] = await Promise.all([
    readFile(new URL("../client/app.js", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/app.js", import.meta.url), "utf8")
  ]);
  for (const script of [production, example]) {
    assert.match(script, /structuredClone\(storedConversation\)/);
    assert.match(script, /mutationSnapshot\s*=\s*\{/);
    assert.match(script, /conversations\s*=\s*mutationSnapshot\.conversations/);
  }
  const productionSync = production.slice(
    production.indexOf("async function syncMessages()"),
    production.indexOf("async function recordTransportQuarantine")
  );
  assert.ok(
    productionSync.lastIndexOf("await saveProfile();") < productionSync.lastIndexOf("await commitMailboxCursor")
  );
  const exampleFetch = example.slice(
    example.indexOf("async function fetchMessages()"),
    example.indexOf("function toggleContactCode")
  );
  assert.ok(exampleFetch.indexOf("await saveState();") > exampleFetch.indexOf("await decodeEnvelope"));
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
