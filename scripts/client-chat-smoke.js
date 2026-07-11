#!/usr/bin/env node
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveBrowserIdentityService,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  base64,
  canonicalJsonBytes,
  createNativeInboundSession,
  createNativeOutboundSession,
  decryptNativeEnvelope,
  encryptNativeTextEnvelope,
  relayRequests,
  swiftISODate,
  swiftUUID,
  verifyNativeContactOffer
} from "../src/index.js";

const endpoint = argument("--relay") ?? "http://127.0.0.1:9340";
const authToken = argument("--auth-token") ?? null;
const crypto = new WebCryptoPrimitives();
const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
const identityService = new NoctweaveBrowserIdentityService({ pqc, crypto });
const relay = new NoctweaveRelayClient(endpoint, { authToken });
const suffix = Date.now().toString(36);

console.log(`Relay: ${endpoint}`);
const alice = await identityService.createAndRegister({ displayName: `Alice ${suffix}`, relay: endpoint, authToken });
const bob = await identityService.createAndRegister({ displayName: `Bob ${suffix}`, relay: endpoint, authToken });
await verifyNativeContactOffer({ crypto, pqc, offer: alice.identity.contactOffer });
await verifyNativeContactOffer({ crypto, pqc, offer: bob.identity.contactOffer });

const aliceContact = contactFromOffer(bob.identity.contactOffer);
const bobContact = contactFromOffer(alice.identity.contactOffer);
const outbound = await createNativeOutboundSession({ crypto, pqc, identity: alice.identity, contact: aliceContact });
const outboundText = `NoctweaveJS encrypted hello ${suffix}`;
const envelope = await encryptNativeTextEnvelope({
  crypto, pqc, identity: alice.identity, contact: aliceContact,
  conversation: outbound.conversation, text: outboundText, kemCiphertext: outbound.kemCiphertext
});
requireType(await relay.send(relayRequests.deliver({ inboxId: bob.identity.inboxId, envelope })), ["delivered", "ok"], "delivery");

const fetched = await fetchInbox(relay, bob.identity);
const receivedEnvelope = fetched.messages?.find((candidate) => candidate.id?.toLowerCase() === envelope.id.toLowerCase());
if (!receivedEnvelope) throw new Error("Bob did not fetch Alice's envelope.");
const inboundConversation = await createNativeInboundSession({
  crypto, pqc, identity: bob.identity, contact: bobContact, kemCiphertext: receivedEnvelope.kemCiphertext
});
const receivedText = await decryptNativeEnvelope({
  crypto, pqc, identity: bob.identity, contact: bobContact, conversation: inboundConversation, envelope: receivedEnvelope
});
if (receivedText !== outboundText) throw new Error("Bob decrypted different plaintext.");
await acknowledge(relay, bob.identity, [receivedEnvelope.id]);

const replyText = `NoctweaveJS encrypted reply ${suffix}`;
const reply = await encryptNativeTextEnvelope({
  crypto, pqc, identity: bob.identity, contact: bobContact,
  conversation: inboundConversation, text: replyText
});
requireType(await relay.send(relayRequests.deliver({ inboxId: alice.identity.inboxId, envelope: reply })), ["delivered", "ok"], "reply delivery");
const aliceFetched = await fetchInbox(relay, alice.identity);
const replyEnvelope = aliceFetched.messages?.find((candidate) => candidate.id?.toLowerCase() === reply.id.toLowerCase());
if (!replyEnvelope) throw new Error("Alice did not fetch Bob's reply.");
const aliceReply = await decryptNativeEnvelope({
  crypto, pqc, identity: alice.identity, contact: aliceContact, conversation: outbound.conversation, envelope: replyEnvelope
});
if (aliceReply !== replyText) throw new Error("Alice decrypted different reply plaintext.");
await acknowledge(relay, alice.identity, [replyEnvelope.id]);

console.log("Pairing signatures: verified");
console.log("Alice → Bob: delivered, fetched, decrypted, acknowledged");
console.log("Bob → Alice: delivered, fetched, decrypted, acknowledged");
console.log("NoctweaveJS direct-chat smoke: passed");

async function fetchInbox(client, identity) {
  const maxCount = 20;
  const signedAt = swiftISODate();
  const nonce = swiftUUID();
  return client.send(relayRequests.fetch({
    inboxId: identity.inboxId,
    routingToken: null,
    maxCount,
    longPollTimeoutSeconds: null,
    accessProof: proof(identity, { inboxId: identity.inboxId, maxCount, nonce, signedAt }, signedAt, nonce)
  }));
}

async function acknowledge(client, identity, messageIds) {
  const signedAt = swiftISODate();
  const nonce = swiftUUID();
  const response = await client.send(relayRequests.acknowledgeMessages({
    inboxId: identity.inboxId,
    messageIds,
    accessProof: proof(identity, { inboxId: identity.inboxId, messageIds, signedAt, nonce }, signedAt, nonce)
  }));
  requireType(response, ["ok"], "acknowledgement");
}

function proof(identity, payload, signedAt, nonce) {
  const secretKey = fromBase64(identity.access.secretKey);
  try {
    return {
      fingerprint: identity.accessFingerprint,
      publicSigningKey: identity.access.publicKey,
      signedAt,
      nonce,
      signature: base64(pqc.sign(canonicalJsonBytes(payload), secretKey))
    };
  } finally { secretKey.fill(0); }
}

function contactFromOffer(offer) {
  return {
    displayName: offer.displayName,
    inboxId: offer.inboxId,
    relay: offer.relay,
    fingerprint: offer.fingerprint,
    signingPublicKey: offer.signingPublicKey,
    agreementPublicKey: offer.agreementPublicKey,
    inboxAccessPublicKey: offer.inboxAccessPublicKey
  };
}

function requireType(response, expected, operation) {
  if (!expected.includes(response?.type)) throw new Error(`Relay ${operation} failed with ${response?.type ?? "no response type"}.`);
}

function fromBase64(value) {
  return new Uint8Array(Buffer.from(value, "base64"));
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}
