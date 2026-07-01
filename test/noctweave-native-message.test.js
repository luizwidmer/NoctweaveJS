import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  createNativeInboundSession,
  createNativeOutboundSession,
  decryptNativeEnvelope,
  encodeNativeContactCode,
  decodeNativeContactCode,
  encryptNativeTextEnvelope,
  makeNativeContactOffer,
  NoctweaveOQSWasmAdapter,
  verifyNativeContactOffer,
  WebCryptoPrimitives,
  base64
} from "../src/index.js";

test("native wire messages establish a session and decrypt replies", async () => {
  const crypto = new WebCryptoPrimitives();
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const alice = await makeIdentity({ crypto, pqc, displayName: "Alice", inboxId: "alice-inbox" });
  const bob = await makeIdentity({ crypto, pqc, displayName: "Bob", inboxId: "bob-inbox" });

  const aliceContact = decodeNativeContactCode(encodeNativeContactCode(alice.contactOffer));
  const bobContact = decodeNativeContactCode(encodeNativeContactCode(bob.contactOffer));
  await verifyNativeContactOffer({ crypto, pqc, offer: aliceContact });
  await verifyNativeContactOffer({ crypto, pqc, offer: bobContact });

  const outbound = await createNativeOutboundSession({
    crypto,
    pqc,
    identity: alice,
    contact: contactFromOffer(bobContact)
  });
  const first = await encryptNativeTextEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: contactFromOffer(bobContact),
    conversation: outbound.conversation,
    text: "hello native wire",
    kemCiphertext: outbound.kemCiphertext,
    sentAt: "2026-06-30T12:00:00Z"
  });

  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    identity: bob,
    contact: contactFromOffer(aliceContact),
    kemCiphertext: first.kemCiphertext
  });
  assert.equal(
    await decryptNativeEnvelope({
      crypto,
      pqc,
      identity: bob,
      contact: contactFromOffer(aliceContact),
      conversation: inbound,
      envelope: first
    }),
    "hello native wire"
  );

  const reply = await encryptNativeTextEnvelope({
    crypto,
    pqc,
    identity: bob,
    contact: contactFromOffer(aliceContact),
    conversation: inbound,
    text: "reply over the same session",
    sentAt: "2026-06-30T12:00:02Z"
  });
  assert.equal(
    await decryptNativeEnvelope({
      crypto,
      pqc,
      identity: alice,
      contact: contactFromOffer(bobContact),
      conversation: outbound.conversation,
      envelope: reply
    }),
    "reply over the same session"
  );
});

async function makeIdentity({ crypto, pqc, displayName, inboxId }) {
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  const access = pqc.generateSigningKeypair();
  const identity = {
    displayName,
    signing: serializeKeypair(signing),
    agreement: serializeKeypair(agreement),
    access: serializeKeypair(access),
    inboxId,
    accessFingerprint: base64(await crypto.sha256(access.publicKey)),
    signingFingerprint: base64(await crypto.sha256(signing.publicKey))
  };
  return {
    ...identity,
    contactOffer: makeNativeContactOffer({
      pqc,
      identity,
      relayEndpoint: { host: "127.0.0.1", port: 9339, useTLS: false, transport: "http" }
    })
  };
}

function contactFromOffer(offer) {
  return {
    displayName: offer.displayName,
    inboxId: offer.inboxId,
    relay: offer.relay,
    fingerprint: offer.fingerprint,
    signingPublicKey: offer.signingPublicKey,
    agreementPublicKey: offer.agreementPublicKey
  };
}

function serializeKeypair(keypair) {
  return {
    publicKey: base64(keypair.publicKey),
    secretKey: base64(keypair.secretKey)
  };
}
