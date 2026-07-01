import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import { envelopeSignableBytes, NoctweaveOQSWasmAdapter } from "../src/index.js";

test("envelope signatures survive Swift optional omission on fetch", async () => {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const signing = pqc.generateSigningKeypair();
  const envelope = {
    id: "a2de6140-6980-496c-841b-3a01195b2175",
    conversationId: "noctweave-js:test",
    sessionId: "noctweave-js-v1",
    senderFingerprint: "sender",
    sentAt: "2026-06-30T23:59:00Z",
    messageCounter: 1,
    kemCiphertext: "abc",
    prekey: null,
    rootRatchet: null,
    authenticatedContext: null,
    payload: {
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "BBBB",
      tag: "CCCC"
    },
    signature: ""
  };

  const signature = pqc.sign(envelopeSignableBytes(envelope), signing.secretKey);
  const fetchedEnvelope = {
    id: envelope.id.toUpperCase(),
    conversationId: envelope.conversationId,
    sessionId: envelope.sessionId,
    senderFingerprint: envelope.senderFingerprint,
    sentAt: envelope.sentAt,
    messageCounter: envelope.messageCounter,
    kemCiphertext: envelope.kemCiphertext,
    payload: envelope.payload,
    signature: Buffer.from(signature).toString("base64")
  };

  assert.equal(pqc.verify(envelopeSignableBytes(fetchedEnvelope), signature, signing.publicKey), true);
});
