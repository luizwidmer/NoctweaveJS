import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import { envelopeSignableBytes, NoctweaveOQSWasmAdapter } from "../src/index.js";

test("envelope signatures bind the id and survive Swift optional omission on fetch", async () => {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const signing = pqc.generateSigningKeypair();
  const envelope = {
    id: "A2DE6140-6980-496C-841B-3A01195B2175",
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
    id: envelope.id,
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
  const idTamperedEnvelope = {
    ...fetchedEnvelope,
    id: "B2DE6140-6980-496C-841B-3A01195B2175"
  };
  assert.equal(pqc.verify(envelopeSignableBytes(idTamperedEnvelope), signature, signing.publicKey), false);
});
