import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  RendezvousV2Error,
  acceptRendezvousOpenV2,
  createPendingRendezvousOfferV2,
  createRendezvousOpenV2,
  createRendezvousRedemptionLedgerV2,
  createRendezvousTransportCapabilityV2,
  openRendezvousFrameV2,
  rendezvousOfferDigestV2,
  rendezvousOfferTranscriptBytesV2,
  rendezvousPurposeV2,
  rendezvousRedemptionSecretV2,
  sealRendezvousFrameV2,
  validateRendezvousOfferV2
} from "../src/rendezvous-v2.js";
import { WebCryptoPrimitives } from "../src/crypto/webcrypto.js";
import { base64 } from "../src/crypto/swift-canonical.js";

const vectors = JSON.parse(readFileSync(
  new URL("../../NoctweaveDocumentation/test_vectors/rendezvous_opaque_v2.json", import.meta.url),
  "utf8"
));
const offerVector = vectors.rendezvousOffer;
const createdAt = offerVector.createdAt;
const openedAt = "2026-07-16T12:01:00Z";
const expiresAt = offerVector.expiresAt;

test("rendezvous public offer matches the Swift canonical transcript vector", async () => {
  const crypto = testCrypto();
  const offer = canonicalOffer();
  const transcript = rendezvousOfferTranscriptBytesV2(offer);
  const digest = await rendezvousOfferDigestV2(crypto, offer);

  assert.equal(transcript.byteLength, offerVector.expectedTranscriptBytes);
  assert.equal(
    Buffer.from(digest).toString("hex"),
    offerVector.expectedTranscriptDigestHex
  );
  assert.equal(Buffer.from(transcript.subarray(0, 4)).toString("hex"), "00000024");
  assert.deepEqual(validateRendezvousOfferV2(offer), offer);

  const publicJson = JSON.stringify(offer);
  for (const forbidden of ["identity", "generation", "provider", "account", "reusableAddress", "owner", "secretKey", "oneTimeToken\""]) {
    assert.equal(publicJson.toLowerCase().includes(forbidden.toLowerCase()), false, forbidden);
  }
});

test("one-use ML-KEM rendezvous derives matching directional sessions and fixed-bucket frames", async () => {
  const crypto = testCrypto();
  const transportCapability = await createRendezvousTransportCapabilityV2({ crypto, expiresAt });
  let pending = await createPendingRendezvousOfferV2({ crypto, transportCapability, createdAt });
  const redemptionSecret = await rendezvousRedemptionSecretV2(crypto, pending);
  const opened = await createRendezvousOpenV2({
    crypto,
    offer: pending.offer,
    redemptionSecret,
    at: openedAt
  });
  const accepted = await acceptRendezvousOpenV2({
    crypto,
    pending,
    request: opened.request,
    ledger: createRendezvousRedemptionLedgerV2(),
    at: openedAt
  });
  pending = accepted.pending;

  assert.equal(pending.redeemedAt, openedAt);
  assert.equal(accepted.ledger.records.length, 1);
  assert.equal(accepted.session.sessionId, opened.session.sessionId);
  assert.deepEqual(accepted.session.sendKey, opened.session.receiveKey);
  assert.deepEqual(accepted.session.receiveKey, opened.session.sendKey);

  const message = new TextEncoder().encode("a one-use contact introduction");
  const sealed = await sealRendezvousFrameV2({
    crypto,
    session: opened.session,
    plaintext: message,
    kind: "introduction",
    at: openedAt
  });
  assert.equal(Buffer.from(sealed.frame.payload.ciphertext, "base64").byteLength, 4_096);
  const decrypted = await openRendezvousFrameV2({
    crypto,
    session: accepted.session,
    frame: sealed.frame,
    at: openedAt
  });
  assert.deepEqual(decrypted.plaintext, message);

  await assert.rejects(
    () => openRendezvousFrameV2({
      crypto,
      session: decrypted.session,
      frame: sealed.frame,
      at: openedAt
    }),
    (error) => error instanceof RendezvousV2Error && error.code === "unexpectedSequence"
  );
  await assert.rejects(
    () => acceptRendezvousOpenV2({
      crypto,
      pending,
      request: opened.request,
      ledger: accepted.ledger,
      at: openedAt
    }),
    (error) => error instanceof RendezvousV2Error && error.code === "alreadyRedeemed"
  );
});

test("rendezvous rejects disabled purposes, wrong bearer material, expiry, and ciphertext tampering", async () => {
  const crypto = testCrypto();
  const transportCapability = await createRendezvousTransportCapabilityV2({ crypto, expiresAt });
  await assert.rejects(
    () => createPendingRendezvousOfferV2({
      crypto,
      transportCapability,
      createdAt,
      purpose: rendezvousPurposeV2.historyTransfer
    }),
    (error) => error.code === "purposeDisabled"
  );

  const pending = await createPendingRendezvousOfferV2({ crypto, transportCapability, createdAt });
  await assert.rejects(
    () => createRendezvousOpenV2({
      crypto,
      offer: pending.offer,
      redemptionSecret: { oneTimeToken: base64(new Uint8Array(32).fill(0xee)) },
      at: openedAt
    }),
    (error) => error.code === "invalidRedemptionSecret"
  );
  const secret = await rendezvousRedemptionSecretV2(crypto, pending);
  await assert.rejects(
    () => createRendezvousOpenV2({ crypto, offer: pending.offer, redemptionSecret: secret, at: expiresAt }),
    (error) => error.code === "expired"
  );

  const opened = await createRendezvousOpenV2({ crypto, offer: pending.offer, redemptionSecret: secret, at: openedAt });
  const accepted = await acceptRendezvousOpenV2({
    crypto,
    pending,
    request: opened.request,
    ledger: createRendezvousRedemptionLedgerV2(),
    at: openedAt
  });
  const sealed = await sealRendezvousFrameV2({
    crypto,
    session: opened.session,
    plaintext: new Uint8Array([1, 2, 3]),
    kind: "confirmation",
    at: openedAt
  });
  const corrupted = structuredClone(sealed.frame);
  const ciphertext = Buffer.from(corrupted.payload.ciphertext, "base64");
  ciphertext[0] ^= 0x80;
  corrupted.payload.ciphertext = ciphertext.toString("base64");
  await assert.rejects(
    () => openRendezvousFrameV2({ crypto, session: accepted.session, frame: corrupted, at: openedAt }),
    (error) => error.code === "decryptionFailed"
  );
});

test("rendezvous fails closed when the post-quantum suite is unavailable", async () => {
  const crypto = new WebCryptoPrimitives();
  const transportCapability = await createRendezvousTransportCapabilityV2({ crypto, expiresAt });
  await assert.rejects(
    () => createPendingRendezvousOfferV2({ crypto, transportCapability, createdAt }),
    /ML-KEM-768 operations are required/
  );
});

function canonicalOffer() {
  return {
    version: 2,
    purpose: "contactPairing",
    transportCapability: {
      opaqueValue: base64(Buffer.from(offerVector.transportCapabilityBytesHex, "hex")),
      expiresAt
    },
    oneTimeTokenDigest: base64(new Uint8Array(32).fill(offerVector.oneTimeTokenDigestRepeatedByte)),
    ephemeralAgreementPublicKey: base64(new Uint8Array(offerVector.ephemeralAgreementPublicKeyBytes)
      .fill(offerVector.ephemeralAgreementPublicKeyRepeatedByte)),
    createdAt,
    expiresAt,
    limits: {
      maximumFrames: offerVector.maximumFrames,
      maximumFramePlaintextBytes: offerVector.maximumFramePlaintextBytes
    }
  };
}

function testCrypto() {
  const webcrypto = new WebCryptoPrimitives();
  let randomSequence = 1;
  return {
    webcrypto,
    profile() {
      return {
        kem: {
          algorithm: "ML-KEM-768",
          publicKeyLength: 1_184,
          secretKeyLength: 2_400,
          ciphertextLength: 1_088,
          sharedSecretLength: 32
        }
      };
    },
    randomBytes(length) {
      const result = new Uint8Array(length);
      for (let index = 0; index < length; index += 1) {
        result[index] = ((randomSequence + index) % 255) + 1;
      }
      randomSequence += 1;
      return result;
    },
    sha256: (data) => webcrypto.sha256(data),
    hkdfSha256: (input) => webcrypto.hkdfSha256(input),
    aesGcmEncrypt: (input) => webcrypto.aesGcmEncrypt(input),
    aesGcmDecrypt: (input) => webcrypto.aesGcmDecrypt(input),
    generateKemKeypair() {
      return {
        publicKey: new Uint8Array(1_184).fill(0x31),
        secretKey: new Uint8Array(2_400).fill(0x32)
      };
    },
    encapsulate(publicKey) {
      assert.equal(publicKey.byteLength, 1_184);
      return {
        ciphertext: new Uint8Array(1_088).fill(0x33),
        sharedSecret: new Uint8Array(32).fill(0x34)
      };
    },
    decapsulate(ciphertext, secretKey) {
      assert.equal(ciphertext.byteLength, 1_088);
      assert.equal(secretKey.byteLength, 2_400);
      return new Uint8Array(32).fill(0x34);
    }
  };
}
