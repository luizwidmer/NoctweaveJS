import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import test from "node:test";
import {
  RendezvousRelayAdapterV2Error,
  WebCryptoPrimitives,
  base64,
  createRendezvousRelayAdapterV2,
  rendezvousOfferDigestV2,
  rendezvousRelayInboundDirectionV2,
  rendezvousRelayOutboundDirectionV2,
  validateAppendRendezvousTransportV2Request,
  validateDeleteRendezvousTransportV2Request,
  validateRegisterRendezvousTransportV2Request,
  validateRendezvousRelayCiphertextFrameV2,
  validateRendezvousRelaySyncBatchV2,
  validateSyncRendezvousTransportV2Request
} from "../src/index.js";

const vectors = JSON.parse(readFileSync(
  new URL("../../NoctweaveDocumentation/test_vectors/rendezvous_opaque_v2.json", import.meta.url),
  "utf8"
));
const offerVector = vectors.rendezvousOffer;

const expected = Object.freeze({
  route: "5a93dcb5bf7fbb7341aba6f7de4a8f7647cc1fe402b52181442c0b1f967ff201",
  offererToResponder: Object.freeze({
    lane: "55bbcfbacea14a9661bb9fb3ed7a9d423d9750e4b471f17027577afb50df0f20",
    publish: "9305ec1db51e890175dd588385a80c039228c9c2a8517803b249c88ab357e959",
    read: "d4808ace48bb8b7da57c9bb1a4663ee8c686307d9b330db4c9b648bcc90737a3",
    delete: "5562e2b92da14adb17507082134bdaf27dad8f74f4e7b665746e88e074a3b1b9",
    key: "5e3b7cecfc15708d9534f881b260a4b99faa4f4919a35de52cdadf6934cf310c"
  }),
  responderToOfferer: Object.freeze({
    lane: "9205142a20d1e305b73bdf9ac8df010b3127c84e707bb97386d1241f905122a8",
    publish: "1f7ff8b37d495ad88c30b9b4f63c9b741187d28bf838b5278cb3147e09c10d46",
    read: "bf4816f0d1bfcbeb16f38aa211c027b54394dfc507f91dc9aef525db356cbacd",
    delete: "f915763d7f7544c4af0ad8e81921bd8ce9b7c6d7c2ab4a368a2f49225abe0807",
    key: "df25911a064fcd66b339dd99118db69016ca6bbb2bead141b7a88b03d533dc56"
  })
});

test("rendezvous relay derivation matches the clean-origin directional vector", async () => {
  const crypto = observedCrypto();
  const adapter = await createRendezvousRelayAdapterV2({ crypto, offer: canonicalOffer() });
  const registration = adapter.registrationRequest;

  assert.equal(hexOpaque(adapter.routeCapability), expected.route);
  assertLane(adapter.offererToResponder, expected.offererToResponder);
  assertLane(adapter.responderToOfferer, expected.responderToOfferer);
  assert.deepEqual(Object.keys(registration), ["version", "routeCapability", "expiresAt", "lanes"]);
  assert.deepEqual(Object.keys(registration.lanes[0]), [
    "laneId", "publishCapability", "readCapability", "deleteCapability"
  ]);
  assert.deepEqual(
    validateRegisterRendezvousTransportV2Request(registration, { at: offerVector.createdAt }),
    registration
  );
  assert.equal(rendezvousRelayOutboundDirectionV2("offerer"), "offererToResponder");
  assert.equal(rendezvousRelayInboundDirectionV2("offerer"), "responderToOfferer");
  assert.equal(rendezvousRelayOutboundDirectionV2("responder"), "responderToOfferer");
  assert.equal(rendezvousRelayInboundDirectionV2("responder"), "offererToResponder");

  const visible = JSON.stringify(registration).toLowerCase();
  for (const forbidden of [
    "purpose", "generation", "identity", "fingerprint", "contact", "relationship",
    "endpoint", "inbox", "provider", "publickey", "account"
  ]) {
    assert.equal(visible.includes(forbidden), false, forbidden);
  }
  assert.deepEqual(JSON.parse(JSON.stringify(adapter)), {
    type: "RendezvousRelayAdapterV2",
    redacted: true
  });
  assert.equal(inspect(adapter), "RendezvousRelayAdapterV2(<redacted>)");
});

test("rendezvous relay seals and authenticates the one-use open in the responder lane", async () => {
  const crypto = observedCrypto();
  const offer = canonicalOffer();
  const adapter = await createRendezvousRelayAdapterV2({ crypto, offer });
  const open = await validOpen(crypto, offer);
  const append = await adapter.sealOpen({ open, frameID: opaque(0x41, 16) });

  assert.equal(append.frame.sequence, 1);
  assert.equal(Buffer.from(append.frame.ciphertext, "base64").byteLength, 4_096);
  assert.deepEqual(append.laneId, adapter.responderToOfferer.registration.laneId);
  assert.deepEqual(append.publishCapability, adapter.responderToOfferer.registration.publishCapability);
  assert.equal(crypto.aesKeys[0], expected.responderToOfferer.key);

  const decoded = await adapter.open({
    frame: append.frame,
    direction: "responderToOfferer"
  });
  assert.deepEqual(decoded, { kind: "open", open });
  assert.equal(crypto.aesKeys[1], expected.responderToOfferer.key);

  await assert.rejects(
    () => adapter.open({ frame: append.frame, direction: "offererToResponder" }),
    isAdapterError("decryptionFailed")
  );
  const tampered = structuredClone(append.frame);
  const ciphertext = Buffer.from(tampered.ciphertext, "base64");
  ciphertext[100] ^= 0x80;
  tampered.ciphertext = ciphertext.toString("base64");
  await assert.rejects(
    () => adapter.open({ frame: tampered, direction: "responderToOfferer" }),
    isAdapterError("decryptionFailed")
  );
  await assert.rejects(
    () => adapter.sealOpen({
      open: { ...open, offerDigest: base64(new Uint8Array(32).fill(0xee)) }
    }),
    isAdapterError("invalidPayload")
  );
});

test("rendezvous relay keeps session traffic directional and uses only fixed outer buckets", async () => {
  const crypto = observedCrypto();
  const adapter = await createRendezvousRelayAdapterV2({ crypto, offer: canonicalOffer() });
  const responderFrame = sessionFrame({
    senderRole: "responder",
    messageKind: "acceptance",
    ciphertextBytes: 4_096
  });
  const responderAppend = await adapter.sealSessionFrame({
    frame: responderFrame,
    transportSequence: 2,
    frameID: opaque(0x51, 16)
  });

  assert.equal(Buffer.from(responderAppend.frame.ciphertext, "base64").byteLength, 16_384);
  assert.deepEqual(responderAppend.laneId, adapter.responderToOfferer.registration.laneId);
  assert.equal(crypto.aesKeys[0], expected.responderToOfferer.key);
  assert.deepEqual(await adapter.open({
    frame: responderAppend.frame,
    direction: "responderToOfferer"
  }), { kind: "sessionFrame", frame: responderFrame });

  const offererFrame = sessionFrame({
    senderRole: "offerer",
    messageKind: "introduction",
    ciphertextBytes: 65_536
  });
  const offererAppend = await adapter.sealSessionFrame({
    frame: offererFrame,
    transportSequence: 1,
    frameID: opaque(0x52, 16)
  });
  assert.equal(Buffer.from(offererAppend.frame.ciphertext, "base64").byteLength, 131_072);
  assert.deepEqual(offererAppend.laneId, adapter.offererToResponder.registration.laneId);
  assert.equal(crypto.aesKeys[2], expected.offererToResponder.key);
  assert.deepEqual(await adapter.open({
    frame: offererAppend.frame,
    direction: "offererToResponder"
  }), { kind: "sessionFrame", frame: offererFrame });

  await assert.rejects(
    () => adapter.sealSessionFrame({ frame: offererFrame, transportSequence: 0 }),
    isAdapterError("invalidPayload")
  );
  await assert.rejects(
    () => adapter.sealSessionFrame({
      frame: offererFrame,
      transportSequence: 2,
      frameID: opaque(0, 16)
    }),
    isAdapterError("invalidPayload")
  );

  const unsupportedInnerBucket = sessionFrame({
    senderRole: "offerer",
    messageKind: "confirmation",
    ciphertextBytes: 131_072
  });
  await assert.rejects(
    () => adapter.sealSessionFrame({ frame: unsupportedInnerBucket, transportSequence: 2 }),
    isAdapterError("invalidPayload")
  );
});

test("rendezvous relay wire schemas are exact, bounded, and gap detecting", async () => {
  const adapter = await createRendezvousRelayAdapterV2({
    crypto: observedCrypto(),
    offer: canonicalOffer()
  });
  const registration = adapter.registrationRequest;
  assert.throws(
    () => validateRegisterRendezvousTransportV2Request({ ...registration, extra: true }),
    /current protocol fields/
  );
  const duplicateAuthority = structuredClone(registration);
  duplicateAuthority.lanes[0].publishCapability = duplicateAuthority.routeCapability;
  assert.throws(
    () => validateRegisterRendezvousTransportV2Request(duplicateAuthority),
    /independent/
  );
  assert.throws(
    () => validateRegisterRendezvousTransportV2Request(registration, {
      at: "2026-07-16T12:10:00Z"
    }),
    /lifetime bound/
  );

  const sync = adapter.syncRequest({ receivingAs: "offerer", afterSequence: 0 });
  assert.equal(sync.maxCount, null);
  assert.deepEqual(validateSyncRendezvousTransportV2Request(sync), sync);
  const withoutExplicitBound = structuredClone(sync);
  delete withoutExplicitBound.maxCount;
  assert.throws(
    () => validateSyncRendezvousTransportV2Request(withoutExplicitBound),
    /current protocol fields/
  );

  const frame1 = relayFrame(1, 0x61);
  const frame2 = relayFrame(2, 0x62);
  assert.deepEqual(validateRendezvousRelaySyncBatchV2({
    frames: [frame1, frame2],
    highWatermark: 3,
    nextSequence: 2,
    hasMore: true
  }, { request: sync }), {
    frames: [frame1, frame2],
    highWatermark: 3,
    nextSequence: 2,
    hasMore: true
  });
  assert.throws(() => validateRendezvousRelaySyncBatchV2({
    frames: [frame1, { ...frame2, sequence: 3 }],
    highWatermark: 3,
    nextSequence: 3,
    hasMore: false
  }, { request: sync }), /sequence gap/);
  assert.throws(() => validateRendezvousRelaySyncBatchV2({
    frames: [frame1],
    highWatermark: 2,
    nextSequence: 1,
    hasMore: false
  }, { request: sync }), /watermarks/);
  assert.throws(() => validateRendezvousRelaySyncBatchV2({
    frames: [frame1, { ...frame1, sequence: 2 }],
    highWatermark: 2,
    nextSequence: 2,
    hasMore: false
  }, { request: sync }), /bounded lane/);

  const append = {
    routeCapability: registration.routeCapability,
    laneId: registration.lanes[0].laneId,
    publishCapability: registration.lanes[0].publishCapability,
    frame: relayFrame(1, 0x63)
  };
  assert.deepEqual(validateAppendRendezvousTransportV2Request(append), append);
  assert.throws(() => validateRendezvousRelayCiphertextFrameV2({
    ...append.frame,
    ciphertext: base64(new Uint8Array(8_192).fill(0x64))
  }), /fixed transport bucket/);

  const deletions = adapter.deletionRequests();
  assert.equal(deletions.length, 2);
  assert.deepEqual(deletions.map((request) => validateDeleteRendezvousTransportV2Request(request)), deletions);
  assert.deepEqual(deletions.map(({ laneId }) => laneId), registration.lanes.map(({ laneId }) => laneId));
});

function canonicalOffer() {
  return {
    version: 2,
    purpose: "contactPairing",
    transportCapability: {
      opaqueValue: base64(Buffer.from(offerVector.transportCapabilityBytesHex, "hex")),
      expiresAt: offerVector.expiresAt
    },
    oneTimeTokenDigest: base64(new Uint8Array(32).fill(offerVector.oneTimeTokenDigestRepeatedByte)),
    ephemeralAgreementPublicKey: base64(new Uint8Array(offerVector.ephemeralAgreementPublicKeyBytes)
      .fill(offerVector.ephemeralAgreementPublicKeyRepeatedByte)),
    createdAt: offerVector.createdAt,
    expiresAt: offerVector.expiresAt,
    limits: {
      maximumFrames: offerVector.maximumFrames,
      maximumFramePlaintextBytes: offerVector.maximumFramePlaintextBytes
    }
  };
}

async function validOpen(crypto, offer) {
  return {
    version: 2,
    purpose: "contactPairing",
    offerDigest: base64(await rendezvousOfferDigestV2(crypto, offer)),
    kemCiphertext: base64(new Uint8Array(1_088).fill(0x71)),
    tokenProof: base64(new Uint8Array(32).fill(0x72)),
    openedAt: "2026-07-16T12:01:00Z"
  };
}

function sessionFrame({ senderRole, messageKind, ciphertextBytes }) {
  return {
    version: 2,
    sessionId: opaque(0x81, 32),
    purpose: "contactPairing",
    senderRole,
    sequence: 1,
    messageKind,
    payload: {
      nonce: base64(new Uint8Array(12).fill(0x82)),
      ciphertext: base64(new Uint8Array(ciphertextBytes).fill(0x83)),
      tag: base64(new Uint8Array(16).fill(0x84))
    }
  };
}

function relayFrame(sequence, repeatedByte) {
  return {
    frameId: opaque(repeatedByte, 16),
    sequence,
    ciphertext: base64(new Uint8Array(4_096).fill(repeatedByte))
  };
}

function opaque(repeatedByte, length) {
  return { rawValue: base64(new Uint8Array(length).fill(repeatedByte)) };
}

function hexOpaque(value) {
  return Buffer.from(value.rawValue, "base64").toString("hex");
}

function assertLane(actual, vector) {
  const registration = actual.registration;
  assert.equal(hexOpaque(registration.laneId), vector.lane);
  assert.equal(hexOpaque(registration.publishCapability), vector.publish);
  assert.equal(hexOpaque(registration.readCapability), vector.read);
  assert.equal(hexOpaque(registration.deleteCapability), vector.delete);
}

function isAdapterError(code) {
  return (error) => error instanceof RendezvousRelayAdapterV2Error && error.code === code;
}

function observedCrypto() {
  const webcrypto = new WebCryptoPrimitives();
  let randomSequence = 0;
  return {
    aesKeys: [],
    randomBytes(length) {
      randomSequence += 1;
      return new Uint8Array(length).map((_, index) => ((randomSequence + index) % 255) + 1);
    },
    sha256: (data) => webcrypto.sha256(data),
    hmacSha256: (input) => webcrypto.hmacSha256(input),
    aesGcmEncrypt(input) {
      this.aesKeys.push(Buffer.from(input.key).toString("hex"));
      return webcrypto.aesGcmEncrypt(input);
    },
    aesGcmDecrypt(input) {
      this.aesKeys.push(Buffer.from(input.key).toString("hex"));
      return webcrypto.aesGcmDecrypt(input);
    }
  };
}
