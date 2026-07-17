import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveOQSWasmAdapter,
  decodeProtocolEnvelopeV1,
  directEnvelopeV4AuthenticatedDataBytes,
  directEnvelopeV4SignableBytes,
  encodeProtocolEnvelopeV1,
  groupApplicationEnvelopeV2SignableBytes,
  validateDirectBootstrapV4,
  validateDirectEnvelopeV4,
  validateGroupApplicationEnvelopeV2,
  validateProtocolEnvelopeV1
} from "../src/index.js";

test("DirectEnvelopeV4 has one exact required field set and canonical transcripts", async () => {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const signing = pqc.generateSigningKeypair();
  const unsigned = directFixture({ signature: "" });
  const signature = pqc.sign(directEnvelopeV4SignableBytes(unsigned), signing.secretKey);
  const envelope = validateDirectEnvelopeV4({
    ...unsigned,
    signature: Buffer.from(signature).toString("base64")
  });
  assert.equal(
    pqc.verify(directEnvelopeV4SignableBytes(envelope), signature, signing.publicKey),
    true
  );

  const header = directHeader(envelope);
  const aad = directEnvelopeV4AuthenticatedDataBytes(header);
  for (const [key, replacement] of [
    ["id", "B2DE6140-6980-496C-841B-3A01195B2175"],
    ["eventId", "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF"],
    ["senderCertificateDigest", repeatedBase64(21, 32)],
    ["senderEndpointSetEpoch", 8],
    ["recipientCertificateDigest", repeatedBase64(22, 32)],
    ["recipientEndpointSetEpoch", 10],
    ["negotiatedCapabilitiesDigest", repeatedBase64(23, 32)],
    ["messageCounter", 12]
  ]) {
    const tamperedHeader = { ...header, [key]: replacement };
    assert.notDeepEqual(directEnvelopeV4AuthenticatedDataBytes(tamperedHeader), aad, key);
    const tamperedEnvelope = { ...envelope, [key]: replacement };
    assert.equal(
      pqc.verify(directEnvelopeV4SignableBytes(tamperedEnvelope), signature, signing.publicKey),
      false,
      key
    );
  }
});

test("DirectBootstrapV4 and DirectEnvelopeV4 reject missing, legacy, and unknown fields", () => {
  assert.deepEqual(validateDirectBootstrapV4({ kind: "none" }), { kind: "none" });
  assert.throws(
    () => validateDirectBootstrapV4({ kind: "none", kemCiphertext: repeatedBase64(1, 1_088) }),
    /canonical field set/
  );
  assert.throws(
    () => validateDirectBootstrapV4({
      kind: "signedPrekey",
      kemCiphertext: repeatedBase64(1, 1_088),
      prekey: { kind: "oneTime", id: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE" }
    }),
    /signed prekey/
  );

  const envelope = directFixture();
  const { eventId: _missing, ...missing } = envelope;
  assert.throws(() => validateDirectEnvelopeV4(missing), /canonical field set/);
  assert.throws(
    () => validateDirectEnvelopeV4({ ...envelope, unknownOuterField: {} }),
    /canonical field set/
  );
  assert.throws(
    () => validateDirectEnvelopeV4({
      ...envelope,
      bootstrap: { ...envelope.bootstrap, unknownNestedField: null }
    }),
    /canonical field set/
  );
  assert.throws(
    () => validateDirectEnvelopeV4({
      ...envelope,
      payload: { ...envelope.payload, extra: true }
    }),
    /canonical field set/
  );
});

test("ProtocolEnvelopeV1 requires exactly one known strict case", () => {
  const direct = directFixture();
  const protocol = validateProtocolEnvelopeV1({ version: 1, directV4: direct });
  assert.deepEqual(
    decodeProtocolEnvelopeV1(encodeProtocolEnvelopeV1(protocol)),
    protocol
  );
  assert.throws(() => validateProtocolEnvelopeV1({ version: 1 }), /exactly one case/);
  assert.throws(
    () => validateProtocolEnvelopeV1({ version: 1, unknownV9: direct }),
    /unknown, missing, or multiple/
  );
  assert.throws(
    () => validateProtocolEnvelopeV1({
      version: 1,
      directV4: direct,
      groupApplicationV2: groupFixture()
    }),
    /exactly one case/
  );
  assert.throws(
    () => validateProtocolEnvelopeV1({ version: 1, directV4: { ...direct, extra: true } }),
    /canonical field set/
  );
  assert.throws(
    () => validateProtocolEnvelopeV1({ version: 1, unknownGroupCase: {} }),
    /unknown, missing, or multiple/
  );
});

test("GroupApplicationEnvelopeV2 is strict, group-scoped, bucketed, and signable", () => {
  const envelope = validateGroupApplicationEnvelopeV2(groupFixture());
  assert.ok(groupApplicationEnvelopeV2SignableBytes(envelope).byteLength > 0);
  assert.deepEqual(Object.keys(envelope).sort(), [
    "cipherSuite",
    "epoch",
    "eventId",
    "groupId",
    "messageCounter",
    "payload",
    "profile",
    "senderClientHandle",
    "sentAt",
    "signature",
    "transcriptHash",
    "version"
  ]);
  assert.throws(
    () => validateGroupApplicationEnvelopeV2({ ...envelope, senderEndpointHandle: {} }),
    /canonical field set/
  );
  assert.throws(
    () => validateGroupApplicationEnvelopeV2({ ...envelope, sentAt: "2026-07-16T12:34:56Z" }),
    /five-minute bucket/
  );
});

function directFixture({ signature = repeatedBase64(7, 3_309) } = {}) {
  return {
    version: 4,
    id: "A2DE6140-6980-496C-841B-3A01195B2175",
    payloadFormat: "nw.wire-payload.v2",
    conversationId: repeatedBase64(1, 32),
    sessionId: repeatedBase64(2, 32),
    eventId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
    senderEndpointHandle: { rawValue: repeatedBase64(3, 32) },
    senderCertificateDigest: repeatedBase64(4, 32),
    senderEndpointSetEpoch: 7,
    recipientEndpointHandle: { rawValue: repeatedBase64(5, 32) },
    recipientCertificateDigest: repeatedBase64(6, 32),
    recipientEndpointSetEpoch: 9,
    cipherSuite: "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm",
    negotiatedCapabilitiesDigest: repeatedBase64(8, 32),
    bootstrap: { kind: "none" },
    sentAt: "2026-07-16T12:34:56Z",
    messageCounter: 11,
    payload: {
      nonce: repeatedBase64(9, 12),
      ciphertext: repeatedBase64(10, 512),
      tag: repeatedBase64(11, 16)
    },
    signature
  };
}

function directHeader(envelope) {
  const { payload: _payload, signature: _signature, ...header } = envelope;
  return header;
}

function groupFixture() {
  return {
    version: 2,
    profile: "nw.pq-group.experimental-2",
    cipherSuite: "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2",
    groupId: "11111111-2222-4333-8444-555555555555",
    epoch: 1,
    transcriptHash: repeatedBase64(12, 32),
    senderClientHandle: { rawValue: repeatedBase64(13, 32) },
    eventId: "99999999-8888-4777-8666-555555555555",
    messageCounter: 0,
    sentAt: "2026-07-16T12:30:00Z",
    payload: {
      nonce: repeatedBase64(14, 12),
      ciphertext: repeatedBase64(15, 64),
      tag: repeatedBase64(16, 16)
    },
    signature: repeatedBase64(17, 3_309)
  };
}

function repeatedBase64(byte, count) {
  return Buffer.alloc(count, byte).toString("base64");
}
