import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CallMediaReceiverV1,
  CallMediaSenderV1,
  CallStateMachineV1,
  CallV1Error,
  WebCryptoPrimitives,
  acceptCallAnswerV1,
  answerCallOfferV1,
  base64,
  callCodecV1,
  callMediaKeyV1,
  callOfferDigestV1,
  createCallSignalEncodedContentV1,
  createEncodedContent,
  createPendingCallOfferV1,
  createProtocolCapabilityManifest,
  decodeCallSignalEncodedContentV1,
  deriveCallKeyMaterialV1,
  enableCallV1,
  noctweaveCallV1,
  openCallMediaFrameV1,
  sealCallMediaFrameV1,
  standardContentTypes,
  supportsCallV1,
  validateCallAnswerV1,
  validateCallOfferV1,
  validateCallSignalV1
} from "../src/index.js";

const vector = JSON.parse(readFileSync(
  new URL("./fixtures/protocol/call_v1.json", import.meta.url),
  "utf8"
));

const callID = "7D5A399D-D3B1-487A-9BDD-2D2F04B93476";
const candidateID = "2566A7F0-E735-4E4A-B0EB-2AF080EAA024";
const createdAt = "2031-02-27T13:46:40Z";
const answerAt = "2031-02-27T13:46:41Z";

test("call-v1 performs ML-KEM setup and exchanges fixed-bucket media", async () => {
  const crypto = testCrypto();
  const pending = await pendingOffer(crypto);
  const responder = await answerCallOfferV1({
    crypto,
    offerSignal: pending.offerSignal,
    tracks: [{ trackID: 1, codecIdentifier: "opus" }],
    selectedCandidateID: candidateID,
    at: answerAt
  });
  const initiator = await acceptCallAnswerV1({
    crypto,
    pending,
    answerSignal: responder.answerSignal,
    at: answerAt
  });

  assert.deepEqual(initiator.keyMaterial, responder.keyMaterial);
  assert.equal(Buffer.from(initiator.keyMaterial.rootKey, "base64").byteLength, 32);

  const frame = {
    trackID: 1,
    timestamp: 960,
    flags: 0,
    payload: new TextEncoder().encode("authenticated audio")
  };
  const sender = new CallMediaSenderV1({
    material: initiator.keyMaterial,
    role: "initiator"
  });
  const receiver = new CallMediaReceiverV1({
    material: responder.keyMaterial,
    remoteRole: "initiator"
  });
  const sealed = await sender.seal({ crypto, frame, targetByteCount: 512 });
  const opened = await receiver.open({ crypto, sealed });

  assert.equal(Buffer.from(sealed.ciphertext, "base64").byteLength, 512);
  assert.equal(opened.trackID, frame.trackID);
  assert.equal(opened.timestamp, frame.timestamp);
  assert.deepEqual(opened.payload, frame.payload);
  await assert.rejects(
    () => receiver.open({ crypto, sealed }),
    (error) => error instanceof CallV1Error && error.code === "replay"
  );
});

test("call-v1 matches the shared Swift canonical KDF and media vector", async () => {
  const crypto = new WebCryptoPrimitives();
  const offer = validateCallOfferV1({
    initiatorAgreementPublicKey: base64(
      new Uint8Array(vector.offerPublicKeyBytes).fill(vector.offerPublicKeyRepeatedByte)
    ),
    tracks: [{
      trackID: 1,
      mediaKind: "audio",
      direction: "sendReceive",
      codecs: [callCodecV1.opus]
    }],
    candidates: [{
      candidateID: vector.candidateID,
      kind: "relayWebSocket",
      privacy: "relayMediated",
      priority: 100,
      descriptor: base64(new TextEncoder().encode(vector.descriptor))
    }],
    maximumDurationSeconds: 14_400
  });
  const offerSignal = validateCallSignalV1({
    version: 1,
    callID: vector.callID,
    senderRole: "initiator",
    sequence: 1,
    kind: "offer",
    createdAt: vector.createdAt,
    expiresAt: vector.expiresAt,
    offer,
    answer: null,
    candidate: null,
    terminationReason: null
  });
  const offerDigest = await callOfferDigestV1(crypto, offer);
  assert.equal(base64(offerDigest), vector.expectedOfferDigestBase64);
  const answer = validateCallAnswerV1({
    offerDigest: base64(offerDigest),
    kemCiphertext: base64(
      new Uint8Array(vector.kemCiphertextBytes).fill(vector.kemCiphertextRepeatedByte)
    ),
    tracks: [{ trackID: 1, codecIdentifier: "opus" }],
    selectedCandidateID: vector.candidateID,
    responderCandidates: []
  });
  const answerSignal = validateCallSignalV1({
    version: 1,
    callID: vector.callID,
    senderRole: "responder",
    sequence: 1,
    kind: "answer",
    createdAt: vector.answerAt,
    expiresAt: vector.expiresAt,
    offer: null,
    answer,
    candidate: null,
    terminationReason: null
  });
  const material = await deriveCallKeyMaterialV1({
    crypto,
    offerSignal,
    answerSignal,
    sharedSecret: new Uint8Array(vector.sharedSecretBytes).fill(vector.sharedSecretRepeatedByte)
  });
  assert.equal(material.transcriptDigest, vector.expectedTranscriptDigestBase64);
  assert.equal(material.rootKey, vector.expectedRootKeyBase64);
  assert.equal(base64(await callMediaKeyV1({
    crypto,
    material,
    senderRole: "initiator",
    epoch: 0
  })), vector.expectedInitiatorMediaKeyEpoch0Base64);
  const sealed = await sealCallMediaFrameV1({
    crypto,
    frame: {
      trackID: vector.mediaFrame.trackID,
      timestamp: vector.mediaFrame.timestamp,
      flags: vector.mediaFrame.flags,
      payload: Buffer.from(vector.mediaFrame.payloadBase64, "base64")
    },
    material,
    senderRole: "initiator",
    epoch: 0,
    sequence: 1,
    targetByteCount: vector.mediaFrame.targetByteCount,
    deterministicPadding: new Uint8Array(479).fill(vector.mediaFrame.paddingRepeatedByte)
  });
  assert.equal(sealed.ciphertext, vector.mediaFrame.expectedCiphertextBase64);
});

test("call-v1 rejects media tampering and the wrong sender direction", async () => {
  const crypto = testCrypto();
  const material = fixedMaterial();
  const frame = { trackID: 1, timestamp: 20, flags: 0, payload: Uint8Array.of(1, 2, 3) };
  const sealed = await sealCallMediaFrameV1({
    crypto,
    frame,
    material,
    senderRole: "initiator",
    epoch: 0,
    sequence: 1,
    targetByteCount: 512,
    deterministicPadding: new Uint8Array(479).fill(0xA5)
  });
  const corrupted = { ...sealed };
  const ciphertext = Buffer.from(corrupted.ciphertext, "base64");
  ciphertext[0] ^= 0x80;
  corrupted.ciphertext = ciphertext.toString("base64");

  await assert.rejects(
    () => openCallMediaFrameV1({ crypto, sealed: corrupted, material, senderRole: "initiator" }),
    (error) => error.code === "authenticationFailed"
  );
  await assert.rejects(
    () => openCallMediaFrameV1({ crypto, sealed, material, senderRole: "responder" }),
    (error) => error.code === "authenticationFailed"
  );
});

test("call-v1 capability and content type remain explicit opt-ins", () => {
  const baseline = createProtocolCapabilityManifest();
  assert.equal(supportsCallV1(baseline), false);
  assert.equal(baseline.contentTypes.some(({ authority }) => authority === "org.noctweave.call"), false);

  const enabled = enableCallV1(baseline);
  assert.equal(supportsCallV1(enabled), true);
  assert.equal(enabled.modules.find(({ module }) => module === "nw.call").status, "experimental");
  assert.equal(enabled.contentTypes.some(({ authority, name }) =>
    authority === "org.noctweave.call" && name === "signal"), true);
});

test("call-v1 signal content is canonical, exact, and silent", async () => {
  const pending = await pendingOffer(testCrypto());
  const content = createCallSignalEncodedContentV1(pending.offerSignal);

  assert.deepEqual(content.type, standardContentTypes.callSignal);
  assert.equal(content.disposition, "silent");
  assert.deepEqual(decodeCallSignalEncodedContentV1(content), pending.offerSignal);

  const object = JSON.parse(Buffer.from(content.payload, "base64").toString("utf8"));
  object.futureField = true;
  const unknown = createEncodedContent({
    type: standardContentTypes.callSignal,
    payload: new TextEncoder().encode(JSON.stringify(object)),
    fallbackText: null,
    disposition: "silent"
  });
  assert.throws(
    () => decodeCallSignalEncodedContentV1(unknown),
    /exactly its current protocol fields/
  );

  delete object.futureField;
  const pretty = createEncodedContent({
    type: standardContentTypes.callSignal,
    payload: new TextEncoder().encode(JSON.stringify(object, null, 2)),
    fallbackText: null,
    disposition: "silent"
  });
  assert.throws(
    () => decodeCallSignalEncodedContentV1(pretty),
    (error) => error.code === "nonCanonicalSignal"
  );
});

test("call-v1 state detects signal forks and accepts both connected acknowledgements", async () => {
  const crypto = testCrypto();
  const pending = await pendingOffer(crypto);
  const state = await CallStateMachineV1.create({ crypto, offerSignal: pending.offerSignal, at: createdAt });
  const ringing = signal({ role: "responder", sequence: 1, kind: "ringing", at: answerAt });
  assert.equal(await state.apply(ringing, answerAt), "applied");
  assert.equal(await state.apply(ringing, answerAt), "exactReplay");

  const fork = signal({
    role: "responder",
    sequence: 1,
    kind: "candidate",
    at: answerAt,
    candidate: candidate()
  });
  await assert.rejects(() => state.apply(fork, answerAt), (error) => error.code === "signalFork");

  const answer = await answerCallOfferV1({
    crypto,
    offerSignal: pending.offerSignal,
    tracks: [{ trackID: 1, codecIdentifier: "opus" }],
    selectedCandidateID: candidateID,
    sequence: 2,
    at: "2031-02-27T13:46:42Z"
  });
  assert.equal(await state.apply(answer.answerSignal, "2031-02-27T13:46:42Z"), "applied");
  assert.equal(state.phase, "connecting");
  assert.equal(await state.apply(signal({
    role: "initiator", sequence: 2, kind: "connected", at: "2031-02-27T13:46:43Z"
  }), "2031-02-27T13:46:43Z"), "applied");
  assert.equal(await state.apply(signal({
    role: "responder", sequence: 3, kind: "connected", at: "2031-02-27T13:46:43Z"
  }), "2031-02-27T13:46:43Z"), "applied");
  assert.equal(state.phase, "active");
});

test("call-v1 rejects unavailable or mismatched post-quantum suites", async () => {
  await assert.rejects(
    () => pendingOffer(new WebCryptoPrimitives()),
    (error) => error.code === "pqcUnavailable"
  );
  const crypto = testCrypto();
  crypto.profile = () => ({ kem: { algorithm: "ML-KEM-512" } });
  await assert.rejects(
    () => pendingOffer(crypto),
    (error) => error.code === "pqcUnavailable"
  );
});

test("call-v1 enforces payload and epoch bounds before decryption", async () => {
  const crypto = testCrypto();
  const material = fixedMaterial();
  await assert.rejects(
    () => sealCallMediaFrameV1({
      crypto,
      frame: {
        trackID: 1,
        timestamp: 0,
        flags: 0,
        payload: new Uint8Array(noctweaveCallV1.maximumMediaPayloadBytes + 1)
      },
      material,
      senderRole: "initiator",
      epoch: 0,
      sequence: 1
    }),
    (error) => error.code === "invalidMediaFrame"
  );

  const receiver = new CallMediaReceiverV1({ material, remoteRole: "initiator" });
  const skipped = await sealCallMediaFrameV1({
    crypto,
    frame: { trackID: 1, timestamp: 1, flags: 0, payload: Uint8Array.of(1) },
    material,
    senderRole: "initiator",
    epoch: 1,
    sequence: 1,
    targetByteCount: 512,
    deterministicPadding: new Uint8Array(481)
  });
  await assert.rejects(
    () => receiver.open({ crypto, sealed: skipped }),
    (error) => error.code === "invalidEpoch"
  );
});

async function pendingOffer(crypto) {
  return createPendingCallOfferV1({
    crypto,
    callID,
    tracks: [{
      trackID: 1,
      mediaKind: "audio",
      direction: "sendReceive",
      codecs: [callCodecV1.opus]
    }],
    candidates: [candidate()],
    createdAt
  });
}

function candidate() {
  return {
    candidateID,
    kind: "relayWebSocket",
    privacy: "relayMediated",
    priority: 100,
    descriptor: base64(new TextEncoder().encode("wss://relay.example/call/opaque-route"))
  };
}

function fixedMaterial() {
  return {
    callID,
    transcriptDigest: base64(new Uint8Array(32).fill(0x11)),
    rootKey: base64(new Uint8Array(32).fill(0x22))
  };
}

function signal({ role, sequence, kind, at, candidate: transportCandidate = null }) {
  const created = new Date(at);
  return validateCallSignalV1({
    version: 1,
    callID,
    senderRole: role,
    sequence,
    kind,
    createdAt: at,
    expiresAt: new Date(created.getTime() + 300_000).toISOString().replace(".000Z", "Z"),
    offer: null,
    answer: null,
    candidate: transportCandidate,
    terminationReason: null
  });
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
