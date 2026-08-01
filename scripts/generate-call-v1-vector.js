import {
  WebCryptoPrimitives,
  base64,
  callMediaKeyV1,
  callOfferDigestV1,
  deriveCallKeyMaterialV1,
  sealCallMediaFrameV1,
  validateCallAnswerV1,
  validateCallOfferV1,
  validateCallSignalV1
} from "../src/index.js";

const crypto = new WebCryptoPrimitives();
const callID = "7D5A399D-D3B1-487A-9BDD-2D2F04B93476";
const candidateID = "2566A7F0-E735-4E4A-B0EB-2AF080EAA024";
const createdAt = "2031-02-27T13:46:40Z";
const expiresAt = "2031-02-27T13:51:40Z";
const answerAt = "2031-02-27T13:46:41Z";
const descriptor = "wss://relay.example/call/opaque-route";
const offerPublicKey = new Uint8Array(1_184).fill(0x31);
const kemCiphertext = new Uint8Array(1_088).fill(0x33);
const sharedSecret = new Uint8Array(32).fill(0x34);
const offer = validateCallOfferV1({
  initiatorAgreementPublicKey: base64(offerPublicKey),
  tracks: [{
    trackID: 1,
    mediaKind: "audio",
    direction: "sendReceive",
    codecs: [{
      identifier: "opus",
      mediaKind: "audio",
      clockRate: 48_000,
      channels: 2,
      parameters: { frameDurationMs: "20" }
    }]
  }],
  candidates: [{
    candidateID,
    kind: "relayWebSocket",
    privacy: "relayMediated",
    priority: 100,
    descriptor: base64(new TextEncoder().encode(descriptor))
  }],
  maximumDurationSeconds: 14_400
});
const offerSignal = validateCallSignalV1({
  version: 1,
  callID,
  senderRole: "initiator",
  sequence: 1,
  kind: "offer",
  createdAt,
  expiresAt,
  offer,
  answer: null,
  candidate: null,
  terminationReason: null
});
const offerDigest = await callOfferDigestV1(crypto, offer);
const answer = validateCallAnswerV1({
  offerDigest: base64(offerDigest),
  kemCiphertext: base64(kemCiphertext),
  tracks: [{ trackID: 1, codecIdentifier: "opus" }],
  selectedCandidateID: candidateID,
  responderCandidates: []
});
const answerSignal = validateCallSignalV1({
  version: 1,
  callID,
  senderRole: "responder",
  sequence: 1,
  kind: "answer",
  createdAt: answerAt,
  expiresAt,
  offer: null,
  answer,
  candidate: null,
  terminationReason: null
});
const material = await deriveCallKeyMaterialV1({
  crypto,
  offerSignal,
  answerSignal,
  sharedSecret
});
const mediaKey = await callMediaKeyV1({
  crypto,
  material,
  senderRole: "initiator",
  epoch: 0
});
const payload = Uint8Array.of(1, 2, 3);
const sealed = await sealCallMediaFrameV1({
  crypto,
  frame: { trackID: 1, timestamp: 960, flags: 1, payload },
  material,
  senderRole: "initiator",
  epoch: 0,
  sequence: 1,
  targetByteCount: 512,
  deterministicPadding: new Uint8Array(479).fill(0xA5)
});

console.log(JSON.stringify({
  profile: "nw.call-v1.ml-kem-768.aes-256-gcm",
  callID,
  candidateID,
  createdAt,
  expiresAt,
  answerAt,
  descriptor,
  offerPublicKeyBytes: offerPublicKey.byteLength,
  offerPublicKeyRepeatedByte: 0x31,
  kemCiphertextBytes: kemCiphertext.byteLength,
  kemCiphertextRepeatedByte: 0x33,
  sharedSecretBytes: sharedSecret.byteLength,
  sharedSecretRepeatedByte: 0x34,
  expectedOfferDigestBase64: base64(offerDigest),
  expectedTranscriptDigestBase64: material.transcriptDigest,
  expectedRootKeyBase64: material.rootKey,
  expectedInitiatorMediaKeyEpoch0Base64: base64(mediaKey),
  mediaFrame: {
    trackID: 1,
    timestamp: 960,
    flags: 1,
    payloadBase64: base64(payload),
    targetByteCount: 512,
    paddingRepeatedByte: 0xA5,
    expectedCiphertextBase64: sealed.ciphertext
  }
}, null, 2));
