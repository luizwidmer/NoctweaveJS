import {
  createContentTypeCapabilityV2,
  createEncodedContent,
  createProtocolCapabilityManifest,
  standardContentTypes,
  validateEncodedContent,
  validateProtocolCapabilityManifest
} from "./architecture-v2.js";
import { canonicalJsonBytes, swiftISODate } from "./crypto/swift-canonical.js";
import { bytes } from "./crypto/webcrypto.js";
import {
  concatBytes,
  cryptoHkdfSha256,
  cryptoRandomBytes,
  cryptoSha256,
  encodeBase64,
  equalBytes,
  freezeWire,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireNonzeroFixedBase64,
  requireRecord,
  timestampMilliseconds,
  uint16Bytes,
  uint32Bytes,
  uint64Bytes
} from "./private-v2.js";
import { parseExactJSON } from "./strict-json.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const identifierPattern = /^[A-Za-z0-9._-]+$/u;
const uuidPattern = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u;
const mediaKinds = new Set(["audio", "video"]);
const mediaDirections = new Set(["sendReceive", "sendOnly", "receiveOnly"]);
const transportKinds = new Set(["webRTC", "datagram", "relayWebSocket"]);
const transportPrivacyModes = new Set(["peerAddressVisible", "relayMediated"]);
const roles = new Set(["initiator", "responder"]);
const signalKinds = new Set([
  "offer", "ringing", "answer", "candidate", "connected", "declined", "canceled", "ended"
]);
const terminationReasons = new Set([
  "declined", "canceled", "completed", "busy", "unavailable", "failed", "securityError", "expired"
]);
const declineReasons = new Set(["declined", "busy", "unavailable"]);
const rootDomain = encoder.encode("org.noctweave.call.root/v1");
const transcriptDomain = encoder.encode("org.noctweave.call.transcript/v1");
const mediaKeyDomain = encoder.encode("org.noctweave.call.media-key/v1");
const mediaAADDomain = encoder.encode("org.noctweave.call.media-aad/v1");
const maximumSafeSequence = Number.MAX_SAFE_INTEGER;
const mediaHeaderBytes = 14;
const gcmTagBytes = 16;

export const noctweaveCallV1 = Object.freeze({
  version: 1,
  module: "nw.call",
  agreementPublicKeyBytes: 1_184,
  agreementSecretKeyBytes: 2_400,
  kemCiphertextBytes: 1_088,
  sharedSecretBytes: 32,
  digestBytes: 32,
  maximumTracks: 4,
  maximumCodecsPerTrack: 8,
  maximumCodecParameters: 16,
  maximumCandidates: 8,
  maximumCandidateDescriptorBytes: 4_096,
  maximumSignalLifetimeSeconds: 5 * 60,
  maximumCallDurationSeconds: 4 * 60 * 60,
  minimumCallDurationSeconds: 30,
  maximumMediaPayloadBytes: 16_000,
  replayWindowSize: 256,
  allowedSealedMediaByteCounts: Object.freeze([512, 1_024, 2_048, 4_096, 8_192, 16_384])
});

export const callV1ModuleCapability = Object.freeze({
  module: noctweaveCallV1.module,
  versions: Object.freeze([1]),
  status: "experimental",
  limits: Object.freeze({
    maxCallDurationSeconds: noctweaveCallV1.maximumCallDurationSeconds,
    maxCandidates: noctweaveCallV1.maximumCandidates,
    maxMediaPayloadBytes: noctweaveCallV1.maximumMediaPayloadBytes,
    maxSignalLifetimeSeconds: noctweaveCallV1.maximumSignalLifetimeSeconds,
    maxTracks: noctweaveCallV1.maximumTracks,
    replayWindow: noctweaveCallV1.replayWindowSize
  })
});

export class CallV1Error extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "CallV1Error";
    this.code = code;
  }
}

export function enableCallV1(value = createProtocolCapabilityManifest()) {
  const manifest = validateProtocolCapabilityManifest(value);
  const callType = createContentTypeCapabilityV2({
    authority: standardContentTypes.callSignal.authority,
    name: standardContentTypes.callSignal.name,
    majorVersions: [standardContentTypes.callSignal.major]
  });
  return createProtocolCapabilityManifest({
    architectureVersion: manifest.architectureVersion,
    modules: [
      ...manifest.modules.filter(({ module }) => module !== noctweaveCallV1.module),
      callV1ModuleCapability
    ],
    contentTypes: [
      ...manifest.contentTypes.filter(({ authority, name }) =>
        authority !== callType.authority || name !== callType.name),
      callType
    ]
  });
}

export function supportsCallV1(value) {
  const manifest = validateProtocolCapabilityManifest(value);
  return manifest.modules.some(({ module, versions }) =>
    module === noctweaveCallV1.module && versions.includes(1)) &&
    manifest.contentTypes.some(({ authority, name, majorVersions }) =>
      authority === standardContentTypes.callSignal.authority &&
      name === standardContentTypes.callSignal.name && majorVersions.includes(1));
}

export function validateCallCodecV1(value) {
  requireExactRecord(value, ["identifier", "mediaKind", "clockRate", "channels", "parameters"], [], "Call codec");
  const identifier = boundedIdentifier(value.identifier, "Call codec identifier");
  const mediaKind = requireEnum(value.mediaKind, mediaKinds, "Call codec mediaKind");
  const clockRate = requireInteger(value.clockRate, "Call codec clockRate", 8_000, 192_000);
  const channels = requireInteger(value.channels, "Call codec channels", 1, 8);
  requireRecord(value.parameters, "Call codec parameters");
  const entries = Object.entries(value.parameters);
  if (entries.length > noctweaveCallV1.maximumCodecParameters) {
    throw new CallV1Error("invalidCodec", "Call codec parameters exceed their bound.");
  }
  const parameters = {};
  for (const [key, rawValue] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    const parameterKey = boundedIdentifier(key, "Call codec parameter", 96);
    if (typeof rawValue !== "string" || encoder.encode(rawValue).byteLength > 256 || /\p{Cc}/u.test(rawValue)) {
      throw new CallV1Error("invalidCodec", "Call codec parameter value is invalid.");
    }
    parameters[parameterKey] = rawValue;
  }
  return freezeWire({ identifier, mediaKind, clockRate, channels, parameters });
}

export const callCodecV1 = Object.freeze({
  opus: validateCallCodecV1({
    identifier: "opus",
    mediaKind: "audio",
    clockRate: 48_000,
    channels: 2,
    parameters: { frameDurationMs: "20" }
  })
});

export function validateCallTrackOfferV1(value) {
  requireExactRecord(value, ["trackID", "mediaKind", "direction", "codecs"], [], "Call track offer");
  const trackID = requireInteger(value.trackID, "Call trackID", 1, 0xffff);
  const mediaKind = requireEnum(value.mediaKind, mediaKinds, "Call track mediaKind");
  const direction = requireEnum(value.direction, mediaDirections, "Call track direction");
  if (!Array.isArray(value.codecs) || value.codecs.length === 0 ||
      value.codecs.length > noctweaveCallV1.maximumCodecsPerTrack) {
    throw new CallV1Error("invalidOffer", "Call track codecs exceed their bounds.");
  }
  const codecs = value.codecs.map(validateCallCodecV1);
  if (new Set(codecs.map(({ identifier }) => identifier)).size !== codecs.length ||
      codecs.some((codec) => codec.mediaKind !== mediaKind)) {
    throw new CallV1Error("invalidOffer", "Call track codecs are incompatible or duplicated.");
  }
  return freezeWire({ trackID, mediaKind, direction, codecs });
}

export function validateCallTransportCandidateV1(value) {
  requireExactRecord(value, ["candidateID", "kind", "privacy", "priority", "descriptor"], [], "Call transport candidate");
  const candidateID = canonicalUUID(value.candidateID, "Call candidateID");
  const kind = requireEnum(value.kind, transportKinds, "Call transport kind");
  const privacy = requireEnum(value.privacy, transportPrivacyModes, "Call transport privacy");
  const priority = requireInteger(value.priority, "Call transport priority", 0, 0xffff);
  const descriptor = requireBase64(value.descriptor, undefined, "Call transport descriptor");
  if (descriptor.byteLength === 0 || descriptor.byteLength > noctweaveCallV1.maximumCandidateDescriptorBytes ||
      (kind === "relayWebSocket" && privacy !== "relayMediated")) {
    throw new CallV1Error("invalidCandidate", "Call transport candidate is invalid.");
  }
  return freezeWire({ candidateID, kind, privacy, priority, descriptor: value.descriptor });
}

export function validateCallOfferV1(value) {
  requireExactRecord(
    value,
    ["initiatorAgreementPublicKey", "tracks", "candidates", "maximumDurationSeconds"],
    [],
    "Call offer"
  );
  requireNonzeroFixedBase64(
    value.initiatorAgreementPublicKey,
    noctweaveCallV1.agreementPublicKeyBytes,
    "Call ML-KEM public key"
  );
  if (!Array.isArray(value.tracks) || value.tracks.length === 0 ||
      value.tracks.length > noctweaveCallV1.maximumTracks ||
      !Array.isArray(value.candidates) || value.candidates.length === 0 ||
      value.candidates.length > noctweaveCallV1.maximumCandidates) {
    throw new CallV1Error("invalidOffer", "Call offer collections exceed their bounds.");
  }
  const tracks = value.tracks.map(validateCallTrackOfferV1);
  const candidates = value.candidates.map(validateCallTransportCandidateV1);
  if (new Set(tracks.map(({ trackID }) => trackID)).size !== tracks.length ||
      new Set(candidates.map(({ candidateID }) => candidateID)).size !== candidates.length) {
    throw new CallV1Error("invalidOffer", "Call offer identifiers must be unique.");
  }
  const maximumDurationSeconds = requireInteger(
    value.maximumDurationSeconds,
    "Call maximum duration",
    noctweaveCallV1.minimumCallDurationSeconds,
    noctweaveCallV1.maximumCallDurationSeconds
  );
  return freezeWire({
    initiatorAgreementPublicKey: value.initiatorAgreementPublicKey,
    tracks,
    candidates,
    maximumDurationSeconds
  });
}

export async function callOfferDigestV1(crypto, value) {
  return cryptoSha256(crypto, canonicalJsonBytes(validateCallOfferV1(value)));
}

export function validateCallTrackSelectionV1(value) {
  requireExactRecord(value, ["trackID", "codecIdentifier"], [], "Call track selection");
  return freezeWire({
    trackID: requireInteger(value.trackID, "Call selected trackID", 1, 0xffff),
    codecIdentifier: boundedIdentifier(value.codecIdentifier, "Call selected codec")
  });
}

export function validateCallAnswerV1(value) {
  requireExactRecord(
    value,
    ["offerDigest", "kemCiphertext", "tracks", "selectedCandidateID", "responderCandidates"],
    [],
    "Call answer"
  );
  requireBase64(value.offerDigest, noctweaveCallV1.digestBytes, "Call offer digest");
  requireNonzeroFixedBase64(
    value.kemCiphertext,
    noctweaveCallV1.kemCiphertextBytes,
    "Call ML-KEM ciphertext"
  );
  if (!Array.isArray(value.tracks) || value.tracks.length === 0 ||
      value.tracks.length > noctweaveCallV1.maximumTracks ||
      !Array.isArray(value.responderCandidates) ||
      value.responderCandidates.length > noctweaveCallV1.maximumCandidates) {
    throw new CallV1Error("invalidAnswer", "Call answer collections exceed their bounds.");
  }
  const tracks = value.tracks.map(validateCallTrackSelectionV1);
  const responderCandidates = value.responderCandidates.map(validateCallTransportCandidateV1);
  if (new Set(tracks.map(({ trackID }) => trackID)).size !== tracks.length ||
      new Set(responderCandidates.map(({ candidateID }) => candidateID)).size !== responderCandidates.length) {
    throw new CallV1Error("invalidAnswer", "Call answer identifiers must be unique.");
  }
  return freezeWire({
    offerDigest: value.offerDigest,
    kemCiphertext: value.kemCiphertext,
    tracks,
    selectedCandidateID: canonicalUUID(value.selectedCandidateID, "Call selected candidateID"),
    responderCandidates
  });
}

export async function isCallAnswerCompatibleV1(crypto, answerValue, offerValue) {
  const answer = validateCallAnswerV1(answerValue);
  const offer = validateCallOfferV1(offerValue);
  if (!equalBytes(
    requireBase64(answer.offerDigest, 32, "Call offer digest"),
    await callOfferDigestV1(crypto, offer)
  ) || !offer.candidates.some(({ candidateID }) => candidateID === answer.selectedCandidateID)) {
    return false;
  }
  const offeredTracks = new Map(offer.tracks.map((track) => [track.trackID, track]));
  return answer.tracks.every((selection) =>
    offeredTracks.get(selection.trackID)?.codecs.some(({ identifier }) =>
      identifier === selection.codecIdentifier) === true);
}

export function validateCallSignalV1(value) {
  requireExactRecord(value, [
    "version", "callID", "senderRole", "sequence", "kind", "createdAt", "expiresAt",
    "offer", "answer", "candidate", "terminationReason"
  ], [], "Call signal");
  if (value.version !== noctweaveCallV1.version) {
    throw new CallV1Error("invalidSignal", "Call signal version is invalid.");
  }
  const callID = canonicalUUID(value.callID, "Call ID");
  const senderRole = requireEnum(value.senderRole, roles, "Call sender role");
  const sequence = requireInteger(value.sequence, "Call signal sequence", 1, maximumSafeSequence);
  const kind = requireEnum(value.kind, signalKinds, "Call signal kind");
  const createdAt = requireCanonicalTimestamp(value.createdAt, "Call signal creation time");
  const expiresAt = requireCanonicalTimestamp(value.expiresAt, "Call signal expiry time");
  const lifetime = timestampMilliseconds(expiresAt) - timestampMilliseconds(createdAt);
  if (lifetime <= 0 || lifetime > noctweaveCallV1.maximumSignalLifetimeSeconds * 1_000) {
    throw new CallV1Error("invalidSignal", "Call signal lifetime is invalid.");
  }
  const offer = value.offer === null ? null : validateCallOfferV1(value.offer);
  const answer = value.answer === null ? null : validateCallAnswerV1(value.answer);
  const candidate = value.candidate === null ? null : validateCallTransportCandidateV1(value.candidate);
  const terminationReason = value.terminationReason === null
    ? null
    : requireEnum(value.terminationReason, terminationReasons, "Call termination reason");
  const emptyPayload = offer === null && answer === null && candidate === null;
  const validKind = (kind === "offer" && senderRole === "initiator" && sequence === 1 && offer !== null &&
      answer === null && candidate === null && terminationReason === null) ||
    (kind === "answer" && senderRole === "responder" && answer !== null && offer === null &&
      candidate === null && terminationReason === null) ||
    (kind === "candidate" && candidate !== null && offer === null && answer === null && terminationReason === null) ||
    (["ringing", "connected"].includes(kind) && emptyPayload && terminationReason === null) ||
    (kind === "declined" && senderRole === "responder" && emptyPayload && declineReasons.has(terminationReason)) ||
    (kind === "canceled" && senderRole === "initiator" && emptyPayload && terminationReason === "canceled") ||
    (kind === "ended" && emptyPayload && terminationReason !== null);
  if (!validKind) {
    throw new CallV1Error("invalidSignal", "Call signal fields do not match its kind.");
  }
  return freezeWire({
    version: noctweaveCallV1.version,
    callID,
    senderRole,
    sequence,
    kind,
    createdAt,
    expiresAt,
    offer,
    answer,
    candidate,
    terminationReason
  });
}

export async function callSignalDigestV1(crypto, value) {
  return cryptoSha256(crypto, canonicalJsonBytes(validateCallSignalV1(value)));
}

export function isCallSignalFreshV1(value, at = new Date()) {
  const signal = validateCallSignalV1(value);
  const now = timestampMilliseconds(at instanceof Date ? swiftISODate(at) : at, "Current call time");
  return now >= timestampMilliseconds(signal.createdAt) - 30_000 &&
    now < timestampMilliseconds(signal.expiresAt);
}

export function createCallSignalEncodedContentV1(value) {
  const signal = validateCallSignalV1(value);
  return createEncodedContent({
    type: standardContentTypes.callSignal,
    parameters: {},
    payload: canonicalJsonBytes(signal),
    fallbackText: null,
    disposition: "silent"
  });
}

export function decodeCallSignalEncodedContentV1(value) {
  const content = validateEncodedContent(value);
  if (content.type.authority !== standardContentTypes.callSignal.authority ||
      content.type.name !== standardContentTypes.callSignal.name ||
      content.type.major !== 1 || content.disposition !== "silent") {
    throw new CallV1Error("invalidSignal", "Encoded content is not a call-v1 signal.");
  }
  const payload = requireBase64(content.payload, undefined, "Call signal payload");
  let parsed;
  try {
    parsed = parseExactJSON(decoder.decode(payload), { canonicalNumbers: true });
  } catch {
    throw new CallV1Error("invalidSignal", "Call signal JSON is invalid.");
  }
  const signal = validateCallSignalV1(parsed);
  if (!equalBytes(payload, canonicalJsonBytes(signal))) {
    throw new CallV1Error("nonCanonicalSignal", "Call signal JSON is not NCJ-1 canonical.");
  }
  return signal;
}

export async function createPendingCallOfferV1({
  crypto,
  callID = globalThis.crypto?.randomUUID?.(),
  tracks,
  candidates,
  maximumDurationSeconds = noctweaveCallV1.maximumCallDurationSeconds,
  createdAt = new Date()
}) {
  assertKEM(crypto);
  const keypair = await crypto.generateKemKeypair();
  const publicKey = bytes(keypair?.publicKey, "Call ML-KEM public key");
  const secretKey = bytes(keypair?.secretKey, "Call ML-KEM secret key");
  if (publicKey.byteLength !== noctweaveCallV1.agreementPublicKeyBytes ||
      secretKey.byteLength !== noctweaveCallV1.agreementSecretKeyBytes) {
    throw new CallV1Error("invalidOffer", "ML-KEM-768 generated an invalid call keypair.");
  }
  const offer = validateCallOfferV1({
    initiatorAgreementPublicKey: encodeBase64(publicKey),
    tracks,
    candidates,
    maximumDurationSeconds
  });
  const canonicalCreatedAt = requireCanonicalTimestamp(createdAt, "Call creation time");
  const offerSignal = validateCallSignalV1({
    version: 1,
    callID: canonicalUUID(callID, "Call ID", true),
    senderRole: "initiator",
    sequence: 1,
    kind: "offer",
    createdAt: canonicalCreatedAt,
    expiresAt: addWholeSeconds(canonicalCreatedAt, noctweaveCallV1.maximumSignalLifetimeSeconds),
    offer,
    answer: null,
    candidate: null,
    terminationReason: null
  });
  return freezeWire({
    offerSignal,
    agreementKey: {
      privateKeyData: encodeBase64(secretKey),
      publicKeyData: encodeBase64(publicKey)
    },
    acceptedAnswerDigest: null
  });
}

export function validatePendingCallOfferV1(value) {
  requireExactRecord(value, ["offerSignal", "agreementKey", "acceptedAnswerDigest"], [], "Pending call offer");
  const offerSignal = validateCallSignalV1(value.offerSignal);
  if (offerSignal.kind !== "offer") {
    throw new CallV1Error("invalidOffer", "Pending call state does not contain an offer.");
  }
  requireExactRecord(value.agreementKey, ["privateKeyData", "publicKeyData"], [], "Pending call keypair");
  const privateKeyData = requireBase64(
    value.agreementKey.privateKeyData,
    noctweaveCallV1.agreementSecretKeyBytes,
    "Pending call ML-KEM private key"
  );
  const publicKeyData = requireBase64(
    value.agreementKey.publicKeyData,
    noctweaveCallV1.agreementPublicKeyBytes,
    "Pending call ML-KEM public key"
  );
  if (!equalBytes(publicKeyData, requireBase64(
    offerSignal.offer.initiatorAgreementPublicKey,
    noctweaveCallV1.agreementPublicKeyBytes,
    "Call offer ML-KEM public key"
  ))) {
    throw new CallV1Error("invalidOffer", "Pending call key does not match its offer.");
  }
  const acceptedAnswerDigest = value.acceptedAnswerDigest === null
    ? null
    : encodeBase64(requireBase64(value.acceptedAnswerDigest, 32, "Accepted call answer digest"));
  return freezeWire({
    offerSignal,
    agreementKey: {
      privateKeyData: encodeBase64(privateKeyData),
      publicKeyData: encodeBase64(publicKeyData)
    },
    acceptedAnswerDigest
  });
}

export async function answerCallOfferV1({
  crypto,
  offerSignal: offerSignalValue,
  tracks,
  selectedCandidateID,
  responderCandidates = [],
  sequence = 1,
  at = new Date()
}) {
  assertKEM(crypto);
  const offerSignal = validateCallSignalV1(offerSignalValue);
  if (offerSignal.kind !== "offer" || !isCallSignalFreshV1(offerSignal, at)) {
    throw new CallV1Error("invalidOffer", "Call offer is invalid or expired.");
  }
  const encapsulated = await crypto.encapsulate(requireBase64(
    offerSignal.offer.initiatorAgreementPublicKey,
    noctweaveCallV1.agreementPublicKeyBytes,
    "Call ML-KEM public key"
  ));
  const ciphertext = bytes(encapsulated?.ciphertext, "Call ML-KEM ciphertext");
  const sharedSecret = new Uint8Array(bytes(encapsulated?.sharedSecret, "Call ML-KEM shared secret"));
  try {
    if (ciphertext.byteLength !== noctweaveCallV1.kemCiphertextBytes ||
        sharedSecret.byteLength !== noctweaveCallV1.sharedSecretBytes) {
      throw new CallV1Error("invalidAnswer", "ML-KEM-768 returned invalid call material.");
    }
    const answer = validateCallAnswerV1({
      offerDigest: encodeBase64(await callOfferDigestV1(crypto, offerSignal.offer)),
      kemCiphertext: encodeBase64(ciphertext),
      tracks,
      selectedCandidateID: canonicalUUID(selectedCandidateID, "Call selected candidateID", true),
      responderCandidates
    });
    if (!await isCallAnswerCompatibleV1(crypto, answer, offerSignal.offer)) {
      throw new CallV1Error("invalidAnswer", "Call answer does not select offered parameters.");
    }
    const createdAt = requireCanonicalTimestamp(at, "Call answer time");
    const expiresAt = earlierTimestamp(
      addWholeSeconds(createdAt, noctweaveCallV1.maximumSignalLifetimeSeconds),
      offerSignal.expiresAt
    );
    const answerSignal = validateCallSignalV1({
      version: 1,
      callID: offerSignal.callID,
      senderRole: "responder",
      sequence,
      kind: "answer",
      createdAt,
      expiresAt,
      offer: null,
      answer,
      candidate: null,
      terminationReason: null
    });
    return freezeWire({
      answerSignal,
      keyMaterial: await deriveCallKeyMaterialV1({
        crypto,
        offerSignal,
        answerSignal,
        sharedSecret
      })
    });
  } finally {
    sharedSecret.fill(0);
  }
}

export async function acceptCallAnswerV1({ crypto, pending: pendingValue, answerSignal: answerValue, at = new Date() }) {
  assertKEM(crypto);
  const pending = validatePendingCallOfferV1(pendingValue);
  const answerSignal = validateCallSignalV1(answerValue);
  if (answerSignal.kind !== "answer" || answerSignal.callID !== pending.offerSignal.callID ||
      !isCallSignalFreshV1(answerSignal, at) ||
      !await isCallAnswerCompatibleV1(crypto, answerSignal.answer, pending.offerSignal.offer)) {
    throw new CallV1Error("invalidAnswer", "Call answer is invalid, expired, or incompatible.");
  }
  const answerDigest = await callSignalDigestV1(crypto, answerSignal);
  if (pending.acceptedAnswerDigest !== null && !equalBytes(
    requireBase64(pending.acceptedAnswerDigest, 32, "Accepted answer digest"),
    answerDigest
  )) {
    throw new CallV1Error("signalFork", "A competing call answer was already accepted.");
  }
  let sharedSecret;
  try {
    sharedSecret = new Uint8Array(await crypto.decapsulate(
      requireBase64(answerSignal.answer.kemCiphertext, noctweaveCallV1.kemCiphertextBytes, "Call ML-KEM ciphertext"),
      requireBase64(pending.agreementKey.privateKeyData, noctweaveCallV1.agreementSecretKeyBytes, "Call ML-KEM private key")
    ));
    if (sharedSecret.byteLength !== noctweaveCallV1.sharedSecretBytes) {
      throw new CallV1Error("invalidAnswer", "ML-KEM-768 decapsulation returned invalid call material.");
    }
    return freezeWire({
      pending: {
        ...pending,
        acceptedAnswerDigest: encodeBase64(answerDigest)
      },
      keyMaterial: await deriveCallKeyMaterialV1({
        crypto,
        offerSignal: pending.offerSignal,
        answerSignal,
        sharedSecret
      })
    });
  } catch (error) {
    if (error instanceof CallV1Error) throw error;
    throw new CallV1Error("invalidAnswer", "Call ML-KEM decapsulation failed.");
  } finally {
    sharedSecret?.fill(0);
  }
}

export async function deriveCallKeyMaterialV1({ crypto, offerSignal: offerValue, answerSignal: answerValue, sharedSecret }) {
  const offerSignal = validateCallSignalV1(offerValue);
  const answerSignal = validateCallSignalV1(answerValue);
  const secret = new Uint8Array(bytes(sharedSecret, "Call shared secret"));
  try {
    if (secret.byteLength !== noctweaveCallV1.sharedSecretBytes || offerSignal.kind !== "offer" ||
        answerSignal.kind !== "answer" || offerSignal.callID !== answerSignal.callID ||
        !await isCallAnswerCompatibleV1(crypto, answerSignal.answer, offerSignal.offer)) {
      throw new CallV1Error("transcriptMismatch", "Call handshake transcript is invalid.");
    }
    const transcriptDigest = await cryptoSha256(crypto, concatBytes(
      transcriptDomain,
      Uint8Array.of(0),
      canonicalJsonBytes(offerSignal),
      Uint8Array.of(0),
      canonicalJsonBytes(answerSignal)
    ));
    const rootKey = await cryptoHkdfSha256(crypto, {
      ikm: secret,
      salt: transcriptDigest,
      info: concatBytes(rootDomain, Uint8Array.of(0), encoder.encode(offerSignal.callID)),
      length: 32
    });
    return freezeWire({
      callID: offerSignal.callID,
      transcriptDigest: encodeBase64(transcriptDigest),
      rootKey: encodeBase64(rootKey)
    });
  } finally {
    secret.fill(0);
  }
}

export function validateCallKeyMaterialV1(value) {
  requireExactRecord(value, ["callID", "transcriptDigest", "rootKey"], [], "Call key material");
  return freezeWire({
    callID: canonicalUUID(value.callID, "Call key material ID"),
    transcriptDigest: encodeBase64(requireBase64(value.transcriptDigest, 32, "Call transcript digest")),
    rootKey: encodeBase64(requireBase64(value.rootKey, 32, "Call root key"))
  });
}

export async function callMediaKeyV1({ crypto, material: materialValue, senderRole, epoch }) {
  const material = validateCallKeyMaterialV1(materialValue);
  const role = requireEnum(senderRole, roles, "Call media sender role");
  const normalizedEpoch = requireInteger(epoch, "Call media epoch", 0, 0xffffffff);
  return cryptoHkdfSha256(crypto, {
    ikm: requireBase64(material.rootKey, 32, "Call root key"),
    salt: requireBase64(material.transcriptDigest, 32, "Call transcript digest"),
    info: concatBytes(
      mediaKeyDomain,
      Uint8Array.of(0),
      encoder.encode(material.callID),
      Uint8Array.of(0),
      encoder.encode(role),
      uint32Bytes(normalizedEpoch)
    ),
    length: 32
  });
}

export function validateCallMediaFrameV1(value) {
  requireExactRecord(value, ["trackID", "timestamp", "flags", "payload"], [], "Call media frame");
  const payload = bytes(value.payload, "Call media payload");
  if (payload.byteLength === 0 || payload.byteLength > noctweaveCallV1.maximumMediaPayloadBytes) {
    throw new CallV1Error("invalidMediaFrame", "Call media payload exceeds its bounds.");
  }
  return Object.freeze({
    trackID: requireInteger(value.trackID, "Call media trackID", 1, 0xffff),
    timestamp: requireUInt64(value.timestamp, "Call media timestamp"),
    flags: requireInteger(value.flags, "Call media flags", 0, 0x07),
    payload: new Uint8Array(payload)
  });
}

export function validateSealedCallMediaFrameV1(value) {
  requireExactRecord(value, ["version", "epoch", "sequence", "ciphertext"], [], "Sealed call media frame");
  const ciphertext = requireBase64(value.ciphertext, undefined, "Sealed call media ciphertext");
  if (value.version !== 1 || !noctweaveCallV1.allowedSealedMediaByteCounts.includes(ciphertext.byteLength)) {
    throw new CallV1Error("invalidMediaFrame", "Sealed call media frame is invalid.");
  }
  return freezeWire({
    version: 1,
    epoch: requireInteger(value.epoch, "Call media epoch", 0, 0xffffffff),
    sequence: requireInteger(value.sequence, "Call media sequence", 1, maximumSafeSequence),
    ciphertext: value.ciphertext
  });
}

export async function sealCallMediaFrameV1({
  crypto,
  frame: frameValue,
  material: materialValue,
  senderRole,
  epoch,
  sequence,
  targetByteCount,
  deterministicPadding
}) {
  const frame = validateCallMediaFrameV1(frameValue);
  const material = validateCallKeyMaterialV1(materialValue);
  const role = requireEnum(senderRole, roles, "Call media sender role");
  const normalizedEpoch = requireInteger(epoch, "Call media epoch", 0, 0xffffffff);
  const normalizedSequence = requireInteger(sequence, "Call media sequence", 1, maximumSafeSequence);
  const minimum = mediaHeaderBytes + frame.payload.byteLength + gcmTagBytes;
  const sealedByteCount = targetByteCount === undefined
    ? noctweaveCallV1.allowedSealedMediaByteCounts.find((count) => count >= minimum)
    : targetByteCount;
  if (!noctweaveCallV1.allowedSealedMediaByteCounts.includes(sealedByteCount) || sealedByteCount < minimum) {
    throw new CallV1Error("invalidMediaFrame", "Call media frame cannot fit the selected padding bucket.");
  }
  const paddingCount = sealedByteCount - gcmTagBytes - mediaHeaderBytes - frame.payload.byteLength;
  const padding = deterministicPadding === undefined
    ? await cryptoRandomBytes(crypto, paddingCount)
    : new Uint8Array(bytes(deterministicPadding, "Call deterministic padding"));
  if (padding.byteLength !== paddingCount) {
    throw new CallV1Error("invalidMediaFrame", "Call media padding length is invalid.");
  }
  const plaintext = concatBytes(
    Uint8Array.of(1),
    uint16Bytes(frame.trackID),
    uint64Bytes(frame.timestamp),
    Uint8Array.of(frame.flags),
    uint16Bytes(frame.payload.byteLength),
    frame.payload,
    padding
  );
  const ciphertext = bytes(await crypto.aesGcmEncrypt({
    key: await callMediaKeyV1({ crypto, material, senderRole: role, epoch: normalizedEpoch }),
    nonce: concatBytes(uint32Bytes(normalizedEpoch), uint64Bytes(normalizedSequence)),
    plaintext,
    additionalData: callMediaAADV1({
      material,
      senderRole: role,
      epoch: normalizedEpoch,
      sequence: normalizedSequence,
      sealedByteCount
    })
  }), "Call AES-GCM output");
  if (ciphertext.byteLength !== sealedByteCount) {
    throw new CallV1Error("invalidMediaFrame", "Call AES-GCM output length is invalid.");
  }
  return validateSealedCallMediaFrameV1({
    version: 1,
    epoch: normalizedEpoch,
    sequence: normalizedSequence,
    ciphertext: encodeBase64(ciphertext)
  });
}

export async function openCallMediaFrameV1({ crypto, sealed: sealedValue, material: materialValue, senderRole }) {
  const sealed = validateSealedCallMediaFrameV1(sealedValue);
  const material = validateCallKeyMaterialV1(materialValue);
  const role = requireEnum(senderRole, roles, "Call media sender role");
  let plaintext;
  try {
    plaintext = bytes(await crypto.aesGcmDecrypt({
      key: await callMediaKeyV1({ crypto, material, senderRole: role, epoch: sealed.epoch }),
      nonce: concatBytes(uint32Bytes(sealed.epoch), uint64Bytes(sealed.sequence)),
      ciphertext: requireBase64(sealed.ciphertext, undefined, "Call media ciphertext"),
      additionalData: callMediaAADV1({
        material,
        senderRole: role,
        epoch: sealed.epoch,
        sequence: sealed.sequence,
        sealedByteCount: requireBase64(sealed.ciphertext).byteLength
      })
    }), "Call media plaintext");
  } catch {
    throw new CallV1Error("authenticationFailed", "Call media authentication failed.");
  }
  if (plaintext.byteLength < mediaHeaderBytes || plaintext[0] !== 1) {
    throw new CallV1Error("invalidMediaFrame", "Call media plaintext header is invalid.");
  }
  const payloadLength = readUInt16(plaintext, 12);
  if (payloadLength <= 0 || mediaHeaderBytes + payloadLength > plaintext.byteLength) {
    throw new CallV1Error("invalidMediaFrame", "Call media payload length is invalid.");
  }
  return validateCallMediaFrameV1({
    trackID: readUInt16(plaintext, 1),
    timestamp: readUInt64(plaintext, 3),
    flags: plaintext[11],
    payload: plaintext.slice(mediaHeaderBytes, mediaHeaderBytes + payloadLength)
  });
}

export class CallMediaSenderV1 {
  constructor({ material, role, epoch = 0 }) {
    this.material = validateCallKeyMaterialV1(material);
    this.role = requireEnum(role, roles, "Call media sender role");
    this.epoch = requireInteger(epoch, "Call media epoch", 0, 0xffffffff);
    this.nextSequence = 1;
  }

  async seal({ crypto, frame, targetByteCount }) {
    if (this.nextSequence > maximumSafeSequence) throw new CallV1Error("sequenceExhausted");
    const sealed = await sealCallMediaFrameV1({
      crypto,
      frame,
      material: this.material,
      senderRole: this.role,
      epoch: this.epoch,
      sequence: this.nextSequence,
      targetByteCount
    });
    this.nextSequence += 1;
    return sealed;
  }

  rotateEpoch() {
    if (this.epoch === 0xffffffff) throw new CallV1Error("sequenceExhausted");
    this.epoch += 1;
    this.nextSequence = 1;
  }
}

export class CallMediaReceiverV1 {
  constructor({ material, remoteRole }) {
    this.material = validateCallKeyMaterialV1(material);
    this.remoteRole = requireEnum(remoteRole, roles, "Call remote role");
    this.highestEpoch = null;
    this.replayWindows = new Map();
  }

  async open({ crypto, sealed: sealedValue }) {
    const sealed = validateSealedCallMediaFrameV1(sealedValue);
    if (this.highestEpoch === null && sealed.epoch !== 0) throw new CallV1Error("invalidEpoch");
    if (this.highestEpoch !== null &&
        (sealed.epoch < Math.max(0, this.highestEpoch - 1) ||
         sealed.epoch > Math.min(0xffffffff, this.highestEpoch + 1))) {
      throw new CallV1Error("invalidEpoch");
    }
    const window = this.replayWindows.get(sealed.epoch) ?? new ReplayWindowV1();
    if (window.contains(sealed.sequence)) throw new CallV1Error("replay");
    const frame = await openCallMediaFrameV1({
      crypto,
      sealed,
      material: this.material,
      senderRole: this.remoteRole
    });
    if (!window.insert(sealed.sequence)) throw new CallV1Error("replay");
    this.replayWindows.set(sealed.epoch, window);
    this.highestEpoch = Math.max(this.highestEpoch ?? sealed.epoch, sealed.epoch);
    for (const epoch of this.replayWindows.keys()) {
      if (epoch !== this.highestEpoch && epoch !== this.highestEpoch - 1) {
        this.replayWindows.delete(epoch);
      }
    }
    return frame;
  }
}

export class CallStateMachineV1 {
  static async create({ crypto, offerSignal: offerValue, at = new Date() }) {
    const offerSignal = validateCallSignalV1(offerValue);
    if (offerSignal.kind !== "offer" || !isCallSignalFreshV1(offerSignal, at)) {
      throw new CallV1Error("invalidOffer");
    }
    const state = new CallStateMachineV1();
    state.crypto = crypto;
    state.callID = offerSignal.callID;
    state.offerSignal = offerSignal;
    state.phase = "ringing";
    state.terminationReason = null;
    state.answerSignal = null;
    state.lastSequence = new Map([["initiator", offerSignal.sequence]]);
    state.lastDigest = new Map([["initiator", encodeBase64(await callSignalDigestV1(crypto, offerSignal))]]);
    return state;
  }

  async apply(signalValue, at = new Date()) {
    const signal = validateCallSignalV1(signalValue);
    if (signal.callID !== this.callID || !isCallSignalFreshV1(signal, at)) {
      throw new CallV1Error("invalidSignal");
    }
    const digest = await callSignalDigestV1(this.crypto, signal);
    const priorSequence = this.lastSequence.get(signal.senderRole);
    if (priorSequence !== undefined && signal.sequence < priorSequence) return "stale";
    if (priorSequence !== undefined && signal.sequence === priorSequence) {
      if (!equalBytes(requireBase64(this.lastDigest.get(signal.senderRole), 32), digest)) {
        throw new CallV1Error("signalFork");
      }
      return "exactReplay";
    }
    if (this.phase === "ended") return "stale";
    if (signal.kind === "offer") throw new CallV1Error("invalidTransition");
    if (signal.kind === "ringing" && (this.phase !== "ringing" || signal.senderRole !== "responder")) {
      throw new CallV1Error("invalidTransition");
    }
    if (signal.kind === "answer") {
      if (this.phase !== "ringing" ||
          !await isCallAnswerCompatibleV1(this.crypto, signal.answer, this.offerSignal.offer)) {
        throw new CallV1Error("transcriptMismatch");
      }
      this.answerSignal = signal;
      this.phase = "connecting";
    } else if (signal.kind === "candidate" && !["ringing", "connecting", "active"].includes(this.phase)) {
      throw new CallV1Error("invalidTransition");
    } else if (signal.kind === "connected") {
      if (!["connecting", "active"].includes(this.phase)) throw new CallV1Error("invalidTransition");
      this.phase = "active";
    } else if (["declined", "canceled", "ended"].includes(signal.kind)) {
      this.phase = "ended";
      this.terminationReason = signal.terminationReason;
    }
    this.lastSequence.set(signal.senderRole, signal.sequence);
    this.lastDigest.set(signal.senderRole, encodeBase64(digest));
    return "applied";
  }
}

function callMediaAADV1({ material, senderRole, epoch, sequence, sealedByteCount }) {
  return concatBytes(
    mediaAADDomain,
    Uint8Array.of(0),
    encoder.encode(material.callID),
    Uint8Array.of(0),
    requireBase64(material.transcriptDigest, 32, "Call transcript digest"),
    Uint8Array.of(0),
    encoder.encode(senderRole),
    uint32Bytes(epoch),
    uint64Bytes(sequence),
    uint32Bytes(sealedByteCount)
  );
}

class ReplayWindowV1 {
  constructor() {
    this.highest = 0;
    this.seen = new Set();
  }

  contains(sequence) {
    return sequence <= 0 ||
      (this.highest >= noctweaveCallV1.replayWindowSize &&
       sequence <= this.highest - noctweaveCallV1.replayWindowSize) ||
      this.seen.has(sequence);
  }

  insert(sequence) {
    if (this.contains(sequence)) return false;
    this.highest = Math.max(this.highest, sequence);
    const floor = Math.max(0, this.highest - noctweaveCallV1.replayWindowSize);
    this.seen = new Set([...this.seen].filter((value) => value > floor));
    this.seen.add(sequence);
    return true;
  }
}

function assertKEM(crypto) {
  if (typeof crypto?.generateKemKeypair !== "function" || typeof crypto?.encapsulate !== "function" ||
      typeof crypto?.decapsulate !== "function") {
    throw new CallV1Error("pqcUnavailable", "ML-KEM-768 operations are required for calls.");
  }
  const profile = typeof crypto.profile === "function" ? crypto.profile()?.kem : null;
  if (profile && (profile.algorithm !== "ML-KEM-768" ||
      profile.publicKeyLength !== noctweaveCallV1.agreementPublicKeyBytes ||
      profile.secretKeyLength !== noctweaveCallV1.agreementSecretKeyBytes ||
      profile.ciphertextLength !== noctweaveCallV1.kemCiphertextBytes ||
      profile.sharedSecretLength !== noctweaveCallV1.sharedSecretBytes)) {
    throw new CallV1Error("pqcUnavailable", "The configured KEM is not the Noctweave ML-KEM-768 profile.");
  }
}

function boundedIdentifier(value, label, maximumBytes = 64) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value ||
      encoder.encode(value).byteLength > maximumBytes || !identifierPattern.test(value)) {
    throw new CallV1Error("invalidIdentifier", `${label} is outside protocol bounds.`);
  }
  return value;
}

function requireEnum(value, allowed, label) {
  if (!allowed.has(value)) throw new CallV1Error("invalidEnum", `${label} is invalid.`);
  return value;
}

function canonicalUUID(value, label, normalize = false) {
  if (typeof value !== "string") throw new CallV1Error("invalidIdentifier", `${label} is invalid.`);
  const canonical = value.toUpperCase();
  if (!uuidPattern.test(canonical) || (!normalize && canonical !== value)) {
    throw new CallV1Error("invalidIdentifier", `${label} must be a canonical uppercase UUID.`);
  }
  return canonical;
}

function addWholeSeconds(value, seconds) {
  return swiftISODate(new Date(timestampMilliseconds(value) + seconds * 1_000));
}

function earlierTimestamp(left, right) {
  return timestampMilliseconds(left) <= timestampMilliseconds(right) ? left : right;
}

function requireUInt64(value, label) {
  const bigint = typeof value === "bigint" ? value : BigInt(requireInteger(value, label, 0, maximumSafeSequence));
  if (bigint < 0n || bigint > 0xffffffffffffffffn) {
    throw new CallV1Error("invalidMediaFrame", `${label} is outside UInt64.`);
  }
  return bigint <= BigInt(maximumSafeSequence) ? Number(bigint) : bigint;
}

function readUInt16(value, offset) {
  return (value[offset] << 8) | value[offset + 1];
}

function readUInt64(value, offset) {
  let result = 0n;
  for (let index = offset; index < offset + 8; index += 1) {
    result = (result << 8n) | BigInt(value[index]);
  }
  return result <= BigInt(maximumSafeSequence) ? Number(result) : result;
}
