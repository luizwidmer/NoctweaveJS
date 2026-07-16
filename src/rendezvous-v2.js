import { bytes } from "./crypto/webcrypto.js";
import {
  concatBytes,
  cryptoHkdfSha256,
  cryptoHmacSha256,
  cryptoRandomBytes,
  cryptoSha256,
  encodeBase64,
  equalBytes,
  freezeWire,
  lengthPrefixed,
  requireBase64,
  requireCanonicalTimestamp,
  requireInteger,
  requireRecord,
  timestampBytes,
  timestampMilliseconds,
  uint16Bytes,
  uint32Bytes,
  uint64Bytes
} from "./private-v2.js";

const encoder = new TextEncoder();
const ML_KEM_768_PUBLIC_KEY_BYTES = 1_184;
const ML_KEM_768_SECRET_KEY_BYTES = 2_400;
const ML_KEM_768_CIPHERTEXT_BYTES = 1_088;
const ML_KEM_SHARED_SECRET_BYTES = 32;
const rendezvousPurposes = new Set([
  "contactPairing",
  "endpointAdmission",
  "relayMigration",
  "groupInvitation",
  "historyTransfer"
]);
const rendezvousRoles = new Set(["offerer", "responder"]);
const rendezvousMessageKinds = new Set([
  "contactOffer",
  "contactAcceptance",
  "confirmation",
  "abort"
]);

export const noctweaveRendezvousV2 = Object.freeze({
  version: 2,
  maximumLifetimeSeconds: 10 * 60,
  tokenBytes: 32,
  tokenDigestBytes: 32,
  transportCapabilityBytes: 32,
  maximumKemCiphertextBytes: 4_096,
  maximumFramesPerDirection: 32,
  maximumFramePlaintextBytes: 60 * 1_024,
  maximumLedgerEntries: 256,
  paddingBuckets: Object.freeze([4_096, 16_384, 65_536])
});

export const rendezvousPurposeV2 = Object.freeze({
  contactPairing: "contactPairing",
  endpointAdmission: "endpointAdmission",
  relayMigration: "relayMigration",
  groupInvitation: "groupInvitation",
  historyTransfer: "historyTransfer"
});

export const rendezvousLimitsV2 = Object.freeze({
  contactPairing: Object.freeze({
    maximumFrames: 16,
    maximumFramePlaintextBytes: noctweaveRendezvousV2.maximumFramePlaintextBytes
  })
});

export class RendezvousV2Error extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "RendezvousV2Error";
    this.code = code;
  }
}

export async function createRendezvousTransportCapabilityV2({ crypto, expiresAt }) {
  const normalizedExpiry = requireCanonicalTimestamp(expiresAt, "Rendezvous capability expiry");
  const opaqueValue = await cryptoRandomBytes(crypto, noctweaveRendezvousV2.transportCapabilityBytes);
  return freezeWire({ opaqueValue: encodeBase64(opaqueValue), expiresAt: normalizedExpiry });
}

export function validateRendezvousTransportCapabilityV2(value) {
  requireRecord(value, "Rendezvous transport capability");
  requireBase64(
    value.opaqueValue,
    noctweaveRendezvousV2.transportCapabilityBytes,
    "Rendezvous transport capability"
  );
  return freezeWire({
    opaqueValue: value.opaqueValue,
    expiresAt: requireCanonicalTimestamp(value.expiresAt, "Rendezvous capability expiry")
  });
}

export function validateRendezvousLimitsV2(value) {
  requireRecord(value, "Rendezvous limits");
  return freezeWire({
    maximumFrames: requireInteger(
      value.maximumFrames,
      "Rendezvous maximumFrames",
      1,
      noctweaveRendezvousV2.maximumFramesPerDirection
    ),
    maximumFramePlaintextBytes: requireInteger(
      value.maximumFramePlaintextBytes,
      "Rendezvous maximumFramePlaintextBytes",
      1,
      noctweaveRendezvousV2.maximumFramePlaintextBytes
    )
  });
}

export function validateRendezvousOfferV2(value) {
  requireRecord(value, "Rendezvous offer");
  if (value.version !== noctweaveRendezvousV2.version || !rendezvousPurposes.has(value.purpose)) {
    throw new RendezvousV2Error("invalidOffer", "Rendezvous offer version or purpose is invalid.");
  }
  const transportCapability = validateRendezvousTransportCapabilityV2(value.transportCapability);
  requireBase64(value.oneTimeTokenDigest, 32, "Rendezvous token digest");
  requireBase64(value.ephemeralAgreementPublicKey, ML_KEM_768_PUBLIC_KEY_BYTES, "Rendezvous ML-KEM public key");
  const createdAt = requireCanonicalTimestamp(value.createdAt, "Rendezvous creation time");
  const expiresAt = requireCanonicalTimestamp(value.expiresAt, "Rendezvous expiry time");
  const lifetime = timestampMilliseconds(expiresAt) - timestampMilliseconds(createdAt);
  if (transportCapability.expiresAt !== expiresAt || lifetime <= 0 ||
      lifetime > noctweaveRendezvousV2.maximumLifetimeSeconds * 1_000) {
    throw new RendezvousV2Error("invalidOffer", "Rendezvous lifetime or transport expiry is invalid.");
  }
  return freezeWire({
    version: noctweaveRendezvousV2.version,
    purpose: value.purpose,
    transportCapability,
    oneTimeTokenDigest: value.oneTimeTokenDigest,
    ephemeralAgreementPublicKey: value.ephemeralAgreementPublicKey,
    createdAt,
    expiresAt,
    limits: validateRendezvousLimitsV2(value.limits)
  });
}

export function rendezvousOfferTranscriptBytesV2(value) {
  const offer = validateRendezvousOfferV2(value);
  return concatBytes(
    lengthPrefixed(encoder.encode("Noctweave/rendezvous-v2/public-offer")),
    uint16Bytes(offer.version),
    lengthPrefixed(encoder.encode(offer.purpose)),
    lengthPrefixed(requireBase64(offer.transportCapability.opaqueValue, 32, "transport capability")),
    timestampBytes(offer.transportCapability.expiresAt),
    lengthPrefixed(requireBase64(offer.oneTimeTokenDigest, 32, "token digest")),
    lengthPrefixed(requireBase64(offer.ephemeralAgreementPublicKey, ML_KEM_768_PUBLIC_KEY_BYTES, "ML-KEM key")),
    timestampBytes(offer.createdAt),
    timestampBytes(offer.expiresAt),
    uint16Bytes(offer.limits.maximumFrames),
    uint32Bytes(offer.limits.maximumFramePlaintextBytes)
  );
}

export async function rendezvousOfferDigestV2(crypto, value) {
  return cryptoSha256(crypto, rendezvousOfferTranscriptBytesV2(value));
}

export async function createPendingRendezvousOfferV2({
  crypto,
  transportCapability,
  createdAt,
  purpose = rendezvousPurposeV2.contactPairing,
  limits = rendezvousLimitsV2.contactPairing
}) {
  if (purpose !== rendezvousPurposeV2.contactPairing) {
    throw new RendezvousV2Error("purposeDisabled", "Only contact pairing rendezvous is enabled.");
  }
  assertKemProfile(crypto);
  const capability = validateRendezvousTransportCapabilityV2(transportCapability);
  const normalizedCreatedAt = requireCanonicalTimestamp(createdAt, "Rendezvous creation time");
  const keypair = await crypto.generateKemKeypair();
  const publicKey = bytes(keypair?.publicKey, "ML-KEM public key");
  const secretKey = bytes(keypair?.secretKey, "ML-KEM secret key");
  if (publicKey.byteLength !== ML_KEM_768_PUBLIC_KEY_BYTES || secretKey.byteLength !== ML_KEM_768_SECRET_KEY_BYTES) {
    throw new Error("ML-KEM-768 generated an invalid keypair.");
  }
  const oneTimeToken = await cryptoRandomBytes(crypto, noctweaveRendezvousV2.tokenBytes);
  const tokenDigest = await cryptoSha256(crypto, oneTimeToken);
  const offer = validateRendezvousOfferV2({
    version: noctweaveRendezvousV2.version,
    purpose,
    transportCapability: capability,
    oneTimeTokenDigest: encodeBase64(tokenDigest),
    ephemeralAgreementPublicKey: encodeBase64(publicKey),
    createdAt: normalizedCreatedAt,
    expiresAt: capability.expiresAt,
    limits
  });
  return freezeWire({
    offer,
    ephemeralAgreementKey: {
      privateKeyData: encodeBase64(secretKey),
      publicKeyData: encodeBase64(publicKey)
    },
    oneTimeToken: encodeBase64(oneTimeToken)
  });
}

export async function validatePendingRendezvousOfferV2(crypto, value) {
  assertKemProfile(crypto);
  requireRecord(value, "Pending rendezvous offer");
  const offer = validateRendezvousOfferV2(value.offer);
  requireRecord(value.ephemeralAgreementKey, "Pending rendezvous ML-KEM keypair");
  const privateKeyData = requireBase64(
    value.ephemeralAgreementKey.privateKeyData,
    ML_KEM_768_SECRET_KEY_BYTES,
    "Pending rendezvous ML-KEM private key"
  );
  const publicKeyData = requireBase64(
    value.ephemeralAgreementKey.publicKeyData,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    "Pending rendezvous ML-KEM public key"
  );
  const oneTimeToken = requireBase64(value.oneTimeToken, 32, "Pending rendezvous token");
  const digest = await cryptoSha256(crypto, oneTimeToken);
  if (!equalBytes(publicKeyData, requireBase64(offer.ephemeralAgreementPublicKey, ML_KEM_768_PUBLIC_KEY_BYTES, "Offer key")) ||
      !equalBytes(digest, requireBase64(offer.oneTimeTokenDigest, 32, "Offer token digest"))) {
    throw new RendezvousV2Error("invalidOffer", "Pending rendezvous secrets do not match the public offer.");
  }
  const keyCheck = await crypto.encapsulate(publicKeyData);
  const checkCiphertext = bytes(keyCheck?.ciphertext, "ML-KEM key-check ciphertext");
  const encapsulatedSecret = new Uint8Array(bytes(keyCheck?.sharedSecret, "ML-KEM key-check shared secret"));
  const decapsulatedSecret = new Uint8Array(await crypto.decapsulate(checkCiphertext, privateKeyData));
  try {
    if (checkCiphertext.byteLength !== ML_KEM_768_CIPHERTEXT_BYTES ||
        encapsulatedSecret.byteLength !== ML_KEM_SHARED_SECRET_BYTES ||
        decapsulatedSecret.byteLength !== ML_KEM_SHARED_SECRET_BYTES ||
        !equalBytes(encapsulatedSecret, decapsulatedSecret)) {
      throw new RendezvousV2Error("invalidOffer", "Pending rendezvous ML-KEM keypair does not match.");
    }
  } finally {
    encapsulatedSecret.fill(0);
    decapsulatedSecret.fill(0);
  }
  const result = {
    offer,
    ephemeralAgreementKey: {
      privateKeyData: encodeBase64(privateKeyData),
      publicKeyData: encodeBase64(publicKeyData)
    },
    oneTimeToken: encodeBase64(oneTimeToken)
  };
  if (value.redeemedAt !== undefined && value.redeemedAt !== null) {
    const redeemedAt = requireCanonicalTimestamp(value.redeemedAt, "Rendezvous redemption time");
    if (timestampMilliseconds(redeemedAt) < timestampMilliseconds(offer.createdAt) ||
        timestampMilliseconds(redeemedAt) >= timestampMilliseconds(offer.expiresAt)) {
      throw new RendezvousV2Error("invalidOffer", "Rendezvous redemption time is outside the offer lifetime.");
    }
    result.redeemedAt = redeemedAt;
  }
  return freezeWire(result);
}

export async function rendezvousRedemptionSecretV2(crypto, pendingValue) {
  const pending = await validatePendingRendezvousOfferV2(crypto, pendingValue);
  if (pending.redeemedAt !== undefined) {
    throw new RendezvousV2Error("alreadyRedeemed");
  }
  return freezeWire({ oneTimeToken: pending.oneTimeToken });
}

export function rendezvousOpenProofBytesV2(value) {
  const request = validateOpenShape(value);
  return concatBytes(
    lengthPrefixed(encoder.encode("Noctweave/rendezvous-v2/open-proof")),
    uint16Bytes(request.version),
    lengthPrefixed(encoder.encode(request.purpose)),
    lengthPrefixed(requireBase64(request.offerDigest, 32, "offer digest")),
    lengthPrefixed(requireBase64(request.kemCiphertext, undefined, "KEM ciphertext")),
    timestampBytes(request.openedAt)
  );
}

export function rendezvousOpenTranscriptBytesV2(value) {
  const request = validateOpenShape(value);
  return concatBytes(
    rendezvousOpenProofBytesV2(request),
    lengthPrefixed(requireBase64(request.tokenProof, 32, "token proof"))
  );
}

export async function createRendezvousOpenV2({
  crypto,
  offer: offerValue,
  redemptionSecret,
  expectedPurpose = rendezvousPurposeV2.contactPairing,
  at
}) {
  assertKemProfile(crypto);
  const offer = validateOfferUse(offerValue, expectedPurpose, at);
  requireRecord(redemptionSecret, "Rendezvous redemption secret");
  const token = requireBase64(redemptionSecret.oneTimeToken, 32, "Rendezvous redemption token");
  const tokenDigest = await cryptoSha256(crypto, token);
  if (!equalBytes(tokenDigest, requireBase64(offer.oneTimeTokenDigest, 32, "Offer token digest"))) {
    throw new RendezvousV2Error("invalidRedemptionSecret");
  }
  const encapsulated = await crypto.encapsulate(
    requireBase64(offer.ephemeralAgreementPublicKey, ML_KEM_768_PUBLIC_KEY_BYTES, "Offer ML-KEM key")
  );
  const kemCiphertext = bytes(encapsulated?.ciphertext, "ML-KEM ciphertext");
  const sharedSecret = new Uint8Array(bytes(encapsulated?.sharedSecret, "ML-KEM shared secret"));
  if (kemCiphertext.byteLength !== ML_KEM_768_CIPHERTEXT_BYTES ||
      sharedSecret.byteLength !== ML_KEM_SHARED_SECRET_BYTES) {
    sharedSecret.fill(0);
    throw new Error("ML-KEM-768 encapsulation returned invalid output.");
  }
  const openedAt = requireCanonicalTimestamp(at, "Rendezvous open time");
  const offerDigest = await rendezvousOfferDigestV2(crypto, offer);
  const unsigned = {
    version: noctweaveRendezvousV2.version,
    purpose: offer.purpose,
    offerDigest: encodeBase64(offerDigest),
    kemCiphertext: encodeBase64(kemCiphertext),
    tokenProof: encodeBase64(new Uint8Array(32)),
    openedAt
  };
  const tokenProof = await cryptoHmacSha256(crypto, {
    key: token,
    data: rendezvousOpenProofBytesV2(unsigned)
  });
  const request = validateRendezvousOpenV2({ ...unsigned, tokenProof: encodeBase64(tokenProof) }, offer);
  try {
    return {
      request,
      session: await makeSession(crypto, "responder", sharedSecret, offer, request)
    };
  } finally {
    sharedSecret.fill(0);
  }
}

export function validateRendezvousOpenV2(value, offerValue) {
  const request = validateOpenShape(value);
  const offer = validateRendezvousOfferV2(offerValue);
  const openedAt = timestampMilliseconds(request.openedAt);
  if (request.purpose !== offer.purpose || openedAt < timestampMilliseconds(offer.createdAt) ||
      openedAt >= timestampMilliseconds(offer.expiresAt)) {
    throw new RendezvousV2Error("invalidOpen", "Rendezvous open purpose or time is invalid.");
  }
  return request;
}

export function createRendezvousRedemptionLedgerV2() {
  return freezeWire({ records: [] });
}

export function validateRendezvousRedemptionLedgerV2(value) {
  requireRecord(value, "Rendezvous redemption ledger");
  if (!Array.isArray(value.records) || value.records.length > noctweaveRendezvousV2.maximumLedgerEntries) {
    throw new RendezvousV2Error("invalidLedger");
  }
  const offers = new Set();
  const records = value.records.map((record) => {
    requireRecord(record, "Rendezvous redemption record");
    requireBase64(record.offerDigest, 32, "Redemption offer digest");
    requireBase64(record.openDigest, 32, "Redemption open digest");
    const redeemedAt = requireCanonicalTimestamp(record.redeemedAt, "Redemption time");
    const expiresAt = requireCanonicalTimestamp(record.expiresAt, "Redemption expiry");
    if (timestampMilliseconds(redeemedAt) >= timestampMilliseconds(expiresAt) || offers.has(record.offerDigest)) {
      throw new RendezvousV2Error("invalidLedger");
    }
    offers.add(record.offerDigest);
    return freezeWire({
      offerDigest: record.offerDigest,
      openDigest: record.openDigest,
      redeemedAt,
      expiresAt
    });
  });
  return freezeWire({ records });
}

export async function acceptRendezvousOpenV2({ crypto, pending: pendingValue, request: requestValue, ledger: ledgerValue, at }) {
  assertKemProfile(crypto);
  const pending = await validatePendingRendezvousOfferV2(crypto, pendingValue);
  if (pending.redeemedAt !== undefined) {
    throw new RendezvousV2Error("alreadyRedeemed");
  }
  const offer = validateOfferUse(pending.offer, pending.offer.purpose, at);
  const request = validateRendezvousOpenV2(requestValue, offer);
  const expectedOfferDigest = await rendezvousOfferDigestV2(crypto, offer);
  if (!equalBytes(expectedOfferDigest, requireBase64(request.offerDigest, 32, "Request offer digest"))) {
    throw new RendezvousV2Error("invalidOpen");
  }
  const token = requireBase64(pending.oneTimeToken, 32, "Pending rendezvous token");
  const expectedProof = await cryptoHmacSha256(crypto, {
    key: token,
    data: rendezvousOpenProofBytesV2(request)
  });
  if (!equalBytes(expectedProof, requireBase64(request.tokenProof, 32, "Request token proof"))) {
    throw new RendezvousV2Error("invalidOpen");
  }
  const ledger = validateRendezvousRedemptionLedgerV2(ledgerValue);
  const now = requireCanonicalTimestamp(at, "Rendezvous redemption time");
  const activeRecords = ledger.records.filter((record) =>
    timestampMilliseconds(record.expiresAt) > timestampMilliseconds(now));
  if (activeRecords.some((record) => record.offerDigest === request.offerDigest)) {
    throw new RendezvousV2Error("alreadyRedeemed");
  }
  if (activeRecords.length >= noctweaveRendezvousV2.maximumLedgerEntries) {
    throw new RendezvousV2Error("ledgerFull");
  }
  const sharedSecret = new Uint8Array(await crypto.decapsulate(
    requireBase64(request.kemCiphertext, ML_KEM_768_CIPHERTEXT_BYTES, "ML-KEM ciphertext"),
    requireBase64(pending.ephemeralAgreementKey.privateKeyData, ML_KEM_768_SECRET_KEY_BYTES, "ML-KEM private key")
  ));
  if (sharedSecret.byteLength !== ML_KEM_SHARED_SECRET_BYTES) {
    sharedSecret.fill(0);
    throw new RendezvousV2Error("invalidOpen");
  }
  try {
    const openDigest = await cryptoSha256(crypto, rendezvousOpenTranscriptBytesV2(request));
    return {
      pending: freezeWire({ ...pending, redeemedAt: now }),
      ledger: freezeWire({
        records: [
          ...activeRecords,
          freezeWire({
            offerDigest: request.offerDigest,
            openDigest: encodeBase64(openDigest),
            redeemedAt: now,
            expiresAt: offer.expiresAt
          })
        ]
      }),
      session: await makeSession(crypto, "offerer", sharedSecret, offer, request)
    };
  } finally {
    sharedSecret.fill(0);
  }
}

export function rendezvousFrameAuthenticatedDataV2(session, {
  senderRole,
  sequence,
  messageKind
}) {
  validateSession(session);
  if (!rendezvousRoles.has(senderRole) || !rendezvousMessageKinds.has(messageKind)) {
    throw new RendezvousV2Error("invalidFrame");
  }
  return concatBytes(
    lengthPrefixed(encoder.encode("Noctweave/rendezvous-v2/frame")),
    uint16Bytes(noctweaveRendezvousV2.version),
    lengthPrefixed(requireBase64(session.sessionId, 32, "session ID")),
    lengthPrefixed(requireBase64(session.transcriptDigest, 32, "transcript digest")),
    lengthPrefixed(encoder.encode(session.purpose)),
    lengthPrefixed(encoder.encode(senderRole)),
    uint64Bytes(sequence),
    lengthPrefixed(encoder.encode(messageKind))
  );
}

export async function sealRendezvousFrameV2({ crypto, session: sessionValue, plaintext, kind, at }) {
  const session = validateActiveSession(sessionValue, at);
  if (!rendezvousMessageKinds.has(kind)) {
    throw new RendezvousV2Error("unsupportedMessageKind");
  }
  if (session.nextOutboundSequence > session.limits.maximumFrames) {
    throw new RendezvousV2Error("frameLimitExceeded");
  }
  const cleartext = bytes(plaintext, "Rendezvous frame plaintext");
  if (cleartext.byteLength > session.limits.maximumFramePlaintextBytes) {
    throw new RendezvousV2Error("payloadTooLarge");
  }
  const padded = pad(cleartext);
  const nonce = await cryptoRandomBytes(crypto, 12);
  const additionalData = rendezvousFrameAuthenticatedDataV2(session, {
    senderRole: session.localRole,
    sequence: session.nextOutboundSequence,
    messageKind: kind
  });
  const sealed = bytes(await crypto.aesGcmEncrypt({
    key: session.sendKey,
    nonce,
    plaintext: padded,
    additionalData
  }), "Rendezvous AES-GCM output");
  if (sealed.byteLength !== padded.byteLength + 16) {
    throw new Error("AES-GCM returned an invalid output length.");
  }
  const frame = freezeWire({
    version: noctweaveRendezvousV2.version,
    sessionId: { rawValue: session.sessionId },
    purpose: session.purpose,
    senderRole: session.localRole,
    sequence: session.nextOutboundSequence,
    messageKind: kind,
    payload: {
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(sealed.subarray(0, -16)),
      tag: encodeBase64(sealed.subarray(-16))
    }
  });
  return {
    frame,
    session: { ...session, nextOutboundSequence: session.nextOutboundSequence + 1 }
  };
}

export async function openRendezvousFrameV2({ crypto, session: sessionValue, frame: frameValue, at }) {
  const session = validateActiveSession(sessionValue, at);
  const frame = validateRendezvousFrameV2(frameValue);
  if (frame.sessionId.rawValue !== session.sessionId) {
    throw new RendezvousV2Error("wrongSession");
  }
  if (frame.purpose !== session.purpose) {
    throw new RendezvousV2Error("wrongPurpose");
  }
  const opposite = session.localRole === "offerer" ? "responder" : "offerer";
  if (frame.senderRole !== opposite) {
    throw new RendezvousV2Error("wrongSenderRole");
  }
  if (frame.sequence !== session.nextInboundSequence) {
    throw new RendezvousV2Error("unexpectedSequence");
  }
  if (frame.sequence > session.limits.maximumFrames) {
    throw new RendezvousV2Error("frameLimitExceeded");
  }
  const ciphertext = requireBase64(frame.payload.ciphertext, undefined, "Frame ciphertext");
  const tag = requireBase64(frame.payload.tag, 16, "Frame tag");
  let padded;
  try {
    padded = await crypto.aesGcmDecrypt({
      key: session.receiveKey,
      nonce: requireBase64(frame.payload.nonce, 12, "Frame nonce"),
      ciphertext: concatBytes(ciphertext, tag),
      additionalData: rendezvousFrameAuthenticatedDataV2(session, {
        senderRole: frame.senderRole,
        sequence: frame.sequence,
        messageKind: frame.messageKind
      })
    });
  } catch {
    throw new RendezvousV2Error("decryptionFailed");
  }
  const plaintext = unpad(bytes(padded, "Rendezvous padded plaintext"), session.limits.maximumFramePlaintextBytes);
  if (paddingBucket(plaintext.byteLength) !== ciphertext.byteLength) {
    throw new RendezvousV2Error("invalidFrame");
  }
  return {
    plaintext,
    session: { ...session, nextInboundSequence: session.nextInboundSequence + 1 }
  };
}

export function validateRendezvousFrameV2(value) {
  requireRecord(value, "Rendezvous frame");
  requireRecord(value.sessionId, "Rendezvous session ID");
  requireRecord(value.payload, "Rendezvous encrypted payload");
  if (value.version !== 2 || !rendezvousPurposes.has(value.purpose) ||
      !rendezvousRoles.has(value.senderRole) || !rendezvousMessageKinds.has(value.messageKind)) {
    throw new RendezvousV2Error("invalidFrame");
  }
  requireBase64(value.sessionId.rawValue, 32, "Rendezvous session ID");
  const sequence = requireInteger(value.sequence, "Rendezvous frame sequence", 1, noctweaveRendezvousV2.maximumFramesPerDirection);
  requireBase64(value.payload.nonce, 12, "Rendezvous frame nonce");
  const ciphertext = requireBase64(value.payload.ciphertext, undefined, "Rendezvous frame ciphertext");
  requireBase64(value.payload.tag, 16, "Rendezvous frame tag");
  if (!noctweaveRendezvousV2.paddingBuckets.includes(ciphertext.byteLength)) {
    throw new RendezvousV2Error("invalidFrame");
  }
  return freezeWire({
    version: 2,
    sessionId: { rawValue: value.sessionId.rawValue },
    purpose: value.purpose,
    senderRole: value.senderRole,
    sequence,
    messageKind: value.messageKind,
    payload: {
      nonce: value.payload.nonce,
      ciphertext: value.payload.ciphertext,
      tag: value.payload.tag
    }
  });
}

function validateOpenShape(value) {
  requireRecord(value, "Rendezvous open");
  if (value.version !== 2 || !rendezvousPurposes.has(value.purpose)) {
    throw new RendezvousV2Error("invalidOpen");
  }
  requireBase64(value.offerDigest, 32, "Rendezvous offer digest");
  const kemCiphertext = requireBase64(value.kemCiphertext, undefined, "Rendezvous KEM ciphertext");
  if (kemCiphertext.byteLength === 0 || kemCiphertext.byteLength > noctweaveRendezvousV2.maximumKemCiphertextBytes) {
    throw new RendezvousV2Error("invalidOpen");
  }
  requireBase64(value.tokenProof, 32, "Rendezvous token proof");
  return freezeWire({
    version: 2,
    purpose: value.purpose,
    offerDigest: value.offerDigest,
    kemCiphertext: value.kemCiphertext,
    tokenProof: value.tokenProof,
    openedAt: requireCanonicalTimestamp(value.openedAt, "Rendezvous open time")
  });
}

function validateOfferUse(value, expectedPurpose, at) {
  const offer = validateRendezvousOfferV2(value);
  if (offer.purpose !== expectedPurpose) {
    throw new RendezvousV2Error("wrongPurpose");
  }
  if (offer.purpose !== rendezvousPurposeV2.contactPairing) {
    throw new RendezvousV2Error("purposeDisabled");
  }
  const instant = timestampMilliseconds(at, "Rendezvous use time");
  if (instant < timestampMilliseconds(offer.createdAt) || instant >= timestampMilliseconds(offer.expiresAt)) {
    throw new RendezvousV2Error("expired");
  }
  return offer;
}

async function makeSession(crypto, localRole, sharedSecret, offer, request) {
  const offerDigest = await rendezvousOfferDigestV2(crypto, offer);
  const requestDigest = await cryptoSha256(crypto, rendezvousOpenTranscriptBytesV2(request));
  const transcript = concatBytes(
    lengthPrefixed(encoder.encode("Noctweave/rendezvous-v2/session-transcript")),
    lengthPrefixed(offerDigest),
    lengthPrefixed(requestDigest)
  );
  const transcriptDigest = await cryptoSha256(crypto, transcript);
  const rootKey = await cryptoHkdfSha256(crypto, {
    ikm: sharedSecret,
    salt: requireBase64(offer.oneTimeTokenDigest, 32, "Offer token digest"),
    info: concatBytes(
      lengthPrefixed(encoder.encode("Noctweave/rendezvous-v2/session-root")),
      lengthPrefixed(transcriptDigest)
    ),
    length: 32
  });
  const offererToResponder = await cryptoHkdfSha256(crypto, {
    ikm: rootKey,
    salt: transcriptDigest,
    info: encoder.encode("Noctweave/rendezvous-v2/offerer-to-responder"),
    length: 32
  });
  const responderToOfferer = await cryptoHkdfSha256(crypto, {
    ikm: rootKey,
    salt: transcriptDigest,
    info: encoder.encode("Noctweave/rendezvous-v2/responder-to-offerer"),
    length: 32
  });
  const sessionId = await cryptoSha256(crypto, concatBytes(
    lengthPrefixed(encoder.encode("Noctweave/rendezvous-v2/session-id")),
    lengthPrefixed(transcriptDigest)
  ));
  rootKey.fill(0);
  return {
    sessionId: encodeBase64(sessionId),
    purpose: offer.purpose,
    localRole,
    transcriptDigest: encodeBase64(transcriptDigest),
    openedAt: request.openedAt,
    expiresAt: offer.expiresAt,
    limits: offer.limits,
    nextOutboundSequence: 1,
    nextInboundSequence: 1,
    sendKey: localRole === "offerer" ? offererToResponder : responderToOfferer,
    receiveKey: localRole === "offerer" ? responderToOfferer : offererToResponder
  };
}

function validateSession(value) {
  requireRecord(value, "Rendezvous session");
  requireBase64(value.sessionId, 32, "Rendezvous session ID");
  requireBase64(value.transcriptDigest, 32, "Rendezvous transcript digest");
  if (value.purpose !== "contactPairing" || !rendezvousRoles.has(value.localRole)) {
    throw new RendezvousV2Error("purposeDisabled");
  }
  const sendKey = bytes(value.sendKey, "Rendezvous send key");
  const receiveKey = bytes(value.receiveKey, "Rendezvous receive key");
  if (sendKey.byteLength !== 32 || receiveKey.byteLength !== 32) {
    throw new RendezvousV2Error("invalidOpen");
  }
  requireInteger(value.nextOutboundSequence, "Rendezvous outbound sequence", 1, noctweaveRendezvousV2.maximumFramesPerDirection + 1);
  requireInteger(value.nextInboundSequence, "Rendezvous inbound sequence", 1, noctweaveRendezvousV2.maximumFramesPerDirection + 1);
  return {
    ...value,
    openedAt: requireCanonicalTimestamp(value.openedAt, "Rendezvous open time"),
    expiresAt: requireCanonicalTimestamp(value.expiresAt, "Rendezvous expiry"),
    limits: validateRendezvousLimitsV2(value.limits),
    sendKey,
    receiveKey
  };
}

function validateActiveSession(value, at) {
  const session = validateSession(value);
  const instant = timestampMilliseconds(at, "Rendezvous frame time");
  if (instant < timestampMilliseconds(session.openedAt) || instant >= timestampMilliseconds(session.expiresAt)) {
    throw new RendezvousV2Error("expired");
  }
  return session;
}

function pad(plaintext) {
  const bucket = paddingBucket(plaintext.byteLength);
  if (bucket === undefined) {
    throw new RendezvousV2Error("payloadTooLarge");
  }
  const output = new Uint8Array(bucket);
  output.set(uint32Bytes(plaintext.byteLength));
  output.set(plaintext, 4);
  return output;
}

function unpad(padded, maximumPlaintextBytes) {
  if (!noctweaveRendezvousV2.paddingBuckets.includes(padded.byteLength) || padded.byteLength < 4) {
    throw new RendezvousV2Error("invalidFrame");
  }
  const length = (padded[0] * 0x1000000) + (padded[1] << 16) + (padded[2] << 8) + padded[3];
  if (length > maximumPlaintextBytes || length + 4 > padded.byteLength ||
      padded.subarray(length + 4).some((octet) => octet !== 0)) {
    throw new RendezvousV2Error("invalidFrame");
  }
  return padded.slice(4, length + 4);
}

function paddingBucket(plaintextBytes) {
  return noctweaveRendezvousV2.paddingBuckets.find((bucket) => plaintextBytes + 4 <= bucket);
}

function assertKemProfile(crypto) {
  if (typeof crypto?.generateKemKeypair !== "function" || typeof crypto?.encapsulate !== "function" ||
      typeof crypto?.decapsulate !== "function") {
    throw new TypeError("ML-KEM-768 operations are required.");
  }
  if (typeof crypto.profile === "function") {
    const profile = crypto.profile();
    if (profile?.kem?.algorithm !== "ML-KEM-768" ||
        profile.kem.publicKeyLength !== ML_KEM_768_PUBLIC_KEY_BYTES ||
        profile.kem.secretKeyLength !== ML_KEM_768_SECRET_KEY_BYTES ||
        profile.kem.ciphertextLength !== ML_KEM_768_CIPHERTEXT_BYTES ||
        profile.kem.sharedSecretLength !== ML_KEM_SHARED_SECRET_BYTES) {
      throw new TypeError("The rendezvous requires the exact ML-KEM-768 profile.");
    }
  }
}
