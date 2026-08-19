import { parseExactJSON } from "./strict-json.js";
import {
  concatBytes,
  cryptoHkdfSha256,
  cryptoRandomBytes,
  cryptoSha256,
  encodeBase64,
  equalBytes,
  freezeWire,
  lengthPrefixed,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireNonzeroFixedBase64,
  timestampBytes,
  timestampMilliseconds,
  uint16Bytes
} from "./private-v2.js";
import { bytes } from "./crypto/webcrypto.js";
import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./crypto/swift-canonical.js";
import {
  pairingLobbyRelayV1Limits,
  validatePairingLobbyLeaseV1
} from "./realtime-relay-v1.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const CAPABILITY_BYTES = 32;
const ML_KEM_PUBLIC_KEY_BYTES = 1_184;
const ML_KEM_SECRET_KEY_BYTES = 2_400;
const ML_KEM_CIPHERTEXT_BYTES = 1_088;
const ML_KEM_SHARED_SECRET_BYTES = 32;
const ML_DSA_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_SECRET_KEY_BYTES = 4_032;
const ML_DSA_SIGNATURE_BYTES = 3_309;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAXIMUM_SEALED_PAYLOAD_BYTES = 192 * 1_024;
const MAXIMUM_PAIRING_LINK_BYTES = 96 * 1_024;
const MAXIMUM_REALTIME_RECORD_BYTES = 512 * 1_024;

const domains = Object.freeze({
  announcement: encoder.encode("org.noctweave.pairing-lobby.announcement/v1\0"),
  announcementDigest: encoder.encode("org.noctweave.pairing-lobby.announcement-digest/v1\0"),
  request: encoder.encode("org.noctweave.pairing-lobby.request/v1\0"),
  requestDigest: encoder.encode("org.noctweave.pairing-lobby.request-digest/v1\0"),
  response: encoder.encode("org.noctweave.pairing-lobby.response/v1\0"),
  requestKey: encoder.encode("org.noctweave.pairing-lobby.request-key/v1"),
  responseKey: encoder.encode("org.noctweave.pairing-lobby.response-key/v1"),
  requestAAD: encoder.encode("org.noctweave.pairing-lobby.request-aad/v1\0"),
  responseAAD: encoder.encode("org.noctweave.pairing-lobby.response-aad/v1\0"),
  badge: encoder.encode("org.noctweave.pairing-lobby.badge/v1\0"),
  leaseID: encoder.encode("org.noctweave.pairing-lobby.lease-id/v1")
});

const badgeWords = Object.freeze([
  "Amber", "Birch", "Cedar", "Dawn", "Ember", "Fern", "Glacier", "Harbor",
  "Indigo", "Juniper", "Kestrel", "Lagoon", "Maple", "Nimbus", "Orchid", "Pine",
  "Quartz", "River", "Saffron", "Tide", "Umber", "Violet", "Willow", "Xenon",
  "Yarrow", "Zephyr", "Acorn", "Breeze", "Cobalt", "Drift", "Elm", "Flint"
]);

export const pairingLobbyV1 = Object.freeze({
  version: 1,
  lifetimeSeconds: 120,
  maximumPairingLinkBytes: MAXIMUM_PAIRING_LINK_BYTES,
  maximumSealedPayloadBytes: MAXIMUM_SEALED_PAYLOAD_BYTES,
  relayLimits: pairingLobbyRelayV1Limits
});

export class PairingLobbyV1Error extends Error {
  constructor(code, message = `Pairing lobby failed: ${code}.`) {
    super(message);
    this.name = "PairingLobbyV1Error";
    this.code = code;
  }
}

export async function pairingLobbyBadgeV1(crypto, signingPublicKeyValue) {
  const signingPublicKey = bytes(signingPublicKeyValue, "Pairing lobby signing public key");
  if (signingPublicKey.byteLength !== ML_DSA_PUBLIC_KEY_BYTES) {
    throw new PairingLobbyV1Error("invalidAnnouncement");
  }
  const digest = await cryptoSha256(crypto, concatBytes(domains.badge, signingPublicKey));
  const number = (
    digest[2] * 0x1000000 + digest[3] * 0x10000 + digest[4] * 0x100 + digest[5]
  ) % 1_000_000;
  const comparisonCode = number.toString().padStart(6, "0");
  const words = `${badgeWords[digest[0] & 31]} ${badgeWords[digest[1] & 31]}`;
  return Object.freeze({ words, comparisonCode, displayText: `${words} · ${comparisonCode}` });
}

export function validatePairingLobbyAnnouncementV1(value) {
  requireExactRecord(value, [
    "version", "listingID", "requestRouteCapability", "requestAppendCapability",
    "agreementPublicKey", "signingPublicKey", "createdAt", "expiresAt", "signature"
  ], [], "Pairing lobby announcement");
  if (value.version !== pairingLobbyV1.version) throw invalid("invalidAnnouncement");
  requireUUID(value.listingID, "Pairing lobby listing ID");
  requireNonzeroFixedBase64(value.requestRouteCapability, CAPABILITY_BYTES,
    "Pairing lobby request route capability");
  requireNonzeroFixedBase64(value.requestAppendCapability, CAPABILITY_BYTES,
    "Pairing lobby request append capability");
  if (value.requestRouteCapability === value.requestAppendCapability) throw invalid("invalidAnnouncement");
  requireBase64(value.agreementPublicKey, ML_KEM_PUBLIC_KEY_BYTES,
    "Pairing lobby agreement public key");
  requireBase64(value.signingPublicKey, ML_DSA_PUBLIC_KEY_BYTES,
    "Pairing lobby signing public key");
  const createdAt = timestampMilliseconds(value.createdAt, "Pairing lobby creation time");
  const expiresAt = timestampMilliseconds(value.expiresAt, "Pairing lobby expiry");
  if (expiresAt <= createdAt || expiresAt - createdAt >
      pairingLobbyRelayV1Limits.maximumLeaseSeconds * 1_000) throw invalid("invalidAnnouncement");
  requireBase64(value.signature, ML_DSA_SIGNATURE_BYTES, "Pairing lobby signature");
  return value;
}

export function pairingLobbyAnnouncementTranscriptBytesV1(value) {
  const announcement = validatePairingLobbyAnnouncementV1(value);
  return concatBytes(
    domains.announcement,
    uint16Bytes(announcement.version),
    uuidBytes(announcement.listingID),
    requireBase64(announcement.requestRouteCapability, CAPABILITY_BYTES, "Request route capability"),
    requireBase64(announcement.requestAppendCapability, CAPABILITY_BYTES, "Request append capability"),
    lengthPrefixed(requireBase64(announcement.agreementPublicKey, ML_KEM_PUBLIC_KEY_BYTES, "Agreement key")),
    lengthPrefixed(requireBase64(announcement.signingPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Signing key")),
    timestampBytes(announcement.createdAt),
    timestampBytes(announcement.expiresAt)
  );
}

export async function pairingLobbyAnnouncementDigestV1(crypto, value) {
  const announcement = validatePairingLobbyAnnouncementV1(value);
  return cryptoSha256(crypto, concatBytes(
    domains.announcementDigest,
    pairingLobbyAnnouncementTranscriptBytesV1(announcement),
    requireBase64(announcement.signature, ML_DSA_SIGNATURE_BYTES, "Announcement signature")
  ));
}

export async function verifyPairingLobbyAnnouncementV1(crypto, value, { at = new Date() } = {}) {
  assertPairingCrypto(crypto);
  const announcement = validatePairingLobbyAnnouncementV1(value);
  const now = canonicalTimeMilliseconds(at, "Pairing lobby verification time");
  if (now < timestampMilliseconds(announcement.createdAt) - 30_000 ||
      now >= timestampMilliseconds(announcement.expiresAt)) throw invalid("expired");
  const verified = await crypto.verify(
    pairingLobbyAnnouncementTranscriptBytesV1(announcement),
    requireBase64(announcement.signature, ML_DSA_SIGNATURE_BYTES, "Announcement signature"),
    requireBase64(announcement.signingPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Announcement signing key")
  );
  if (!verified) throw invalid("invalidAnnouncement");
  return announcement;
}

export async function verifyPairingLobbyListingV1(crypto, leaseValue, { at = new Date() } = {}) {
  const lease = validatePairingLobbyLeaseV1(leaseValue);
  const now = canonicalTimeMilliseconds(at, "Pairing lobby verification time");
  if (timestampMilliseconds(lease.expiresAt) <= now) throw invalid("expired");
  const announcement = parseWire(requireBase64(
    lease.announcement, undefined, "Pairing lobby announcement"
  ), "Pairing lobby announcement");
  await verifyPairingLobbyAnnouncementV1(crypto, announcement, { at });
  const digest = await pairingLobbyAnnouncementDigestV1(crypto, announcement);
  return freezeWire({
    id: base64(digest),
    leaseID: lease.leaseID,
    announcement,
    relayExpiresAt: lease.expiresAt,
    expiresAt: earlierTimestamp(announcement.expiresAt, lease.expiresAt),
    badge: await pairingLobbyBadgeV1(
      crypto,
      requireBase64(announcement.signingPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Signing key")
    )
  });
}

export class PairingLobbyHostSessionV1 {
  static async create({
    crypto,
    at = new Date(),
    lifetimeSeconds = pairingLobbyV1.lifetimeSeconds,
    ...unsupported
  }) {
    if (Object.keys(unsupported).length !== 0) throw invalid("invalidState");
    assertPairingCrypto(crypto);
    requireInteger(lifetimeSeconds, "Pairing lobby lifetime",
      pairingLobbyRelayV1Limits.minimumLeaseSeconds,
      pairingLobbyRelayV1Limits.maximumLeaseSeconds);
    const createdAt = canonicalTimestamp(at, "Pairing lobby creation time");
    const expiresAt = swiftISODate(new Date(timestampMilliseconds(createdAt) + lifetimeSeconds * 1_000));
    const signing = await generatedSigningKeypair(crypto);
    const agreement = await generatedAgreementKeypair(crypto);
    const [routeCapability, appendCapability, readCapability] = await distinctCapabilities(crypto, 3);
    const listingID = swiftUUID();
    const unsigned = {
      version: pairingLobbyV1.version,
      listingID,
      requestRouteCapability: base64(routeCapability),
      requestAppendCapability: base64(appendCapability),
      agreementPublicKey: base64(agreement.publicKey),
      signingPublicKey: base64(signing.publicKey),
      createdAt,
      expiresAt,
      signature: base64(new Uint8Array(ML_DSA_SIGNATURE_BYTES))
    };
    const signature = bytes(await crypto.sign(
      pairingLobbyAnnouncementTranscriptBytesV1(unsigned), signing.secretKey
    ), "Pairing lobby announcement signature");
    if (signature.byteLength !== ML_DSA_SIGNATURE_BYTES) throw invalid("invalidAnnouncement");
    const announcement = freezeWire(validatePairingLobbyAnnouncementV1({
      ...unsigned,
      signature: base64(signature)
    }));
    await verifyPairingLobbyAnnouncementV1(crypto, announcement, { at: createdAt });
    const encodedAnnouncement = canonicalJsonBytes(announcement);
    if (encodedAnnouncement.byteLength > pairingLobbyRelayV1Limits.maximumAnnouncementBytes) {
      throw invalid("invalidAnnouncement");
    }
    const leaseCapability = await randomCapability(crypto);
    const leaseDigest = await cryptoSha256(crypto, concatBytes(domains.leaseID, leaseCapability));
    const leaseID = leaseDigest.slice(0, pairingLobbyRelayV1Limits.leaseIDBytes);
    const badge = await pairingLobbyBadgeV1(crypto, signing.publicKey);
    return new PairingLobbyHostSessionV1({
      crypto,
      signingSecretKey: signing.secretKey,
      agreementSecretKey: agreement.secretKey,
      requestReadCapability: readCapability,
      announcement,
      badge,
      requestRouteCreateRequest: freezeWire({
        routeCapability: base64(routeCapability),
        appendCapability: base64(appendCapability),
        readCapability: base64(readCapability),
        expiresAt
      }),
      leaseAcquireRequest: freezeWire({
        leaseID: base64(leaseID),
        leaseCapability: base64(leaseCapability),
        announcement: base64(encodedAnnouncement),
        ttlSeconds: lifetimeSeconds
      }),
      leaseReleaseRequest: freezeWire({
        leaseID: base64(leaseID),
        leaseCapability: base64(leaseCapability)
      })
    });
  }

  constructor(state) {
    Object.assign(this, state);
    this.processedRequestIDs = new Set();
    this.disposed = false;
  }

  requestRouteSubscribeRequest(afterSequence = 0) {
    this.requireActive();
    requireInteger(afterSequence, "Pairing lobby request cursor", 0, Number.MAX_SAFE_INTEGER);
    return freezeWire({
      routeCapability: this.announcement.requestRouteCapability,
      readCapability: base64(this.requestReadCapability),
      afterSequence
    });
  }

  async openRequest(payloadValue, { at = new Date() } = {}) {
    this.requireActive();
    const outer = validateSealedRequest(parseWire(
      requirePayload(payloadValue, "Sealed pairing lobby request"),
      "Sealed pairing lobby request"
    ));
    if (outer.listingID.toUpperCase() !== this.announcement.listingID.toUpperCase()) {
      throw invalid("invalidRequest");
    }
    const replayKey = outer.requestID.toUpperCase();
    if (this.processedRequestIDs.has(replayKey)) throw invalid("replay");
    const announcementDigest = await pairingLobbyAnnouncementDigestV1(this.crypto, this.announcement);
    const plaintext = await openSealed({
      crypto: this.crypto,
      outer,
      recipientSecretKey: this.agreementSecretKey,
      salt: announcementDigest,
      info: domains.requestKey,
      aadDomain: domains.requestAAD
    });
    const request = validateJoinRequest(parseWire(plaintext, "Pairing lobby join request"));
    if (request.requestID.toUpperCase() !== replayKey) throw invalid("invalidRequest");
    await verifyJoinRequest(this.crypto, request, this.announcement, { at });
    this.processedRequestIDs.add(replayKey);
    return freezeWire({
      id: request.requestID,
      request,
      requesterBadge: await pairingLobbyBadgeV1(
        this.crypto,
        requireBase64(request.requesterSigningPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Requester signing key")
      )
    });
  }

  async decisionAppendRequest({
    pending,
    decision,
    pairingLink = "",
    at = new Date(),
    ...unsupported
  }) {
    this.requireActive();
    if (Object.keys(unsupported).length !== 0 || !pending?.request) throw invalid("invalidState");
    const request = validateJoinRequest(pending.request);
    const now = canonicalTimestamp(at, "Pairing lobby response time");
    if (timestampMilliseconds(now) >= timestampMilliseconds(request.expiresAt)) throw invalid("expired");
    if (!['accepted', 'rejected'].includes(decision)) throw invalid("invalidResponse");
    if (typeof pairingLink !== "string" ||
        encoder.encode(pairingLink).byteLength > MAXIMUM_PAIRING_LINK_BYTES ||
        (decision === "accepted") !== (pairingLink.length > 0)) throw invalid("invalidResponse");
    const listingDigest = await pairingLobbyAnnouncementDigestV1(this.crypto, this.announcement);
    const requestDigest = await joinRequestDigest(this.crypto, request);
    const unsigned = {
      version: pairingLobbyV1.version,
      listingID: this.announcement.listingID,
      requestID: request.requestID,
      listingDigest: base64(listingDigest),
      requestDigest: base64(requestDigest),
      decision,
      pairingLink: decision === "accepted" ? pairingLink : "",
      respondedAt: now,
      expiresAt: request.expiresAt,
      signature: base64(new Uint8Array(ML_DSA_SIGNATURE_BYTES))
    };
    const signature = bytes(await this.crypto.sign(
      decisionTranscriptBytes(unsigned), this.signingSecretKey
    ), "Pairing lobby decision signature");
    if (signature.byteLength !== ML_DSA_SIGNATURE_BYTES) throw invalid("invalidResponse");
    const response = validateDecisionResponse({ ...unsigned, signature: base64(signature) });
    const sealed = await sealPayload({
      crypto: this.crypto,
      plaintext: canonicalJsonBytes(response),
      recipientPublicKey: requireBase64(
        request.requesterAgreementPublicKey, ML_KEM_PUBLIC_KEY_BYTES, "Requester agreement key"
      ),
      salt: requestDigest,
      info: domains.responseKey,
      aadDomain: domains.responseAAD,
      listingID: response.listingID,
      requestID: response.requestID
    });
    const payload = canonicalJsonBytes(sealed);
    if (payload.byteLength > MAXIMUM_REALTIME_RECORD_BYTES) throw invalid("invalidResponse");
    return freezeWire({
      routeCapability: request.responseRouteCapability,
      appendCapability: request.responseAppendCapability,
      recordID: request.requestID,
      payload: base64(payload)
    });
  }

  dispose() {
    this.signingSecretKey.fill(0);
    this.agreementSecretKey.fill(0);
    this.requestReadCapability.fill(0);
    this.disposed = true;
  }

  requireActive() {
    if (this.disposed) throw invalid("invalidState");
  }
}

export class PairingLobbyRequesterSessionV1 {
  static async create({ crypto, listing: listingValue, at = new Date(), ...unsupported }) {
    if (Object.keys(unsupported).length !== 0) throw invalid("invalidState");
    assertPairingCrypto(crypto);
    const listing = await verifyPairingLobbyListingV1(crypto, listingValue, { at });
    const createdAt = canonicalTimestamp(at, "Pairing lobby request time");
    const expiresAt = earlierTimestamp(
      listing.expiresAt,
      swiftISODate(new Date(timestampMilliseconds(createdAt) + pairingLobbyV1.lifetimeSeconds * 1_000))
    );
    if (timestampMilliseconds(expiresAt) <= timestampMilliseconds(createdAt)) throw invalid("expired");
    const signing = await generatedSigningKeypair(crypto);
    const agreement = await generatedAgreementKeypair(crypto);
    const [routeCapability, appendCapability, readCapability] = await distinctCapabilities(crypto, 3);
    const requestID = swiftUUID();
    const listingDigest = await pairingLobbyAnnouncementDigestV1(crypto, listing.announcement);
    const unsigned = {
      version: pairingLobbyV1.version,
      requestID,
      listingDigest: base64(listingDigest),
      requesterAgreementPublicKey: base64(agreement.publicKey),
      requesterSigningPublicKey: base64(signing.publicKey),
      responseRouteCapability: base64(routeCapability),
      responseAppendCapability: base64(appendCapability),
      createdAt,
      expiresAt,
      signature: base64(new Uint8Array(ML_DSA_SIGNATURE_BYTES))
    };
    const signature = bytes(await crypto.sign(
      joinRequestTranscriptBytes(unsigned), signing.secretKey
    ), "Pairing lobby request signature");
    signing.secretKey.fill(0);
    if (signature.byteLength !== ML_DSA_SIGNATURE_BYTES) throw invalid("invalidRequest");
    const request = freezeWire(validateJoinRequest({ ...unsigned, signature: base64(signature) }));
    await verifyJoinRequest(crypto, request, listing.announcement, { at: createdAt });
    const sealed = await sealPayload({
      crypto,
      plaintext: canonicalJsonBytes(request),
      recipientPublicKey: requireBase64(
        listing.announcement.agreementPublicKey, ML_KEM_PUBLIC_KEY_BYTES, "Host agreement key"
      ),
      salt: listingDigest,
      info: domains.requestKey,
      aadDomain: domains.requestAAD,
      listingID: listing.announcement.listingID,
      requestID
    });
    const payload = canonicalJsonBytes(sealed);
    if (payload.byteLength > MAXIMUM_REALTIME_RECORD_BYTES) throw invalid("invalidRequest");
    return new PairingLobbyRequesterSessionV1({
      crypto,
      announcement: listing.announcement,
      request,
      agreementSecretKey: agreement.secretKey,
      responseReadCapability: readCapability,
      hostBadge: listing.badge,
      requesterBadge: await pairingLobbyBadgeV1(
        crypto,
        requireBase64(request.requesterSigningPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Requester signing key")
      ),
      responseRouteCreateRequest: freezeWire({
        routeCapability: base64(routeCapability),
        appendCapability: base64(appendCapability),
        readCapability: base64(readCapability),
        expiresAt
      }),
      requestAppendRequest: freezeWire({
        routeCapability: listing.announcement.requestRouteCapability,
        appendCapability: listing.announcement.requestAppendCapability,
        recordID: requestID,
        payload: base64(payload)
      })
    });
  }

  constructor(state) {
    Object.assign(this, state);
    this.consumed = false;
    this.disposed = false;
  }

  responseRouteSubscribeRequest(afterSequence = 0) {
    this.requireActive();
    requireInteger(afterSequence, "Pairing lobby response cursor", 0, Number.MAX_SAFE_INTEGER);
    return freezeWire({
      routeCapability: this.request.responseRouteCapability,
      readCapability: base64(this.responseReadCapability),
      afterSequence
    });
  }

  async openResponse(payloadValue, { at = new Date() } = {}) {
    this.requireActive();
    if (this.consumed) throw invalid("replay");
    const outer = validateSealedResponse(parseWire(
      requirePayload(payloadValue, "Sealed pairing lobby response"),
      "Sealed pairing lobby response"
    ));
    if (outer.listingID.toUpperCase() !== this.announcement.listingID.toUpperCase() ||
        outer.requestID.toUpperCase() !== this.request.requestID.toUpperCase()) {
      throw invalid("invalidResponse");
    }
    const requestDigest = await joinRequestDigest(this.crypto, this.request);
    const plaintext = await openSealed({
      crypto: this.crypto,
      outer,
      recipientSecretKey: this.agreementSecretKey,
      salt: requestDigest,
      info: domains.responseKey,
      aadDomain: domains.responseAAD
    });
    const response = validateDecisionResponse(parseWire(plaintext, "Pairing lobby decision response"));
    await verifyDecisionResponse(this.crypto, response, this.announcement, this.request, { at });
    this.consumed = true;
    return freezeWire(response);
  }

  dispose() {
    this.agreementSecretKey.fill(0);
    this.responseReadCapability.fill(0);
    this.disposed = true;
  }

  requireActive() {
    if (this.disposed) throw invalid("invalidState");
  }
}

export function validatePairingLobbyJoinRequestV1(value) {
  return validateJoinRequest(value);
}

export function pairingLobbyJoinRequestTranscriptBytesV1(value) {
  return joinRequestTranscriptBytes(value);
}

export function validatePairingLobbyDecisionResponseV1(value) {
  return validateDecisionResponse(value);
}

export function pairingLobbyDecisionTranscriptBytesV1(value) {
  return decisionTranscriptBytes(value);
}

function validateJoinRequest(value) {
  requireExactRecord(value, [
    "version", "requestID", "listingDigest", "requesterAgreementPublicKey",
    "requesterSigningPublicKey", "responseRouteCapability", "responseAppendCapability",
    "createdAt", "expiresAt", "signature"
  ], [], "Pairing lobby join request");
  if (value.version !== pairingLobbyV1.version) throw invalid("invalidRequest");
  requireUUID(value.requestID, "Pairing lobby request ID");
  requireBase64(value.listingDigest, 32, "Pairing lobby listing digest");
  requireBase64(value.requesterAgreementPublicKey, ML_KEM_PUBLIC_KEY_BYTES, "Requester agreement key");
  requireBase64(value.requesterSigningPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Requester signing key");
  requireNonzeroFixedBase64(value.responseRouteCapability, CAPABILITY_BYTES, "Response route capability");
  requireNonzeroFixedBase64(value.responseAppendCapability, CAPABILITY_BYTES, "Response append capability");
  if (value.responseRouteCapability === value.responseAppendCapability) throw invalid("invalidRequest");
  const created = timestampMilliseconds(value.createdAt, "Pairing request creation time");
  const expires = timestampMilliseconds(value.expiresAt, "Pairing request expiry");
  if (expires <= created || expires - created > pairingLobbyRelayV1Limits.maximumLeaseSeconds * 1_000) {
    throw invalid("invalidRequest");
  }
  requireBase64(value.signature, ML_DSA_SIGNATURE_BYTES, "Pairing request signature");
  return value;
}

function joinRequestTranscriptBytes(value) {
  const request = validateJoinRequest(value);
  return concatBytes(
    domains.request,
    uint16Bytes(request.version),
    uuidBytes(request.requestID),
    requireBase64(request.listingDigest, 32, "Listing digest"),
    lengthPrefixed(requireBase64(request.requesterAgreementPublicKey, ML_KEM_PUBLIC_KEY_BYTES, "Agreement key")),
    lengthPrefixed(requireBase64(request.requesterSigningPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Signing key")),
    requireBase64(request.responseRouteCapability, CAPABILITY_BYTES, "Response route capability"),
    requireBase64(request.responseAppendCapability, CAPABILITY_BYTES, "Response append capability"),
    timestampBytes(request.createdAt),
    timestampBytes(request.expiresAt)
  );
}

async function joinRequestDigest(crypto, value) {
  const request = validateJoinRequest(value);
  return cryptoSha256(crypto, concatBytes(
    domains.requestDigest,
    joinRequestTranscriptBytes(request),
    requireBase64(request.signature, ML_DSA_SIGNATURE_BYTES, "Request signature")
  ));
}

async function verifyJoinRequest(crypto, requestValue, announcementValue, { at = new Date() } = {}) {
  const request = validateJoinRequest(requestValue);
  const announcement = validatePairingLobbyAnnouncementV1(announcementValue);
  const expectedDigest = await pairingLobbyAnnouncementDigestV1(crypto, announcement);
  const now = canonicalTimeMilliseconds(at, "Pairing request verification time");
  if (!equalBytes(expectedDigest, requireBase64(request.listingDigest, 32, "Listing digest")) ||
      timestampMilliseconds(request.createdAt) < timestampMilliseconds(announcement.createdAt) - 30_000 ||
      timestampMilliseconds(request.expiresAt) > timestampMilliseconds(announcement.expiresAt) ||
      now < timestampMilliseconds(request.createdAt) - 30_000 ||
      now >= timestampMilliseconds(request.expiresAt)) throw invalid("invalidRequest");
  if (!await crypto.verify(
    joinRequestTranscriptBytes(request),
    requireBase64(request.signature, ML_DSA_SIGNATURE_BYTES, "Request signature"),
    requireBase64(request.requesterSigningPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Requester signing key")
  )) throw invalid("invalidRequest");
  return request;
}

function validateDecisionResponse(value) {
  requireExactRecord(value, [
    "version", "listingID", "requestID", "listingDigest", "requestDigest", "decision",
    "pairingLink", "respondedAt", "expiresAt", "signature"
  ], [], "Pairing lobby decision response");
  if (value.version !== pairingLobbyV1.version || !["accepted", "rejected"].includes(value.decision)) {
    throw invalid("invalidResponse");
  }
  requireUUID(value.listingID, "Pairing lobby listing ID");
  requireUUID(value.requestID, "Pairing lobby request ID");
  requireBase64(value.listingDigest, 32, "Pairing lobby listing digest");
  requireBase64(value.requestDigest, 32, "Pairing lobby request digest");
  if (typeof value.pairingLink !== "string" ||
      encoder.encode(value.pairingLink).byteLength > MAXIMUM_PAIRING_LINK_BYTES ||
      (value.decision === "accepted") !== (value.pairingLink.length > 0)) throw invalid("invalidResponse");
  if (timestampMilliseconds(value.respondedAt, "Pairing response time") >=
      timestampMilliseconds(value.expiresAt, "Pairing response expiry")) throw invalid("invalidResponse");
  requireBase64(value.signature, ML_DSA_SIGNATURE_BYTES, "Pairing response signature");
  return value;
}

function decisionTranscriptBytes(value) {
  const response = validateDecisionResponse(value);
  return concatBytes(
    domains.response,
    uint16Bytes(response.version),
    uuidBytes(response.listingID),
    uuidBytes(response.requestID),
    requireBase64(response.listingDigest, 32, "Listing digest"),
    requireBase64(response.requestDigest, 32, "Request digest"),
    Uint8Array.of(response.decision === "accepted" ? 1 : 0),
    lengthPrefixed(encoder.encode(response.pairingLink)),
    timestampBytes(response.respondedAt),
    timestampBytes(response.expiresAt)
  );
}

async function verifyDecisionResponse(crypto, responseValue, announcementValue, requestValue, { at }) {
  const response = validateDecisionResponse(responseValue);
  const announcement = validatePairingLobbyAnnouncementV1(announcementValue);
  const request = validateJoinRequest(requestValue);
  const listingDigest = await pairingLobbyAnnouncementDigestV1(crypto, announcement);
  const requestDigest = await joinRequestDigest(crypto, request);
  const now = canonicalTimeMilliseconds(at, "Pairing response verification time");
  if (response.listingID.toUpperCase() !== announcement.listingID.toUpperCase() ||
      response.requestID.toUpperCase() !== request.requestID.toUpperCase() ||
      !equalBytes(listingDigest, requireBase64(response.listingDigest, 32, "Listing digest")) ||
      !equalBytes(requestDigest, requireBase64(response.requestDigest, 32, "Request digest")) ||
      timestampMilliseconds(response.respondedAt) < timestampMilliseconds(request.createdAt) - 30_000 ||
      timestampMilliseconds(response.expiresAt) > timestampMilliseconds(request.expiresAt) ||
      now < timestampMilliseconds(response.respondedAt) - 30_000 ||
      now >= timestampMilliseconds(response.expiresAt)) throw invalid("invalidResponse");
  if (!await crypto.verify(
    decisionTranscriptBytes(response),
    requireBase64(response.signature, ML_DSA_SIGNATURE_BYTES, "Response signature"),
    requireBase64(announcement.signingPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Host signing key")
  )) throw invalid("invalidResponse");
  return response;
}

function validateSealedRequest(value) {
  return validateSealed(value, "invalidRequest", "Pairing lobby sealed request");
}

function validateSealedResponse(value) {
  return validateSealed(value, "invalidResponse", "Pairing lobby sealed response");
}

function validateSealed(value, code, label) {
  requireExactRecord(value, [
    "version", "listingID", "requestID", "kemCiphertext", "nonce", "ciphertext", "tag"
  ], [], label);
  if (value.version !== pairingLobbyV1.version) throw invalid(code);
  requireUUID(value.listingID, `${label} listing ID`);
  requireUUID(value.requestID, `${label} request ID`);
  requireBase64(value.kemCiphertext, ML_KEM_CIPHERTEXT_BYTES, `${label} ML-KEM ciphertext`);
  requireBase64(value.nonce, NONCE_BYTES, `${label} nonce`);
  const ciphertext = requireBase64(value.ciphertext, undefined, `${label} ciphertext`);
  requireBase64(value.tag, TAG_BYTES, `${label} tag`);
  if (ciphertext.byteLength === 0 || ciphertext.byteLength > MAXIMUM_SEALED_PAYLOAD_BYTES) throw invalid(code);
  return value;
}

async function sealPayload({
  crypto, plaintext, recipientPublicKey, salt, info, aadDomain, listingID, requestID
}) {
  const encapsulation = await crypto.encapsulate(recipientPublicKey);
  const kemCiphertext = bytes(encapsulation?.ciphertext, "Pairing lobby ML-KEM ciphertext");
  const sharedSecret = new Uint8Array(bytes(encapsulation?.sharedSecret, "Pairing lobby shared secret"));
  if (kemCiphertext.byteLength !== ML_KEM_CIPHERTEXT_BYTES ||
      sharedSecret.byteLength !== ML_KEM_SHARED_SECRET_BYTES) {
    sharedSecret.fill(0);
    throw invalid("invalidState");
  }
  let key;
  try {
    key = await cryptoHkdfSha256(crypto, { ikm: sharedSecret, salt, info, length: 32 });
    const nonce = await cryptoRandomBytes(crypto, NONCE_BYTES);
    const aad = sealedAAD(aadDomain, listingID, requestID, kemCiphertext);
    const combined = bytes(await crypto.aesGcmEncrypt({
      key, nonce, plaintext, additionalData: aad
    }), "Pairing lobby ciphertext");
    if (combined.byteLength <= TAG_BYTES || combined.byteLength - TAG_BYTES > MAXIMUM_SEALED_PAYLOAD_BYTES) {
      throw invalid("invalidState");
    }
    return freezeWire({
      version: pairingLobbyV1.version,
      listingID,
      requestID,
      kemCiphertext: base64(kemCiphertext),
      nonce: base64(nonce),
      ciphertext: base64(combined.slice(0, -TAG_BYTES)),
      tag: base64(combined.slice(-TAG_BYTES))
    });
  } finally {
    sharedSecret.fill(0);
    key?.fill?.(0);
  }
}

async function openSealed({ crypto, outer, recipientSecretKey, salt, info, aadDomain }) {
  const kemCiphertext = requireBase64(outer.kemCiphertext, ML_KEM_CIPHERTEXT_BYTES, "ML-KEM ciphertext");
  const sharedSecret = new Uint8Array(bytes(await crypto.decapsulate(
    kemCiphertext, recipientSecretKey
  ), "Pairing lobby shared secret"));
  if (sharedSecret.byteLength !== ML_KEM_SHARED_SECRET_BYTES) {
    sharedSecret.fill(0);
    throw invalid("invalidState");
  }
  let key;
  try {
    key = await cryptoHkdfSha256(crypto, { ikm: sharedSecret, salt, info, length: 32 });
    return new Uint8Array(await crypto.aesGcmDecrypt({
      key,
      nonce: requireBase64(outer.nonce, NONCE_BYTES, "Pairing lobby nonce"),
      ciphertext: concatBytes(
        requireBase64(outer.ciphertext, undefined, "Pairing lobby ciphertext"),
        requireBase64(outer.tag, TAG_BYTES, "Pairing lobby tag")
      ),
      additionalData: sealedAAD(aadDomain, outer.listingID, outer.requestID, kemCiphertext)
    }));
  } catch (error) {
    if (error instanceof PairingLobbyV1Error) throw error;
    throw invalid("decryptionFailed");
  } finally {
    sharedSecret.fill(0);
    key?.fill?.(0);
  }
}

function sealedAAD(domain, listingID, requestID, kemCiphertext) {
  return concatBytes(
    domain,
    uint16Bytes(pairingLobbyV1.version),
    uuidBytes(listingID),
    uuidBytes(requestID),
    lengthPrefixed(kemCiphertext)
  );
}

async function generatedSigningKeypair(crypto) {
  const keypair = await crypto.generateSigningKeypair();
  const publicKey = new Uint8Array(bytes(keypair?.publicKey, "ML-DSA public key"));
  const secretKey = new Uint8Array(bytes(keypair?.secretKey, "ML-DSA secret key"));
  if (publicKey.byteLength !== ML_DSA_PUBLIC_KEY_BYTES || secretKey.byteLength !== ML_DSA_SECRET_KEY_BYTES) {
    publicKey.fill(0); secretKey.fill(0); throw invalid("invalidState");
  }
  return { publicKey, secretKey };
}

async function generatedAgreementKeypair(crypto) {
  const keypair = await crypto.generateKemKeypair();
  const publicKey = new Uint8Array(bytes(keypair?.publicKey, "ML-KEM public key"));
  const secretKey = new Uint8Array(bytes(keypair?.secretKey, "ML-KEM secret key"));
  if (publicKey.byteLength !== ML_KEM_PUBLIC_KEY_BYTES || secretKey.byteLength !== ML_KEM_SECRET_KEY_BYTES) {
    publicKey.fill(0); secretKey.fill(0); throw invalid("invalidState");
  }
  return { publicKey, secretKey };
}

async function randomCapability(crypto) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const capability = await cryptoRandomBytes(crypto, CAPABILITY_BYTES);
    if (capability.some((octet) => octet !== 0)) return capability;
  }
  throw invalid("invalidState");
}

async function distinctCapabilities(crypto, count) {
  const values = [];
  const seen = new Set();
  while (values.length < count) {
    const value = await randomCapability(crypto);
    const key = base64(value);
    if (!seen.has(key)) { seen.add(key); values.push(value); }
  }
  return values;
}

function assertPairingCrypto(crypto) {
  for (const method of [
    "randomBytes", "sha256", "hkdfSha256", "aesGcmEncrypt", "aesGcmDecrypt",
    "generateKemKeypair", "encapsulate", "decapsulate", "generateSigningKeypair", "sign", "verify"
  ]) {
    if (typeof crypto?.[method] !== "function") {
      throw new TypeError("Pairing lobby requires ML-KEM-768, ML-DSA-65, SHA-256, HKDF, AES-GCM, and secure randomness.");
    }
  }
}

function requirePayload(value, label) {
  const payload = typeof value === "string" ? requireBase64(value, undefined, label) : bytes(value, label);
  if (payload.byteLength === 0 || payload.byteLength > MAXIMUM_REALTIME_RECORD_BYTES) throw invalid("invalidState");
  return payload;
}

function parseWire(value, label) {
  try {
    return parseExactJSON(decoder.decode(value));
  } catch {
    throw new PairingLobbyV1Error("invalidWire", `${label} is not strict current JSON.`);
  }
}

function canonicalTimestamp(value, label) {
  return requireCanonicalTimestamp(value instanceof Date ? value : value, label);
}

function canonicalTimeMilliseconds(value, label) {
  return timestampMilliseconds(canonicalTimestamp(value, label), label);
}

function earlierTimestamp(left, right) {
  return timestampMilliseconds(left) <= timestampMilliseconds(right) ? left : right;
}

function uuidBytes(value) {
  requireUUID(value, "UUID");
  const hex = value.replaceAll("-", "");
  return Uint8Array.from({ length: 16 }, (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

function requireUUID(value, label) {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function invalid(code) {
  return new PairingLobbyV1Error(code);
}
