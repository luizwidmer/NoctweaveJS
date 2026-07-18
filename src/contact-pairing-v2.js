import { normalizeRelayEndpoint } from "./endpoint.js";
import {
  createOpaqueReceiveRouteV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteCreateRequestV2
} from "./opaque-route-v2.js";
import { createOpaqueRoutePayloadKeyV2 } from "./opaque-route-packet-v2.js";
import { parseExactJSON } from "./strict-json.js";
import {
  createContactIntroductionV2,
  createLocalOpaqueReceiveRouteV2,
  createPairwiseRouteSetV2,
  createOpaqueSendRouteV2,
  derivePairwiseRelationshipIDV2,
  validateContactIntroductionV2,
  validateLocalOpaqueReceiveRouteV2,
  validatePairwiseRouteSetV2,
  verifyContactIntroductionV2,
  verifyPairwiseRouteSetV2
} from "./pairwise-opaque-route-v2.js";
import {
  acceptRendezvousOpenV2,
  createPendingRendezvousOfferV2,
  createRendezvousOpenV2,
  createRendezvousRedemptionLedgerV2,
  createRendezvousTransportCapabilityV2,
  openRendezvousFrameV2,
  rendezvousRedemptionSecretV2,
  sealRendezvousFrameV2,
  validateRendezvousOfferV2,
  validateRendezvousRedemptionLedgerV2
} from "./rendezvous-v2.js";
import {
  preparePairwiseDirectV4Identity,
  verifyRelationshipEndpointBindingV4
} from "./crypto/direct-v4.js";
import { createProtocolCapabilityManifest } from "./architecture-v2.js";
import {
  createRelationshipLocalPolicyV2,
  validateRelationshipLocalPolicyV2
} from "./relationship-local-policy-v2.js";
import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./crypto/swift-canonical.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_INVITATION_BYTES = 32 * 1_024;
const MAX_FRAME_OBJECT_BYTES = 60 * 1_024;
const PAIRING_VERSION = 2;

const invitationFields = Object.freeze(["version", "offer", "redemptionSecret"]);
const redemptionFields = Object.freeze(["oneTimeToken"]);
const participantFields = Object.freeze([
  "version",
  "localIdentity",
  "localEndpointHandle",
  "localReceiveRoute",
  "routeCreateRequest",
  "createdAt"
]);
const localReceiveRouteFields = Object.freeze([
  "relay",
  "route",
  "clientCapabilities",
  "payloadKey",
  "committedCursor",
  "committedSequence",
  "committedRecordDigest",
  "gapState"
]);
const preparedLocalIdentityFields = Object.freeze([
  "version",
  "scope",
  "id",
  "relationshipPseudonym",
  "signing",
  "agreement",
  "signingFingerprint",
  "createdAt",
  "localEndpoint",
  "endpointBinding"
]);
const boundLocalIdentityFields = Object.freeze([
  ...preparedLocalIdentityFields,
  "relationshipID",
  "endpointHandle"
]);
const peerFields = Object.freeze([
  "version",
  "id",
  "relationshipID",
  "relationshipPseudonym",
  "signingPublicKey",
  "agreementPublicKey",
  "endpointBinding",
  "sendRoutes",
  "createdAt"
]);
const relationshipFields = Object.freeze([
  "version",
  "relationshipID",
  "localIdentity",
  "localEndpointHandle",
  "localReceiveRoutes",
  "localAdvertisedRoutes",
  "peerIdentity",
  "localPolicy",
  "createdAt"
]);

export const noctweaveContactPairingV2 = Object.freeze({
  version: PAIRING_VERSION,
  invitationMaximumBytes: MAX_INVITATION_BYTES,
  relationshipScope: "pairwise-only"
});

export class ContactPairingV2Error extends Error {
  constructor(code, message = code, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ContactPairingV2Error";
    this.code = code;
  }
}

/**
 * Creates the only shareable pairing artifact. It contains ephemeral
 * rendezvous material and no persona, relationship, endpoint, or relay route.
 */
export async function createContactPairingInvitationV2({ crypto, createdAt, expiresAt }) {
  const capability = await createRendezvousTransportCapabilityV2({ crypto, expiresAt });
  const pending = await createPendingRendezvousOfferV2({
    crypto,
    transportCapability: capability,
    createdAt
  });
  const redemptionSecret = await rendezvousRedemptionSecretV2(crypto, pending);
  const invitation = await validateContactPairingInvitationV2(crypto, {
    version: PAIRING_VERSION,
    offer: pending.offer,
    redemptionSecret
  });
  return { pending, invitation };
}

export async function validateContactPairingInvitationV2(crypto, value) {
  try {
    requireExactRecord(value, invitationFields, "Contact pairing invitation");
    if (value.version !== PAIRING_VERSION) throw new TypeError("Pairing version is invalid.");
    requireExactRecord(value.offer, [
      "version",
      "purpose",
      "transportCapability",
      "oneTimeTokenDigest",
      "ephemeralAgreementPublicKey",
      "createdAt",
      "expiresAt",
      "limits"
    ], "Rendezvous offer");
    requireExactRecord(
      value.offer.transportCapability,
      ["opaqueValue", "expiresAt"],
      "Rendezvous transport capability"
    );
    requireExactRecord(
      value.offer.limits,
      ["maximumFrames", "maximumFramePlaintextBytes"],
      "Rendezvous limits"
    );
    const offer = validateRendezvousOfferV2(value.offer);
    if (offer.purpose !== "contactPairing") throw new TypeError("Pairing purpose is invalid.");
    requireExactRecord(value.redemptionSecret, redemptionFields, "Rendezvous redemption secret");
    const redemptionSecret = Object.freeze({
      oneTimeToken: requireCanonicalBase64(value.redemptionSecret.oneTimeToken, 32, "one-time token")
    });
    // Public validation needs only the token hash and authenticated offer
    // digest. The offerer's ephemeral private key never enters the invitation.
    const tokenDigest = base64(await crypto.sha256(decodeBase64(redemptionSecret.oneTimeToken)));
    if (tokenDigest !== offer.oneTimeTokenDigest) {
      throw new TypeError("Pairing redemption secret does not match its offer.");
    }
    return Object.freeze({ version: PAIRING_VERSION, offer, redemptionSecret });
  } catch (error) {
    if (error instanceof ContactPairingV2Error) throw error;
    throw new ContactPairingV2Error("invalidInvitation", "Contact pairing invitation is invalid.", error);
  }
}

export async function encodeContactPairingInvitationV2({ crypto, invitation }) {
  const validated = await validateContactPairingInvitationV2(crypto, invitation);
  const bytes = canonicalJsonBytes(validated);
  if (bytes.byteLength > MAX_INVITATION_BYTES) {
    throw new ContactPairingV2Error("invalidInvitation", "Contact pairing invitation is too large.");
  }
  return base64(bytes);
}

export async function decodeContactPairingInvitationV2({ crypto, encoded }) {
  if (typeof encoded !== "string" || encoded.trim() !== encoded || encoded.length === 0 ||
      encoded.length > Math.ceil(MAX_INVITATION_BYTES / 3) * 4 + 4) {
    throw new ContactPairingV2Error("invalidInvitation", "Contact pairing invitation is malformed.");
  }
  const bytes = decodeBase64(encoded, MAX_INVITATION_BYTES, "pairing invitation");
  let value;
  try {
    value = parseExactJSON(decoder.decode(bytes));
  } catch (error) {
    throw new ContactPairingV2Error("invalidInvitation", "Contact pairing invitation is malformed.", error);
  }
  if (!equalBytes(bytes, canonicalJsonBytes(value))) {
    throw new ContactPairingV2Error("invalidInvitation", "Contact pairing invitation is not canonical.");
  }
  return validateContactPairingInvitationV2(crypto, value);
}

/**
 * Mints a fresh PQ authority, endpoint, prekey package, and opaque receive
 * route for exactly one relationship. No key in this result may be shared by
 * another pairing.
 */
export async function prepareContactPairingParticipantV2({
  crypto,
  pqc,
  relationshipPseudonym,
  relay,
  endpointCapabilities = createProtocolCapabilityManifest(),
  createdAt = swiftISODate(),
  routeExpiresAt = swiftISODate(new Date(Date.parse(createdAt) + 6 * 60 * 60 * 1_000)),
  policy = createOpaqueRoutePolicyV2({
    paddingBucket: 4_096,
    retentionBucket: 21_600,
    quotaBucket: 256
  }),
  ...unsupported
}) {
  if (Object.keys(unsupported).length !== 0) {
    throw new TypeError("Contact pairing participant parameters do not match the current protocol.");
  }
  const pseudonym = validateRelationshipPseudonym(relationshipPseudonym);
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  requireGeneratedKeypair(signing, "relationship signing");
  requireGeneratedKeypair(agreement, "relationship agreement");
  const localIdentity = {
    version: PAIRING_VERSION,
    scope: "pairwise",
    id: swiftUUID(),
    relationshipPseudonym: pseudonym,
    signing: serializeKeypair(signing),
    agreement: serializeKeypair(agreement),
    signingFingerprint: base64(await crypto.sha256(signing.publicKey)),
    createdAt
  };
  await preparePairwiseDirectV4Identity({
    crypto,
    pqc,
    localIdentity,
    capabilities: endpointCapabilities,
    issuedAt: createdAt
  });

  const clientCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const lease = createOpaqueRouteLeaseV2({ issuedAt: createdAt, expiresAt: routeExpiresAt, policy });
  const routeCreateRequest = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities: clientCapabilities,
    lease,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const opaqueRoute = await createOpaqueReceiveRouteV2({
    crypto,
    request: routeCreateRequest,
    presentedRenewCapability: clientCapabilities.renewCapability,
    confidentialTransport: true,
    receivedAt: createdAt
  });
  const localReceiveRoute = await createLocalOpaqueReceiveRouteV2({
    crypto,
    relay: normalizeRelayEndpoint(relay),
    route: opaqueRoute,
    clientCapabilities,
    payloadKey: await createOpaqueRoutePayloadKeyV2(crypto)
  });
  const localEndpointHandle = Object.freeze({ rawValue: base64(await crypto.randomBytes(32)) });
  const participant = {
    version: PAIRING_VERSION,
    localIdentity,
    localEndpointHandle,
    localReceiveRoute,
    routeCreateRequest,
    createdAt
  };
  await validatePreparedContactParticipantV2({ crypto, pqc, participant });
  return participant;
}

export async function validatePreparedContactParticipantV2({ crypto, pqc, participant: value }) {
  try {
    requireExactRecord(value, participantFields, "Prepared contact participant");
    requireExactRecord(value.localIdentity, preparedLocalIdentityFields, "Local pairwise identity");
    if (value.version !== PAIRING_VERSION || value.localIdentity?.scope !== "pairwise" ||
        value.localIdentity?.version !== PAIRING_VERSION || value.localIdentity?.createdAt !== value.createdAt) {
      throw new TypeError("Prepared participant scope is invalid.");
    }
    requireCanonicalBase64(value.localEndpointHandle?.rawValue, 32, "relationship endpoint handle");
    requireExactRecord(value.localReceiveRoute, localReceiveRouteFields, "Local opaque receive route");
    const localReceiveRoute = await validateLocalOpaqueReceiveRouteV2({
      crypto,
      route: value.localReceiveRoute
    });
    const capabilities = localReceiveRoute.clientCapabilities;
    const opaqueRoute = localReceiveRoute.route;
    if (capabilities.routeID.rawValue !== opaqueRoute.routeID.rawValue ||
        value.routeCreateRequest?.routeID?.rawValue !== opaqueRoute.routeID.rawValue) {
      throw new TypeError("Prepared participant route state is inconsistent.");
    }
    await verifyRelationshipEndpointBindingV4({
      crypto,
      pqc,
      authoritySigningPublicKey: value.localIdentity.signing.publicKey,
      endpointBinding: value.localIdentity.endpointBinding,
      now: value.createdAt
    });
    return value;
  } catch (error) {
    if (error instanceof ContactPairingV2Error) throw error;
    throw new ContactPairingV2Error("invalidParticipant", "Prepared contact participant is invalid.", error);
  }
}

/**
 * Executes the transport-independent state machine. Network adapters carry
 * the returned request and frames in this exact order; the helper is also a
 * runnable Node/browser conformance slice.
 */
export async function establishContactPairingV2({
  crypto,
  pqc,
  pending,
  invitation: invitationValue,
  offerer,
  responder,
  ledger = createRendezvousRedemptionLedgerV2(),
  at = swiftISODate()
}) {
  const invitation = await validateContactPairingInvitationV2(crypto, invitationValue);
  await validatePreparedContactParticipantV2({ crypto, pqc, participant: offerer });
  await validatePreparedContactParticipantV2({ crypto, pqc, participant: responder });
  const opened = await createRendezvousOpenV2({
    crypto,
    offer: invitation.offer,
    redemptionSecret: invitation.redemptionSecret,
    at
  });
  const accepted = await acceptRendezvousOpenV2({
    crypto,
    pending,
    request: opened.request,
    ledger: validateRendezvousRedemptionLedgerV2(ledger),
    at
  });
  let offererSession = accepted.session;
  let responderSession = opened.session;
  const relationshipID = await derivePairwiseRelationshipIDV2({
    crypto,
    rendezvousTranscriptDigest: offererSession.transcriptDigest
  });
  const expiresAt = invitation.offer.expiresAt;

  const responderBundle = await makeIntroductionBundle({
    crypto,
    pqc,
    participant: responder,
    relationshipID,
    transcriptDigest: responderSession.transcriptDigest,
    issuedAt: at,
    expiresAt
  });
  const responderSealed = await sealJsonFrame({
    crypto,
    session: responderSession,
    value: responderBundle.introduction,
    kind: "acceptance",
    at
  });
  responderSession = responderSealed.session;
  const responderOpened = await openJsonFrame({
    crypto,
    session: offererSession,
    frame: responderSealed.frame,
    expectedKind: "acceptance",
    at
  });
  offererSession = responderOpened.session;
  const responderIntroduction = await verifyContactIntroductionV2({
    crypto,
    pqc,
    introduction: responderOpened.value,
    rendezvousTranscriptDigest: offererSession.transcriptDigest,
    at
  });

  const offererBundle = await makeIntroductionBundle({
    crypto,
    pqc,
    participant: offerer,
    relationshipID,
    transcriptDigest: offererSession.transcriptDigest,
    issuedAt: at,
    expiresAt
  });
  const offererSealed = await sealJsonFrame({
    crypto,
    session: offererSession,
    value: offererBundle.introduction,
    kind: "introduction",
    at
  });
  offererSession = offererSealed.session;
  const offererOpened = await openJsonFrame({
    crypto,
    session: responderSession,
    frame: offererSealed.frame,
    expectedKind: "introduction",
    at
  });
  responderSession = offererOpened.session;
  const offererIntroduction = await verifyContactIntroductionV2({
    crypto,
    pqc,
    introduction: offererOpened.value,
    rendezvousTranscriptDigest: responderSession.transcriptDigest,
    at
  });

  const confirmation = Object.freeze({
    version: PAIRING_VERSION,
    relationshipID,
    offererIntroductionDigest: base64(await crypto.sha256(canonicalJsonBytes(offererIntroduction))),
    responderIntroductionDigest: base64(await crypto.sha256(canonicalJsonBytes(responderIntroduction)))
  });
  const responderConfirmation = await sealJsonFrame({
    crypto,
    session: responderSession,
    value: confirmation,
    kind: "confirmation",
    at
  });
  responderSession = responderConfirmation.session;
  const offererConfirmation = await openJsonFrame({
    crypto,
    session: offererSession,
    frame: responderConfirmation.frame,
    expectedKind: "confirmation",
    at
  });
  offererSession = offererConfirmation.session;
  requireMatchingConfirmation(confirmation, offererConfirmation.value);

  const offererAck = await sealJsonFrame({
    crypto,
    session: offererSession,
    value: confirmation,
    kind: "confirmation",
    at
  });
  offererSession = offererAck.session;
  const responderAck = await openJsonFrame({
    crypto,
    session: responderSession,
    frame: offererAck.frame,
    expectedKind: "confirmation",
    at
  });
  responderSession = responderAck.session;
  requireMatchingConfirmation(confirmation, responderAck.value);

  const offererRelationship = await createPairwiseRelationshipV2({
    crypto,
    pqc,
    participant: offerer,
    localBundle: offererBundle,
    peerIntroduction: responderIntroduction,
    relationshipID,
    acceptedAt: at
  });
  const responderRelationship = await createPairwiseRelationshipV2({
    crypto,
    pqc,
    participant: responder,
    localBundle: responderBundle,
    peerIntroduction: offererIntroduction,
    relationshipID,
    acceptedAt: at
  });
  return Object.freeze({
    relationshipID,
    offererRelationship,
    responderRelationship,
    pending: accepted.pending,
    ledger: accepted.ledger,
    offererSession,
    responderSession
  });
}

export async function validatePairwiseRelationshipV2({ crypto, pqc, relationship: value }) {
  try {
    requireExactRecord(value, relationshipFields, "Pairwise relationship");
    if (value.version !== PAIRING_VERSION || value.localIdentity?.scope !== "pairwise" ||
        value.localIdentity?.relationshipID !== value.relationshipID ||
        value.peerIdentity?.relationshipID !== value.relationshipID ||
        value.localAdvertisedRoutes?.relationshipID !== value.relationshipID ||
        value.localIdentity?.endpointHandle?.rawValue !== value.localEndpointHandle?.rawValue ||
        value.localAdvertisedRoutes?.ownerEndpointHandle?.rawValue !== value.localEndpointHandle?.rawValue ||
        value.peerIdentity?.sendRoutes?.relationshipID !== value.relationshipID ||
        !canonicalUUID(value.localIdentity?.id) || !canonicalUUID(value.peerIdentity?.id) ||
        !Number.isFinite(Date.parse(value.createdAt)) ||
        !Number.isFinite(Date.parse(value.peerIdentity?.createdAt)) ||
        validateRelationshipPseudonym(value.peerIdentity?.relationshipPseudonym) !==
          value.peerIdentity.relationshipPseudonym) {
      throw new TypeError("Pairwise relationship scope is invalid.");
    }
    requireExactRecord(value.localIdentity, boundLocalIdentityFields, "Bound local pairwise identity");
    validateRelationshipLocalPolicyV2(value.localPolicy);
    if (!Array.isArray(value.localReceiveRoutes) || value.localReceiveRoutes.length !== 1) {
      throw new TypeError("Pairwise relationship receive routes are invalid.");
    }
    for (const route of value.localReceiveRoutes) {
      await validateLocalOpaqueReceiveRouteV2({ crypto, route });
    }
    requireExactRecord(value.peerIdentity, peerFields, "Peer pairwise identity");
    requireCanonicalBase64(value.localEndpointHandle?.rawValue, 32, "local relationship endpoint handle");
    validatePairwiseRouteSetV2(value.localAdvertisedRoutes);
    validatePairwiseRouteSetV2(value.peerIdentity.sendRoutes);
    if (!verifyPairwiseRouteSetV2({
      pqc,
      routeSet: value.localAdvertisedRoutes,
      ownerSigningPublicKey: value.localIdentity.endpointBinding.signingPublicKey
    })) {
      throw new TypeError("Local route-set signature is invalid.");
    }
    if (!verifyPairwiseRouteSetV2({
      pqc,
      routeSet: value.peerIdentity.sendRoutes,
      ownerSigningPublicKey: value.peerIdentity.endpointBinding.signingPublicKey
    })) {
      throw new TypeError("Peer route-set signature is invalid.");
    }
    await verifyRelationshipEndpointBindingV4({
      crypto,
      pqc,
      authoritySigningPublicKey: value.localIdentity.signing.publicKey,
      endpointBinding: value.localIdentity.endpointBinding,
      now: value.localIdentity.endpointBinding.prekeyBundle.createdAt
    });
    await verifyRelationshipEndpointBindingV4({
      crypto,
      pqc,
      authoritySigningPublicKey: value.peerIdentity.signingPublicKey,
      endpointBinding: value.peerIdentity.endpointBinding,
      now: value.peerIdentity.endpointBinding.prekeyBundle.createdAt
    });
    return value;
  } catch (error) {
    if (error instanceof ContactPairingV2Error) throw error;
    throw new ContactPairingV2Error("invalidRelationship", "Pairwise relationship is invalid.", error);
  }
}

async function makeIntroductionBundle({
  crypto,
  pqc,
  participant,
  relationshipID,
  transcriptDigest,
  issuedAt,
  expiresAt
}) {
  const local = participant.localIdentity;
  const sendRoute = await createOpaqueSendRouteV2({
    crypto,
    relay: participant.localReceiveRoute.relay,
    route: participant.localReceiveRoute.route,
    clientCapabilities: participant.localReceiveRoute.clientCapabilities,
    payloadKey: participant.localReceiveRoute.payloadKey
  });
  const routeSet = createPairwiseRouteSetV2({
    pqc,
    relationshipID,
    ownerEndpointHandle: participant.localEndpointHandle,
    activeRoutes: [sendRoute],
    issuedAt,
    ownerSigningPublicKey: local.localEndpoint.signing.publicKey,
    ownerSigningSecretKey: local.localEndpoint.signing.secretKey
  });
  const introduction = await createContactIntroductionV2({
    crypto,
    pqc,
    relationshipPseudonym: local.relationshipPseudonym,
    relationshipSigningPublicKey: local.signing.publicKey,
    relationshipSigningSecretKey: local.signing.secretKey,
    relationshipAgreementPublicKey: local.agreement.publicKey,
    endpointBinding: local.endpointBinding,
    receiveRoutes: routeSet,
    rendezvousTranscriptDigest: transcriptDigest,
    issuedAt,
    expiresAt
  });
  return Object.freeze({ routeSet, introduction });
}

async function createPairwiseRelationshipV2({
  crypto,
  pqc,
  participant,
  localBundle,
  peerIntroduction,
  relationshipID,
  acceptedAt
}) {
  const peer = validateContactIntroductionV2(peerIntroduction, { pqc });
  const peerIdentity = Object.freeze({
    version: PAIRING_VERSION,
    id: swiftUUID(),
    relationshipID,
    relationshipPseudonym: peer.relationshipPseudonym,
    signingPublicKey: peer.relationshipSigningPublicKey,
    agreementPublicKey: peer.relationshipAgreementPublicKey,
    endpointBinding: peer.endpointBinding,
    sendRoutes: peer.receiveRoutes,
    createdAt: acceptedAt
  });
  const relationship = {
    version: PAIRING_VERSION,
    relationshipID,
    localIdentity: {
      ...participant.localIdentity,
      relationshipID,
      endpointHandle: participant.localEndpointHandle
    },
    localEndpointHandle: participant.localEndpointHandle,
    localReceiveRoutes: [participant.localReceiveRoute],
    localAdvertisedRoutes: localBundle.routeSet,
    peerIdentity,
    localPolicy: createRelationshipLocalPolicyV2(),
    createdAt: acceptedAt
  };
  await validatePairwiseRelationshipV2({ crypto, pqc, relationship });
  return relationship;
}

async function sealJsonFrame({ crypto, session, value, kind, at }) {
  const bytes = canonicalJsonBytes(value);
  if (bytes.byteLength > MAX_FRAME_OBJECT_BYTES) {
    throw new ContactPairingV2Error("invalidParticipant", "Pairing frame is too large.");
  }
  return sealRendezvousFrameV2({ crypto, session, plaintext: bytes, kind, at });
}

async function openJsonFrame({ crypto, session, frame, expectedKind, at }) {
  if (frame?.messageKind !== expectedKind) {
    throw new ContactPairingV2Error("invalidFrame", "Pairing frame kind is invalid.");
  }
  const opened = await openRendezvousFrameV2({ crypto, session, frame, at });
  let value;
  try {
    value = parseExactJSON(decoder.decode(opened.plaintext));
  } catch (error) {
    throw new ContactPairingV2Error("invalidFrame", "Pairing frame is not JSON.", error);
  }
  if (!equalBytes(opened.plaintext, canonicalJsonBytes(value))) {
    throw new ContactPairingV2Error("invalidFrame", "Pairing frame is not canonical.");
  }
  return { value, session: opened.session };
}

function requireMatchingConfirmation(expected, actual) {
  requireExactRecord(actual, [
    "version",
    "relationshipID",
    "offererIntroductionDigest",
    "responderIntroductionDigest"
  ], "Pairing confirmation");
  if (actual.version !== PAIRING_VERSION || actual.relationshipID !== expected.relationshipID ||
      actual.offererIntroductionDigest !== expected.offererIntroductionDigest ||
      actual.responderIntroductionDigest !== expected.responderIntroductionDigest) {
    throw new ContactPairingV2Error("invalidConfirmation", "Pairing confirmation does not match.");
  }
}

function requireExactRecord(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new TypeError(`${label} fields do not match the current protocol.`);
  }
}

function validateRelationshipPseudonym(value) {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 ||
      encoder.encode(value).byteLength > 512 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError("Relationship pseudonym is invalid.");
  }
  return value;
}

function canonicalUUID(value) {
  return typeof value === "string" &&
    /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u.test(value);
}

function requireGeneratedKeypair(value, label) {
  if (!(value?.publicKey instanceof Uint8Array) || !(value?.secretKey instanceof Uint8Array) ||
      value.publicKey.byteLength === 0 || value.secretKey.byteLength === 0) {
    throw new TypeError(`${label} key creation failed.`);
  }
}

function serializeKeypair(value) {
  return Object.freeze({ publicKey: base64(value.publicKey), secretKey: base64(value.secretKey) });
}

function requireCanonicalBase64(value, bytes, label) {
  const decoded = decodeBase64(value, bytes, label);
  if (decoded.byteLength !== bytes) throw new TypeError(`${label} length is invalid.`);
  return value;
}

function decodeBase64(value, maximumBytes = 128 * 1_024, label = "base64 value") {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > Math.ceil(maximumBytes / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  const binary = atob(value);
  if (binary.length > maximumBytes) throw new TypeError(`${label} is too large.`);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64(bytes) !== value) throw new TypeError(`${label} is not canonical.`);
  return bytes;
}

function equalBytes(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) ||
      left.byteLength !== right.byteLength) return false;
  let different = 0;
  for (let index = 0; index < left.byteLength; index += 1) different |= left[index] ^ right[index];
  return different === 0;
}
