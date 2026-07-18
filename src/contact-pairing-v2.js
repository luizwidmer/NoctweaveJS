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
  rendezvousOfferDigestV2,
  rendezvousRedemptionSecretV2,
  sealRendezvousFrameV2,
  validatePendingRendezvousOfferV2,
  validateRendezvousOfferV2,
  validateRendezvousRedemptionLedgerV2
} from "./rendezvous-v2.js";
import {
  createRendezvousRelayAdapterV2,
  rendezvousRelayInboundDirectionV2,
  rendezvousRelayOutboundDirectionV2,
  validateAppendRendezvousTransportV2Request,
  validateRendezvousRelayCiphertextFrameV2
} from "./rendezvous-relay-v2.js";
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
const PAIRING_STATE_SCHEMA = "nw.contact-pairing-state.v2";
const pairingRoles = new Set(["offerer", "responder"]);
const pairingPhases = new Set([
  "awaitingOpen",
  "awaitingAcceptance",
  "awaitingIntroduction",
  "awaitingConfirmation",
  "ready"
]);

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
  "gapState",
  "reassembler"
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
const pairingStateFields = Object.freeze([
  "stateSchema",
  "version",
  "pairingID",
  "role",
  "phase",
  "offer",
  "participant",
  "pendingOffer",
  "ledger",
  "session",
  "relationshipID",
  "localBundle",
  "peerIntroduction",
  "confirmation",
  "nextOutboundTransportSequence",
  "nextInboundTransportSequence",
  "outboundTransportFrames",
  "createdAt",
  "updatedAt"
]);
const persistedSessionFields = Object.freeze([
  "sessionId",
  "purpose",
  "localRole",
  "transcriptDigest",
  "openedAt",
  "expiresAt",
  "limits",
  "nextOutboundSequence",
  "nextInboundSequence",
  "sendKey",
  "receiveKey"
]);

export const noctweaveContactPairingV2 = Object.freeze({
  version: PAIRING_VERSION,
  invitationMaximumBytes: MAX_INVITATION_BYTES,
  relationshipScope: "pairwise-only",
  stateSchema: PAIRING_STATE_SCHEMA
});

export const contactPairingStateSchemaV2 = PAIRING_STATE_SCHEMA;

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
 * Creates the offerer's independently persisted pairing machine. The state
 * contains only the offerer's fresh relationship authority and one-use offer
 * secrets. No responder state is accepted or retained.
 */
export async function prepareContactPairingOffererV2({
  crypto,
  pqc,
  pending: pendingValue,
  invitation: invitationValue,
  participant,
  ledger = createRendezvousRedemptionLedgerV2(),
  at = participant?.createdAt
}) {
  const invitation = await validateContactPairingInvitationV2(crypto, invitationValue);
  const pending = await validatePendingRendezvousOfferV2(crypto, pendingValue);
  await validatePreparedContactParticipantV2({ crypto, pqc, participant });
  if (pending.redeemedAt !== undefined) {
    throw new ContactPairingV2Error("alreadyRedeemed");
  }
  if (!equalBytes(canonicalJsonBytes(pending.offer), canonicalJsonBytes(invitation.offer))) {
    throw new ContactPairingV2Error("invalidState", "Offerer pairing secrets do not match the invitation.");
  }
  const state = pairingState({
    pairingID: base64(await rendezvousOfferDigestV2(crypto, invitation.offer)),
    role: "offerer",
    phase: "awaitingOpen",
    offer: invitation.offer,
    participant,
    pendingOffer: pending,
    ledger: validateRendezvousRedemptionLedgerV2(ledger),
    session: null,
    relationshipID: null,
    localBundle: null,
    peerIntroduction: null,
    confirmation: null,
    nextOutboundTransportSequence: 1,
    nextInboundTransportSequence: 1,
    outboundTransportFrames: [],
    createdAt: at,
    updatedAt: at
  });
  return resumeContactPairingV2({ crypto, pqc, state });
}

/**
 * Creates the responder's independently persisted pairing machine and its
 * exact opaque relay outbox. Only the responder's private participant state
 * is accepted. The returned frames can be retried byte-for-byte after a crash.
 */
export async function prepareContactPairingResponderV2({
  crypto,
  pqc,
  invitation: invitationValue,
  participant,
  at = participant?.createdAt
}) {
  const invitation = await validateContactPairingInvitationV2(crypto, invitationValue);
  await validatePreparedContactParticipantV2({ crypto, pqc, participant });
  const opened = await createRendezvousOpenV2({
    crypto,
    offer: invitation.offer,
    redemptionSecret: invitation.redemptionSecret,
    at
  });
  const relationshipID = await derivePairwiseRelationshipIDV2({
    crypto,
    rendezvousTranscriptDigest: opened.session.transcriptDigest
  });
  const localBundle = await makeIntroductionBundle({
    crypto,
    pqc,
    participant,
    relationshipID,
    transcriptDigest: opened.session.transcriptDigest,
    issuedAt: at,
    expiresAt: invitation.offer.expiresAt
  });
  const acceptance = await sealJsonFrame({
    crypto,
    session: opened.session,
    value: localBundle.introduction,
    kind: "acceptance",
    at
  });
  const adapter = await createRendezvousRelayAdapterV2({ crypto, offer: invitation.offer });
  const [openTransport, acceptanceTransport] = await Promise.all([
    adapter.sealOpen({ open: opened.request }),
    adapter.sealSessionFrame({ frame: acceptance.frame, transportSequence: 2 })
  ]);
  const state = pairingState({
    pairingID: base64(await rendezvousOfferDigestV2(crypto, invitation.offer)),
    role: "responder",
    phase: "awaitingIntroduction",
    offer: invitation.offer,
    participant,
    pendingOffer: null,
    ledger: null,
    session: persistSession(acceptance.session),
    relationshipID,
    localBundle,
    peerIntroduction: null,
    confirmation: null,
    nextOutboundTransportSequence: 3,
    nextInboundTransportSequence: 1,
    outboundTransportFrames: [openTransport, acceptanceTransport],
    createdAt: at,
    updatedAt: at
  });
  return resumeContactPairingV2({ crypto, pqc, state });
}

/** Restores and cryptographically validates one side's exact persisted state. */
export async function resumeContactPairingV2({ crypto, pqc, state: stateValue }) {
  try {
    const state = clonePersistedPairingState(stateValue);
    validateContactPairingStateShapeV2(state);
    const offer = validateRendezvousOfferV2(state.offer);
    const expectedPairingID = base64(await rendezvousOfferDigestV2(crypto, offer));
    if (state.pairingID !== expectedPairingID) {
      throw new TypeError("Pairing state belongs to another rendezvous offer.");
    }
    await validatePreparedContactParticipantV2({ crypto, pqc, participant: state.participant });
    if (state.role === "offerer") {
      const pending = await validatePendingRendezvousOfferV2(crypto, state.pendingOffer);
      if (!equalBytes(canonicalJsonBytes(pending.offer), canonicalJsonBytes(offer))) {
        throw new TypeError("Offerer pending state belongs to another rendezvous.");
      }
      validateRendezvousRedemptionLedgerV2(state.ledger);
    } else if (state.pendingOffer !== null || state.ledger !== null) {
      throw new TypeError("Responder state cannot contain offerer redemption authority.");
    }
    const session = state.session === null ? null : reviveSession(state.session);
    validatePairingPhaseState(state, session);
    if (session !== null) {
      const relationshipID = await derivePairwiseRelationshipIDV2({
        crypto,
        rendezvousTranscriptDigest: session.transcriptDigest
      });
      if (session.localRole !== state.role || state.relationshipID !== relationshipID) {
        throw new TypeError("Pairing role or rendezvous transcript does not match persisted state.");
      }
      if (state.localBundle !== null) {
        const introduction = await verifyContactIntroductionV2({
          crypto,
          pqc,
          introduction: state.localBundle.introduction,
          rendezvousTranscriptDigest: session.transcriptDigest,
          at: state.updatedAt
        });
        validatePairwiseRouteSetV2(state.localBundle.routeSet);
        if (!equalBytes(canonicalJsonBytes(introduction), canonicalJsonBytes(state.localBundle.introduction)) ||
            !equalBytes(canonicalJsonBytes(introduction.receiveRoutes), canonicalJsonBytes(state.localBundle.routeSet))) {
          throw new TypeError("Local pairing introduction is inconsistent.");
        }
      }
      if (state.peerIntroduction !== null) {
        await verifyContactIntroductionV2({
          crypto,
          pqc,
          introduction: state.peerIntroduction,
          rendezvousTranscriptDigest: session.transcriptDigest,
          at: state.updatedAt
        });
      }
      if (state.confirmation !== null) {
        requireMatchingConfirmation(
          await makeConfirmation({
            crypto,
            relationshipID,
            offererIntroduction: state.role === "offerer"
              ? state.localBundle?.introduction
              : state.peerIntroduction,
            responderIntroduction: state.role === "responder"
              ? state.localBundle?.introduction
              : state.peerIntroduction
          }),
          state.confirmation
        );
      }
    }
    const adapter = await createRendezvousRelayAdapterV2({ crypto, offer });
    const outboundDirection = rendezvousRelayOutboundDirectionV2(state.role);
    const outboundLane = adapter.lane(outboundDirection).registration;
    const outboundSequences = new Set();
    for (const frameValue of state.outboundTransportFrames) {
      const append = validateAppendRendezvousTransportV2Request(frameValue);
      if (append.routeCapability.rawValue !== adapter.routeCapability.rawValue ||
          append.laneId.rawValue !== outboundLane.laneId.rawValue ||
          append.publishCapability.rawValue !== outboundLane.publishCapability.rawValue ||
          outboundSequences.has(append.frame.sequence) ||
          append.frame.sequence >= state.nextOutboundTransportSequence) {
        throw new TypeError("Pairing outbox authority or transport sequence is inconsistent.");
      }
      outboundSequences.add(append.frame.sequence);
      const opened = await adapter.open({
        frame: append.frame,
        direction: outboundDirection
      });
      if ((opened.kind === "open" && state.role !== "responder") ||
          (opened.kind === "sessionFrame" && opened.frame.senderRole !== state.role)) {
        throw new TypeError("Pairing outbox role is inconsistent.");
      }
    }
    return state;
  } catch (error) {
    if (error instanceof ContactPairingV2Error) throw error;
    throw new ContactPairingV2Error("invalidState", "Persisted contact pairing state is invalid.", error);
  }
}

/**
 * Processes exactly one opaque relay ciphertext frame. The caller never
 * supplies peer participant state, and state is returned only after the frame
 * passes role, sequence, transcript, and signature validation.
 */
export async function processContactPairingTransportFrameV2({
  crypto,
  pqc,
  state: stateValue,
  transportFrame: transportFrameValue,
  at = swiftISODate()
}) {
  const state = await resumeContactPairingV2({ crypto, pqc, state: stateValue });
  if (state.phase === "ready") {
    throw new ContactPairingV2Error("invalidPhase", "Pairing is already ready to finalize.");
  }
  const transportFrame = validateRendezvousRelayCiphertextFrameV2(transportFrameValue);
  if (transportFrame.sequence !== state.nextInboundTransportSequence) {
    throw new ContactPairingV2Error("replayedFrame", "Pairing transport sequence is unexpected.");
  }
  const adapter = await createRendezvousRelayAdapterV2({ crypto, offer: state.offer });
  const opened = await adapter.open({
    frame: transportFrame,
    direction: rendezvousRelayInboundDirectionV2(state.role)
  });
  if (state.role === "offerer") {
    return processOffererFrame({ crypto, pqc, state, opened, at, adapter });
  }
  return processResponderFrame({ crypto, pqc, state, opened, at, adapter });
}

/** Removes relay-accepted frames from the exact persisted outbox. */
export async function acknowledgeContactPairingOutboundV2({ crypto, pqc, state: stateValue, frameIDs }) {
  const state = await resumeContactPairingV2({ crypto, pqc, state: stateValue });
  if (!Array.isArray(frameIDs) || frameIDs.length === 0 ||
      frameIDs.some((value) => typeof value !== "string")) {
    throw new TypeError("Pairing frame acknowledgements must contain frame ID strings.");
  }
  const acknowledged = new Set(frameIDs);
  const known = new Set(state.outboundTransportFrames.map(({ frame }) => frame.frameId.rawValue));
  if (acknowledged.size !== frameIDs.length || [...acknowledged].some((frameID) => !known.has(frameID))) {
    throw new ContactPairingV2Error("invalidAcknowledgement", "Pairing outbox acknowledgement is invalid.");
  }
  return resumeContactPairingV2({
    crypto,
    pqc,
    state: pairingState({
      ...state,
      outboundTransportFrames: state.outboundTransportFrames.filter(({ frame }) =>
        !acknowledged.has(frame.frameId.rawValue))
    })
  });
}

/** Finalizes one ready side into a pairwise relationship and a secret-free receipt. */
export async function finalizeContactPairingV2({
  crypto,
  pqc,
  state: stateValue,
  at = swiftISODate()
}) {
  const state = await resumeContactPairingV2({ crypto, pqc, state: stateValue });
  if (state.phase !== "ready") {
    throw new ContactPairingV2Error("invalidPhase", "Pairing is not ready to finalize.");
  }
  if (state.outboundTransportFrames.length !== 0) {
    throw new ContactPairingV2Error(
      "outboundNotAccepted",
      "Pairing cannot finalize before its exact relay outbox is acknowledged."
    );
  }
  const relationship = await createPairwiseRelationshipV2({
    crypto,
    pqc,
    participant: state.participant,
    localBundle: state.localBundle,
    peerIntroduction: state.peerIntroduction,
    relationshipID: state.relationshipID,
    acceptedAt: at
  });
  return Object.freeze({
    relationship,
    receipt: Object.freeze({
      stateSchema: PAIRING_STATE_SCHEMA,
      version: PAIRING_VERSION,
      pairingID: state.pairingID,
      relationshipID: state.relationshipID,
      role: state.role,
      phase: "finalized",
      finalizedAt: at
    })
  });
}

/** Cancels locally without preserving participant or rendezvous secrets. */
export async function cancelContactPairingV2({ crypto, pqc, state: stateValue, at = swiftISODate() }) {
  const state = await resumeContactPairingV2({ crypto, pqc, state: stateValue });
  return Object.freeze({
    stateSchema: PAIRING_STATE_SCHEMA,
    version: PAIRING_VERSION,
    pairingID: state.pairingID,
    role: state.role,
    phase: "cancelled",
    cancelledAt: at
  });
}

/** Cheap synchronous shape check used by encrypted local persona storage. */
export function validateContactPairingStateShapeV2(value) {
  requireExactRecord(value, pairingStateFields, "Contact pairing state");
  if (value.stateSchema !== PAIRING_STATE_SCHEMA || value.version !== PAIRING_VERSION ||
      !pairingRoles.has(value.role) || !pairingPhases.has(value.phase) ||
      typeof value.pairingID !== "string" || value.pairingID.length === 0 ||
      !Number.isFinite(Date.parse(value.createdAt)) || !Number.isFinite(Date.parse(value.updatedAt)) ||
      !Number.isInteger(value.nextOutboundTransportSequence) || value.nextOutboundTransportSequence < 1 ||
      value.nextOutboundTransportSequence > 33 ||
      !Number.isInteger(value.nextInboundTransportSequence) || value.nextInboundTransportSequence < 1 ||
      value.nextInboundTransportSequence > 33 ||
      !Array.isArray(value.outboundTransportFrames) || value.outboundTransportFrames.length > 32) {
    throw new TypeError("Contact pairing state shape is invalid.");
  }
  return value;
}

async function processOffererFrame({ crypto, pqc, state, opened, at, adapter }) {
  if (state.phase === "awaitingOpen") {
    if (opened.kind !== "open") {
      throw new ContactPairingV2Error("invalidPhase", "Offerer expected the rendezvous open frame.");
    }
    const accepted = await acceptRendezvousOpenV2({
      crypto,
      pending: state.pendingOffer,
      request: opened.open,
      ledger: state.ledger,
      at
    });
    const relationshipID = await derivePairwiseRelationshipIDV2({
      crypto,
      rendezvousTranscriptDigest: accepted.session.transcriptDigest
    });
    return resumeContactPairingV2({
      crypto,
      pqc,
      state: pairingState({
        ...state,
        phase: "awaitingAcceptance",
        pendingOffer: accepted.pending,
        ledger: accepted.ledger,
        session: persistSession(accepted.session),
        relationshipID,
        nextInboundTransportSequence: state.nextInboundTransportSequence + 1,
        updatedAt: at
      })
    });
  }
  if (opened.kind !== "sessionFrame") {
    throw new ContactPairingV2Error("invalidPhase", "Offerer expected an encrypted session frame.");
  }
  if (state.phase === "awaitingAcceptance") {
    const accepted = await openJsonFrame({
      crypto,
      session: reviveSession(state.session),
      frame: opened.frame,
      expectedKind: "acceptance",
      at
    });
    const peerIntroduction = await verifyContactIntroductionV2({
      crypto,
      pqc,
      introduction: accepted.value,
      rendezvousTranscriptDigest: accepted.session.transcriptDigest,
      at
    });
    const localBundle = await makeIntroductionBundle({
      crypto,
      pqc,
      participant: state.participant,
      relationshipID: state.relationshipID,
      transcriptDigest: accepted.session.transcriptDigest,
      issuedAt: at,
      expiresAt: state.offer.expiresAt
    });
    const confirmation = await makeConfirmation({
      crypto,
      relationshipID: state.relationshipID,
      offererIntroduction: localBundle.introduction,
      responderIntroduction: peerIntroduction
    });
    const introduction = await sealJsonFrame({
      crypto,
      session: accepted.session,
      value: localBundle.introduction,
      kind: "introduction",
      at
    });
    const transport = await adapter.sealSessionFrame({
      frame: introduction.frame,
      transportSequence: state.nextOutboundTransportSequence
    });
    return resumeContactPairingV2({
      crypto,
      pqc,
      state: pairingState({
        ...state,
        phase: "awaitingConfirmation",
        session: persistSession(introduction.session),
        localBundle,
        peerIntroduction,
        confirmation,
        nextOutboundTransportSequence: state.nextOutboundTransportSequence + 1,
        nextInboundTransportSequence: state.nextInboundTransportSequence + 1,
        outboundTransportFrames: [...state.outboundTransportFrames, transport],
        updatedAt: at
      })
    });
  }
  if (state.phase === "awaitingConfirmation") {
    const confirmed = await openJsonFrame({
      crypto,
      session: reviveSession(state.session),
      frame: opened.frame,
      expectedKind: "confirmation",
      at
    });
    requireMatchingConfirmation(state.confirmation, confirmed.value);
    const acknowledgement = await sealJsonFrame({
      crypto,
      session: confirmed.session,
      value: state.confirmation,
      kind: "confirmation",
      at
    });
    const transport = await adapter.sealSessionFrame({
      frame: acknowledgement.frame,
      transportSequence: state.nextOutboundTransportSequence
    });
    return resumeContactPairingV2({
      crypto,
      pqc,
      state: pairingState({
        ...state,
        phase: "ready",
        session: persistSession(acknowledgement.session),
        nextOutboundTransportSequence: state.nextOutboundTransportSequence + 1,
        nextInboundTransportSequence: state.nextInboundTransportSequence + 1,
        outboundTransportFrames: [...state.outboundTransportFrames, transport],
        updatedAt: at
      })
    });
  }
  throw new ContactPairingV2Error("invalidPhase", "Offerer pairing phase is invalid.");
}

async function processResponderFrame({ crypto, pqc, state, opened, at, adapter }) {
  if (opened.kind !== "sessionFrame") {
    throw new ContactPairingV2Error("invalidPhase", "Responder expected an encrypted session frame.");
  }
  if (state.phase === "awaitingIntroduction") {
    const introduced = await openJsonFrame({
      crypto,
      session: reviveSession(state.session),
      frame: opened.frame,
      expectedKind: "introduction",
      at
    });
    const peerIntroduction = await verifyContactIntroductionV2({
      crypto,
      pqc,
      introduction: introduced.value,
      rendezvousTranscriptDigest: introduced.session.transcriptDigest,
      at
    });
    const confirmation = await makeConfirmation({
      crypto,
      relationshipID: state.relationshipID,
      offererIntroduction: peerIntroduction,
      responderIntroduction: state.localBundle.introduction
    });
    const confirmed = await sealJsonFrame({
      crypto,
      session: introduced.session,
      value: confirmation,
      kind: "confirmation",
      at
    });
    const transport = await adapter.sealSessionFrame({
      frame: confirmed.frame,
      transportSequence: state.nextOutboundTransportSequence
    });
    return resumeContactPairingV2({
      crypto,
      pqc,
      state: pairingState({
        ...state,
        phase: "awaitingConfirmation",
        session: persistSession(confirmed.session),
        peerIntroduction,
        confirmation,
        nextOutboundTransportSequence: state.nextOutboundTransportSequence + 1,
        nextInboundTransportSequence: state.nextInboundTransportSequence + 1,
        outboundTransportFrames: [...state.outboundTransportFrames, transport],
        updatedAt: at
      })
    });
  }
  if (state.phase === "awaitingConfirmation") {
    const acknowledged = await openJsonFrame({
      crypto,
      session: reviveSession(state.session),
      frame: opened.frame,
      expectedKind: "confirmation",
      at
    });
    requireMatchingConfirmation(state.confirmation, acknowledged.value);
    return resumeContactPairingV2({
      crypto,
      pqc,
      state: pairingState({
        ...state,
        phase: "ready",
        session: persistSession(acknowledged.session),
        nextInboundTransportSequence: state.nextInboundTransportSequence + 1,
        updatedAt: at
      })
    });
  }
  throw new ContactPairingV2Error("invalidPhase", "Responder pairing phase is invalid.");
}

async function makeConfirmation({
  crypto,
  relationshipID,
  offererIntroduction,
  responderIntroduction
}) {
  if (offererIntroduction == null || responderIntroduction == null) {
    throw new TypeError("Pairing confirmation requires both introductions.");
  }
  return Object.freeze({
    version: PAIRING_VERSION,
    relationshipID,
    offererIntroductionDigest: base64(await crypto.sha256(canonicalJsonBytes(offererIntroduction))),
    responderIntroductionDigest: base64(await crypto.sha256(canonicalJsonBytes(responderIntroduction)))
  });
}

function pairingState(value) {
  return Object.freeze({
    stateSchema: PAIRING_STATE_SCHEMA,
    version: PAIRING_VERSION,
    ...value
  });
}

function clonePersistedPairingState(value) {
  try {
    return parseExactJSON(decoder.decode(canonicalJsonBytes(value)));
  } catch (error) {
    throw new ContactPairingV2Error("invalidState", "Pairing state is not serializable.", error);
  }
}

function persistSession(value) {
  const session = {
    ...value,
    sendKey: base64(value.sendKey),
    receiveKey: base64(value.receiveKey)
  };
  requireExactRecord(session, persistedSessionFields, "Persisted rendezvous session");
  return Object.freeze(session);
}

function reviveSession(value) {
  requireExactRecord(value, persistedSessionFields, "Persisted rendezvous session");
  return {
    ...value,
    sendKey: decodeBase64(value.sendKey, 32, "rendezvous send key"),
    receiveKey: decodeBase64(value.receiveKey, 32, "rendezvous receive key")
  };
}

function validatePairingPhaseState(state, session) {
  const offererPhases = new Set([
    "awaitingOpen",
    "awaitingAcceptance",
    "awaitingConfirmation",
    "ready"
  ]);
  const responderPhases = new Set([
    "awaitingIntroduction",
    "awaitingConfirmation",
    "ready"
  ]);
  if ((state.role === "offerer" && !offererPhases.has(state.phase)) ||
      (state.role === "responder" && !responderPhases.has(state.phase))) {
    throw new TypeError("Pairing phase is invalid for its role.");
  }
  const counters = {
    "offerer:awaitingOpen": [1, 1, null, null],
    "offerer:awaitingAcceptance": [1, 2, 1, 1],
    "offerer:awaitingConfirmation": [2, 3, 2, 2],
    "offerer:ready": [3, 4, 3, 3],
    "responder:awaitingIntroduction": [3, 1, 2, 1],
    "responder:awaitingConfirmation": [4, 2, 3, 2],
    "responder:ready": [4, 3, 3, 3]
  }[`${state.role}:${state.phase}`];
  if (state.nextOutboundTransportSequence !== counters[0] ||
      state.nextInboundTransportSequence !== counters[1] ||
      (session !== null && (session.nextOutboundSequence !== counters[2] ||
        session.nextInboundSequence !== counters[3]))) {
    throw new TypeError("Pairing phase counters are inconsistent.");
  }
  if (state.role === "offerer" && state.phase === "awaitingOpen") {
    if (session !== null || state.relationshipID !== null || state.localBundle !== null ||
        state.peerIntroduction !== null || state.confirmation !== null) {
      throw new TypeError("Unopened offerer state contains active-session data.");
    }
    return;
  }
  if (session === null || typeof state.relationshipID !== "string") {
    throw new TypeError("Active pairing state is missing its rendezvous session.");
  }
  if (state.role === "offerer" && state.phase === "awaitingAcceptance") {
    if (state.localBundle !== null || state.peerIntroduction !== null || state.confirmation !== null) {
      throw new TypeError("Offerer acceptance state is inconsistent.");
    }
    return;
  }
  if (state.role === "responder" && state.phase === "awaitingIntroduction") {
    if (state.localBundle === null || state.peerIntroduction !== null || state.confirmation !== null) {
      throw new TypeError("Responder introduction state is inconsistent.");
    }
    return;
  }
  if (state.localBundle === null || state.peerIntroduction === null || state.confirmation === null) {
    throw new TypeError("Confirmed pairing state is incomplete.");
  }
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
