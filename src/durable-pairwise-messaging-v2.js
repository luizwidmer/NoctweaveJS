import {
  advanceDeliveryState,
  createConversationEvent,
  createDeliveryReceiptEncodedContent,
  createDeliveryStateRecord,
  createReadReceiptEncodedContent,
  createTextEncodedContent,
  validateConversationEvent,
  validateDeliveryStateRecord,
  validateEncodedContent
} from "./architecture-v2.js";
import { validatePairwiseRelationshipV2 } from "./contact-pairing-v2.js";
import {
  NoctweaveRemoteEnvelopeError,
  createNativeInboundSession,
  createNativeOutboundSession,
  decryptNativeProtocolEnvelope,
  encryptNativeApplicationEnvelope,
  encryptNativeRelationshipControlEnvelope
} from "./crypto/noctweave-native-message.js";
import {
  derivePairwiseDirectV4Binding,
  isPeerPairwiseIdentityV2,
  relationshipEndpointAuthorizationDigestV4,
  verifyRelationshipEndpointBindingV4
} from "./crypto/direct-v4.js";
import { validateDirectEnvelopeV4 } from "./crypto/noctweave-wire.js";
import {
  base64,
  canonicalJsonBytes,
  swiftISODate,
  swiftUUID
} from "./crypto/swift-canonical.js";
import {
  OpaqueRoutePacketV2Error,
  opaqueRoutePacketSendAuthorizationExpiredV2,
  refreshOpaqueRoutePacketSendAuthorizationV2,
  sealOpaqueRouteBundleV2,
  validateOpaqueRoutePacketV2,
  validateOpaqueRouteSealedBundleV2
} from "./opaque-route-packet-v2.js";
import { validateOpaqueRouteEnqueueResponseShapeV2 } from "./opaque-route-relay-v2.js";
import {
  teardownOpaqueReceiveRouteV2,
  validateOpaqueReceiveRouteV2,
  validateOpaqueRouteTeardownRequestV2
} from "./opaque-route-v2.js";
import {
  createOpaqueSendRouteV2,
  pairwiseRouteSetV2Digest,
  updateLocalOpaqueReceiveRouteReassemblerV2,
  usablePairwiseRoutesV2,
  validateLocalOpaqueReceiveRouteV2,
  validateOpaqueSendRouteV2,
  validatePairwiseRouteSetV2,
  verifyPairwiseRouteSetV2Throwing
} from "./pairwise-opaque-route-v2.js";
import {
  createRelationshipEndpointPrekeyUpdateV2,
  createRelationshipRouteProbeV2,
  createRelationshipRouteSetUpdateV2,
  relationshipControlKindsV2
} from "./relationship-control-v2.js";
import { NoctweaveRelayClient } from "./relay-client.js";
import { validateRelationshipLocalPolicyV2 } from "./relationship-local-policy-v2.js";
import { EncryptedNoctweaveStore, NoctweaveStateRepository } from "./storage.js";
import { parseExactJSON } from "./strict-json.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const STATE_SCHEMA = "org.noctweave.js.durable-pairwise-messaging.v2";
const STATE_VERSION = 2;
const STATE_ANCHOR_VERSION = 2;
const MAXIMUM_PENDING_INTENTS = 32;
const MAXIMUM_RETAINED_INTENTS = 512;
const MAXIMUM_RECEIVED_EVENTS = 512;
const MAXIMUM_QUARANTINED_PACKETS = 64;
const MAXIMUM_QUARANTINED_ENVELOPES = 128;
const MAXIMUM_QUARANTINED_CONTROLS = 64;
const MAXIMUM_LOCAL_ENDPOINT_BINDINGS = 4;
const MAXIMUM_PEER_ENDPOINT_BINDINGS = 4;
const MAXIMUM_RETIRED_LOCAL_ROUTES = 8;
const MAXIMUM_SESSIONS = 4;
const MAXIMUM_ATTEMPTS = 8;
const MAXIMUM_STATE_BYTES = 7 * 1_024 * 1_024;
const MAXIMUM_INBOUND_DELIVERY_DELAY_MS = 7 * 86_400_000;
const MAXIMUM_INBOUND_FUTURE_SKEW_MS = 5 * 60_000;
const intentStates = new Set([
  "prepared",
  "publishing",
  "retryableFailure",
  "relayAccepted",
  "permanentFailure",
  "discarded"
]);
const routeDeliveryStates = new Set(["pending", "relayAccepted"]);
const terminalOpaquePacketFailures = new Set([
  "packetIdentifierConflict",
  "bundleConflict",
  "fragmentConflict",
  "malformedFrame",
  "bundleDigestMismatch"
]);
const terminalQuarantineReasons = new Set([
  ...terminalOpaquePacketFailures,
  "invalidEnvelopeEncoding"
]);

export const durablePairwiseMessagingV2 = Object.freeze({
  stateSchema: STATE_SCHEMA,
  version: STATE_VERSION,
  maximumPendingIntents: MAXIMUM_PENDING_INTENTS,
  maximumRetainedIntents: MAXIMUM_RETAINED_INTENTS,
  maximumReceivedEvents: MAXIMUM_RECEIVED_EVENTS,
  maximumQuarantinedPackets: MAXIMUM_QUARANTINED_PACKETS,
  maximumQuarantinedEnvelopes: MAXIMUM_QUARANTINED_ENVELOPES,
  maximumQuarantinedControls: MAXIMUM_QUARANTINED_CONTROLS,
  maximumLocalEndpointBindings: MAXIMUM_LOCAL_ENDPOINT_BINDINGS,
  maximumPeerEndpointBindings: MAXIMUM_PEER_ENDPOINT_BINDINGS,
  maximumRetiredLocalRoutes: MAXIMUM_RETIRED_LOCAL_ROUTES,
  maximumSessions: MAXIMUM_SESSIONS,
  maximumAttempts: MAXIMUM_ATTEMPTS,
  maximumStateBytes: MAXIMUM_STATE_BYTES,
  maximumInboundDeliveryDelayMilliseconds: MAXIMUM_INBOUND_DELIVERY_DELAY_MS,
  maximumInboundFutureSkewMilliseconds: MAXIMUM_INBOUND_FUTURE_SKEW_MS
});

export const relationshipStateAnchorV2 = Object.freeze({
  version: STATE_ANCHOR_VERSION,
  authenticationTagBytes: 32,
  stateDigestBytes: 32
});

export class DurablePairwiseMessagingV2Error extends Error {
  constructor(code, message = code, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "DurablePairwiseMessagingV2Error";
    this.code = code;
  }
}

/**
 * Crash-durable application and receipt messaging for exactly one disposable
 * pairwise relationship. The runtime never creates an account, global inbox,
 * installation identity, or shared device state. Its only authority is the
 * relationship supplied by contact pairing, and its state must be encrypted.
 */
export class DurablePairwiseMessagingRuntimeV2 {
  constructor({
    crypto,
    pqc,
    relationship,
    store,
    stateKey,
    stateAnchorStore,
    anchorKey,
    relayClientFactory,
    relayClientOptions = {}
  }) {
    if (!crypto || !pqc) {
      throw new TypeError("Durable pairwise messaging requires protocol cryptography.");
    }
    if (!(store instanceof EncryptedNoctweaveStore)) {
      throw new TypeError("Durable pairwise messaging requires EncryptedNoctweaveStore.");
    }
    if (!stateAnchorStore || typeof stateAnchorStore.load !== "function" ||
        typeof stateAnchorStore.commit !== "function" ||
        typeof stateAnchorStore.destroy !== "function") {
      throw new TypeError(
        "Durable pairwise messaging requires a relationship-local rollback anchor store."
      );
    }
    this.crypto = crypto;
    this.pqc = pqc;
    this.relationship = relationship;
    this.stateKey = validateStateKey(
      stateKey ?? `pairwise-runtime-v2:${relationship?.relationshipID ?? "invalid"}`
    );
    this.repository = new NoctweaveStateRepository(store, { key: this.stateKey });
    this.stateAnchorStore = stateAnchorStore;
    this.anchorKey = validateStateKey(anchorKey ?? `${this.stateKey}:anchor`);
    this.currentAnchor = null;
    this.relayClientOptions = relayClientOptions;
    this.relayClientFactory = relayClientFactory ?? ((relay) => new NoctweaveRelayClient(
      relay,
      { ...this.relayClientOptions, crypto: this.crypto }
    ));
    if (typeof this.relayClientFactory !== "function") {
      throw new TypeError("relayClientFactory must be a function.");
    }
    this.queue = Promise.resolve();
    this.relationshipValidation = null;
    this.destroyed = false;
  }

  async open() {
    return this.serialized(async () => publicState(await this.ensureState()));
  }

  async relationshipSnapshot() {
    return this.serialized(async () => clone(runtimeRelationship(await this.ensureState(), this.relationship)));
  }

  async lifecycleSnapshot() {
    return this.serialized(async () => clone((await this.ensureState()).lifecycle));
  }

  async updateLifecycle(patch) {
    requirePlainRecord(patch, "Relationship lifecycle patch");
    const allowed = new Set(["routeMaintenance", "routeTeardown"]);
    if (Object.keys(patch).length === 0 ||
        Object.keys(patch).some((field) => !allowed.has(field))) {
      throw new TypeError("Relationship lifecycle patch fields are invalid.");
    }
    return this.serialized(async () => {
      const state = await this.ensureState();
      const candidate = clone(state);
      candidate.lifecycle = { ...candidate.lifecycle, ...clone(patch) };
      candidate.updatedAt = monotonicStateTimestamp(candidate, swiftISODate());
      await this.saveCandidate(candidate);
      return clone(candidate.lifecycle);
    });
  }

  /**
   * Commits host-local policy into this relationship's monotonic anchor.
   * Blocking is terminal for the relationship scope and cannot be reversed by
   * restoring an older aggregate vault. Non-authoritative presentation
   * preferences share the record so callers receive one coherent snapshot.
   */
  async updateLocalPolicy(localPolicy) {
    const validated = validateRelationshipLocalPolicyV2(localPolicy);
    return this.serialized(async () => {
      const state = await this.ensureState();
      if (state.localPolicy.consent === "blocked" && validated.consent !== "blocked") {
        throw new DurablePairwiseMessagingV2Error(
          "terminalPolicyRollback",
          "A blocked disposable relationship cannot be restored from older local policy."
        );
      }
      if (equalCanonical(state.localPolicy, validated)) return clone(state.localPolicy);
      const candidate = clone(state);
      candidate.localPolicy = clone(validated);
      candidate.updatedAt = monotonicStateTimestamp(candidate, swiftISODate());
      await this.saveCandidate(candidate);
      this.relationship = Object.freeze({
        ...this.relationship,
        localPolicy: validated
      });
      return clone(validated);
    });
  }

  /**
   * Irreversibly removes this runtime's encrypted record and independent
   * rollback anchor as one host-coordinated transaction. The runtime instance
   * is terminal after success and must be discarded with the relationship.
   */
  async destroyRelationshipState() {
    return this.serialized(async () => {
      let expectedAnchor = null;
      try {
        await this.ensureState();
        expectedAnchor = clone(this.currentAnchor);
      } catch (error) {
        if (this.destroyed || (error instanceof DurablePairwiseMessagingV2Error &&
            error.code === "relationshipDestroyed")) throw error;
        // A local burn must still tombstone its fixed relationship scope when
        // encrypted state is missing, corrupt, or rolled back. The secure host
        // is responsible for making a null-expectation destruction terminal.
        this.currentAnchor = null;
      }
      const result = await this.stateAnchorStore.destroy({
        anchorKey: this.anchorKey,
        relationshipID: this.relationship.relationshipID,
        expectedAnchor,
        destroyEncryptedState: () => this.repository.clear()
      });
      exact(result, ["destroyed"], "Relationship anchor destruction result");
      if (result.destroyed !== true) {
        throw new DurablePairwiseMessagingV2Error(
          "rollbackDetected",
          "Relationship anchor store did not confirm atomic state destruction."
        );
      }
      this.currentAnchor = null;
      this.destroyed = true;
      return Object.freeze({ destroyed: true });
    });
  }

  async finalizeLocalRouteRetirement({ evidence, retiredAt = swiftISODate() } = {}) {
    return this.serialized(async () => {
      const state = await this.ensureState();
      const validated = await validateLocalRouteRetirementEvidence(this.crypto, evidence);
      const routeID = validated.request.routeID.rawValue;
      const index = state.localReceiveRoutes.findIndex(({ route }) =>
        route.routeID.rawValue === routeID
      );
      if (index < 0) {
        const retired = state.retiredLocalRoutes.find(({ routeID: candidate }) =>
          candidate.rawValue === routeID
        );
        if (!retired || retired.renewalSequence !== validated.request.renewalSequence ||
            retired.terminalTransitionDigest !== validated.tombstone.lastTransitionDigest) {
          throw new DurablePairwiseMessagingV2Error(
            "invalidRouteRetirement",
            "Retired route has no authenticated durable terminal transition."
          );
        }
        return Object.freeze({
          retired: false,
          routeID: validated.request.routeID,
          relationship: clone(runtimeRelationship(state, this.relationship))
        });
      }
      const advertised = state.localAdvertisedRoutes.routes.find(({ routeID: candidate }) =>
        candidate.rawValue === routeID
      );
      if (!advertised || advertised.state !== "revoked" ||
          advertised.routeRevision !== validated.request.renewalSequence) {
        throw new DurablePairwiseMessagingV2Error(
          "invalidRouteRetirement",
          "Local route retirement requires its signed revoked route-set state."
        );
      }
      const local = state.localReceiveRoutes[index];
      if (state.localReceiveRoutes.length <= 1 || local.gapState !== null ||
          local.reassembler.pendingBundles.length !== 0 ||
          local.route.lease.renewalSequence !== validated.request.renewalSequence ||
          local.route.lastTransitionDigest !== validated.request.previousTransitionDigest ||
          local.clientCapabilities.teardownCapability.rawValue !==
            validated.teardownCapability.rawValue ||
          !opaqueRouteTombstoneMatchesLocal(local.route, validated.tombstone)) {
        throw new DurablePairwiseMessagingV2Error(
          "invalidRouteRetirement",
          "Local route retirement evidence does not close the exact drained route."
        );
      }
      const authenticatedTombstone = await teardownOpaqueReceiveRouteV2({
        crypto: this.crypto,
        current: local.route,
        request: validated.request,
        presentedCapability: validated.teardownCapability,
        confidentialTransport: true,
        receivedAt: validated.tombstone.tornDownAt
      });
      if (!equalCanonical(authenticatedTombstone, validated.tombstone)) {
        throw new DurablePairwiseMessagingV2Error(
          "invalidRouteRetirement",
          "Relay teardown result is not the authenticated terminal transaction result."
        );
      }
      const retirementTime = canonicalTimestamp(retiredAt, "Local route retirement time");
      if (Date.parse(retirementTime) < Date.parse(validated.tombstone.tornDownAt)) {
        throw new DurablePairwiseMessagingV2Error(
          "invalidRouteRetirement",
          "Local route retirement predates its authenticated relay tombstone."
        );
      }
      const candidate = clone(state);
      candidate.localReceiveRoutes.splice(index, 1);
      candidate.retiredLocalRoutes = candidate.retiredLocalRoutes.slice(
        -(MAXIMUM_RETIRED_LOCAL_ROUTES - 1)
      );
      candidate.retiredLocalRoutes.push({
        routeID: validated.request.routeID,
        renewalSequence: validated.request.renewalSequence,
        terminalTransitionDigest: validated.tombstone.lastTransitionDigest,
        revokedRouteSet: clone(state.localAdvertisedRoutes),
        retiredAt: validated.tombstone.tornDownAt
      });
      candidate.updatedAt = monotonicStateTimestamp(
        candidate,
        retirementTime
      );
      await this.saveCandidate(candidate);
      return Object.freeze({
        retired: true,
        routeID: validated.request.routeID,
        relationship: clone(runtimeRelationship(candidate, this.relationship))
      });
    });
  }

  async prepareText({ text, relation, clientTransactionId, eventId, sentAt } = {}) {
    return this.prepareApplication({
      content: createTextEncodedContent(text),
      relation,
      clientTransactionId,
      eventId,
      sentAt,
      eventKind: "application"
    });
  }

  async prepareDeliveryReceipt({ targetEventId, clientTransactionId, eventId, sentAt } = {}) {
    return this.prepareApplication({
      content: createDeliveryReceiptEncodedContent(targetEventId),
      clientTransactionId,
      eventId,
      sentAt,
      eventKind: "receipt"
    });
  }

  async prepareReadReceipt({ targetEventId, clientTransactionId, eventId, sentAt } = {}) {
    return this.prepareApplication({
      content: createReadReceiptEncodedContent(targetEventId),
      clientTransactionId,
      eventId,
      sentAt,
      eventKind: "receipt"
    });
  }

  async prepareApplication({
    content,
    relation,
    clientTransactionId = swiftUUID(),
    eventId = swiftUUID(),
    sentAt = swiftISODate(),
    eventKind = "application"
  }) {
    return this.serialized(async () => {
      const state = await this.ensureState();
      const validatedContent = validateEncodedContent(content);
      const transactionID = canonicalUUID(clientTransactionId, "Client transaction ID");
      const existing = state.intents.find((intent) =>
        intent.clientTransactionId === transactionID
      );
      if (existing) {
        if (!sameLogicalRequest(existing.event, { validatedContent, relation, eventKind })) {
          throw new DurablePairwiseMessagingV2Error(
            "transactionConflict",
            "The client transaction ID already names different content."
          );
        }
        return publicIntent(existing);
      }
      const canonicalSentAt = canonicalTimestamp(sentAt, "Message send time");
      const candidate = clone(state);
      assertOutboxCapacity(candidate);
      const relationship = runtimeRelationship(candidate, this.relationship);
      let conversation = activeOutboundSession(candidate);
      let bootstrap = { kind: "none" };
      if (conversation === null) {
        reserveSessionCapacity(candidate);
        const created = await createNativeOutboundSession({
          crypto: this.crypto,
          pqc: this.pqc,
          localIdentity: relationship.localIdentity,
          peerIdentity: relationship.peerIdentity,
          now: Date.parse(canonicalSentAt)
        });
        conversation = created.conversation;
        bootstrap = created.bootstrap;
        candidate.sessions.push(conversation);
        candidate.activeOutboundSessionID = conversation.sessionId;
      }

      const event = createConversationEvent({
        id: canonicalUUID(eventId, "Event ID"),
        clientTransactionId: transactionID,
        conversationId: conversation.id,
        authorEndpointHandle: conversation.endpointSession.localEndpointHandle,
        createdAt: canonicalSentAt,
        kind: eventKind,
        content: validatedContent,
        relation
      });
      const envelope = await encryptNativeApplicationEnvelope({
        crypto: this.crypto,
        pqc: this.pqc,
        localIdentity: relationship.localIdentity,
        peerIdentity: relationship.peerIdentity,
        conversation,
        content: validatedContent,
        relation,
        eventKind,
        bootstrap,
        eventId: event.id,
        clientTransactionId: transactionID,
        sentAt: canonicalSentAt
      });
      const routes = usablePairwiseRoutesV2(
        relationship.peerIdentity.sendRoutes,
        Date.parse(canonicalSentAt)
      );
      if (routes.length === 0) {
        throw new DurablePairwiseMessagingV2Error(
          "noUsableRoute",
          "The relationship has no usable peer route."
        );
      }
      const payload = canonicalJsonBytes(envelope);
      const routeDeliveries = [];
      for (const route of routes) {
        const sealedBundle = await sealOpaqueRouteBundleV2({
          crypto: this.crypto,
          payload,
          routeRevision: route.routeRevision,
          paddingBucket: route.policy.paddingBucket,
          payloadKey: route.payloadKey,
          sendAuthority: {
            routeID: route.routeID,
            sendCapability: route.sendCapability
          },
          authorizedAt: canonicalSentAt
        });
        routeDeliveries.push({
          route,
          sealedBundle,
          nextPacketIndex: 0,
          status: "pending",
          acceptedAt: null
        });
      }
      const now = canonicalSentAt;
      const intent = {
        id: swiftUUID(),
        sequence: candidate.nextIntentSequence,
        sessionID: conversation.sessionId,
        event,
        clientTransactionId: transactionID,
        directEnvelope: envelope,
        routeDeliveries,
        status: "prepared",
        attemptCount: 0,
        lastFailureCode: null,
        delivery: createDeliveryStateRecord({
          eventId: event.id,
          destinationEndpoint: conversation.endpointSession.peerEndpointHandle,
          state: "locallyPersisted",
          updatedAt: now
        }),
        createdAt: now,
        updatedAt: now
      };
      candidate.nextIntentSequence += 1;
      candidate.intents.push(intent);
      candidate.updatedAt = monotonicStateTimestamp(candidate, now);

      // This is the durability boundary: no relay client exists until the
      // complete event, ratchet mutation, envelope, packets, and intent save.
      await this.saveCandidate(candidate);
      return publicIntent(intent);
    });
  }

  async prepareRouteSetUpdate({
    routeSet,
    localReceiveRoutes,
    clientTransactionId,
    eventId,
    sentAt
  } = {}) {
    const payload = createRelationshipRouteSetUpdateV2({
      relationshipID: this.relationship.relationshipID,
      routeSet
    });
    return this.prepareRelationshipControl({
      kind: "routeSetUpdate",
      payload,
      localEffect: {
        localAdvertisedRoutes: payload.routeSet,
        localReceiveRoutes
      },
      clientTransactionId,
      eventId,
      sentAt
    });
  }

  async prepareRouteProbe({
    routeID,
    routeSetRevision,
    nonce,
    destinationRouteIDs = [routeID],
    clientTransactionId,
    eventId,
    sentAt
  } = {}) {
    return this.prepareRelationshipControl({
      kind: "routeProbe",
      payload: createRelationshipRouteProbeV2({
        relationshipID: this.relationship.relationshipID,
        routeID,
        routeSetRevision,
        nonce
      }),
      destinationRouteIDs,
      clientTransactionId,
      eventId,
      sentAt
    });
  }

  async prepareEndpointPrekeyUpdate({
    endpointBinding,
    localIdentity,
    clientTransactionId,
    eventId,
    sentAt
  } = {}) {
    const payload = createRelationshipEndpointPrekeyUpdateV2({
      relationshipID: this.relationship.relationshipID,
      endpointBinding
    });
    if (localIdentity === undefined ||
        !equalBytes(
          canonicalJsonBytes(localIdentity.endpointBinding),
          canonicalJsonBytes(payload.endpointBinding)
        )) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidLocalControlEffect",
        "Endpoint-prekey publication requires the complete renewed local identity."
      );
    }
    return this.prepareRelationshipControl({
      kind: "endpointPrekeyUpdate",
      payload,
      localEffect: { localIdentity },
      clientTransactionId,
      eventId,
      sentAt
    });
  }

  async prepareRelationshipControl({
    kind,
    payload,
    localEffect = null,
    destinationRouteIDs = null,
    clientTransactionId = swiftUUID(),
    eventId = swiftUUID(),
    sentAt = swiftISODate()
  }) {
    return this.serialized(async () => {
      const state = await this.ensureState();
      const transactionID = canonicalUUID(clientTransactionId, "Client transaction ID");
      const existing = state.intents.find((intent) =>
        intent.clientTransactionId === transactionID
      );
      if (existing) {
        if (!sameLogicalControlRequest(existing.event, { kind, payload })) {
          throw new DurablePairwiseMessagingV2Error(
            "transactionConflict",
            "The client transaction ID already names a different relationship control."
          );
        }
        return publicIntent(existing);
      }
      if (!Object.hasOwn(relationshipControlKindsV2, kind)) {
        throw new DurablePairwiseMessagingV2Error(
          "unknownControl",
          "Only implemented relationship controls may enter the durable outbox."
        );
      }

      const canonicalSentAt = canonicalTimestamp(sentAt, "Control send time");
      const candidate = clone(state);
      assertOutboxCapacity(candidate);
      if (localEffect !== null) {
        exactOptionalLocalControlEffect(localEffect);
        await validateLocalRelationshipControlEffect({
          crypto: this.crypto,
          pqc: this.pqc,
          state,
          baseRelationship: this.relationship,
          kind,
          payload,
          localEffect,
          sentAt: canonicalSentAt
        });
      }
      // The transition event itself is authenticated under the pre-transition
      // endpoint/session. Otherwise a peer could not validate the control that
      // teaches it the successor binding.
      const relationship = runtimeRelationship(state, this.relationship);
      let conversation = activeOutboundSession(candidate);
      let bootstrap = { kind: "none" };
      if (conversation === null) {
        reserveSessionCapacity(candidate);
        const created = await createNativeOutboundSession({
          crypto: this.crypto,
          pqc: this.pqc,
          localIdentity: relationship.localIdentity,
          peerIdentity: relationship.peerIdentity,
          now: Date.parse(canonicalSentAt)
        });
        conversation = created.conversation;
        bootstrap = created.bootstrap;
        candidate.sessions.push(conversation);
        candidate.activeOutboundSessionID = conversation.sessionId;
      }
      const prepared = await encryptNativeRelationshipControlEnvelope({
        crypto: this.crypto,
        pqc: this.pqc,
        localIdentity: relationship.localIdentity,
        peerIdentity: relationship.peerIdentity,
        conversation,
        kind,
        payload,
        bootstrap,
        eventId: canonicalUUID(eventId, "Event ID"),
        clientTransactionId: transactionID,
        sentAt: canonicalSentAt
      });
      const routes = relationshipControlDestinationRoutes({
        kind,
        payload,
        routeSet: relationship.peerIdentity.sendRoutes,
        destinationRouteIDs,
        at: canonicalSentAt
      });
      if (routes.length === 0) {
        throw new DurablePairwiseMessagingV2Error(
          "noUsableRoute",
          "The relationship has no usable peer route."
        );
      }
      const encodedEnvelope = canonicalJsonBytes(prepared.envelope);
      const routeDeliveries = [];
      for (const route of routes) {
        routeDeliveries.push({
          route,
          sealedBundle: await sealOpaqueRouteBundleV2({
            crypto: this.crypto,
            payload: encodedEnvelope,
            routeRevision: route.routeRevision,
            paddingBucket: route.policy.paddingBucket,
            payloadKey: route.payloadKey,
            sendAuthority: {
              routeID: route.routeID,
              sendCapability: route.sendCapability
            },
            authorizedAt: canonicalSentAt
          }),
          nextPacketIndex: 0,
          status: "pending",
          acceptedAt: null
        });
      }
      if (localEffect !== null) {
        if (localEffect.localReceiveRoutes !== undefined) {
          candidate.localReceiveRoutes = clone(localEffect.localReceiveRoutes);
        }
        if (localEffect.localAdvertisedRoutes !== undefined) {
          candidate.localAdvertisedRoutes = clone(localEffect.localAdvertisedRoutes);
        }
        if (localEffect.localIdentity !== undefined) {
          candidate.localIdentity = clone(localEffect.localIdentity);
          candidate.localEndpointBindings = prependEndpointBinding(
            candidate.localEndpointBindings,
            localEffect.localIdentity.endpointBinding,
            MAXIMUM_LOCAL_ENDPOINT_BINDINGS
          );
          // Future sends use the successor binding and a fresh session. The
          // old session remains bounded state for in-flight old-binding data.
          candidate.activeOutboundSessionID = null;
        }
      }
      const intent = {
        id: swiftUUID(),
        sequence: candidate.nextIntentSequence,
        sessionID: conversation.sessionId,
        event: prepared.event,
        clientTransactionId: transactionID,
        directEnvelope: prepared.envelope,
        routeDeliveries,
        status: "prepared",
        attemptCount: 0,
        lastFailureCode: null,
        delivery: createDeliveryStateRecord({
          eventId: prepared.event.id,
          destinationEndpoint: conversation.endpointSession.peerEndpointHandle,
          state: "locallyPersisted",
          updatedAt: canonicalSentAt
        }),
        createdAt: canonicalSentAt,
        updatedAt: canonicalSentAt
      };
      candidate.nextIntentSequence += 1;
      candidate.intents.push(intent);
      candidate.updatedAt = monotonicStateTimestamp(candidate, canonicalSentAt);
      await this.saveCandidate(candidate);
      return publicIntent(intent);
    });
  }

  /**
   * Publishes exact persisted packets in intent order. Every independent route
   * is attempted; one complete route acceptance advances the logical outbox.
   */
  async resumeOutbound({
    maximumIntents = MAXIMUM_PENDING_INTENTS,
    authorizedAt = swiftISODate()
  } = {}) {
    return this.serialized(async () => {
      integer(maximumIntents, "Maximum resumed intents", 1, MAXIMUM_PENDING_INTENTS);
      const retryAuthorizationTime = canonicalTimestamp(
        authorizedAt,
        "Outbound retry authorization time"
      );
      let state = await this.ensureState();
      let completed = 0;
      while (completed < maximumIntents) {
        const index = state.intents.findIndex(isBlockingIntent);
        if (index < 0) break;
        const current = state.intents[index];
        if (current.status === "permanentFailure") break;

        let candidate = clone(state);
        // The persisted counter is diagnostic and saturating. Network
        // failures never become permanent merely because they happened often.
        candidate.intents[index].attemptCount = Math.min(
          MAXIMUM_ATTEMPTS,
          candidate.intents[index].attemptCount + 1
        );
        candidate.intents[index].status = "publishing";
        candidate.intents[index].lastFailureCode = null;
        candidate.intents[index].updatedAt = swiftISODate();
        candidate.updatedAt = candidate.intents[index].updatedAt;
        await this.saveCandidate(candidate);
        state = candidate;

        const routeFailures = [];
        for (let deliveryIndex = 0;
          deliveryIndex < state.intents[index].routeDeliveries.length;
          deliveryIndex += 1) {
          try {
            while (state.intents[index].routeDeliveries[deliveryIndex].status !== "relayAccepted") {
              let delivery = state.intents[index].routeDeliveries[deliveryIndex];
              let packet = delivery.sealedBundle.packets[delivery.nextPacketIndex];
              if (opaqueRoutePacketSendAuthorizationExpiredV2({
                packet,
                at: retryAuthorizationTime
              })) {
                const refreshed = await refreshOpaqueRoutePacketSendAuthorizationV2({
                  crypto: this.crypto,
                  packet,
                  sendAuthority: {
                    routeID: delivery.route.routeID,
                    sendCapability: delivery.route.sendCapability
                  },
                  authorizedAt: retryAuthorizationTime
                });
                candidate = clone(state);
                candidate.intents[index]
                  .routeDeliveries[deliveryIndex]
                  .sealedBundle
                  .packets[delivery.nextPacketIndex] = refreshed;
                candidate.intents[index].updatedAt = swiftISODate();
                candidate.updatedAt = candidate.intents[index].updatedAt;
                // Refreshed proof is durable before the relay can observe it.
                await this.saveCandidate(candidate);
                state = candidate;
                delivery = state.intents[index].routeDeliveries[deliveryIndex];
                packet = delivery.sealedBundle.packets[delivery.nextPacketIndex];
              }
              const relay = await this.relayClientFactory(delivery.route.relay);
              if (typeof relay?.enqueueOpaqueRoute !== "function") {
                throw new TypeError("Relay client must implement enqueueOpaqueRoute(...).");
              }
              const rawReceipt = await relay.enqueueOpaqueRoute({
                packet,
                sendCapability: delivery.route.sendCapability
              });
              const receipt = validateOpaqueRouteEnqueueResponseShapeV2(rawReceipt);
              if (receipt.packetID.rawValue !== packet.packetID.rawValue) {
                throw new Error("Relay accepted a different opaque-route packet.");
              }

              candidate = clone(state);
              const nextDelivery = candidate.intents[index].routeDeliveries[deliveryIndex];
              nextDelivery.nextPacketIndex += 1;
              if (nextDelivery.nextPacketIndex === nextDelivery.sealedBundle.packets.length) {
                nextDelivery.status = "relayAccepted";
                nextDelivery.acceptedAt = swiftISODate();
              }
              candidate.intents[index].updatedAt = swiftISODate();
              candidate.updatedAt = candidate.intents[index].updatedAt;
              await this.saveCandidate(candidate);
              state = candidate;
            }
          } catch (error) {
            routeFailures.push(error);
          }
        }

        if (state.intents[index].routeDeliveries.some(({ status }) =>
          status === "relayAccepted")) {
          candidate = clone(state);
          const accepted = candidate.intents[index];
          accepted.status = "relayAccepted";
          accepted.lastFailureCode = null;
          accepted.updatedAt = swiftISODate();
          accepted.delivery = advanceDeliveryState(
            accepted.delivery,
            "relayAccepted",
            { updatedAt: accepted.updatedAt }
          );
          // Relay acceptance no longer needs the large exact retry material.
          accepted.directEnvelope = null;
          accepted.routeDeliveries = [];
          candidate.updatedAt = accepted.updatedAt;
          await this.saveCandidate(candidate);
          state = candidate;
          completed += 1;
        } else {
          candidate = clone(state);
          const failed = candidate.intents[index];
          const hasDependentIntent = candidate.intents.slice(index + 1).some((intent) =>
            isPendingIntent(intent) && intent.sessionID === failed.sessionID
          );
          failed.status = !hasDependentIntent && routeFailures.length > 0 &&
            routeFailures.every(isDeterministicOutboundFailure)
            ? "permanentFailure"
            : "retryableFailure";
          failed.lastFailureCode = boundedFailureCode(routeFailures[0]);
          failed.updatedAt = swiftISODate();
          if (failed.status === "permanentFailure") {
            failed.directEnvelope = null;
            failed.routeDeliveries = [];
          }
          candidate.updatedAt = failed.updatedAt;
          await this.saveCandidate(candidate);
          state = candidate;
          break;
        }
      }
      return Object.freeze({ completed, intents: Object.freeze(state.intents.map(publicIntent)) });
    });
  }

  async discard(clientTransactionId) {
    return this.serialized(async () => {
      const state = await this.ensureState();
      const transactionID = canonicalUUID(clientTransactionId, "Client transaction ID");
      const index = state.intents.findIndex((intent) =>
        intent.clientTransactionId === transactionID
      );
      if (index < 0) {
        throw new DurablePairwiseMessagingV2Error("unknownIntent", "The outbound intent is unknown.");
      }
      if (state.intents[index].status === "relayAccepted") {
        throw new DurablePairwiseMessagingV2Error(
          "alreadyAccepted",
          "Relay-accepted messages cannot be discarded."
        );
      }
      if (state.intents[index].event.kind === "control") {
        throw new DurablePairwiseMessagingV2Error(
          "controlDiscardForbidden",
          "Security-sensitive relationship transitions must be completed, not discarded."
        );
      }
      const candidate = clone(state);
      const discarded = candidate.intents[index];
      const discardedAt = swiftISODate();
      const abandonsBootstrap = discarded.directEnvelope?.bootstrap?.kind === "signedPrekey";
      if (abandonsBootstrap && discarded.routeDeliveries.some(({ status }) =>
        status === "relayAccepted")) {
        throw new DurablePairwiseMessagingV2Error(
          "bootstrapDiscardForbidden",
          "A session bootstrap accepted on any route cannot be safely discarded."
        );
      }
      const discardedSessionID = discarded.sessionID;
      for (const intent of candidate.intents) {
        if (intent.id !== discarded.id &&
            (!abandonsBootstrap || intent.sessionID !== discardedSessionID)) continue;
        if (intent.status === "relayAccepted") {
          throw new DurablePairwiseMessagingV2Error(
            "bootstrapDiscardForbidden",
            "A session with relay-accepted successors cannot be discarded."
          );
        }
        intent.status = "discarded";
        intent.directEnvelope = null;
        intent.routeDeliveries = [];
        intent.lastFailureCode = null;
        intent.updatedAt = discardedAt;
      }
      if (abandonsBootstrap) {
        candidate.sessions = candidate.sessions.filter(({ sessionId }) =>
          sessionId !== discardedSessionID
        );
        if (candidate.activeOutboundSessionID === discardedSessionID) {
          candidate.activeOutboundSessionID = null;
        }
      }
      candidate.updatedAt = discardedAt;
      await this.saveCandidate(candidate);
      return publicIntent(candidate.intents[index]);
    });
  }

  /**
   * Receives one opaque-route page. Reassembly, ratchet advancement, event and
   * receipt effects, and the candidate cursor are written in the single
   * persistence callback required by NoctweaveWebClient. Relay GC follows that
   * local transaction and is therefore never its durability oracle.
   */
  async syncReceive({
    client,
    routeID,
    limit = 256,
    authorizedAt = swiftISODate(),
    persistAppliedRelationship
  }) {
    return this.serialized(async () => {
      if (typeof client?.syncOpaqueRoute !== "function" ||
          typeof client?.commitOpaqueRoute !== "function") {
        throw new TypeError("Receive sync requires NoctweaveWebClient-compatible route methods.");
      }
      if (persistAppliedRelationship !== undefined &&
          typeof persistAppliedRelationship !== "function") {
        throw new TypeError("persistAppliedRelationship must be a function.");
      }
      let state = await this.ensureState();
      const routeIndex = receiveRouteIndex(state, routeID);
      const synced = await client.syncOpaqueRoute(state.localReceiveRoutes[routeIndex], {
        limit,
        authorizedAt,
        persistLocalState: async ({ localReceiveRoute }) => {
          const gapCandidate = clone(state);
          gapCandidate.localReceiveRoutes[routeIndex] = localReceiveRoute;
          gapCandidate.updatedAt = monotonicStateTimestamp(
            gapCandidate,
            canonicalTimestamp(authorizedAt, "Receive sync time")
          );
          await this.saveCandidate(gapCandidate);
          state = gapCandidate;
        }
      });

      const candidate = clone(state);
      let route = candidate.localReceiveRoutes[routeIndex];
      const received = [];
      const receivedAt = canonicalTimestamp(authorizedAt, "Receive sync time");
      for (const record of synced.batch.packets) {
        let consumed;
        try {
          consumed = await updateLocalOpaqueReceiveRouteReassemblerV2({
            crypto: this.crypto,
            localReceiveRoute: route,
            update: (reassembler) => reassembler.consume({
              crypto: this.crypto,
              packet: record.packet,
              payloadKey: route.payloadKey,
              routeRevision: record.routeRevision
            })
          });
        } catch (error) {
          if (!isTerminalOpaquePacketFailure(error)) throw error;
          const outcome = quarantinePacket(candidate, record, error.code, receivedAt);
          received.push(outcome);
          continue;
        }
        route = consumed.localReceiveRoute;
        candidate.localReceiveRoutes[routeIndex] = route;
        if (consumed.result.status !== "complete") continue;
        let outcome;
        try {
          outcome = await this.processReceivedBundle({
            state: candidate,
            payload: consumed.result.bundle.payload,
            receivedAt,
            sourceRouteID: route.route.routeID
          });
        } catch (error) {
          if (!isTerminalEnvelopeFailure(error)) throw error;
          outcome = quarantinePacket(candidate, record, error.code, receivedAt);
        }
        if (outcome !== null) received.push(outcome);
      }

      const committed = await client.commitOpaqueRoute({
        localReceiveRoute: route,
        batch: synced.batch,
        persistLocalState: async ({ localReceiveRoute }) => {
          candidate.localReceiveRoutes[routeIndex] = localReceiveRoute;
          candidate.updatedAt = monotonicStateTimestamp(candidate, receivedAt);
          await this.saveCandidate(candidate);
          if (persistAppliedRelationship !== undefined) {
            await persistAppliedRelationship({
              relationship: clone(runtimeRelationship(candidate, this.relationship)),
              received: Object.freeze([...received])
            });
          }
        }
      }, { authorizedAt });
      const appliedRelationship = clone(runtimeRelationship(candidate, this.relationship));
      return Object.freeze({
        received: Object.freeze(received),
        hasMore: synced.batch.hasMore,
        relayCommit: committed.relayCommit,
        appliedRelationship
      });
    });
  }

  async listOutbound() {
    return this.serialized(async () => {
      const state = await this.ensureState();
      return Object.freeze(state.intents.map(publicIntent));
    });
  }

  async listReceived() {
    return this.serialized(async () => {
      const state = await this.ensureState();
      return Object.freeze(clone(state.receivedEvents));
    });
  }

  async processReceivedBundle({ state, payload, receivedAt, sourceRouteID }) {
    const envelope = decodeCanonicalEnvelope(payload);
    const duplicate = state.receivedEvents.some(({ envelopeID }) => envelopeID === envelope.id) ||
      state.quarantinedEnvelopes.some(({ envelope: quarantined }) =>
        quarantined.id === envelope.id
      ) || state.quarantinedControls.some(({ envelope: quarantined }) =>
        quarantined.id === envelope.id
      );
    if (duplicate) return null;
    const sourceRoute = state.localReceiveRoutes.find(({ route }) =>
      route.routeID.rawValue === sourceRouteID?.rawValue
    );
    if (!sourceRoute) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidInboundFreshness",
        "Inbound bundle source route is not current local relationship state."
      );
    }
    const maximumDelayMilliseconds = Math.min(
      MAXIMUM_INBOUND_DELIVERY_DELAY_MS,
      sourceRoute.route.lease.policy.retentionBucket * 1_000
    );
    validateInboundDeliveryObservation({
      sentAt: envelope.sentAt,
      receivedAt,
      maximumDelayMilliseconds
    });
    const relationship = await runtimeRelationshipForEnvelope({
      crypto: this.crypto,
      state,
      baseRelationship: this.relationship,
      envelope,
      receivedAt,
      maximumDelayMilliseconds
    });

    let conversation = state.sessions.find(({ sessionId }) => sessionId === envelope.sessionId) ?? null;
    let priorSessionState = null;
    if (conversation === null) {
      if (envelope.bootstrap.kind === "none") {
        throw new DurablePairwiseMessagingV2Error(
          "unknownSession",
          "The direct envelope does not establish a bounded relationship session."
        );
      }
      priorSessionState = {
        sessions: [...state.sessions],
        activeOutboundSessionID: state.activeOutboundSessionID
      };
      reserveSessionCapacity(state);
      conversation = await createNativeInboundSession({
        crypto: this.crypto,
        pqc: this.pqc,
        localIdentity: relationship.localIdentity,
        peerIdentity: relationship.peerIdentity,
        bootstrap: envelope.bootstrap,
        now: Date.parse(receivedAt),
        bootstrapSentAt: Date.parse(envelope.sentAt)
      });
      if (conversation.sessionId !== envelope.sessionId) {
        throw new DurablePairwiseMessagingV2Error(
          "sessionMismatch",
          "The direct bootstrap established a different session."
        );
      }
      state.sessions.push(conversation);
      // A received bootstrap establishes a bidirectional direct session. Reuse
      // it for the first local reply instead of creating a redundant KEM root.
      if (state.activeOutboundSessionID === null) {
        state.activeOutboundSessionID = conversation.sessionId;
      }
    }

    let decoded;
    try {
      decoded = await decryptNativeProtocolEnvelope({
        crypto: this.crypto,
        pqc: this.pqc,
        localIdentity: relationship.localIdentity,
        peerIdentity: relationship.peerIdentity,
        conversation,
        envelope,
        receivedAt
      });
    } catch (error) {
      if (!(error instanceof NoctweaveRemoteEnvelopeError) ||
          (error.reason !== "unsupportedPayload" &&
            error.reason !== "invalidAttribution")) {
        throw error;
      }
      if (error.reason === "invalidAttribution" && priorSessionState !== null) {
        state.sessions = priorSessionState.sessions;
        state.activeOutboundSessionID = priorSessionState.activeOutboundSessionID;
      }
      compactArrayHistory(
        state.quarantinedEnvelopes,
        MAXIMUM_QUARANTINED_ENVELOPES,
        96
      );
      state.quarantinedEnvelopes.push({
        envelope,
        reason: error.reason === "invalidAttribution"
          ? "invalidRelationshipAttribution"
          : "unsupportedAuthenticatedPayload",
        receivedAt
      });
      return Object.freeze({ kind: "quarantined", eventID: envelope.eventId });
    }

    if (decoded.kind === "quarantinedControl") {
      compactArrayHistory(
        state.quarantinedControls,
        MAXIMUM_QUARANTINED_CONTROLS,
        48
      );
      state.quarantinedControls.push({
        envelope,
        event: decoded.quarantine.event,
        reason: decoded.quarantine.reason,
        receivedAt
      });
      return Object.freeze({
        kind: "quarantinedControl",
        event: decoded.quarantine.event,
        reason: decoded.quarantine.reason
      });
    }

    compactArrayHistory(state.receivedEvents, MAXIMUM_RECEIVED_EVENTS, 384);
    let projection = decoded.projection;
    if (decoded.kind === "control") {
      await applyReceivedRelationshipControl({
        crypto: this.crypto,
        pqc: this.pqc,
        state,
        relationship,
        control: decoded.control,
        receivedAt,
        sourceRouteID
      });
      projection = Object.freeze({
        kind: "relationshipControl",
        controlKind: decoded.control.kind,
        sourceRouteID: clone(sourceRouteID)
      });
    }
    const stored = {
      envelopeID: envelope.id,
      event: decoded.event,
      projection,
      receivedAt
    };
    state.receivedEvents.push(stored);
    applyAuthenticatedReceipt(state, decoded, receivedAt);
    return Object.freeze({ kind: decoded.kind, event: decoded.event, projection });
  }

  async ensureState() {
    if (this.destroyed) {
      throw new DurablePairwiseMessagingV2Error(
        "relationshipDestroyed",
        "This disposable relationship runtime has been destroyed."
      );
    }
    this.relationshipValidation ??= validatePairwiseRelationshipV2({
      crypto: this.crypto,
      pqc: this.pqc,
      relationship: this.relationship
    });
    await this.relationshipValidation;
    const loaded = await this.stateAnchorStore.load({
      anchorKey: this.anchorKey,
      relationshipID: this.relationship.relationshipID,
      loadEncryptedState: () => this.repository.load()
    });
    exact(loaded, ["anchor", "state"], "Relationship anchor load result");
    if ((loaded.anchor === null) !== (loaded.state === null)) {
      throw new DurablePairwiseMessagingV2Error(
        "rollbackDetected",
        "Relationship anchor and encrypted state are not the same committed generation."
      );
    }
    if (loaded.anchor !== null) {
      const anchor = validateRelationshipStateAnchorV2(
        loaded.anchor,
        this.relationship.relationshipID
      );
      const stored = await validateDurablePairwiseMessagingStateV2({
        crypto: this.crypto,
        pqc: this.pqc,
        relationship: this.relationship,
        state: loaded.state
      });
      const digest = await durableStateDigest(this.crypto, stored);
      if (stored.anchorGeneration !== anchor.generation || digest !== anchor.stateDigest) {
        throw new DurablePairwiseMessagingV2Error(
          "rollbackDetected",
          "Encrypted relationship state does not match its authenticated monotonic anchor."
        );
      }
      this.currentAnchor = anchor;
      return stored;
    }
    this.currentAnchor = null;
    const now = swiftISODate();
    const initial = {
      stateSchema: STATE_SCHEMA,
      version: STATE_VERSION,
      anchorGeneration: 0,
      relationshipID: this.relationship.relationshipID,
      localPolicy: clone(this.relationship.localPolicy),
      localIdentity: clone(this.relationship.localIdentity),
      localEndpointBindings: [clone(this.relationship.localIdentity.endpointBinding)],
      localAdvertisedRoutes: clone(this.relationship.localAdvertisedRoutes),
      peerIdentity: clone(this.relationship.peerIdentity),
      peerEndpointBindings: [clone(this.relationship.peerIdentity.endpointBinding)],
      activeOutboundSessionID: null,
      sessions: [],
      localReceiveRoutes: clone(this.relationship.localReceiveRoutes),
      retiredLocalRoutes: [],
      nextIntentSequence: 1,
      intents: [],
      receivedEvents: [],
      quarantinedPackets: [],
      quarantinedEnvelopes: [],
      quarantinedControls: [],
      lifecycle: {
        routeMaintenance: null,
        routeTeardown: null
      },
      createdAt: now,
      updatedAt: now
    };
    return this.saveCandidate(initial);
  }

  async saveCandidate(candidate) {
    const expectedAnchor = this.currentAnchor;
    const expectedGeneration = expectedAnchor?.generation ?? 0;
    if (candidate.anchorGeneration !== expectedGeneration ||
        expectedGeneration >= Number.MAX_SAFE_INTEGER) {
      throw new DurablePairwiseMessagingV2Error(
        "rollbackDetected",
        "Candidate relationship state does not advance the current secure anchor."
      );
    }
    compactCandidateState(candidate);
    candidate.anchorGeneration = expectedGeneration + 1;
    const validated = await validateDurablePairwiseMessagingStateV2({
      crypto: this.crypto,
      pqc: this.pqc,
      relationship: this.relationship,
      state: candidate
    });
    const size = encoder.encode(JSON.stringify(validated)).byteLength;
    if (size > MAXIMUM_STATE_BYTES) {
      throw new DurablePairwiseMessagingV2Error(
        "stateCapacityExceeded",
        "Durable pairwise state exceeds its encrypted-record budget."
      );
    }
    const stateDigest = await durableStateDigest(this.crypto, validated);
    const committed = await this.stateAnchorStore.commit({
      anchorKey: this.anchorKey,
      relationshipID: this.relationship.relationshipID,
      expectedAnchor: expectedAnchor === null ? null : clone(expectedAnchor),
      nextGeneration: candidate.anchorGeneration,
      nextStateDigest: stateDigest,
      persistEncryptedState: () => this.repository.save(validated)
    });
    const anchor = validateRelationshipStateAnchorV2(
      committed,
      this.relationship.relationshipID
    );
    if (anchor.generation !== candidate.anchorGeneration || anchor.stateDigest !== stateDigest) {
      throw new DurablePairwiseMessagingV2Error(
        "rollbackDetected",
        "Relationship anchor store committed a different state generation."
      );
    }
    this.currentAnchor = anchor;
    return validated;
  }

  serialized(operation) {
    const next = this.queue.then(operation, operation);
    this.queue = next.catch(() => {});
    return next;
  }
}

export async function validateDurablePairwiseMessagingStateV2({
  crypto,
  pqc,
  relationship,
  state
}) {
  exact(state, [
    "stateSchema",
    "version",
    "anchorGeneration",
    "relationshipID",
    "localPolicy",
    "localIdentity",
    "localEndpointBindings",
    "localAdvertisedRoutes",
    "peerIdentity",
    "peerEndpointBindings",
    "activeOutboundSessionID",
    "sessions",
    "localReceiveRoutes",
    "retiredLocalRoutes",
    "nextIntentSequence",
    "intents",
    "receivedEvents",
    "quarantinedPackets",
    "quarantinedEnvelopes",
    "quarantinedControls",
    "lifecycle",
    "createdAt",
    "updatedAt"
  ], "Durable pairwise messaging state");
  if (encoder.encode(JSON.stringify(state)).byteLength > MAXIMUM_STATE_BYTES) {
    throw new DurablePairwiseMessagingV2Error(
      "stateCapacityExceeded",
      "Durable pairwise state exceeds its encrypted-record budget."
    );
  }
  if (state.stateSchema !== STATE_SCHEMA || state.version !== STATE_VERSION ||
      state.relationshipID !== relationship?.relationshipID) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Durable state scope is invalid.");
  }
  integer(state.anchorGeneration, "State anchor generation", 1, Number.MAX_SAFE_INTEGER);
  validateRelationshipLocalPolicyV2(state.localPolicy);
  const currentRelationship = await validateRuntimeRelationshipSnapshot({
    crypto,
    pqc,
    baseRelationship: relationship,
    state
  });
  if (!Array.isArray(state.sessions) || state.sessions.length > MAXIMUM_SESSIONS) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Direct session bounds are invalid.");
  }
  const sessionIDs = new Set();
  for (const session of state.sessions) {
    validateSessionSnapshot(session, relationship);
    if (sessionIDs.has(session.sessionId)) {
      throw new DurablePairwiseMessagingV2Error("invalidState", "Direct session IDs are duplicated.");
    }
    sessionIDs.add(session.sessionId);
  }
  if (state.activeOutboundSessionID !== null &&
      (!boundedString(state.activeOutboundSessionID, 256) ||
        !sessionIDs.has(state.activeOutboundSessionID))) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Active direct session is invalid.");
  }
  if (!Array.isArray(state.localReceiveRoutes) || state.localReceiveRoutes.length === 0 ||
      state.localReceiveRoutes.length > 8) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Receive route bounds are invalid.");
  }
  const routeIDs = new Set();
  for (const route of state.localReceiveRoutes) {
    const validated = await validateLocalOpaqueReceiveRouteV2({ crypto, route });
    const routeID = validated.route.routeID.rawValue;
    if (routeIDs.has(routeID)) {
      throw new DurablePairwiseMessagingV2Error("invalidState", "Receive routes are duplicated.");
    }
    routeIDs.add(routeID);
  }
  if (!Array.isArray(state.retiredLocalRoutes) ||
      state.retiredLocalRoutes.length > MAXIMUM_RETIRED_LOCAL_ROUTES) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Retired local route evidence bounds are invalid."
    );
  }
  for (const retired of state.retiredLocalRoutes) {
    exact(retired, [
      "routeID",
      "renewalSequence",
      "terminalTransitionDigest",
      "revokedRouteSet",
      "retiredAt"
    ], "Retired local route");
    exact(retired.routeID, ["rawValue"], "Retired local route ID");
    canonicalBase64(retired.routeID.rawValue, 32, "Retired local route ID");
    const revokedRouteSet = validatePairwiseRouteSetV2(retired.revokedRouteSet);
    const advertised = revokedRouteSet.routes.find(({ routeID }) =>
      routeID.rawValue === retired.routeID.rawValue
    );
    if (routeIDs.has(retired.routeID.rawValue) || !advertised ||
        advertised.state !== "revoked" ||
        advertised.routeRevision !== retired.renewalSequence ||
        revokedRouteSet.relationshipID !== relationship.relationshipID ||
        revokedRouteSet.ownerEndpointHandle.rawValue !==
          relationship.localEndpointHandle.rawValue ||
        !verifyPairwiseRouteSetV2Throwing({
          pqc,
          routeSet: revokedRouteSet,
          ownerSigningPublicKey: relationship.localIdentity.endpointBinding.signingPublicKey
        })) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        "Retired local route is not self-authenticated by signed terminal route state."
      );
    }
    routeIDs.add(retired.routeID.rawValue);
    integer(
      retired.renewalSequence,
      "Retired local route revision",
      0,
      Number.MAX_SAFE_INTEGER
    );
    canonicalBase64(
      retired.terminalTransitionDigest,
      32,
      "Retired route terminal transition digest"
    );
    canonicalTimestamp(retired.retiredAt, "Retired local route time");
  }
  integer(state.nextIntentSequence, "Next intent sequence", 1, Number.MAX_SAFE_INTEGER);
  if (!Array.isArray(state.intents) || state.intents.length > MAXIMUM_RETAINED_INTENTS ||
      state.intents.filter(isPendingIntent).length > MAXIMUM_PENDING_INTENTS) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Outbound intent bounds are invalid.");
  }
  let priorSequence = 0;
  const transactionIDs = new Set();
  const eventIDs = new Set();
  for (const intent of state.intents) {
    await validateIntent({ crypto, relationship: currentRelationship, intent, sessionIDs });
    if (intent.sequence <= priorSequence || transactionIDs.has(intent.clientTransactionId) ||
        eventIDs.has(intent.event.id)) {
      throw new DurablePairwiseMessagingV2Error("invalidState", "Outbound intent ordering is invalid.");
    }
    priorSequence = intent.sequence;
    transactionIDs.add(intent.clientTransactionId);
    eventIDs.add(intent.event.id);
  }
  if (priorSequence >= state.nextIntentSequence) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Next intent sequence does not advance state.");
  }
  if (!Array.isArray(state.receivedEvents) ||
      state.receivedEvents.length > MAXIMUM_RECEIVED_EVENTS) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Received event bounds are invalid.");
  }
  const receivedEnvelopeIDs = new Set();
  for (const received of state.receivedEvents) {
    exact(received, ["envelopeID", "event", "projection", "receivedAt"], "Received event");
    canonicalUUID(received.envelopeID, "Received envelope ID");
    validateConversationEvent(received.event);
    canonicalTimestamp(received.receivedAt, "Received event time");
    requirePlainRecord(received.projection, "Received event projection");
    if (receivedEnvelopeIDs.has(received.envelopeID)) {
      throw new DurablePairwiseMessagingV2Error("invalidState", "Received envelopes are duplicated.");
    }
    receivedEnvelopeIDs.add(received.envelopeID);
  }
  if (!Array.isArray(state.quarantinedPackets) ||
      state.quarantinedPackets.length > MAXIMUM_QUARANTINED_PACKETS) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Packet quarantine bounds are invalid."
    );
  }
  const quarantinedPacketIDs = new Set();
  for (const quarantined of state.quarantinedPackets) {
    exact(quarantined, [
      "packet",
      "sequence",
      "recordDigest",
      "routeRevision",
      "reason",
      "quarantinedAt"
    ], "Quarantined opaque-route packet");
    const packet = await validateOpaqueRoutePacketV2({
      crypto,
      packet: quarantined.packet
    });
    integer(quarantined.sequence, "Quarantined packet sequence", 1, Number.MAX_SAFE_INTEGER);
    canonicalBase64(quarantined.recordDigest, 32, "Quarantined record digest");
    integer(
      quarantined.routeRevision,
      "Quarantined route revision",
      0,
      Number.MAX_SAFE_INTEGER
    );
    if (!terminalQuarantineReasons.has(quarantined.reason) ||
        quarantinedPacketIDs.has(packet.packetID.rawValue)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        "Quarantined packet is invalid."
      );
    }
    quarantinedPacketIDs.add(packet.packetID.rawValue);
    canonicalTimestamp(quarantined.quarantinedAt, "Packet quarantine time");
  }
  if (!Array.isArray(state.quarantinedEnvelopes) ||
      state.quarantinedEnvelopes.length > MAXIMUM_QUARANTINED_ENVELOPES) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Quarantine bounds are invalid.");
  }
  for (const quarantined of state.quarantinedEnvelopes) {
    exact(quarantined, ["envelope", "reason", "receivedAt"], "Quarantined envelope");
    const envelope = validateDirectEnvelopeV4(quarantined.envelope);
    if ((quarantined.reason !== "unsupportedAuthenticatedPayload" &&
        quarantined.reason !== "invalidRelationshipAttribution") ||
        receivedEnvelopeIDs.has(envelope.id)) {
      throw new DurablePairwiseMessagingV2Error("invalidState", "Quarantined envelope is invalid.");
    }
    receivedEnvelopeIDs.add(envelope.id);
    canonicalTimestamp(quarantined.receivedAt, "Quarantine time");
  }
  if (!Array.isArray(state.quarantinedControls) ||
      state.quarantinedControls.length > MAXIMUM_QUARANTINED_CONTROLS) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Relationship-control quarantine bounds are invalid."
    );
  }
  for (const quarantined of state.quarantinedControls) {
    exact(
      quarantined,
      ["envelope", "event", "reason", "receivedAt"],
      "Quarantined relationship control"
    );
    const envelope = validateDirectEnvelopeV4(quarantined.envelope);
    const event = validateConversationEvent(quarantined.event);
    if (event.kind !== "control" || event.id !== envelope.eventId ||
        !boundedString(quarantined.reason, 512) || receivedEnvelopeIDs.has(envelope.id)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        "Quarantined relationship control is invalid."
      );
    }
    receivedEnvelopeIDs.add(envelope.id);
    canonicalTimestamp(quarantined.receivedAt, "Control quarantine time");
  }
  validateLifecycleState(state.lifecycle);
  canonicalTimestamp(state.createdAt, "Durable state creation time");
  canonicalTimestamp(state.updatedAt, "Durable state update time");
  if (Date.parse(state.updatedAt) < Date.parse(state.createdAt)) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Durable state time is invalid.");
  }
  return state;
}

function validateLifecycleState(value) {
  exact(value, ["routeMaintenance", "routeTeardown"], "Relationship lifecycle state");
  for (const [label, record] of Object.entries(value)) {
    if (record === null) continue;
    requireJSONValue(record, `Relationship ${label} lifecycle`);
    if (encoder.encode(JSON.stringify(record)).byteLength > 2 * 1_024 * 1_024) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        `Relationship ${label} lifecycle exceeds its bound.`
      );
    }
  }
}

function requireJSONValue(value, label, depth = 0) {
  if (depth > 32) throw new DurablePairwiseMessagingV2Error("invalidState", `${label} is too deep.`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (Array.isArray(value)) {
    for (const item of value) requireJSONValue(item, label, depth + 1);
    return;
  }
  requirePlainRecord(value, label);
  for (const item of Object.values(value)) requireJSONValue(item, label, depth + 1);
}

async function validateIntent({ crypto, relationship, intent, sessionIDs }) {
  exact(intent, [
    "id",
    "sequence",
    "sessionID",
    "event",
    "clientTransactionId",
    "directEnvelope",
    "routeDeliveries",
    "status",
    "attemptCount",
    "lastFailureCode",
    "delivery",
    "createdAt",
    "updatedAt"
  ], "Outbound intent");
  canonicalUUID(intent.id, "Intent ID");
  integer(intent.sequence, "Intent sequence", 1, Number.MAX_SAFE_INTEGER);
  if (!boundedString(intent.sessionID, 256) ||
      (intent.status !== "discarded" && !sessionIDs.has(intent.sessionID))) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Intent session is invalid.");
  }
  const event = validateConversationEvent(intent.event);
  const transactionID = canonicalUUID(intent.clientTransactionId, "Client transaction ID");
  if (event.clientTransactionId !== transactionID || !intentStates.has(intent.status)) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Intent identity or status is invalid.");
  }
  integer(intent.attemptCount, "Intent attempt count", 0, MAXIMUM_ATTEMPTS);
  if (intent.lastFailureCode !== null && !boundedString(intent.lastFailureCode, 96)) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Intent failure code is invalid.");
  }
  const delivery = validateDeliveryStateRecord(intent.delivery);
  if (delivery.eventId !== event.id ||
      delivery.destinationEndpoint.rawValue !== relationship.peerIdentity.sendRoutes.ownerEndpointHandle.rawValue) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Intent delivery scope is invalid.");
  }
  const pending = isPendingIntent(intent);
  if (pending) {
    const envelope = validateDirectEnvelopeV4(intent.directEnvelope);
    if (envelope.eventId !== event.id || envelope.sessionId !== intent.sessionID ||
        !Array.isArray(intent.routeDeliveries) || intent.routeDeliveries.length === 0 ||
        intent.routeDeliveries.length > 8) {
      throw new DurablePairwiseMessagingV2Error("invalidState", "Intent envelope is invalid.");
    }
    const seenRoutes = new Set();
    for (const routeDelivery of intent.routeDeliveries) {
      exact(routeDelivery, [
        "route",
        "sealedBundle",
        "nextPacketIndex",
        "status",
        "acceptedAt"
      ], "Route delivery");
      const route = validateOpaqueSendRouteV2(routeDelivery.route);
      const bundle = await validateOpaqueRouteSealedBundleV2({
        crypto,
        bundle: routeDelivery.sealedBundle
      });
      if (bundle.routeRevision !== route.routeRevision ||
          bundle.paddingBucket !== route.policy.paddingBucket ||
          bundle.packets.some(({ routeID }) => routeID.rawValue !== route.routeID.rawValue) ||
          seenRoutes.has(route.routeID.rawValue) || !routeDeliveryStates.has(routeDelivery.status)) {
        throw new DurablePairwiseMessagingV2Error("invalidState", "Route delivery binding is invalid.");
      }
      seenRoutes.add(route.routeID.rawValue);
      integer(
        routeDelivery.nextPacketIndex,
        "Next route packet index",
        0,
        bundle.packets.length
      );
      const accepted = routeDelivery.status === "relayAccepted";
      if ((accepted && (routeDelivery.nextPacketIndex !== bundle.packets.length ||
          routeDelivery.acceptedAt === null)) || (!accepted &&
          (routeDelivery.nextPacketIndex >= bundle.packets.length || routeDelivery.acceptedAt !== null))) {
        throw new DurablePairwiseMessagingV2Error("invalidState", "Route delivery progress is invalid.");
      }
      if (routeDelivery.acceptedAt !== null) {
        canonicalTimestamp(routeDelivery.acceptedAt, "Route acceptance time");
      }
    }
  } else if (intent.directEnvelope !== null || !Array.isArray(intent.routeDeliveries) ||
      intent.routeDeliveries.length !== 0) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Final intent retained retry material.");
  }
  canonicalTimestamp(intent.createdAt, "Intent creation time");
  canonicalTimestamp(intent.updatedAt, "Intent update time");
  if (Date.parse(intent.updatedAt) < Date.parse(intent.createdAt)) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Intent time is invalid.");
  }
}

function validateSessionSnapshot(session, relationship) {
  exact(session, [
    "endpointSession",
    "id",
    "receiveChain",
    "relationshipID",
    "rootKey",
    "sendChain",
    "sessionId"
  ], "Direct session");
  exact(session.endpointSession, [
    "localBindingReferenceDigest",
    "localEndpointHandle",
    "peerBindingReferenceDigest",
    "peerEndpointHandle",
    "relationshipID"
  ], "Direct endpoint session");
  if (session.relationshipID !== relationship.relationshipID ||
      session.endpointSession.relationshipID !== relationship.relationshipID ||
      session.id !== relationship.relationshipID.toLowerCase() ||
      session.endpointSession.localEndpointHandle.rawValue !== relationship.localEndpointHandle.rawValue ||
      session.endpointSession.peerEndpointHandle.rawValue !==
        relationship.peerIdentity.sendRoutes.ownerEndpointHandle.rawValue ||
      !boundedString(session.sessionId, 256)) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Direct session scope is invalid.");
  }
  canonicalBase64(session.rootKey, 32, "Direct root key");
  canonicalBase64(session.endpointSession.localBindingReferenceDigest, 32, "Local binding digest");
  canonicalBase64(session.endpointSession.peerBindingReferenceDigest, 32, "Peer binding digest");
  validateChain(session.sendChain);
  validateChain(session.receiveChain);
}

function validateChain(chain) {
  exact(chain, ["keyData", "counter", "skippedMessageKeys"], "Direct ratchet chain");
  canonicalBase64(chain.keyData, 32, "Direct chain key");
  integer(chain.counter, "Direct chain counter", 0, Number.MAX_SAFE_INTEGER);
  requirePlainRecord(chain.skippedMessageKeys, "Skipped direct message keys");
  const skipped = Object.entries(chain.skippedMessageKeys);
  if (skipped.length > 64) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Skipped-key bounds are invalid.");
  }
  for (const [counter, key] of skipped) {
    const numeric = Number(counter);
    if (!Number.isSafeInteger(numeric) || numeric < 0 || numeric >= chain.counter ||
        String(numeric) !== counter) {
      throw new DurablePairwiseMessagingV2Error("invalidState", "Skipped-key counter is invalid.");
    }
    canonicalBase64(key, 32, "Skipped direct message key");
  }
}

function runtimeRelationship(state, baseRelationship) {
  return {
    ...baseRelationship,
    localPolicy: state.localPolicy,
    localIdentity: state.localIdentity,
    localReceiveRoutes: state.localReceiveRoutes,
    localAdvertisedRoutes: state.localAdvertisedRoutes,
    peerIdentity: state.peerIdentity
  };
}

async function runtimeRelationshipForEnvelope({
  crypto,
  state,
  baseRelationship,
  envelope,
  receivedAt,
  maximumDelayMilliseconds
}) {
  const sentAt = envelope.sentAt;
  validateInboundDeliveryObservation({ sentAt, receivedAt, maximumDelayMilliseconds });
  const sent = Date.parse(sentAt);
  const requiresFreshBootstrap = envelope.bootstrap.kind === "signedPrekey";
  const localBindings = state.localEndpointBindings.filter((binding) => {
    const signed = binding.prekeyBundle.signedPrekey;
    const issued = Date.parse(signed.issuedAt);
    const expires = Date.parse(signed.expiresAt);
    return issued <= sent && (!requiresFreshBootstrap || sent < expires);
  });
  const peerBindings = state.peerEndpointBindings.filter((binding) => {
    const signed = binding.prekeyBundle.signedPrekey;
    const issued = Date.parse(signed.issuedAt);
    return issued <= sent;
  });
  const current = runtimeRelationship(state, baseRelationship);
  for (const localBinding of localBindings) {
    for (const peerBinding of peerBindings) {
      const relationship = {
        ...current,
        localIdentity: { ...current.localIdentity, endpointBinding: localBinding },
        peerIdentity: { ...current.peerIdentity, endpointBinding: peerBinding }
      };
      const binding = await derivePairwiseDirectV4Binding({
        crypto,
        localIdentity: relationship.localIdentity,
        peerIdentity: relationship.peerIdentity
      });
      if (binding.localBindingReferenceDigest === envelope.recipientBindingDigest &&
          binding.peerBindingReferenceDigest === envelope.senderBindingDigest &&
          binding.cipherSuite === envelope.cipherSuite &&
          binding.negotiatedCapabilitiesDigest === envelope.negotiatedCapabilitiesDigest) {
        return relationship;
      }
    }
  }
  {
    throw new DurablePairwiseMessagingV2Error(
      "invalidInboundFreshness",
      "No exact authorized endpoint-binding pair was valid for the authenticated send time."
    );
  }
}

function prependEndpointBinding(history, binding, limit) {
  const prekeyID = binding.prekeyBundle.signedPrekey.id;
  return [
    clone(binding),
    ...history.filter((candidate) =>
      candidate.prekeyBundle.signedPrekey.id !== prekeyID
    )
  ].slice(0, limit);
}

function validateInboundDeliveryObservation({
  sentAt,
  receivedAt,
  maximumDelayMilliseconds
}) {
  const sent = Date.parse(canonicalTimestamp(sentAt, "Inbound envelope send time"));
  const observed = Date.parse(canonicalTimestamp(receivedAt, "Inbound observation time"));
  integer(
    maximumDelayMilliseconds,
    "Inbound delivery window",
    1,
    MAXIMUM_INBOUND_DELIVERY_DELAY_MS
  );
  if (sent - observed > MAXIMUM_INBOUND_FUTURE_SKEW_MS ||
      observed - sent > maximumDelayMilliseconds) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidInboundFreshness",
      "Inbound envelope time is outside its explicit route delivery window."
    );
  }
}

async function validateRuntimeRelationshipSnapshot({
  crypto,
  pqc,
  baseRelationship,
  state
}) {
  const relationship = runtimeRelationship(state, baseRelationship);
  if (!isPeerPairwiseIdentityV2(relationship.peerIdentity) ||
      !equalCanonical(
        stableLocalIdentityProjection(relationship.localIdentity),
        stableLocalIdentityProjection(baseRelationship.localIdentity)
      ) || !equalCanonical(
        stablePeerIdentityProjection(relationship.peerIdentity),
        stablePeerIdentityProjection(baseRelationship.peerIdentity)
      )) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Durable relationship authority changed outside its disposable relationship."
    );
  }
  const localRoutes = validatePairwiseRouteSetV2(relationship.localAdvertisedRoutes);
  const peerRoutes = validatePairwiseRouteSetV2(relationship.peerIdentity.sendRoutes);
  if (localRoutes.relationshipID !== relationship.relationshipID ||
      peerRoutes.relationshipID !== relationship.relationshipID ||
      localRoutes.ownerEndpointHandle.rawValue !== relationship.localEndpointHandle.rawValue ||
      peerRoutes.ownerEndpointHandle.rawValue !==
        baseRelationship.peerIdentity.sendRoutes.ownerEndpointHandle.rawValue ||
      !verifyPairwiseRouteSetV2Throwing({
        pqc,
        routeSet: localRoutes,
        ownerSigningPublicKey: relationship.localIdentity.endpointBinding.signingPublicKey
      }) || !verifyPairwiseRouteSetV2Throwing({
        pqc,
        routeSet: peerRoutes,
        ownerSigningPublicKey: relationship.peerIdentity.endpointBinding.signingPublicKey
      }) || localRoutes.revision < baseRelationship.localAdvertisedRoutes.revision ||
      peerRoutes.revision < baseRelationship.peerIdentity.sendRoutes.revision) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Durable relationship route snapshot is invalid."
    );
  }
  await validateStableEndpointBinding({
    crypto,
    pqc,
    authoritySigningPublicKey: relationship.localIdentity.signing.publicKey,
    baseBinding: baseRelationship.localIdentity.endpointBinding,
    candidateBinding: relationship.localIdentity.endpointBinding,
    label: "local"
  });
  if (!Array.isArray(state.localEndpointBindings) ||
      state.localEndpointBindings.length === 0 ||
      state.localEndpointBindings.length > MAXIMUM_LOCAL_ENDPOINT_BINDINGS ||
      !equalCanonical(state.localEndpointBindings[0], relationship.localIdentity.endpointBinding)) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Durable local endpoint history is invalid."
    );
  }
  const localPrekeyIDs = new Set();
  for (const binding of state.localEndpointBindings) {
    await validateStableEndpointBinding({
      crypto,
      pqc,
      authoritySigningPublicKey: relationship.localIdentity.signing.publicKey,
      baseBinding: baseRelationship.localIdentity.endpointBinding,
      candidateBinding: binding,
      label: "historical local"
    });
    const prekeyID = binding.prekeyBundle.signedPrekey.id;
    if (localPrekeyIDs.has(prekeyID)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        "Durable local endpoint history contains a duplicate prekey."
      );
    }
    localPrekeyIDs.add(prekeyID);
  }
  await validateStableEndpointBinding({
    crypto,
    pqc,
    authoritySigningPublicKey: relationship.peerIdentity.signingPublicKey,
    baseBinding: baseRelationship.peerIdentity.endpointBinding,
    candidateBinding: relationship.peerIdentity.endpointBinding,
    label: "peer"
  });
  if (!Array.isArray(state.peerEndpointBindings) ||
      state.peerEndpointBindings.length === 0 ||
      state.peerEndpointBindings.length > MAXIMUM_PEER_ENDPOINT_BINDINGS ||
      !equalCanonical(state.peerEndpointBindings[0], relationship.peerIdentity.endpointBinding)) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Durable peer endpoint history is invalid."
    );
  }
  const endpointPrekeyIDs = new Set();
  for (const binding of state.peerEndpointBindings) {
    await validateStableEndpointBinding({
      crypto,
      pqc,
      authoritySigningPublicKey: relationship.peerIdentity.signingPublicKey,
      baseBinding: baseRelationship.peerIdentity.endpointBinding,
      candidateBinding: binding,
      label: "historical peer"
    });
    const prekeyID = binding.prekeyBundle.signedPrekey.id;
    if (endpointPrekeyIDs.has(prekeyID)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        "Durable peer endpoint history contains a duplicate prekey."
      );
    }
    endpointPrekeyIDs.add(prekeyID);
  }
  await validateLocalRouteProjection({ crypto, relationship });
  return relationship;
}

async function validateStableEndpointBinding({
  crypto,
  pqc,
  authoritySigningPublicKey,
  baseBinding,
  candidateBinding,
  label
}) {
  await verifyRelationshipEndpointBindingV4({
    crypto,
    pqc,
    authoritySigningPublicKey,
    endpointBinding: candidateBinding,
    now: Date.parse(candidateBinding.prekeyBundle.createdAt)
  });
  const [baseDigest, candidateDigest] = await Promise.all([
    relationshipEndpointAuthorizationDigestV4({ crypto, endpointBinding: baseBinding }),
    relationshipEndpointAuthorizationDigestV4({ crypto, endpointBinding: candidateBinding })
  ]);
  if (baseDigest !== candidateDigest) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      `Durable ${label} endpoint authorization changed instead of renewing only its prekey.`
    );
  }
}

async function validateLocalRouteProjection({ crypto, relationship }) {
  if (!Array.isArray(relationship.localReceiveRoutes) ||
      relationship.localReceiveRoutes.length === 0 ||
      relationship.localReceiveRoutes.length > 8) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Durable local route count is invalid."
    );
  }
  const advertised = relationship.localAdvertisedRoutes.routes;
  const localIDs = new Set();
  for (const localValue of relationship.localReceiveRoutes) {
    const local = await validateLocalOpaqueReceiveRouteV2({ crypto, route: localValue });
    const routeID = local.route.routeID.rawValue;
    const peerRoute = advertised.find((route) => route.routeID.rawValue === routeID);
    if (!peerRoute || localIDs.has(routeID)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        "Durable local receive route is not represented by its signed route set."
      );
    }
    localIDs.add(routeID);
    const projected = await createOpaqueSendRouteV2({
      crypto,
      relay: peerRoute.relay,
      route: local.route,
      clientCapabilities: local.clientCapabilities,
      payloadKey: local.payloadKey,
      priority: peerRoute.priority,
      state: peerRoute.state === "testing" ? "testing" : "active"
    });
    const authorityFields = [
      "routeID",
      "relay",
      "sendCapability",
      "payloadKey",
      "routeRevision",
      "policy",
      "validFrom",
      "expiresAt",
      "priority"
    ];
    if (!equalCanonical(
      Object.fromEntries(authorityFields.map((field) => [field, projected[field]])),
      Object.fromEntries(authorityFields.map((field) => [field, peerRoute[field]]))
    )) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidState",
        "Durable local route authority does not match its signed projection."
      );
    }
  }
  if (advertised.some((route) => route.state !== "revoked" &&
      !localIDs.has(route.routeID.rawValue))) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidState",
      "Signed usable routes are missing their endpoint-local receive authority."
    );
  }
}

async function applyReceivedRelationshipControl({
  crypto,
  pqc,
  state,
  relationship,
  control,
  receivedAt,
  sourceRouteID
}) {
  switch (control.kind) {
  case "routeSetUpdate": {
    const next = validatePairwiseRouteSetV2(control.value.routeSet);
    if (!verifyPairwiseRouteSetV2Throwing({
      pqc,
      routeSet: next,
      ownerSigningPublicKey: relationship.peerIdentity.endpointBinding.signingPublicKey
    }) || usablePairwiseRoutesV2(next, Date.parse(receivedAt)).length === 0) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidControlTransition",
        "Peer route-set control is not a current authenticated route snapshot."
      );
    }
    if (await validateRouteSetSuccessor({
      crypto,
      current: state.peerIdentity.sendRoutes,
      next
    })) {
      state.peerIdentity.sendRoutes = next;
    }
    return;
  }
  case "routeProbe": {
    const probe = control.value;
    const route = state.localAdvertisedRoutes.routes.find(({ routeID }) =>
      routeID.rawValue === probe.routeID.rawValue
    );
    const observed = Date.parse(receivedAt);
    if (probe.routeSetRevision !== state.localAdvertisedRoutes.revision ||
        probe.routeID.rawValue !== sourceRouteID?.rawValue ||
        !route || route.state !== "testing" ||
        observed < Date.parse(route.validFrom) || observed >= Date.parse(route.expiresAt)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidControlTransition",
        "Peer route probe does not reference our durable signed route set."
      );
    }
    return;
  }
  case "endpointPrekeyUpdate": {
    const next = control.value.endpointBinding;
    await verifyRelationshipEndpointBindingV4({
      crypto,
      pqc,
      authoritySigningPublicKey: relationship.peerIdentity.signingPublicKey,
      endpointBinding: next,
      now: Date.parse(receivedAt)
    });
    const [currentAuthorization, nextAuthorization] = await Promise.all([
      relationshipEndpointAuthorizationDigestV4({
        crypto,
        endpointBinding: state.peerIdentity.endpointBinding
      }),
      relationshipEndpointAuthorizationDigestV4({ crypto, endpointBinding: next })
    ]);
    const currentCreatedAt = Date.parse(state.peerIdentity.endpointBinding.prekeyBundle.createdAt);
    const nextCreatedAt = Date.parse(next.prekeyBundle.createdAt);
    if (currentAuthorization !== nextAuthorization || nextCreatedAt < currentCreatedAt) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidControlTransition",
        "Peer endpoint-prekey control changes endpoint authority or rolls state back."
      );
    }
    if (equalCanonical(next, state.peerIdentity.endpointBinding)) return;
    if (nextCreatedAt === currentCreatedAt) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidControlTransition",
        "Peer endpoint-prekey control conflicts at the current creation time."
      );
    }
    state.peerIdentity.endpointBinding = next;
    state.peerEndpointBindings = prependEndpointBinding(
      state.peerEndpointBindings,
      next,
      MAXIMUM_PEER_ENDPOINT_BINDINGS
    );
    state.activeOutboundSessionID = null;
    return;
  }
  default:
    throw new DurablePairwiseMessagingV2Error(
      "unknownControl",
      "Unknown relationship controls cannot mutate durable state."
    );
  }
}

async function validateRouteSetSuccessor({ crypto, current, next }) {
  const currentSet = validatePairwiseRouteSetV2(current);
  const nextSet = validatePairwiseRouteSetV2(next);
  if (nextSet.revision === currentSet.revision) {
    if (!equalCanonical(nextSet, currentSet)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidControlTransition",
        "Route-set revision conflicts with the durable current snapshot."
      );
    }
    return false;
  }
  if (nextSet.revision !== currentSet.revision + 1 ||
      nextSet.previousDigest !== await pairwiseRouteSetV2Digest(crypto, currentSet) ||
      Date.parse(nextSet.issuedAt) < Date.parse(currentSet.issuedAt)) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidControlTransition",
      "Route-set update is not the signed successor of durable current state."
    );
  }
  return true;
}

async function validateLocalRelationshipControlEffect({
  crypto,
  pqc,
  state,
  baseRelationship,
  kind,
  payload,
  localEffect,
  sentAt
}) {
  if (kind === "routeSetUpdate") {
    if (localEffect.localAdvertisedRoutes === undefined ||
        localEffect.localReceiveRoutes === undefined ||
        !equalCanonical(localEffect.localAdvertisedRoutes, payload.routeSet) ||
        !verifyPairwiseRouteSetV2Throwing({
          pqc,
          routeSet: payload.routeSet,
          ownerSigningPublicKey: state.localIdentity.endpointBinding.signingPublicKey
        })) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidLocalControlEffect",
        "Route-set publication requires matching local route authority and signature."
      );
    }
    await validateRouteSetSuccessor({
      crypto,
      current: state.localAdvertisedRoutes,
      next: payload.routeSet
    });
    const candidate = clone(state);
    candidate.localAdvertisedRoutes = clone(payload.routeSet);
    candidate.localReceiveRoutes = clone(localEffect.localReceiveRoutes);
    await validateRuntimeRelationshipSnapshot({
      crypto,
      pqc,
      baseRelationship,
      state: candidate
    });
    return;
  }
  if (kind === "endpointPrekeyUpdate") {
    if (localEffect.localIdentity === undefined ||
        !equalCanonical(localEffect.localIdentity.endpointBinding, payload.endpointBinding) ||
        !equalCanonical(
          stableLocalIdentityProjection(localEffect.localIdentity),
          stableLocalIdentityProjection(state.localIdentity)
        )) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidLocalControlEffect",
        "Endpoint-prekey publication changes local relationship authority."
      );
    }
    await validateStableEndpointBinding({
      crypto,
      pqc,
      authoritySigningPublicKey: state.localIdentity.signing.publicKey,
      baseBinding: state.localIdentity.endpointBinding,
      candidateBinding: payload.endpointBinding,
      label: "local"
    });
    const currentCreatedAt = Date.parse(state.localIdentity.endpointBinding.prekeyBundle.createdAt);
    const nextCreatedAt = Date.parse(payload.endpointBinding.prekeyBundle.createdAt);
    if (nextCreatedAt < currentCreatedAt ||
        Date.parse(payload.endpointBinding.prekeyBundle.createdAt) > Date.parse(sentAt)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidLocalControlEffect",
        "Endpoint-prekey publication time is invalid."
      );
    }
    if (nextCreatedAt === currentCreatedAt &&
        !equalCanonical(payload.endpointBinding, state.localIdentity.endpointBinding)) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidLocalControlEffect",
        "Endpoint-prekey publication conflicts at the current creation time."
      );
    }
    return;
  }
  if (kind === "routeProbe" && Object.keys(localEffect).length === 0) return;
  throw new DurablePairwiseMessagingV2Error(
    "invalidLocalControlEffect",
    "This relationship control does not accept that local state effect."
  );
}

function relationshipControlDestinationRoutes({
  kind,
  payload,
  routeSet,
  destinationRouteIDs,
  at
}) {
  const validatedRouteSet = validatePairwiseRouteSetV2(routeSet);
  if (kind !== "routeProbe") {
    if (destinationRouteIDs !== null) {
      throw new DurablePairwiseMessagingV2Error(
        "invalidControlDestination",
        "Only a route probe may target an explicit non-active route."
      );
    }
    return usablePairwiseRoutesV2(validatedRouteSet, Date.parse(at));
  }
  const rawIDs = destinationRouteIDs ?? [payload.routeID];
  if (!Array.isArray(rawIDs) || rawIDs.length !== 1) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidControlDestination",
      "A bounded route probe targets exactly one peer route."
    );
  }
  const routeID = typeof rawIDs[0] === "string" ? rawIDs[0] : rawIDs[0]?.rawValue;
  const route = validatedRouteSet.routes.find((candidate) =>
    candidate.routeID.rawValue === routeID
  );
  const timestamp = Date.parse(at);
  if (payload.routeSetRevision !== validatedRouteSet.revision ||
      payload.routeID.rawValue !== routeID || !route || route.state === "revoked" ||
      timestamp < Date.parse(route.validFrom) || timestamp >= Date.parse(route.expiresAt) ||
      (route.state === "draining" && timestamp >= Date.parse(route.drainAfter))) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidControlDestination",
      "Route probe destination is not the exact current peer route under test."
    );
  }
  return [route];
}

function stableLocalIdentityProjection(value) {
  const projected = clone(value);
  delete projected.endpointBinding;
  if (projected.localEndpoint && typeof projected.localEndpoint === "object") {
    delete projected.localEndpoint.prekeys;
  }
  return projected;
}

function stablePeerIdentityProjection(value) {
  const projected = clone(value);
  delete projected.endpointBinding;
  delete projected.sendRoutes;
  return projected;
}

function sameLogicalControlRequest(event, { kind, payload }) {
  return event.kind === "control" &&
    equalCanonical(event.content.type, relationshipControlKindsV2[kind]) &&
    event.content.payload === base64(canonicalJsonBytes(payload));
}

function assertOutboxCapacity(state) {
  compactTerminalIntents(state, { reserve: 1 });
  if (state.intents.length >= MAXIMUM_RETAINED_INTENTS ||
      state.intents.filter(isPendingIntent).length >= MAXIMUM_PENDING_INTENTS) {
    throw new DurablePairwiseMessagingV2Error(
      "outboxCapacityExceeded",
      "The bounded durable outbox is full."
    );
  }
}

function compactTerminalIntents(state, { reserve = 0 } = {}) {
  const pendingCount = state.intents.filter(isPendingIntent).length;
  const target = Math.min(
    MAXIMUM_RETAINED_INTENTS - reserve,
    pendingCount + 256
  );
  while (state.intents.length > target) {
    const index = state.intents.findIndex((intent, candidateIndex) =>
      intentCanBeCompacted(state, intent, candidateIndex)
    );
    if (index < 0) break;
    state.intents.splice(index, 1);
  }
}

function intentCanBeCompacted(state, intent, index) {
  if (intent.status === "relayAccepted" || intent.status === "discarded") return true;
  if (intent.status !== "permanentFailure") return false;
  return !state.intents.slice(index + 1).some((candidate) =>
    isPendingIntent(candidate) && candidate.sessionID === intent.sessionID
  );
}

function reserveSessionCapacity(state) {
  const protectedSessionIDs = new Set([
    ...(state.activeOutboundSessionID === null ? [] : [state.activeOutboundSessionID]),
    ...state.intents
      .filter((intent) => isPendingIntent(intent) || intent.status === "permanentFailure")
      .map(({ sessionID }) => sessionID)
  ]);
  while (state.sessions.length >= MAXIMUM_SESSIONS) {
    const index = state.sessions.findIndex(({ sessionId }) => !protectedSessionIDs.has(sessionId));
    if (index < 0) {
      throw new DurablePairwiseMessagingV2Error(
        "sessionCapacityExceeded",
        "All bounded direct sessions still have active or in-flight dependencies."
      );
    }
    state.sessions.splice(index, 1);
  }
}

function compactArrayHistory(array, hardLimit, target) {
  if (array.length < hardLimit) return;
  array.splice(0, array.length - target);
}

function compactCandidateState(state) {
  compactTerminalIntents(state);
  let encodedBytes = encoder.encode(JSON.stringify(state)).byteLength;
  while (encodedBytes > MAXIMUM_STATE_BYTES) {
    const terminalIndex = state.intents.findIndex((intent, index) =>
      intentCanBeCompacted(state, intent, index)
    );
    if (terminalIndex >= 0) {
      state.intents.splice(terminalIndex, 1);
    } else if (state.receivedEvents.length > 0) {
      state.receivedEvents.shift();
    } else if (state.quarantinedEnvelopes.length > 0) {
      state.quarantinedEnvelopes.shift();
    } else if (state.quarantinedControls.length > 0) {
      state.quarantinedControls.shift();
    } else if (state.quarantinedPackets.length > 0) {
      state.quarantinedPackets.shift();
    } else if (state.retiredLocalRoutes.length > 0) {
      state.retiredLocalRoutes.shift();
    } else {
      const protectedSessionIDs = new Set([
        ...(state.activeOutboundSessionID === null ? [] : [state.activeOutboundSessionID]),
        ...state.intents
          .filter((intent) => isPendingIntent(intent) || intent.status === "permanentFailure")
          .map(({ sessionID }) => sessionID)
      ]);
      const sessionIndex = state.sessions.findIndex(({ sessionId }) =>
        !protectedSessionIDs.has(sessionId)
      );
      if (sessionIndex < 0) break;
      state.sessions.splice(sessionIndex, 1);
    }
    encodedBytes = encoder.encode(JSON.stringify(state)).byteLength;
  }
}

function exactOptionalLocalControlEffect(value) {
  requirePlainRecord(value, "Local relationship-control effect");
  const allowed = new Set(["localAdvertisedRoutes", "localReceiveRoutes", "localIdentity"]);
  if (Object.keys(value).some((field) => !allowed.has(field))) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidLocalControlEffect",
      "Local relationship-control effect has unknown fields."
    );
  }
}

async function validateLocalRouteRetirementEvidence(crypto, value) {
  exact(value, [
    "request",
    "teardownCapability",
    "tombstone"
  ], "Local route retirement evidence");
  const request = await validateOpaqueRouteTeardownRequestV2(crypto, value.request);
  exact(value.teardownCapability, ["rawValue"], "Retired route teardown capability");
  canonicalBase64(
    value.teardownCapability.rawValue,
    32,
    "Retired route teardown capability"
  );
  const tombstone = validateOpaqueReceiveRouteV2(value.tombstone);
  if (tombstone.status !== "tornDown" ||
      tombstone.routeID.rawValue !== request.routeID.rawValue ||
      tombstone.lease.renewalSequence !== request.renewalSequence ||
      Date.parse(tombstone.tornDownAt) < Date.parse(request.authorizedAt)) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidRouteRetirement",
      "Opaque-route tombstone does not match its durable teardown evidence."
    );
  }
  return Object.freeze({
    request,
    teardownCapability: { rawValue: value.teardownCapability.rawValue },
    tombstone
  });
}

function opaqueRouteTombstoneMatchesLocal(local, tombstone) {
  const stableFields = [
    "version",
    "routeID",
    "sendCapabilityDigest",
    "readCredentialDigest",
    "renewCapabilityDigest",
    "teardownCapabilityDigest",
    "lease",
    "createdAt",
    "creationIdempotencyKey",
    "creationDigest"
  ];
  return equalCanonical(
    Object.fromEntries(stableFields.map((field) => [field, local[field]])),
    Object.fromEntries(stableFields.map((field) => [field, tombstone[field]]))
  );
}

function validateRelationshipStateAnchorV2(value, relationshipID) {
  exact(value, [
    "version",
    "relationshipID",
    "generation",
    "stateDigest",
    "authenticationTag"
  ], "Relationship state anchor");
  if (value.version !== STATE_ANCHOR_VERSION ||
      canonicalUUID(value.relationshipID, "Anchor relationship") !== relationshipID) {
    throw new DurablePairwiseMessagingV2Error(
      "rollbackDetected",
      "Relationship state anchor scope is invalid."
    );
  }
  return Object.freeze({
    version: STATE_ANCHOR_VERSION,
    relationshipID,
    generation: integer(
      value.generation,
      "Anchor generation",
      1,
      Number.MAX_SAFE_INTEGER
    ),
    stateDigest: canonicalBase64(value.stateDigest, 32, "Anchor state digest"),
    authenticationTag: canonicalBase64(
      value.authenticationTag,
      32,
      "Anchor authentication tag"
    )
  });
}

async function durableStateDigest(crypto, state) {
  if (typeof crypto?.sha256 !== "function") {
    throw new TypeError("Durable state anchoring requires SHA-256.");
  }
  return base64(await crypto.sha256(canonicalJsonBytes(state)));
}

function equalCanonical(left, right) {
  return equalBytes(canonicalJsonBytes(left), canonicalJsonBytes(right));
}

function activeOutboundSession(state) {
  if (state.activeOutboundSessionID === null) return null;
  const session = state.sessions.find(({ sessionId }) =>
    sessionId === state.activeOutboundSessionID
  );
  if (!session) {
    throw new DurablePairwiseMessagingV2Error("invalidState", "Active session is missing.");
  }
  return session;
}

function isPendingIntent(intent) {
  return intentStates.has(intent.status) &&
    !["relayAccepted", "permanentFailure", "discarded"].includes(intent.status);
}

function isBlockingIntent(intent) {
  return isPendingIntent(intent) || intent.status === "permanentFailure";
}

function publicIntent(intent) {
  return Object.freeze({
    id: intent.id,
    sequence: intent.sequence,
    event: intent.event,
    clientTransactionId: intent.clientTransactionId,
    status: intent.status,
    attemptCount: intent.attemptCount,
    lastFailureCode: intent.lastFailureCode,
    delivery: intent.delivery,
    createdAt: intent.createdAt,
    updatedAt: intent.updatedAt
  });
}

function publicState(state) {
  return Object.freeze({
    stateSchema: state.stateSchema,
    version: state.version,
    anchorGeneration: state.anchorGeneration,
    relationshipID: state.relationshipID,
    localPolicy: clone(state.localPolicy),
    intents: Object.freeze(state.intents.map(publicIntent)),
    receivedEventCount: state.receivedEvents.length,
    quarantinedPacketCount: state.quarantinedPackets.length,
    quarantinedEnvelopeCount: state.quarantinedEnvelopes.length,
    quarantinedControlCount: state.quarantinedControls.length,
    peerRouteSetRevision: state.peerIdentity.sendRoutes.revision,
    sessionCount: state.sessions.length,
    createdAt: state.createdAt,
    updatedAt: state.updatedAt
  });
}

function isTerminalOpaquePacketFailure(error) {
  return error instanceof OpaqueRoutePacketV2Error &&
    terminalOpaquePacketFailures.has(error.code);
}

function isTerminalEnvelopeFailure(error) {
  return error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "invalidEnvelopeEncoding";
}

function quarantinePacket(state, record, reason, quarantinedAt) {
  if (!terminalQuarantineReasons.has(reason)) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidQuarantineReason",
      "Only deterministic terminal packet failures may be quarantined."
    );
  }
  compactArrayHistory(state.quarantinedPackets, MAXIMUM_QUARANTINED_PACKETS, 48);
  state.quarantinedPackets.push({
    packet: record.packet,
    sequence: record.sequence,
    recordDigest: record.recordDigest,
    routeRevision: record.routeRevision,
    reason,
    quarantinedAt
  });
  return Object.freeze({
    kind: "quarantinedPacket",
    packetID: record.packet.packetID,
    reason
  });
}

function sameLogicalRequest(event, { validatedContent, relation, eventKind }) {
  if (event.kind !== eventKind) return false;
  const candidate = {
    content: validatedContent,
    relation: relation ?? null
  };
  const existing = {
    content: event.content,
    relation: event.relation ?? null
  };
  return equalBytes(canonicalJsonBytes(candidate), canonicalJsonBytes(existing));
}

function decodeCanonicalEnvelope(payload) {
  const data = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  let value;
  try {
    value = parseExactJSON(decoder.decode(data));
  } catch (error) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidEnvelopeEncoding",
      "Opaque-route bundle is not a strict direct envelope.",
      error
    );
  }
  if (!equalBytes(data, canonicalJsonBytes(value))) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidEnvelopeEncoding",
      "Opaque-route direct envelope is not canonical."
    );
  }
  try {
    return validateDirectEnvelopeV4(value);
  } catch (error) {
    throw new DurablePairwiseMessagingV2Error(
      "invalidEnvelopeEncoding",
      "Opaque-route bundle is not a valid direct envelope.",
      error
    );
  }
}

function applyAuthenticatedReceipt(state, decoded, receivedAt) {
  if (decoded.kind !== "receipt") return;
  const targetEventId = decoded.projection.targetEventId;
  const intent = state.intents.find(({ event }) => event.id === targetEventId);
  if (!intent) return;
  const nextState = decoded.projection.kind === "readReceipt" ? "peerRead" : "peerStored";
  const advanced = advanceDeliveryState(intent.delivery, nextState, { updatedAt: receivedAt });
  if (advanced !== null) intent.delivery = advanced;
}

function receiveRouteIndex(state, routeIDValue) {
  const routeID = typeof routeIDValue === "string" ? routeIDValue : routeIDValue?.rawValue;
  if (typeof routeID !== "string") {
    if (state.localReceiveRoutes.length === 1) return 0;
    throw new TypeError("routeID is required when more than one receive route exists.");
  }
  const index = state.localReceiveRoutes.findIndex(({ route }) =>
    route.routeID.rawValue === routeID
  );
  if (index < 0) {
    throw new DurablePairwiseMessagingV2Error("unknownRoute", "The local receive route is unknown.");
  }
  return index;
}

function boundedFailureCode(error) {
  const value = typeof error?.code === "string"
    ? error.code
    : typeof error?.reason === "string"
      ? error.reason
      : error?.name === "AbortError"
        ? "timeout"
        : "relayFailure";
  const normalized = value.replace(/[^A-Za-z0-9._-]/gu, "_");
  return encoder.encode(normalized).byteLength <= 96 ? normalized : "relayFailure";
}

function isDeterministicOutboundFailure(error) {
  return error instanceof OpaqueRoutePacketV2Error &&
    ["invalidPacket", "invalidBundle"].includes(error.code);
}

function validateStateKey(value) {
  if (typeof value !== "string" || value.length === 0 ||
      encoder.encode(value).byteLength > 256 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError("Durable pairwise state key is invalid.");
  }
  return value;
}

function canonicalTimestamp(value, label) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError(`${label} is invalid.`);
  const canonical = swiftISODate(date);
  if (typeof value === "string" && value !== canonical) {
    throw new TypeError(`${label} must use canonical protocol time.`);
  }
  return canonical;
}

function monotonicStateTimestamp(state, candidate) {
  const canonicalCandidate = canonicalTimestamp(candidate, "State update time");
  return [state.createdAt, state.updatedAt, canonicalCandidate]
    .reduce((latest, value) => Date.parse(value) > Date.parse(latest) ? value : latest);
}

function canonicalUUID(value, label) {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value)) {
    throw new TypeError(`${label} must be a UUID.`);
  }
  return value.toUpperCase();
}

function canonicalBase64(value, exactBytes, label) {
  if (typeof value !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new TypeError(`${label} must be canonical base64.`);
  }
  const decoded = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  if (decoded.byteLength !== exactBytes || base64(decoded) !== value) {
    throw new TypeError(`${label} must be canonical base64.`);
  }
  return value;
}

function integer(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} is outside its bound.`);
  }
  return value;
}

function exact(value, fields, label) {
  requirePlainRecord(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new TypeError(`${label} fields do not match schema ${STATE_VERSION}.`);
  }
}

function requirePlainRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
  return value;
}

function boundedString(value, maximumBytes) {
  return typeof value === "string" && value.length > 0 &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function equalBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function clone(value) {
  return typeof structuredClone === "function"
    ? structuredClone(value)
    : JSON.parse(JSON.stringify(value));
}
