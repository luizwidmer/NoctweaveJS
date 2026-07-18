import { parseRelayEndpoint } from "./endpoint.js";
import { NoctweaveRelayClient } from "./relay-client.js";
import {
  acknowledgeContactPairingOutboundV2,
  cancelContactPairingV2,
  contactPairingStateSchemaV2,
  createContactPairingInvitationV2,
  finalizeContactPairingV2,
  prepareContactPairingParticipantV2,
  prepareContactPairingOffererV2,
  prepareContactPairingResponderV2,
  processContactPairingTransportFrameV2,
  resumeContactPairingV2,
  validateContactPairingStateShapeV2,
  validatePairwiseRelationshipV2,
  validatePreparedContactParticipantV2
} from "./contact-pairing-v2.js";
import { createRendezvousRelayAdapterV2 } from "./rendezvous-relay-v2.js";
import { swiftISODate } from "./crypto/swift-canonical.js";
import { validateProtocolCapabilityManifest } from "./architecture-v2.js";
import {
  createRelationshipLocalPolicyV2,
  validateRelationshipLocalPolicyV2
} from "./relationship-local-policy-v2.js";

const encoder = new TextEncoder();
const personaFields = Object.freeze([
  "stateSchema",
  "version",
  "displayName",
  "relationships",
  "pendingPairings",
  "createdAt"
]);

export const browserPersonaStateSchema = "nw.browser-persona.v2";
export const defaultRelationshipPseudonymV2 = "Noctweave peer";

/**
 * Browser orchestration for local personas and one-use pairings. A persona is
 * only a UI container: it has no signing key, agreement key, network address, route, or
 * protocol identifier of its own.
 */
export class NoctweaveBrowserPairingService {
  constructor({ pqc, crypto, relayClientFactory } = {}) {
    if (!pqc?.generateSigningKeypair || !pqc?.generateKemKeypair || !pqc?.sign || !pqc?.verify) {
      throw new TypeError("A compatible Noctweave post-quantum adapter is required.");
    }
    if (!crypto?.sha256 || !crypto?.generateKemKeypair || !crypto?.encapsulate ||
        !crypto?.decapsulate || !crypto?.randomBytes) {
      throw new TypeError("The browser pairing service requires the complete Noctweave crypto suite.");
    }
    this.pqc = pqc;
    this.crypto = crypto;
    this.relayClientFactory = relayClientFactory ?? ((endpoint, options) => (
      new NoctweaveRelayClient(endpoint, options)
    ));
  }

  async verifyRelay(endpoint, options = {}) {
    const parsed = parseBrowserRelayEndpoint(endpoint);
    const client = this.relayClientFactory(endpoint, {
      authToken: normalizedOptionalSecret(options.authToken),
      fetch: options.fetch,
      WebSocket: options.WebSocket,
      timeoutMs: options.timeoutMs,
      crypto: this.crypto
    });
    const [health, info] = await Promise.all([client.health(), client.info()]);
    if (!health || typeof health !== "object" || Array.isArray(health) || Object.keys(health).length !== 0) {
      throw new Error("The relay health check returned an incompatible response.");
    }
    if (!info || Object.keys(info).length !== 1 || !info.relayInfo ||
        info.relayInfo.kind === "coordinator") {
      throw new Error("The address did not return a compatible client-facing Noctweave relay profile.");
    }
    let capabilities;
    try {
      capabilities = validateProtocolCapabilityManifest(info.relayInfo.protocolCapabilities);
    } catch {
      throw new Error("The relay does not advertise a valid Noctweave architecture-v2 capability manifest.");
    }
    if (!capabilities.modules.some((module) =>
      module.module === "nw.opaque-route" && module.versions.includes(2))) {
      throw new Error("The relay does not support opaque route v2 delivery.");
    }
    if (!capabilities.modules.some((module) =>
      module.module === "nw.rendezvous-transport" && module.versions.includes(2))) {
      throw new Error("The relay does not support rendezvous transport v2 pairing.");
    }
    return { endpoint: parsed, health, info };
  }

  createPersona({ displayName, createdAt = swiftISODate() } = {}) {
    const persona = {
      stateSchema: browserPersonaStateSchema,
      version: 2,
      displayName: validateBrowserDisplayName(displayName),
      relationships: [],
      pendingPairings: [],
      createdAt
    };
    return validateBrowserPersonaState(persona);
  }

  async createPairingInvitation({ createdAt = swiftISODate(), expiresAt } = {}) {
    const expiry = expiresAt ?? swiftISODate(new Date(Date.parse(createdAt) + 10 * 60 * 1_000));
    return createContactPairingInvitationV2({ crypto: this.crypto, createdAt, expiresAt: expiry });
  }

  async preparePairingParticipant({
    persona,
    relay,
    relationshipPseudonym = defaultRelationshipPseudonymV2,
    createdAt = swiftISODate(),
    ...unsupported
  } = {}) {
    if (Object.keys(unsupported).length !== 0) {
      throw new TypeError("Pairing participant parameters do not match the current protocol.");
    }
    validateBrowserPersonaState(persona);
    const endpoint = typeof relay === "string" ? parseBrowserRelayEndpoint(relay) : relay;
    const participant = await prepareContactPairingParticipantV2({
      crypto: this.crypto,
      pqc: this.pqc,
      relationshipPseudonym: validateBrowserDisplayName(relationshipPseudonym),
      relay: endpoint,
      createdAt
    });
    const client = this.relayClientFactory(endpoint, { crypto: this.crypto });
    const registered = await client.createOpaqueRoute({
      request: participant.routeCreateRequest,
      renewCapability: participant.localReceiveRoute.clientCapabilities.renewCapability
    });
    const activated = {
      ...participant,
      localReceiveRoute: {
        ...participant.localReceiveRoute,
        route: registered
      }
    };
    await validatePreparedContactParticipantV2({
      crypto: this.crypto,
      pqc: this.pqc,
      participant: activated
    });
    return activated;
  }

  async prepareOffererPairing({
    persona: personaValue,
    relay,
    relationshipPseudonym = defaultRelationshipPseudonymV2,
    createdAt = swiftISODate(),
    expiresAt,
    ledger
  }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const endpoint = typeof relay === "string" ? parseBrowserRelayEndpoint(relay) : relay;
    const expiry = expiresAt ?? swiftISODate(new Date(Date.parse(createdAt) + 10 * 60 * 1_000));
    const made = await this.createPairingInvitation({ createdAt, expiresAt: expiry });
    const participant = await this.preparePairingParticipant({
      persona,
      relay: endpoint,
      relationshipPseudonym,
      createdAt
    });
    const pairing = await prepareContactPairingOffererV2({
      crypto: this.crypto,
      pqc: this.pqc,
      pending: made.pending,
      invitation: made.invitation,
      participant,
      ledger,
      at: createdAt
    });
    const adapter = await createRendezvousRelayAdapterV2({
      crypto: this.crypto,
      offer: made.invitation.offer
    });
    const relayClient = this.relayClientFactory(endpoint, { crypto: this.crypto });
    if (typeof relayClient.registerRendezvousTransportV2 !== "function") {
      throw new TypeError("The relay client does not support rendezvous transport registration.");
    }
    await relayClient.registerRendezvousTransportV2(adapter.registrationRequest);
    storePendingPairing(persona, pairing);
    return {
      persona: validateBrowserPersonaState(persona),
      pairingID: pairing.pairingID,
      invitation: made.invitation,
      outboundTransportFrames: pairing.outboundTransportFrames
    };
  }

  async prepareResponderPairing({
    persona: personaValue,
    invitation,
    relay,
    relationshipPseudonym = defaultRelationshipPseudonymV2,
    at = swiftISODate()
  }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const endpoint = typeof relay === "string" ? parseBrowserRelayEndpoint(relay) : relay;
    const participant = await this.preparePairingParticipant({
      persona,
      relay: endpoint,
      relationshipPseudonym,
      createdAt: at
    });
    const pairing = await prepareContactPairingResponderV2({
      crypto: this.crypto,
      pqc: this.pqc,
      invitation,
      participant,
      at
    });
    storePendingPairing(persona, pairing);
    return {
      persona: validateBrowserPersonaState(persona),
      pairingID: pairing.pairingID,
      outboundTransportFrames: pairing.outboundTransportFrames
    };
  }

  async resumePairing({ persona: personaValue, pairingID }) {
    const persona = validateBrowserPersonaState(personaValue);
    const pairing = await resumeContactPairingV2({
      crypto: this.crypto,
      pqc: this.pqc,
      state: requirePendingPairing(persona, pairingID)
    });
    return { pairing, outboundTransportFrames: pairing.outboundTransportFrames };
  }

  async processPairingFrame({
    persona: personaValue,
    pairingID,
    transportFrame,
    at = swiftISODate()
  }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const index = pendingPairingIndex(persona, pairingID);
    const pairing = await processContactPairingTransportFrameV2({
      crypto: this.crypto,
      pqc: this.pqc,
      state: persona.pendingPairings[index],
      transportFrame,
      at
    });
    persona.pendingPairings[index] = pairing;
    return {
      persona: validateBrowserPersonaState(persona),
      pairingID,
      phase: pairing.phase,
      outboundTransportFrames: pairing.outboundTransportFrames
    };
  }

  async acknowledgePairingOutbound({ persona: personaValue, pairingID, frameIDs }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const index = pendingPairingIndex(persona, pairingID);
    const pairing = await acknowledgeContactPairingOutboundV2({
      crypto: this.crypto,
      pqc: this.pqc,
      state: persona.pendingPairings[index],
      frameIDs
    });
    persona.pendingPairings[index] = pairing;
    return {
      persona: validateBrowserPersonaState(persona),
      pairingID,
      outboundTransportFrames: pairing.outboundTransportFrames
    };
  }

  async finalizePairing({
    persona: personaValue,
    pairingID,
    at = swiftISODate(),
    consent = "accepted"
  }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const index = pendingPairingIndex(persona, pairingID);
    const pairing = persona.pendingPairings[index];
    const finalized = await finalizeContactPairingV2({
      crypto: this.crypto,
      pqc: this.pqc,
      state: pairing,
      at
    });
    const relationship = Object.freeze({
      ...finalized.relationship,
      localPolicy: createRelationshipLocalPolicyV2({
        ...finalized.relationship.localPolicy,
        consent
      })
    });
    if (persona.relationships.some(({ relationshipID }) => relationshipID === relationship.relationshipID)) {
      throw new Error("This one-use rendezvous relationship is already stored.");
    }
    await validatePairwiseRelationshipV2({ crypto: this.crypto, pqc: this.pqc, relationship });
    const adapter = await createRendezvousRelayAdapterV2({ crypto: this.crypto, offer: pairing.offer });
    persona.pendingPairings.splice(index, 1);
    persona.relationships.push(relationship);
    return {
      persona: validateBrowserPersonaState(persona),
      relationship,
      receipt: finalized.receipt,
      rendezvousDeletionRequests: adapter.deletionRequests()
    };
  }

  async cancelPairing({ persona: personaValue, pairingID, at = swiftISODate() }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const index = pendingPairingIndex(persona, pairingID);
    const pairing = persona.pendingPairings[index];
    const receipt = await cancelContactPairingV2({
      crypto: this.crypto,
      pqc: this.pqc,
      state: pairing,
      at
    });
    const adapter = await createRendezvousRelayAdapterV2({ crypto: this.crypto, offer: pairing.offer });
    persona.pendingPairings.splice(index, 1);
    return {
      persona: validateBrowserPersonaState(persona),
      receipt,
      rendezvousDeletionRequests: adapter.deletionRequests()
    };
  }

  setRelationshipLocalPolicy({ persona: personaValue, relationshipID, policy }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const index = persona.relationships.findIndex((relationship) =>
      relationship.relationshipID === relationshipID);
    if (index < 0) throw new Error("Pairwise relationship was not found.");
    persona.relationships[index] = {
      ...persona.relationships[index],
      localPolicy: validateRelationshipLocalPolicyV2(policy)
    };
    return validateBrowserPersonaState(persona);
  }
}

export function validateBrowserPersonaState(value) {
  requireExactRecord(value, personaFields, "Browser persona");
  if (value.stateSchema !== browserPersonaStateSchema || value.version !== 2) {
    throw new Error("The browser persona uses an unsupported state schema.");
  }
  validateBrowserDisplayName(value.displayName);
  if (!Array.isArray(value.relationships) || value.relationships.length > 4_096 ||
      !Array.isArray(value.pendingPairings) || value.pendingPairings.length > 32 ||
      !Number.isFinite(Date.parse(value.createdAt))) {
    throw new Error("The browser persona state is malformed.");
  }
  const relationshipIDs = new Set();
  for (const relationship of value.relationships) {
    if (!relationship || relationship.version !== 2 ||
        typeof relationship.relationshipID !== "string" ||
        relationship.localIdentity?.scope !== "pairwise" ||
        relationship.localIdentity?.relationshipID !== relationship.relationshipID ||
        relationship.peerIdentity?.relationshipID !== relationship.relationshipID ||
        relationshipIDs.has(relationship.relationshipID)) {
      throw new Error("The browser persona contains an invalid pairwise relationship.");
    }
    validateRelationshipLocalPolicyV2(relationship.localPolicy);
    relationshipIDs.add(relationship.relationshipID);
  }
  const pendingPairingIDs = new Set();
  for (const pending of value.pendingPairings) {
    try {
      validateContactPairingStateShapeV2(pending);
    } catch {
      throw new Error("The browser persona contains invalid pending pairing state.");
    }
    if (pending.stateSchema !== contactPairingStateSchemaV2 ||
        pending.participant?.localIdentity?.scope !== "pairwise" ||
        pendingPairingIDs.has(pending.pairingID)) {
      throw new Error("The browser persona contains invalid pending pairing state.");
    }
    pendingPairingIDs.add(pending.pairingID);
  }
  requireUniqueRelationshipScopes(value);
  return value;
}

export function validateBrowserDisplayName(value) {
  if (typeof value !== "string") throw new TypeError("Display name is required.");
  const normalized = value.trim().replace(/\s+/gu, " ");
  const byteLength = encoder.encode(normalized).byteLength;
  if (normalized.length < 1 || byteLength > 128 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError("Display name must contain 1 to 128 UTF-8 bytes without control characters.");
  }
  return normalized;
}

export function parseBrowserRelayEndpoint(value) {
  const endpoint = parseRelayEndpoint(value);
  if (endpoint.transport === "tcp") {
    throw new TypeError("The browser client requires an HTTP, HTTPS, WS, or WSS relay URL.");
  }
  return endpoint;
}

function normalizedOptionalSecret(value) {
  if (value == null || value === "") return null;
  if (typeof value !== "string" || encoder.encode(value).byteLength > 4096) {
    throw new TypeError("Relay access password must not exceed 4096 UTF-8 bytes.");
  }
  return value;
}

function storePendingPairing(persona, pairing) {
  validateContactPairingStateShapeV2(pairing);
  if (persona.pendingPairings.some(({ pairingID }) => pairingID === pairing.pairingID)) {
    throw new Error("This one-use rendezvous pairing is already pending.");
  }
  persona.pendingPairings.push(pairing);
}

function pendingPairingIndex(persona, pairingID) {
  if (typeof pairingID !== "string" || pairingID.length === 0) {
    throw new TypeError("A pairing ID is required.");
  }
  const index = persona.pendingPairings.findIndex((pairing) => pairing.pairingID === pairingID);
  if (index < 0) throw new Error("Pending pairwise pairing was not found.");
  return index;
}

function requirePendingPairing(persona, pairingID) {
  return persona.pendingPairings[pendingPairingIndex(persona, pairingID)];
}

function requireUniqueRelationshipScopes(persona) {
  const identityIDs = new Set();
  const signingKeys = new Set();
  const agreementKeys = new Set();
  const endpointHandles = new Set();
  const routeIDs = new Set();
  const routePayloadKeys = new Set();

  for (const relationship of persona.relationships) {
    const local = relationship.localIdentity;
    const peer = relationship.peerIdentity;
    insertUniqueScope(identityIDs, local?.id);
    insertUniqueScope(identityIDs, peer?.id);
    insertUniqueScope(signingKeys, local?.signing?.publicKey);
    insertUniqueScope(signingKeys, local?.localEndpoint?.signing?.publicKey);
    insertUniqueScope(signingKeys, peer?.signingPublicKey);
    insertUniqueScope(signingKeys, peer?.endpointBinding?.signingPublicKey);
    insertUniqueScope(agreementKeys, local?.agreement?.publicKey);
    insertUniqueScope(agreementKeys, local?.localEndpoint?.agreement?.publicKey);
    insertUniqueScope(agreementKeys, peer?.agreementPublicKey);
    insertUniqueScope(agreementKeys, peer?.endpointBinding?.agreementPublicKey);
    insertUniqueScope(endpointHandles, relationship.localEndpointHandle?.rawValue);
    insertUniqueScope(endpointHandles, peer?.sendRoutes?.ownerEndpointHandle?.rawValue);
    insertUniqueRoutes(local?.relationshipID, relationship.localAdvertisedRoutes?.routes);
    insertUniqueRoutes(peer?.relationshipID, peer?.sendRoutes?.routes);
  }

  for (const pairing of persona.pendingPairings) {
    const participant = pairing.participant;
    const local = participant?.localIdentity;
    insertUniqueScope(identityIDs, local?.id);
    insertUniqueScope(signingKeys, local?.signing?.publicKey);
    insertUniqueScope(signingKeys, local?.localEndpoint?.signing?.publicKey);
    insertUniqueScope(agreementKeys, local?.agreement?.publicKey);
    insertUniqueScope(agreementKeys, local?.localEndpoint?.agreement?.publicKey);
    insertUniqueScope(endpointHandles, participant?.localEndpointHandle?.rawValue);
    insertUniqueScope(routeIDs, participant?.localReceiveRoute?.route?.routeID?.rawValue);
    insertUniqueScope(routePayloadKeys, participant?.localReceiveRoute?.payloadKey?.rawValue);
  }

  function insertUniqueRoutes(relationshipID, routes) {
    if (typeof relationshipID !== "string" || !Array.isArray(routes)) {
      throw new Error("The browser persona contains malformed relationship-scoped routes.");
    }
    for (const route of routes) {
      insertUniqueScope(routeIDs, route?.routeID?.rawValue);
      insertUniqueScope(routePayloadKeys, route?.payloadKey?.rawValue);
    }
  }
}

function insertUniqueScope(set, value) {
  if (typeof value !== "string" || value.length === 0 || set.has(value)) {
    throw new Error("The browser persona reuses relationship-scoped authority, endpoint, or route material.");
  }
  set.add(value);
}

function requireExactRecord(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} fields do not match the current schema.`);
  }
}
