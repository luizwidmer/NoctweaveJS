import { parseRelayEndpoint } from "./endpoint.js";
import { NoctweaveRelayClient } from "./relay-client.js";
import {
  createContactPairingInvitationV2,
  establishContactPairingV2,
  prepareContactPairingParticipantV2,
  validatePairwiseRelationshipV2,
  validatePreparedContactParticipantV2
} from "./contact-pairing-v2.js";
import { swiftISODate } from "./crypto/swift-canonical.js";
import { validateProtocolCapabilityManifest } from "./architecture-v2.js";

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
    if (!health || (health.type !== "ok" && health.type !== "health")) {
      throw new Error("The relay health check returned an incompatible response.");
    }
    if (info?.type !== "info" || !info.relayInfo || info.relayInfo.kind === "coordinator") {
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
    relationshipLabel = defaultRelationshipPseudonymV2,
    createdAt = swiftISODate()
  } = {}) {
    validateBrowserPersonaState(persona);
    const endpoint = typeof relay === "string" ? parseBrowserRelayEndpoint(relay) : relay;
    const participant = await prepareContactPairingParticipantV2({
      crypto: this.crypto,
      pqc: this.pqc,
      displayName: validateBrowserDisplayName(relationshipLabel),
      relay: endpoint,
      createdAt
    });
    const client = this.relayClientFactory(endpoint, { crypto: this.crypto });
    const registered = await client.createOpaqueRoute({
      transition: participant.routeCreateRequest,
      renewCapability: participant.localReceiveRoute.clientCapabilities.renewCapability
    });
    const activated = {
      ...participant,
      localReceiveRoute: {
        ...participant.localReceiveRoute,
        opaqueRoute: registered.opaqueRouteV2
      }
    };
    await validatePreparedContactParticipantV2({
      crypto: this.crypto,
      pqc: this.pqc,
      participant: activated
    });
    return activated;
  }

  async establishPairing({
    persona: personaValue,
    pending,
    invitation,
    localParticipant,
    peerParticipant,
    ledger,
    at = swiftISODate(),
    role = "offerer"
  }) {
    const persona = structuredClone(validateBrowserPersonaState(personaValue));
    const result = await establishContactPairingV2({
      crypto: this.crypto,
      pqc: this.pqc,
      pending,
      invitation,
      offerer: role === "offerer" ? localParticipant : peerParticipant,
      responder: role === "offerer" ? peerParticipant : localParticipant,
      ledger,
      at
    });
    const relationship = role === "offerer"
      ? result.offererRelationship
      : result.responderRelationship;
    if (persona.relationships.some(({ relationshipID }) => relationshipID === relationship.relationshipID)) {
      throw new Error("This one-use rendezvous relationship is already stored.");
    }
    await validatePairwiseRelationshipV2({
      crypto: this.crypto,
      pqc: this.pqc,
      relationship
    });
    persona.relationships.push(relationship);
    validateBrowserPersonaState(persona);
    return { persona, relationship, handshake: result };
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
    relationshipIDs.add(relationship.relationshipID);
  }
  for (const pending of value.pendingPairings) {
    if (!pending || typeof pending !== "object" || Array.isArray(pending) ||
        pending.version !== 2 || typeof pending.createdAt !== "string" ||
        typeof pending.expiresAt !== "string") {
      throw new Error("The browser persona contains invalid pending pairing state.");
    }
  }
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
