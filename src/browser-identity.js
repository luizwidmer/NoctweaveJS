import { parseRelayEndpoint } from "./endpoint.js";
import { NoctweaveRelayClient } from "./relay-client.js";
import { relayRequests } from "./requests.js";
import { makeNativeContactOffer } from "./crypto/noctweave-native-message.js";
import {
  inboxIdForAccessPublicKey,
  prepareNativeDirectV4Identity
} from "./crypto/direct-v4.js";
import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./crypto/swift-canonical.js";
import {
  buildRegisterMailboxConsumerRequest,
  generateMailboxConsumerId,
  validateMailboxCursor,
  validateMailboxConsumerId,
  validateMailboxConsumerRegistration,
  validateProtocolCapabilityManifest
} from "./architecture-v2.js";

const encoder = new TextEncoder();
export const browserIdentityStateSchema = "nw.browser-identity.v1";

export class NoctweaveBrowserIdentityService {
  constructor({ pqc, crypto, relayClientFactory } = {}) {
    if (!pqc?.generateSigningKeypair || !pqc?.generateKemKeypair || !pqc?.sign || !pqc?.verify) {
      throw new TypeError("A compatible Noctweave post-quantum adapter is required.");
    }
    if (!crypto?.sha256) {
      throw new TypeError("Compatible Noctweave WebCrypto primitives are required.");
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
      timeoutMs: options.timeoutMs
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
      module.module === "nw.mailbox" && module.versions.includes(2))) {
      throw new Error("The relay does not support endpoint-scoped mailbox v2 synchronization.");
    }
    return { endpoint: parsed, health, info };
  }

  async createAndRegister({ displayName, relay, authToken, fetch, WebSocket, timeoutMs } = {}) {
    const normalizedName = validateBrowserDisplayName(displayName);
    const verified = await this.verifyRelay(relay, { authToken, fetch, WebSocket, timeoutMs });
    const identity = await this.createFreshIdentityState({
      displayName: normalizedName,
      relay: verified.endpoint
    });
    const access = deserializeKeypair(identity.access, "inbox access", 1_952, 4_032);
    const inboxId = identity.inboxId;
    const signedAt = swiftISODate();
    const nonce = swiftUUID();
    const payload = {
      accessPublicKey: base64(access.publicKey),
      inboxId,
      nonce,
      registrationVersion: 2,
      signedAt
    };
    const request = relayRequests.registerInbox({
      inboxId,
      accessPublicKey: base64(access.publicKey),
      registrationVersion: 2,
      accessProof: {
        fingerprint: identity.accessFingerprint,
        publicSigningKey: base64(access.publicKey),
        signedAt,
        nonce,
        signature: base64(this.pqc.sign(canonicalJsonBytes(payload), access.secretKey))
      }
    });
    const client = this.relayClientFactory(relay, {
      authToken: normalizedOptionalSecret(authToken),
      fetch,
      WebSocket,
      timeoutMs
    });
    const response = await client.send(request);
    if (response?.type !== "ok") {
      throw new Error("The relay rejected inbox registration.");
    }
    const contactOffer = makeNativeContactOffer({
      pqc: this.pqc,
      identity,
      relayEndpoint: relayEndpointForContactOffer(verified.endpoint)
    });
    const boundIdentity = await this.bindMailboxConsumer({
      identity,
      relay,
      endpoint: verified.endpoint,
      authToken,
      fetch,
      WebSocket,
      timeoutMs
    });
    return {
      identity: { ...boundIdentity, contactOffer },
      relay: {
        address: String(relay).trim(),
        endpoint: verified.endpoint,
        relayInfo: verified.info.relayInfo,
        verifiedAt: new Date().toISOString()
      }
    };
  }

  async createFreshIdentityState({ displayName, relay }) {
    const normalizedName = validateBrowserDisplayName(displayName);
    const signing = this.pqc.generateSigningKeypair();
    const agreement = this.pqc.generateKemKeypair();
    const access = this.pqc.generateSigningKeypair();
    const endpointSigning = this.pqc.generateSigningKeypair();
    const endpointAgreement = this.pqc.generateKemKeypair();
    const routeSigning = this.pqc.generateSigningKeypair();
    for (const [pair, label] of [
      [signing, "signing"],
      [agreement, "agreement"],
      [access, "inbox access"],
      [endpointSigning, "endpoint signing"],
      [endpointAgreement, "endpoint agreement"],
      [routeSigning, "mailbox route signing"]
    ]) validateGeneratedKeypair(pair, label);

    const identityGenerationId = swiftUUID();
    const inboxId = await inboxIdForAccessPublicKey({ crypto: this.crypto, publicKey: access.publicKey });
    const routeKey = browserMailboxRouteKey(relay, inboxId);
    const consumerId = await generateMailboxConsumerId({ crypto: this.crypto });
    const issuedAt = swiftISODate();
    const identity = {
      stateSchema: browserIdentityStateSchema,
      architectureVersion: 2,
      identityGenerationId,
      displayName: normalizedName,
      signing: serializeKeypair(signing),
      agreement: serializeKeypair(agreement),
      access: serializeKeypair(access),
      inboxId,
      accessFingerprint: base64(await this.crypto.sha256(access.publicKey)),
      signingFingerprint: base64(await this.crypto.sha256(signing.publicKey)),
      localEndpoint: {
        id: swiftUUID(),
        identityGenerationId,
        signing: serializeKeypair(endpointSigning),
        agreement: serializeKeypair(endpointAgreement),
        signingFingerprint: base64(await this.crypto.sha256(endpointSigning.publicKey)),
        mailboxRoutes: {
          [routeKey]: {
            mode: "pending-v2-registration",
            consumerId,
            signing: serializeKeypair(routeSigning),
            signingFingerprint: base64(await this.crypto.sha256(routeSigning.publicKey)),
            cursor: null,
            committedSequence: 0,
            pendingCommit: null
          }
        },
        createdAt: issuedAt
      }
    };
    await prepareNativeDirectV4Identity({ crypto: this.crypto, pqc: this.pqc, identity, issuedAt });
    validateBrowserIdentityState(identity);
    return identity;
  }

  async bindMailboxConsumer({
    identity: identityValue,
    relay,
    endpoint,
    authToken,
    fetch,
    WebSocket,
    timeoutMs
  }) {
    const normalizedEndpoint = endpoint ?? parseBrowserRelayEndpoint(relay);
    validateBrowserIdentityState(identityValue);
    const identity = cloneIdentity(identityValue);
    const routeKey = browserMailboxRouteKey(normalizedEndpoint, identity.inboxId);
    const route = identity.localEndpoint.mailboxRoutes[routeKey];
    if (!route) {
      throw new Error("The browser identity has no route for this relay.");
    }
    if (route.mode === "v2" && route.registration?.state === "active") {
      return identity;
    }
    if (route.mode !== "pending-v2-registration" || route.registration != null) {
      throw new Error("The browser identity mailbox route is not registerable.");
    }
    const request = await buildRegisterMailboxConsumerRequest({
      inboxId: identity.inboxId,
      consumerId: route.consumerId,
      consumerSigningKey: route.signing,
      authoritySigningKey: identity.access,
      authorityFingerprint: identity.accessFingerprint,
      consumerFingerprint: route.signingFingerprint,
      startingSequence: route.committedSequence,
      pqc: this.pqc,
      crypto: this.crypto
    });
    const client = this.relayClientFactory(relay, {
      authToken: normalizedOptionalSecret(authToken),
      fetch,
      WebSocket,
      timeoutMs
    });
    const response = await client.send(relayRequests.registerMailboxConsumer(request));
    if (response?.type !== "mailboxConsumer" || response.mailboxConsumer == null) {
      throw new Error("The relay rejected mailbox consumer registration.");
    }
    const registration = validateMailboxConsumerRegistration(response.mailboxConsumer);
    if (registration.consumerId !== route.consumerId ||
        registration.consumerSigningPublicKey !== route.signing.publicKey ||
        registration.state !== "active") {
      throw new Error("The relay returned a mismatched mailbox consumer registration.");
    }
    identity.localEndpoint.mailboxRoutes[routeKey] = {
      mode: "v2",
      consumerId: route.consumerId,
      signing: route.signing,
      signingFingerprint: route.signingFingerprint,
      registration,
      cursor: route.cursor,
      committedSequence: registration.committedSequence,
      pendingCommit: route.pendingCommit
    };
    validateBrowserIdentityState(identity);
    return identity;
  }
}

export function browserMailboxRouteKey(relay, inboxId) {
  const endpoint = typeof relay === "string" ? parseBrowserRelayEndpoint(relay) : relay;
  if (!endpoint || typeof endpoint !== "object") {
    throw new TypeError("A relay endpoint is required for a mailbox route.");
  }
  const transport = String(endpoint.transport);
  const tls = endpoint.useTLS ? 1 : 0;
  const host = String(endpoint.host).toLowerCase();
  const port = Number(endpoint.port);
  if (!['http', 'websocket'].includes(transport) || !host ||
      !Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new TypeError("Mailbox route endpoint is invalid.");
  }
  if (typeof inboxId !== "string" || inboxId.length === 0) {
    throw new TypeError("Mailbox route inbox ID is invalid.");
  }
  return `${transport}:${tls}:${host}:${port}:${inboxId.toLowerCase()}`;
}

export function validateBrowserDisplayName(value) {
  if (typeof value !== "string") {
    throw new TypeError("Display name is required.");
  }
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
  if (value == null || value === "") {
    return null;
  }
  if (typeof value !== "string" || encoder.encode(value).byteLength > 4096) {
    throw new TypeError("Relay access password must not exceed 4096 UTF-8 bytes.");
  }
  return value;
}

function validateGeneratedKeypair(value, label) {
  if (!(value?.publicKey instanceof Uint8Array) || !(value?.secretKey instanceof Uint8Array) ||
      value.publicKey.byteLength === 0 || value.secretKey.byteLength === 0) {
    throw new Error(`Post-quantum ${label} key generation failed.`);
  }
}

function serializeKeypair(keypair) {
  return {
    publicKey: base64(keypair.publicKey),
    secretKey: base64(keypair.secretKey)
  };
}

export function validateBrowserIdentityState(identity) {
  if (!identity || typeof identity !== "object" || Array.isArray(identity) ||
      identity.stateSchema !== browserIdentityStateSchema || identity.architectureVersion !== 2) {
    throw new Error("The browser identity uses an unsupported state schema.");
  }
  assertKnownKeys(identity, new Set([
    "stateSchema", "architectureVersion", "identityGenerationId", "displayName", "signing",
    "agreement", "access", "inboxId", "accessFingerprint", "signingFingerprint",
    "localEndpoint", "endpointSetManifest", "endpointSetCheckpoint",
    "certifiedGenerationEndpoint", "contactOffer"
  ]), "browser identity");
  validateBrowserDisplayName(identity.displayName);
  validateSerializedKeypair(identity.signing, "identity signing key", 1_952, 4_032);
  validateSerializedKeypair(identity.agreement, "identity agreement key", 1_184, 2_400);
  validateSerializedKeypair(identity.access, "inbox access key", 1_952, 4_032);
  if (typeof identity.inboxId !== "string" || !identity.inboxId.startsWith("noctweave1") ||
      typeof identity.accessFingerprint !== "string" || typeof identity.signingFingerprint !== "string" ||
      normalizedUUID(identity.identityGenerationId, "identity generation ID") !== identity.identityGenerationId) {
    throw new Error("The browser identity is malformed.");
  }
  decodeBase64(identity.accessFingerprint, "inbox access fingerprint", 32);
  decodeBase64(identity.signingFingerprint, "identity signing fingerprint", 32);
  validateLocalEndpoint(identity.localEndpoint, identity.identityGenerationId, identity);
  for (const required of [
    "endpointSetManifest",
    "endpointSetCheckpoint",
    "certifiedGenerationEndpoint"
  ]) {
    if (!identity[required] || typeof identity[required] !== "object" || Array.isArray(identity[required])) {
      throw new Error("The browser identity direct-v4 state is incomplete.");
    }
  }
  return identity;
}

function validateLocalEndpoint(local, identityGenerationId, identity) {
  if (!local || typeof local !== "object" || Array.isArray(local) ||
      normalizedUUID(local.id, "endpoint ID") !== local.id.toUpperCase() ||
      normalizedUUID(local.identityGenerationId, "endpoint identity generation ID") !== identityGenerationId) {
    throw new Error("The browser endpoint state is malformed.");
  }
  assertKnownKeys(local, new Set([
    "id", "identityGenerationId", "signing", "agreement", "signingFingerprint",
    "mailboxRoutes", "createdAt", "prekeys"
  ]), "browser endpoint state");
  validateSerializedKeypair(local.signing, "endpoint signing key", 1_952, 4_032);
  validateSerializedKeypair(local.agreement, "endpoint agreement key", 1_184, 2_400);
  decodeBase64(local.signingFingerprint, "endpoint signing fingerprint", 32);
  if (!local.prekeys || typeof local.prekeys !== "object" || Array.isArray(local.prekeys)) {
    throw new Error("The browser endpoint prekey state is incomplete.");
  }
  if (local.signing.publicKey === identity.signing.publicKey ||
      local.agreement.publicKey === identity.agreement.publicKey) {
    throw new Error("An endpoint must not reuse the identity's live cryptographic keys.");
  }
  if (!local.mailboxRoutes || typeof local.mailboxRoutes !== "object" ||
      Array.isArray(local.mailboxRoutes) || Object.keys(local.mailboxRoutes).length < 1 ||
      Object.keys(local.mailboxRoutes).length > 8) {
    throw new Error("The browser endpoint mailbox state is malformed.");
  }
  for (const route of Object.values(local.mailboxRoutes)) {
    validateLocalMailboxRoute(route);
  }
  normalizedUUID(local.id, "endpoint ID");
  if (!Number.isFinite(new Date(local.createdAt).getTime())) {
    throw new Error("The browser endpoint creation date is malformed.");
  }
}

function validateLocalMailboxRoute(route) {
  const consumerId = validateMailboxConsumerId(route?.consumerId);
  if (!route || typeof route !== "object" || Array.isArray(route) ||
      !["pending-v2-registration", "v2"].includes(route.mode) ||
      !Number.isSafeInteger(route.committedSequence) || route.committedSequence < 0 ||
      !Object.hasOwn(route, "cursor") || !Object.hasOwn(route, "pendingCommit")) {
    throw new Error("The browser endpoint mailbox route is malformed.");
  }
  assertKnownKeys(route, new Set([
    "mode", "consumerId", "signing", "signingFingerprint", "registration", "cursor",
    "committedSequence", "pendingCommit"
  ]), "browser mailbox route");
  validateSerializedKeypair(route.signing, "mailbox route signing key", 1_952, 4_032);
  if (typeof route.signingFingerprint !== "string" || route.signingFingerprint.length === 0) {
    throw new Error("The browser endpoint mailbox route fingerprint is malformed.");
  }
  if (route.cursor != null) validateMailboxCursor(route.cursor);
  if (route.mode === "v2") {
    const registration = validateMailboxConsumerRegistration(route.registration);
    if (registration.state !== "active" || registration.consumerId !== consumerId ||
        registration.consumerSigningPublicKey !== route.signing.publicKey ||
        registration.committedSequence !== route.committedSequence) {
      throw new Error("The browser endpoint mailbox registration is not active.");
    }
  } else if (route.registration != null || route.committedSequence !== 0 ||
      route.cursor !== null || route.pendingCommit !== null) {
    throw new Error("The browser endpoint pending mailbox route is malformed.");
  }
  if (route.pendingCommit != null) {
    const pending = route.pendingCommit;
    if (!pending || typeof pending !== "object" || Array.isArray(pending) ||
        validateMailboxCursor(pending.cursor).length === 0 ||
        !Number.isSafeInteger(pending.sequence) || pending.sequence < route.committedSequence ||
        !Number.isFinite(Date.parse(pending.preparedAt))) {
      throw new Error("The browser endpoint mailbox pending commit is malformed.");
    }
  }
}

function validateSerializedKeypair(value, label, publicLength, secretLength) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`The ${label} is malformed.`);
  }
  if (typeof value.publicKey !== "string" ||
      value.publicKey.length !== Math.ceil(publicLength / 3) * 4 ||
      typeof value.secretKey !== "string" ||
      value.secretKey.length !== Math.ceil(secretLength / 3) * 4) {
    throw new Error(`The ${label} is malformed.`);
  }
  if (decodeBase64(value.publicKey, `${label} public key`).byteLength !== publicLength ||
      decodeBase64(value.secretKey, `${label} secret key`).byteLength !== secretLength) {
    throw new Error(`The ${label} is malformed.`);
  }
}

function decodeBase64(value, label, expectedLength) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`The ${label} is malformed.`);
  }
  try {
    const binary = atob(value);
    if (btoa(binary) !== value) throw new Error();
    const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (expectedLength != null && decoded.byteLength !== expectedLength) throw new Error();
    return decoded;
  } catch {
    throw new Error(`The ${label} is malformed.`);
  }
}

function deserializeKeypair(value, label, publicLength, secretLength) {
  validateSerializedKeypair(value, label, publicLength, secretLength);
  return {
    publicKey: decodeBase64(value.publicKey, `${label} public key`, publicLength),
    secretKey: decodeBase64(value.secretKey, `${label} secret key`, secretLength)
  };
}

function assertKnownKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`The ${label} contains unsupported state.`);
    }
  }
}

function cloneIdentity(identity) {
  return typeof structuredClone === "function"
    ? structuredClone(identity)
    : JSON.parse(JSON.stringify(identity));
}

function normalizedUUID(value, label) {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error(`The ${label} is malformed.`);
  }
  return value.toUpperCase();
}

function relayEndpointForContactOffer(endpoint) {
  return {
    host: endpoint.host,
    port: endpoint.port,
    useTLS: Boolean(endpoint.useTLS),
    transport: endpoint.transport
  };
}
