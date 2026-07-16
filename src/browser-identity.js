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
  buildRevokeMailboxConsumerRequest,
  generateMailboxConsumerId,
  validateMailboxCursor,
  validateMailboxConsumerId,
  validateMailboxConsumerRegistration,
  validateProtocolCapabilityManifest
} from "./architecture-v2.js";

const encoder = new TextEncoder();

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
      throw new Error("The relay does not support installation-scoped mailbox v2 synchronization.");
    }
    return { endpoint: parsed, health, info };
  }

  async createAndRegister({ displayName, relay, authToken, fetch, WebSocket, timeoutMs } = {}) {
    const normalizedName = validateBrowserDisplayName(displayName);
    const verified = await this.verifyRelay(relay, { authToken, fetch, WebSocket, timeoutMs });
    const signing = this.pqc.generateSigningKeypair();
    const agreement = this.pqc.generateKemKeypair();
    const access = this.pqc.generateSigningKeypair();
    validateGeneratedKeypair(signing, "signing");
    validateGeneratedKeypair(agreement, "agreement");
    validateGeneratedKeypair(access, "inbox access");

    const accessDigest = await this.crypto.sha256(access.publicKey);
    const signingDigest = await this.crypto.sha256(signing.publicKey);
    const inboxId = await inboxIdForAccessPublicKey({ crypto: this.crypto, publicKey: access.publicKey });
    const identity = {
      displayName: normalizedName,
      signing: serializeKeypair(signing),
      agreement: serializeKeypair(agreement),
      access: serializeKeypair(access),
      inboxId,
      accessFingerprint: base64(accessDigest),
      signingFingerprint: base64(signingDigest)
    };
    const prepared = await this.prepareArchitectureV2Identity(identity, {
      relay: verified.endpoint
    });
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
      identity: prepared.identity,
      relayEndpoint: relayEndpointForContactOffer(verified.endpoint)
    });
    const boundIdentity = await this.bindMailboxConsumer({
      identity: prepared.identity,
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

  async prepareArchitectureV2Identity(identityValue, { relay } = {}) {
    validateLegacyIdentityShape(identityValue);
    const identity = cloneIdentity(identityValue);
    let changed = false;
    if (identity.architectureVersion == null) {
      identity.architectureVersion = 2;
      changed = true;
    } else if (identity.architectureVersion !== 2) {
      throw new Error("The browser identity uses an unsupported architecture version.");
    }
    if (identity.identityGenerationId == null) {
      identity.identityGenerationId = swiftUUID();
      changed = true;
    } else {
      identity.identityGenerationId = normalizedUUID(identity.identityGenerationId, "identity generation ID");
    }
    if (identity.localInstallation == null) {
      const signing = this.pqc.generateSigningKeypair();
      const agreement = this.pqc.generateKemKeypair();
      validateGeneratedKeypair(signing, "installation signing");
      validateGeneratedKeypair(agreement, "installation agreement");
      const signingDigest = await this.crypto.sha256(signing.publicKey);
      identity.localInstallation = {
        id: swiftUUID(),
        identityGenerationId: identity.identityGenerationId,
        signing: serializeKeypair(signing),
        agreement: serializeKeypair(agreement),
        signingFingerprint: base64(signingDigest),
        mailboxConsumerIdsByRoute: {},
        mailboxRoutes: {},
        cursorsByStream: {},
        pendingMailboxCommitsByStream: {},
        createdAt: swiftISODate()
      };
      changed = true;
    } else {
      validateLocalInstallation(identity.localInstallation, identity.identityGenerationId, identity);
    }
    if (relay != null) {
      const routeKey = browserMailboxRouteKey(relay, identity.inboxId);
      const local = identity.localInstallation;
      let consumerId = local.mailboxConsumerIdsByRoute[routeKey];
      if (consumerId == null) {
        consumerId = await generateMailboxConsumerId({ crypto: this.crypto });
        local.mailboxConsumerIdsByRoute[routeKey] = consumerId;
        changed = true;
      } else {
        consumerId = validateMailboxConsumerId(consumerId);
        local.mailboxConsumerIdsByRoute[routeKey] = consumerId;
      }
      if (local.mailboxRoutes[routeKey] == null) {
        const routeSigning = this.pqc.generateSigningKeypair();
        validateGeneratedKeypair(routeSigning, "mailbox route signing");
        const routeSigningFingerprint = base64(
          await this.crypto.sha256(routeSigning.publicKey)
        );
        local.mailboxRoutes[routeKey] = {
          mode: "pending-v2-registration",
          consumerId,
          signing: serializeKeypair(routeSigning),
          signingFingerprint: routeSigningFingerprint,
          cursor: null,
          committedSequence: 0,
          pendingCommit: null
        };
        changed = true;
      } else {
        if (local.mailboxRoutes[routeKey].committedSequence == null) {
          local.mailboxRoutes[routeKey].committedSequence =
            local.mailboxRoutes[routeKey].registration?.committedSequence ?? 0;
          changed = true;
        }
        const existingRoute = local.mailboxRoutes[routeKey];
        if (existingRoute.signing == null) {
          const routeSigning = this.pqc.generateSigningKeypair();
          validateGeneratedKeypair(routeSigning, "mailbox route signing");
          const replacementConsumerId = await generateMailboxConsumerId({ crypto: this.crypto });
          local.mailboxRoutes[routeKey] = {
            mode: "pending-v2-registration",
            consumerId: replacementConsumerId,
            signing: serializeKeypair(routeSigning),
            signingFingerprint: base64(await this.crypto.sha256(routeSigning.publicKey)),
            legacySponsorConsumerId: consumerId,
            cursor: null,
            committedSequence: existingRoute.committedSequence,
            pendingCommit: null
          };
          local.mailboxConsumerIdsByRoute[routeKey] = replacementConsumerId;
          changed = true;
        } else {
          validateLocalMailboxRoute(existingRoute, consumerId);
        }
      }
    }
    const hadDirectV4 = identity.certifiedInstallationEndpoint != null;
    await prepareNativeDirectV4Identity({ crypto: this.crypto, pqc: this.pqc, identity });
    changed = changed || !hadDirectV4;
    return { identity, changed };
  }

  async bindMailboxConsumer({
    identity: identityValue,
    relay,
    endpoint,
    authToken,
    fetch,
    WebSocket,
    timeoutMs,
    sponsorConsumerId,
    sponsorSigningKey,
    sponsorFingerprint
  }) {
    const normalizedEndpoint = endpoint ?? parseBrowserRelayEndpoint(relay);
    const prepared = await this.prepareArchitectureV2Identity(identityValue, {
      relay: normalizedEndpoint
    });
    const identity = prepared.identity;
    const routeKey = browserMailboxRouteKey(normalizedEndpoint, identity.inboxId);
    const route = identity.localInstallation.mailboxRoutes[routeKey];
    if (route.mode === "v2" && route.registration?.state === "active") {
      return identity;
    }
    const internalLegacySponsorId = route.legacySponsorConsumerId ?? null;
    const effectiveSponsorId = internalLegacySponsorId ?? sponsorConsumerId;
    const effectiveSponsorKey = internalLegacySponsorId == null
      ? sponsorSigningKey
      : identity.localInstallation.signing;
    const effectiveSponsorFingerprint = internalLegacySponsorId == null
      ? sponsorFingerprint
      : identity.localInstallation.signingFingerprint;
    const makeCurrentRequest = () => buildRegisterMailboxConsumerRequest({
      inboxId: identity.inboxId,
      consumerId: route.consumerId,
      consumerSigningKey: route.signing,
      authoritySigningKey: identity.access,
      authorityFingerprint: identity.accessFingerprint,
      consumerFingerprint: route.signingFingerprint,
      sponsorConsumerId: effectiveSponsorId,
      sponsorSigningKey: effectiveSponsorKey,
      sponsorFingerprint: effectiveSponsorFingerprint,
      startingSequence: route.committedSequence,
      pqc: this.pqc,
      crypto: this.crypto
    });
    let request = await makeCurrentRequest();
    const client = this.relayClientFactory(relay, {
      authToken: normalizedOptionalSecret(authToken),
      fetch,
      WebSocket,
      timeoutMs
    });
    let response = await client.send(relayRequests.registerMailboxConsumer(request));
    if ((response?.type !== "mailboxConsumer" || response.mailboxConsumer == null) &&
        internalLegacySponsorId != null) {
      const legacyRequest = await buildRegisterMailboxConsumerRequest({
        inboxId: identity.inboxId,
        consumerId: internalLegacySponsorId,
        consumerSigningKey: identity.localInstallation.signing,
        authoritySigningKey: identity.access,
        authorityFingerprint: identity.accessFingerprint,
        consumerFingerprint: identity.localInstallation.signingFingerprint,
        startingSequence: route.committedSequence,
        pqc: this.pqc,
        crypto: this.crypto
      });
      const legacyResponse = await client.send(
        relayRequests.registerMailboxConsumer(legacyRequest)
      );
      if (legacyResponse?.type !== "mailboxConsumer" ||
          legacyResponse.mailboxConsumer?.consumerId !== internalLegacySponsorId ||
          legacyResponse.mailboxConsumer?.state !== "active") {
        throw new Error("The relay rejected legacy mailbox consumer migration.");
      }
      request = await makeCurrentRequest();
      response = await client.send(relayRequests.registerMailboxConsumer(request));
    }
    if (response?.type !== "mailboxConsumer" || response.mailboxConsumer == null) {
      if (response?.type === "error" &&
          /fresh identity generation|no active (mailbox consumer|route credential) remains|new inbox generation/i.test(String(response.error))) {
        throw new Error("The old inbox is closed: create a fresh identity generation and inbox.");
      }
      throw new Error("The relay rejected mailbox consumer registration.");
    }
    const registration = validateMailboxConsumerRegistration(response.mailboxConsumer);
    if (registration.consumerId !== route.consumerId ||
        registration.consumerSigningPublicKey !== route.signing.publicKey ||
        registration.state !== "active") {
      throw new Error("The relay returned a mismatched mailbox consumer registration.");
    }
    if (internalLegacySponsorId != null) {
      const revokeRequest = await buildRevokeMailboxConsumerRequest({
        inboxId: identity.inboxId,
        consumerId: internalLegacySponsorId,
        authoritySigningKey: identity.access,
        authorityFingerprint: identity.accessFingerprint,
        pqc: this.pqc,
        crypto: this.crypto
      });
      const revokeResponse = await client.send(
        relayRequests.revokeMailboxConsumer(revokeRequest)
      );
      if (revokeResponse?.type !== "mailboxConsumer" ||
          revokeResponse.mailboxConsumer?.consumerId !== internalLegacySponsorId ||
          revokeResponse.mailboxConsumer?.state !== "revoked") {
        throw new Error("The relay rejected legacy mailbox consumer revocation.");
      }
    }
    identity.localInstallation.mailboxRoutes[routeKey] = {
      mode: "v2",
      consumerId: route.consumerId,
      signing: route.signing,
      signingFingerprint: route.signingFingerprint,
      registration,
      cursor: internalLegacySponsorId == null ? (route.cursor ?? null) : null,
      committedSequence: registration.committedSequence,
      pendingCommit: route.pendingCommit ?? null
    };
    return identity;
  }

  async migrateAndRegisterIdentity({ identity, relay, persist, ...options }) {
    if (typeof persist !== "function") {
      throw new TypeError("Identity migration requires a durable persist callback.");
    }
    const endpoint = options.endpoint ?? parseBrowserRelayEndpoint(relay);
    const prepared = await this.prepareArchitectureV2Identity(identity, { relay: endpoint });
    if (prepared.changed) {
      await persist(prepared.identity);
    }
    const routeKey = browserMailboxRouteKey(endpoint, prepared.identity.inboxId);
    const route = prepared.identity.localInstallation.mailboxRoutes[routeKey];
    if (route.mode === "v2" && route.registration?.state === "active") {
      return prepared.identity;
    }
    const bound = await this.bindMailboxConsumer({
      identity: prepared.identity,
      relay,
      endpoint,
      ...options
    });
    await persist(bound);
    return bound;
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

function validateLegacyIdentityShape(identity) {
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
    throw new Error("The browser identity is malformed.");
  }
  validateBrowserDisplayName(identity.displayName);
  validateSerializedKeypair(identity.signing, "identity signing key", 1_952, 4_032);
  validateSerializedKeypair(identity.agreement, "identity agreement key", 1_184, 2_400);
  validateSerializedKeypair(identity.access, "inbox access key", 1_952, 4_032);
  if (typeof identity.inboxId !== "string" || !identity.inboxId.startsWith("noctweave1") ||
      typeof identity.accessFingerprint !== "string" || typeof identity.signingFingerprint !== "string") {
    throw new Error("The browser identity is malformed.");
  }
}

function validateLocalInstallation(local, identityGenerationId, identity) {
  if (!local || typeof local !== "object" || Array.isArray(local) ||
      normalizedUUID(local.id, "installation ID") !== local.id.toUpperCase() ||
      normalizedUUID(local.identityGenerationId, "installation identity generation ID") !== identityGenerationId) {
    throw new Error("The browser installation state is malformed.");
  }
  validateSerializedKeypair(local.signing, "installation signing key", 1_952, 4_032);
  validateSerializedKeypair(local.agreement, "installation agreement key", 1_184, 2_400);
  if (local.signing.publicKey === identity.signing.publicKey ||
      local.agreement.publicKey === identity.agreement.publicKey) {
    throw new Error("An installation must not reuse the identity's live cryptographic keys.");
  }
  if (!local.mailboxConsumerIdsByRoute || typeof local.mailboxConsumerIdsByRoute !== "object" ||
      Array.isArray(local.mailboxConsumerIdsByRoute) ||
      !local.mailboxRoutes || typeof local.mailboxRoutes !== "object" || Array.isArray(local.mailboxRoutes) ||
      Object.keys(local.mailboxConsumerIdsByRoute).length > 8 || Object.keys(local.mailboxRoutes).length > 8) {
    throw new Error("The browser installation mailbox state is malformed.");
  }
  normalizedUUID(local.id, "installation ID");
  if (!Number.isFinite(new Date(local.createdAt).getTime())) {
    throw new Error("The browser installation creation date is malformed.");
  }
}

function validateLocalMailboxRoute(route, consumerId) {
  if (!route || typeof route !== "object" || Array.isArray(route) ||
      !["pending-v2-registration", "v2"].includes(route.mode) ||
      validateMailboxConsumerId(route.consumerId) !== consumerId ||
      !Number.isSafeInteger(route.committedSequence) || route.committedSequence < 0) {
    throw new Error("The browser installation mailbox route is malformed.");
  }
  validateSerializedKeypair(route.signing, "mailbox route signing key", 1_952, 4_032);
  if (typeof route.signingFingerprint !== "string" || route.signingFingerprint.length === 0) {
    throw new Error("The browser installation mailbox route fingerprint is malformed.");
  }
  if (route.legacySponsorConsumerId != null) {
    validateMailboxConsumerId(route.legacySponsorConsumerId);
    if (route.legacySponsorConsumerId === consumerId || route.mode !== "pending-v2-registration") {
      throw new Error("The browser installation mailbox migration state is malformed.");
    }
  }
  if (route.cursor != null) validateMailboxCursor(route.cursor);
  if (route.mode === "v2") {
    const registration = validateMailboxConsumerRegistration(route.registration);
    if (registration.state !== "active" || registration.consumerId !== consumerId ||
        registration.consumerSigningPublicKey !== route.signing.publicKey ||
        registration.committedSequence !== route.committedSequence) {
      throw new Error("The browser installation mailbox registration is not active.");
    }
  }
  if (route.pendingCommit != null) {
    const pending = route.pendingCommit;
    if (!pending || typeof pending !== "object" || Array.isArray(pending) ||
        validateMailboxCursor(pending.cursor).length === 0 ||
        !Number.isSafeInteger(pending.sequence) || pending.sequence < route.committedSequence ||
        !Number.isFinite(Date.parse(pending.preparedAt))) {
      throw new Error("The browser installation mailbox pending commit is malformed.");
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

function decodeBase64(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`The ${label} is malformed.`);
  }
  try {
    const binary = atob(value);
    if (btoa(binary) !== value) throw new Error();
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error(`The ${label} is malformed.`);
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
