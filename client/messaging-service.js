import {
  DurablePairwiseMessagingRuntimeV2,
  DurablePairwiseMessagingV2Error,
  EncryptedNoctweaveStore,
  MemoryNoctweaveStore,
  NoctweaveStateRepository,
  NoctweaveWebClient,
  addTestingPairwiseRouteV2,
  base64,
  canonicalJsonBytes,
  createLocalOpaqueReceiveRouteV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePayloadKeyV2,
  createOpaqueRouteProofNonceV2,
  createOpaqueSendRouteV2,
  makeOpaqueRouteCreateRequestV2,
  makeOpaqueRouteTeardownRequestV2,
  promoteProbedPairwiseRouteV2,
  relationshipAcceptsInboundEventsV2,
  relationshipAllowsUserSendingV2,
  relationshipIsMutedV2,
  renewPairwiseDirectV4PrekeyIfNeeded,
  revokeDrainedPairwiseRouteV2,
  swiftISODate,
  swiftUUID,
  usablePairwiseRoutesV2,
  validateLocalOpaqueReceiveRouteV2,
  validateOpaqueReceiveRouteV2,
  validateOpaqueRouteClientCapabilityMaterialV2,
  validateOpaqueRouteCreateRequestV2,
  validateOpaqueRoutePayloadKeyV2,
  validateOpaqueRouteTeardownRequestV2,
  validateOpaqueSendRouteV2
} from "../src/index.js";

const encoder = new TextEncoder();
const unsafeDisplayControls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;
const maximumTextBytes = 16 * 1024;
const routeMaintenanceWindowMilliseconds = 30 * 60 * 1_000;
const routeReplacementLeaseMilliseconds = 6 * 60 * 60 * 1_000;
const routeOverlapMilliseconds = 10 * 60 * 1_000;
const maximumTeardownRelationships = 128;
const maximumTeardownRoutes = 8;
const maximumMaintenanceRelationships = 1;
const APPLICATION_VAULT_SLOT_SCOPE = "4E574156-4556-4002-8000-000000000001";
const APPLICATION_VAULT_SLOT_ANCHOR_KEY = "browser-application-vault-slot-anchor-v2";
const APPLICATION_VAULT_SLOT_STATE_KEY = "browser-application-vault-slot-state-v2";
const APPLICATION_VAULT_SCHEMA = "org.noctweave.browser-application-vault-slot.v2";

export const browserMessagingAttachmentBlocker =
  "Encrypted attachment upload is not yet exposed by the durable browser runtime.";
export const browserRollbackAnchorRequirement =
  "Durable messaging requires an embedding host that provides an authenticated, atomic relationship-local monotonic anchor. Ordinary browser storage does not provide hardware rollback resistance.";

/**
 * Fixed host application-state slot for the encrypted local UI aggregate.
 * The UUID exists only because the host CAS API uses UUID-shaped scopes. It is
 * never serialized into a persona, relationship, contact, or wire object and
 * is not a protocol identity. A fresh random vault scope may be installed only
 * by CAS from this authenticated slot's absent or burned generation.
 */
export const browserApplicationVaultSlotV2 = Object.freeze({
  scope: APPLICATION_VAULT_SLOT_SCOPE,
  schema: APPLICATION_VAULT_SCHEMA
});

export class HostAnchoredBrowserApplicationVaultV2 {
  constructor({
    crypto,
    storageCrypto = globalThis.crypto,
    stateAnchorStoreFactory
  }) {
    if (typeof crypto?.sha256 !== "function" || !storageCrypto?.subtle ||
        typeof storageCrypto?.getRandomValues !== "function") {
      throw new TypeError("The application vault requires protocol and storage cryptography.");
    }
    if (typeof stateAnchorStoreFactory !== "function") {
      throw new BrowserMessagingAvailabilityError(
        "rollbackAnchorUnavailable",
        browserRollbackAnchorRequirement
      );
    }
    this.crypto = crypto;
    this.storageCrypto = storageCrypto;
    this.stateAnchorStoreFactory = stateAnchorStoreFactory;
    this.anchorStorePromise = null;
    this.currentAnchor = null;
    this.currentRecord = null;
    this.innerBackend = null;
    this.innerStore = null;
    this.innerRepository = null;
    this.innerVaultScopeID = null;
    this.queue = Promise.resolve();
  }

  async inspect() {
    return this.serialized(async () => {
      const record = await this.loadSlot();
      return Object.freeze({
        status: record?.status ?? "empty",
        vaultScopeID: record?.vaultScopeID ?? null
      });
    });
  }

  async initialize({ passphrase, persona }) {
    return this.serialized(async () => {
      const current = await this.loadSlot();
      if (current !== null && current.status !== "burned") {
        throw new BrowserMessagingAvailabilityError(
          current.status === "burning" ? "vaultBurnInProgress" : "vaultAlreadyActive",
          current.status === "burning"
            ? "The fixed application vault must finish its authenticated burn before reinitialization."
            : "The fixed application vault slot already contains an active encrypted persona."
        );
      }
      const vaultScopeID = swiftUUID();
      const saltBytes = new Uint8Array(16);
      this.storageCrypto.getRandomValues(saltBytes);
      try {
        const session = this.createInnerSession({
          passphrase,
          salt: saltBytes,
          vaultScopeID,
          encryptedRecord: null
        });
        await session.repository.save(persona);
        const encryptedRecord = await session.backend.get(session.stateKey);
        if (encryptedRecord === null) throw new Error("Encrypted persona state was not created.");
        const now = swiftISODate();
        const next = validateApplicationVaultSlotRecord({
          stateSchema: APPLICATION_VAULT_SCHEMA,
          version: 2,
          status: "active",
          vaultScopeID,
          salt: base64(saltBytes),
          encryptedRecord,
          createdAt: now,
          updatedAt: now
        });
        await this.commitSlot(next);
        this.adoptInnerSession(session);
        return Object.freeze({ persona: structuredClone(persona), encryptedStore: session.store });
      } finally {
        saltBytes.fill(0);
      }
    });
  }

  async unlock({ passphrase }) {
    return this.serialized(async () => {
      const current = await this.loadSlot();
      if (current?.status !== "active") {
        throw new BrowserMessagingAvailabilityError(
          "vaultUnavailable",
          "The fixed application vault slot has no active encrypted persona."
        );
      }
      const saltBytes = decodeBase64(current.salt);
      try {
        if (saltBytes.byteLength !== 16) throw new TypeError("Application vault salt is invalid.");
        const session = this.createInnerSession({
          passphrase,
          salt: saltBytes,
          vaultScopeID: current.vaultScopeID,
          encryptedRecord: current.encryptedRecord
        });
        const persona = await session.repository.load();
        if (persona === null) throw new Error("Encrypted persona state is missing.");
        this.adoptInnerSession(session);
        return Object.freeze({ persona, encryptedStore: session.store });
      } finally {
        saltBytes.fill(0);
      }
    });
  }

  async save(persona) {
    return this.serialized(async () => {
      if (this.innerRepository === null || this.innerBackend === null || this.currentRecord === null) {
        throw new BrowserMessagingAvailabilityError(
          "vaultLocked",
          "Unlock the host-anchored application vault before saving."
        );
      }
      const current = await this.loadSlot();
      if (current?.status !== "active" ||
          current.vaultScopeID !== this.innerVaultScopeID) {
        throw new BrowserMessagingAvailabilityError(
          "vaultScopeRollback",
          "The authenticated application vault scope changed or was burned."
        );
      }
      await this.innerRepository.save(persona);
      const encryptedRecord = await this.innerBackend.get(
        applicationVaultPersonaStateKey(current.vaultScopeID)
      );
      if (encryptedRecord === null) throw new Error("Encrypted persona state was not staged.");
      const next = validateApplicationVaultSlotRecord({
        ...current,
        encryptedRecord,
        updatedAt: monotonicTimestamp(current.updatedAt)
      });
      await this.commitSlot(next);
      return structuredClone(persona);
    });
  }

  async beginBurn() {
    return this.serialized(async () => {
      const current = await this.loadSlot();
      if (current === null || current.status === "burned") {
        throw new BrowserMessagingAvailabilityError(
          "vaultUnavailable",
          "The application vault has no active authority to burn."
        );
      }
      if (current.status === "burning") {
        return Object.freeze({ burning: true, vaultScopeID: current.vaultScopeID });
      }
      const next = validateApplicationVaultSlotRecord({
        ...current,
        status: "burning",
        updatedAt: monotonicTimestamp(current.updatedAt)
      });
      await this.commitSlot(next);
      return Object.freeze({ burning: true, vaultScopeID: current.vaultScopeID });
    });
  }

  async unlockBurnRecovery({ passphrase }) {
    return this.serialized(async () => {
      const current = await this.loadSlot();
      if (current?.status !== "burning") {
        throw new BrowserMessagingAvailabilityError(
          "vaultBurnNotPending",
          "The fixed application vault has no burn recovery to complete."
        );
      }
      const saltBytes = decodeBase64(current.salt);
      try {
        if (saltBytes.byteLength !== 16) throw new TypeError("Application vault salt is invalid.");
        const session = this.createInnerSession({
          passphrase,
          salt: saltBytes,
          vaultScopeID: current.vaultScopeID,
          encryptedRecord: current.encryptedRecord
        });
        const persona = await session.repository.load();
        if (persona === null) throw new Error("Burn recovery relationship state is missing.");
        // Recovery returns the decryption key only to the caller's terminal
        // erasure path. It never adopts an active aggregate repository.
        return Object.freeze({ persona, encryptedStore: session.store });
      } finally {
        saltBytes.fill(0);
      }
    });
  }

  async finishBurn() {
    return this.serialized(async () => {
      const current = await this.loadSlot();
      if (current?.status === "burned") {
        this.lock();
        return Object.freeze({ burned: true, vaultScopeID: current.vaultScopeID });
      }
      if (current?.status !== "burning") {
        throw new BrowserMessagingAvailabilityError(
          "vaultBurnNotPending",
          "Application vault erasure must advance through its authenticated burning generation."
        );
      }
      const next = validateApplicationVaultSlotRecord({
        ...current,
        status: "burned",
        salt: null,
        encryptedRecord: null,
        updatedAt: monotonicTimestamp(current.updatedAt)
      });
      await this.commitSlot(next);
      const vaultScopeID = current.vaultScopeID;
      this.lock();
      return Object.freeze({ burned: true, vaultScopeID });
    });
  }

  lock() {
    this.innerBackend = null;
    this.innerStore = null;
    this.innerRepository = null;
    this.innerVaultScopeID = null;
  }

  async loadSlot() {
    const anchorStore = await this.anchorStore();
    const backend = anchorStore.encryptedStateStoreBackend;
    const loaded = await anchorStore.load({
      anchorKey: APPLICATION_VAULT_SLOT_ANCHOR_KEY,
      relationshipID: APPLICATION_VAULT_SLOT_SCOPE,
      loadEncryptedState: () => backend.get(APPLICATION_VAULT_SLOT_STATE_KEY)
    });
    exactKeys(loaded, ["anchor", "state"], "Application vault anchor load result");
    if ((loaded.anchor === null) !== (loaded.state === null)) {
      throw new BrowserMessagingAvailabilityError(
        "vaultRollbackDetected",
        "The application vault record and its authenticated host anchor disagree."
      );
    }
    if (loaded.anchor === null) {
      this.currentAnchor = null;
      this.currentRecord = null;
      return null;
    }
    const anchor = validateApplicationVaultAnchor(loaded.anchor);
    const record = validateApplicationVaultSlotRecord(loaded.state);
    const digest = base64(await this.crypto.sha256(canonicalJsonBytes(record)));
    if (digest !== anchor.stateDigest) {
      throw new BrowserMessagingAvailabilityError(
        "vaultRollbackDetected",
        "The encrypted application vault record does not match its authenticated host anchor."
      );
    }
    this.currentAnchor = anchor;
    this.currentRecord = record;
    return structuredClone(record);
  }

  async commitSlot(record) {
    const anchorStore = await this.anchorStore();
    const backend = anchorStore.encryptedStateStoreBackend;
    const expectedAnchor = this.currentAnchor;
    const nextGeneration = (expectedAnchor?.generation ?? 0) + 1;
    const nextStateDigest = base64(await this.crypto.sha256(canonicalJsonBytes(record)));
    const committed = await anchorStore.commit({
      anchorKey: APPLICATION_VAULT_SLOT_ANCHOR_KEY,
      relationshipID: APPLICATION_VAULT_SLOT_SCOPE,
      expectedAnchor: expectedAnchor === null ? null : structuredClone(expectedAnchor),
      nextGeneration,
      nextStateDigest,
      persistEncryptedState: () => backend.set(
        APPLICATION_VAULT_SLOT_STATE_KEY,
        structuredClone(record)
      )
    });
    const anchor = validateApplicationVaultAnchor(committed);
    if (anchor.generation !== nextGeneration || anchor.stateDigest !== nextStateDigest) {
      throw new BrowserMessagingAvailabilityError(
        "vaultRollbackDetected",
        "The host committed a different application vault generation."
      );
    }
    this.currentAnchor = anchor;
    this.currentRecord = structuredClone(record);
  }

  async anchorStore() {
    this.anchorStorePromise ??= (async () => {
      const store = await this.stateAnchorStoreFactory({
        relationshipID: APPLICATION_VAULT_SLOT_SCOPE,
        anchorKey: APPLICATION_VAULT_SLOT_ANCHOR_KEY,
        stateKey: APPLICATION_VAULT_SLOT_STATE_KEY
      });
      if (!store || typeof store.load !== "function" || typeof store.commit !== "function" ||
          !store.encryptedStateStoreBackend || ["get", "set", "delete"].some((method) =>
            typeof store.encryptedStateStoreBackend[method] !== "function")) {
        throw new BrowserMessagingAvailabilityError(
          "rollbackAnchorUnavailable",
          "The embedding host does not provide an atomic fixed application-vault slot."
        );
      }
      return store;
    })();
    return this.anchorStorePromise;
  }

  createInnerSession({ passphrase, salt, vaultScopeID, encryptedRecord }) {
    const stateKey = applicationVaultPersonaStateKey(vaultScopeID);
    const backend = new MemoryNoctweaveStore(
      encryptedRecord === null ? [] : [[stateKey, encryptedRecord]]
    );
    const store = new EncryptedNoctweaveStore(backend, {
      crypto: this.storageCrypto,
      passphrase,
      salt
    });
    return {
      vaultScopeID,
      stateKey,
      backend,
      store,
      repository: new NoctweaveStateRepository(store, { key: stateKey })
    };
  }

  adoptInnerSession(session) {
    this.innerBackend = session.backend;
    this.innerStore = session.store;
    this.innerRepository = session.repository;
    this.innerVaultScopeID = session.vaultScopeID;
  }

  serialized(operation) {
    const next = this.queue.then(operation, operation);
    this.queue = next.catch(() => {});
    return next;
  }
}

/**
 * Local burn state machine. The fixed application slot enters `burning`
 * before any relationship is touched, each relationship is then blocked and
 * tombstoned independently, and the aggregate ciphertext is removed before
 * optional relay cleanup. Re-running from `burning` is idempotent.
 */
export async function executeAnchoredBrowserLocalBurnV2({
  vault,
  messaging,
  relationships,
  at = Date.now(),
  checkpoint = async () => {}
}) {
  if (!vault || typeof vault.beginBurn !== "function" ||
      typeof vault.finishBurn !== "function" ||
      !messaging || typeof messaging.anchorRelationshipsForBurn !== "function" ||
      typeof messaging.destroyRollbackAnchors !== "function" ||
      typeof messaging.teardownRelationshipRoutes !== "function" ||
      !Array.isArray(relationships) || typeof checkpoint !== "function" ||
      !Number.isFinite(at)) {
    throw new TypeError("Anchored local burn dependencies are invalid.");
  }
  await vault.beginBurn();
  await checkpoint(Object.freeze({ phase: "aggregateBurning" }));
  for (let index = 0; index < relationships.length; index += 1) {
    await messaging.anchorRelationshipsForBurn([relationships[index]]);
    await checkpoint(Object.freeze({ phase: "relationshipBlocked", index }));
  }
  for (let index = 0; index < relationships.length; index += 1) {
    await messaging.destroyRollbackAnchors([relationships[index]]);
    await checkpoint(Object.freeze({ phase: "relationshipDestroyed", index }));
  }
  await vault.finishBurn();
  await checkpoint(Object.freeze({ phase: "aggregateBurned" }));

  const failures = [];
  for (const relationship of relationships) {
    const result = await messaging.teardownRelationshipRoutes(relationship, "burned", at);
    failures.push(...result.failures);
  }
  return Object.freeze({
    burned: true,
    relayCleanupComplete: failures.length === 0,
    failures: Object.freeze(failures)
  });
}

/**
 * Browser integration around the clean-v1 durable pairwise runtime. All
 * protocol state is scoped to one independently paired relationship and all
 * records share the caller's encrypted vault. This service has no account,
 * installation, global identity, or persona-wide synchronization authority.
 * Durable runtime construction additionally requires a host-supplied,
 * relationship-local authenticated CAS coordinator; ordinary web storage is
 * deliberately not treated as rollback-resistant.
 */
export class NoctweaveBrowserMessagingServiceV2 {
  constructor({
    crypto,
    pqc,
    store,
    relayClientFactory,
    stateAnchorStoreFactory = null,
    runtimeFactory,
    webClientFactory
  }) {
    if (!crypto || !pqc) {
      throw new TypeError("Browser messaging requires protocol cryptography.");
    }
    if (!(store instanceof EncryptedNoctweaveStore)) {
      throw new TypeError("Browser messaging requires EncryptedNoctweaveStore.");
    }
    if (typeof relayClientFactory !== "function") {
      throw new TypeError("Browser messaging requires a relay-client factory.");
    }
    if (stateAnchorStoreFactory !== null && typeof stateAnchorStoreFactory !== "function") {
      throw new TypeError("stateAnchorStoreFactory must be a function when provided.");
    }
    this.crypto = crypto;
    this.pqc = pqc;
    this.store = store;
    this.relayClientFactory = relayClientFactory;
    this.stateAnchorStoreFactory = stateAnchorStoreFactory;
    this.runtimeFactory = runtimeFactory ?? ((options) =>
      new DurablePairwiseMessagingRuntimeV2(options));
    this.webClientFactory = webClientFactory ?? ((options) => new NoctweaveWebClient(options));
    this.runtimes = new Map();
    this.runtimePromises = new Map();
  }

  async open(relationship, {
    at = Date.now(),
    persistAppliedRelationship
  } = {}) {
    const runtime = await this.runtimeFor(relationship);
    await runtime.open();
    if (relationship.localPolicy?.consent === "blocked") {
      await runtime.updateLocalPolicy(relationship.localPolicy);
    }
    await this.reconcileRelationship(runtime, relationship, persistAppliedRelationship);
    return this.snapshot(relationship, at);
  }

  async updateRelationshipLocalPolicy(relationship, localPolicy, {
    at = Date.now(),
    persistAppliedRelationship
  } = {}) {
    const runtime = await this.runtimeFor(relationship);
    await runtime.updateLocalPolicy(localPolicy);
    const current = await runtime.relationshipSnapshot();
    if (persistAppliedRelationship !== undefined) {
      if (typeof persistAppliedRelationship !== "function") {
        throw new TypeError("persistAppliedRelationship must be a function.");
      }
      // The relationship anchor is deliberately committed before this
      // rollbackable UI projection. A crash can lose the projection, never
      // the terminal block decision.
      await persistAppliedRelationship({ relationship: current, received: Object.freeze([]) });
    }
    return Object.freeze({ relationship: current, snapshot: await this.snapshot(current, at) });
  }

  async sendText({ relationship, text, at = Date.now() }) {
    const availability = await this.availabilityFor(relationship, at);
    if (!availability.canSend) {
      throw new BrowserMessagingAvailabilityError(availability.maintenanceState, availability.message);
    }
    const normalized = validateMessageText(text);
    const runtime = await this.runtimeFor(relationship);
    const intent = await runtime.prepareText({ text: normalized });
    const resumed = await runtime.resumeOutbound();
    return Object.freeze({ intent, resumed, snapshot: await this.snapshot(relationship, at) });
  }

  async prepareFile() {
    throw new BrowserMessagingAvailabilityError(
      "attachmentUnavailable",
      browserMessagingAttachmentBlocker
    );
  }

  async resumeOutbound(relationship, at = Date.now()) {
    const availability = await this.availabilityFor(relationship, at);
    if (availability.consent === "blocked" || availability.routeTeardownState !== null) {
      throw new BrowserMessagingAvailabilityError("blocked", availability.message);
    }
    const runtime = await this.runtimeFor(relationship);
    const resumed = await runtime.resumeOutbound();
    return Object.freeze({ resumed, snapshot: await this.snapshot(relationship, at) });
  }

  async discard(relationship, clientTransactionId, at = Date.now()) {
    const runtime = await this.runtimeFor(relationship);
    const intent = await runtime.discard(clientTransactionId);
    return Object.freeze({ intent, snapshot: await this.snapshot(relationship, at) });
  }

  async syncReceiveRoutes(relationship, {
    at = Date.now(),
    persistAppliedRelationship
  } = {}) {
    const runtime = await this.runtimeFor(relationship);
    const current = await runtime.relationshipSnapshot();
    const availability = await this.availabilityFor(current, at);
    if (!availability.canReceive) {
      throw new BrowserMessagingAvailabilityError(availability.maintenanceState, availability.message);
    }
    const authorizedAt = swiftISODate(new Date(at));
    const outcomes = [];
    for (const localRoute of current.localReceiveRoutes) {
      const routeID = localRoute.route.routeID.rawValue;
      if (Date.parse(localRoute.route.lease.expiresAt) <= at) {
        outcomes.push(Object.freeze({ routeID, status: "expired", received: 0, hasMore: false }));
        continue;
      }
      if (localRoute.gapState !== null) {
        outcomes.push(Object.freeze({ routeID, status: "continuityGap", received: 0, hasMore: false }));
        continue;
      }
      try {
        const relay = this.relayClientFactory(localRoute.relay);
        const client = this.webClientFactory({
          relay,
          store: this.store,
          stateKey: await this.storageKey("route-client", current.relationshipID, routeID),
          crypto: this.crypto
        });
        const synced = await runtime.syncReceive({
          client,
          routeID,
          authorizedAt,
          persistAppliedRelationship
        });
        outcomes.push(Object.freeze({
          routeID,
          status: synced.relayCommit.status === "accepted" ? "synchronized" : "localCommitted",
          received: synced.received.length,
          hasMore: synced.hasMore
        }));
      } catch (error) {
        outcomes.push(Object.freeze({
          routeID,
          status: error?.code === "routeGapDetected" ? "continuityGap" : "failed",
          received: 0,
          hasMore: false,
          failure: boundedFailure(error)
        }));
      }
    }
    let routeControlStatus = "current";
    try {
      const controls = await this.advanceRouteControls(runtime, {
        at,
        persistAppliedRelationship
      });
      routeControlStatus = controls.status;
    } catch (error) {
      routeControlStatus = `pending:${boundedFailure(error)}`;
    }
    let receiptStatus = "disabled";
    try {
      const receiptResult = await this.prepareEnabledDeliveryReceipts(runtime);
      receiptStatus = receiptResult.prepared > 0
        ? `prepared:${receiptResult.prepared}`
        : receiptResult.enabled ? "current" : "disabled";
    } catch (error) {
      receiptStatus = `pending:${boundedFailure(error)}`;
    }
    return Object.freeze({
      outcomes: Object.freeze(outcomes),
      receiptStatus,
      routeControlStatus,
      snapshot: await this.snapshot(relationship, at)
    });
  }

  async markRead(relationship, targetEventId, at = Date.now()) {
    const runtime = await this.runtimeFor(relationship);
    const current = await runtime.relationshipSnapshot();
    const availability = await this.availabilityFor(current, at);
    if (!availability.canSend || !current.localPolicy.readReceiptsEnabled) {
      throw new BrowserMessagingAvailabilityError(
        "readReceiptDisabled",
        "Read receipts are disabled for this relationship."
      );
    }
    const received = await runtime.listReceived();
    if (!received.some(({ event }) => event.id === targetEventId && event.kind === "application")) {
      throw new BrowserMessagingAvailabilityError(
        "unknownReceivedEvent",
        "Read receipts require a stored inbound application event."
      );
    }
    const clientTransactionId = await this.receiptTransactionID(
      "read",
      current.relationshipID,
      targetEventId
    );
    const intent = await runtime.prepareReadReceipt({ targetEventId, clientTransactionId });
    const resumed = await runtime.resumeOutbound();
    return Object.freeze({ intent, resumed, snapshot: await this.snapshot(current, at) });
  }

  async snapshot(relationship, at = Date.now()) {
    const runtime = await this.runtimeFor(relationship);
    const [outbound, received, currentRelationship] = await Promise.all([
      runtime.listOutbound(),
      runtime.listReceived(),
      runtime.relationshipSnapshot()
    ]);
    return Object.freeze({
      availability: await this.availabilityFor(currentRelationship, at),
      outbound,
      received,
      timeline: browserMessageTimelineV2({ outbound, received })
    });
  }

  async maintainRelationship(relationship, {
    at = Date.now(),
    persistAppliedRelationship
  } = {}) {
    if (!Number.isFinite(at)) throw new TypeError("Relationship maintenance time is invalid.");
    const runtime = await this.runtimeFor(relationship);
    const current = await runtime.relationshipSnapshot();
    const availability = await this.availabilityFor(current, at);
    if (availability.consent === "blocked" || availability.routeTeardownState !== null) {
      return Object.freeze({
        prekey: "blocked",
        routes: availability.maintenanceState,
        routeBlocker: null
      });
    }
    let prekey = "current";
    if (usablePairwiseRoutesV2(current.peerIdentity.sendRoutes, at).length === 0) {
      prekey = "awaitingPeerRoute";
    } else {
      const nextIdentity = structuredClone(current.localIdentity);
      const renewed = await renewPairwiseDirectV4PrekeyIfNeeded({
        crypto: this.crypto,
        pqc: this.pqc,
        localIdentity: nextIdentity,
        now: at
      });
      if (renewed) {
        await runtime.prepareEndpointPrekeyUpdate({
          endpointBinding: nextIdentity.endpointBinding,
          localIdentity: nextIdentity,
          sentAt: swiftISODate(new Date(at))
        });
        await this.reconcileRelationship(runtime, relationship, persistAppliedRelationship);
        const resumed = await runtime.resumeOutbound({ authorizedAt: swiftISODate(new Date(at)) });
        prekey = resumed.completed > 0 ? "published" : "publicationPending";
      }
    }
    const controls = await this.advanceRouteControls(runtime, {
      at,
      persistAppliedRelationship
    });
    let refreshed = await runtime.relationshipSnapshot();
    const maintenance = await this.advanceRouteMaintenance(runtime, refreshed, {
      at,
      persistAppliedRelationship
    });
    refreshed = await runtime.relationshipSnapshot();
    await this.reconcileRelationship(runtime, relationship, persistAppliedRelationship);
    const routeAvailability = describeBrowserRelationshipAvailabilityV2(refreshed, at);
    return Object.freeze({
      prekey,
      routes: maintenance.status === "current"
        ? routeAvailability.maintenanceState
        : maintenance.status,
      routeBlocker: maintenance.failure ??
        (controls.status.startsWith("pending:") ? controls.status.slice(8) : null)
    });
  }

  async advanceRouteControls(runtime, {
    at = Date.now(),
    persistAppliedRelationship
  } = {}) {
    let current = await runtime.relationshipSnapshot();
    const outbound = await runtime.listOutbound();
    const existingTransactions = new Set(outbound.map(({ clientTransactionId }) =>
      clientTransactionId));
    let preparedProbes = 0;
    for (const route of current.peerIdentity.sendRoutes.routes) {
      if (route.state !== "testing" || Date.parse(route.expiresAt) <= at) continue;
      const clientTransactionId = await this.routeControlTransactionID(
        "probe",
        current.relationshipID,
        route.routeID.rawValue
      );
      if (existingTransactions.has(clientTransactionId)) continue;
      await runtime.prepareRouteProbe({
        routeID: route.routeID,
        routeSetRevision: current.peerIdentity.sendRoutes.revision,
        destinationRouteIDs: [route.routeID],
        clientTransactionId,
        sentAt: transitionTimestamp(current.peerIdentity.sendRoutes.issuedAt, at)
      });
      existingTransactions.add(clientTransactionId);
      preparedProbes += 1;
    }
    if (preparedProbes > 0) await runtime.resumeOutbound();

    // Promotion is driven only from the runtime's durable received-event log;
    // the transient sync result intentionally does not own receive timestamps.
    const storedControls = (await runtime.listReceived()).filter(({ projection }) =>
      projection?.kind === "relationshipControl" &&
      projection.controlKind === "routeProbe");
    const maintenanceRecord = await this.loadMaintenanceRecord(runtime);
    let promoted = 0;
    for (const received of storedControls) {
      const routeID = received.projection.sourceRouteID?.rawValue;
      if (typeof routeID !== "string") continue;
      const record = maintenanceRecord?.relationshipID === current.relationshipID &&
        maintenanceRecord.clientCapabilities.routeID.rawValue === routeID
        ? maintenanceRecord
        : null;
      const route = current.localAdvertisedRoutes.routes.find((candidate) =>
        candidate.routeID.rawValue === routeID);
      if (record === null || route?.state !== "testing") continue;
      const replacing = record.replacingRouteIDs.map(({ rawValue }) =>
        current.localAdvertisedRoutes.routes.find((candidate) =>
          candidate.routeID.rawValue === rawValue));
      if (replacing.some((candidate) => candidate?.state !== "active")) continue;
      const testedAt = transitionTimestamp(route.validFrom, Date.parse(received.receivedAt));
      const issuedAt = transitionTimestamp(
        current.localAdvertisedRoutes.issuedAt,
        Math.max(at, Date.parse(testedAt))
      );
      const latestDrain = Math.min(...replacing.map(({ expiresAt }) => Date.parse(expiresAt)));
      const overlapAt = Math.min(Date.parse(issuedAt) + routeOverlapMilliseconds, latestDrain);
      if (overlapAt <= Date.parse(issuedAt)) {
        throw new BrowserMessagingAvailabilityError(
          "routeOverlapUnavailable",
          "The old receive route expired before an authenticated overlap could be established; fresh pairing is required."
        );
      }
      const nextRouteSet = await promoteProbedPairwiseRouteV2({
        crypto: this.crypto,
        pqc: this.pqc,
        current: current.localAdvertisedRoutes,
        routeID: route.routeID,
        replacingRouteIDs: record.replacingRouteIDs,
        testedAt,
        overlapUntil: swiftISODate(new Date(overlapAt)),
        issuedAt,
        ...relationshipSigningKeys(current)
      });
      await runtime.prepareRouteSetUpdate({
        routeSet: nextRouteSet,
        localReceiveRoutes: current.localReceiveRoutes,
        clientTransactionId: await this.routeControlTransactionID(
          "promotion",
          current.relationshipID,
          routeID
        ),
        sentAt: issuedAt
      });
      await this.reconcileRelationship(runtime, current, persistAppliedRelationship);
      await runtime.resumeOutbound();
      current = await runtime.relationshipSnapshot();
      promoted += 1;
    }
    return Object.freeze({
      status: promoted > 0
        ? "promoted"
        : preparedProbes > 0 ? "probePublished" : "current",
      preparedProbes,
      promoted
    });
  }

  async advanceRouteMaintenance(runtime, relationship, {
    at = Date.now(),
    persistAppliedRelationship
  } = {}) {
    let record = await this.loadMaintenanceRecord(runtime);
    if (record === null) {
      const candidate = routeReplacementCandidate(relationship, at);
      if (candidate === null) return Object.freeze({ status: "current", failure: null });
      if (candidate.failure !== null) {
        return Object.freeze({ status: candidate.status, failure: candidate.failure });
      }
      const issuedAt = transitionTimestamp(relationship.localAdvertisedRoutes.issuedAt, at);
      const clientCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(this.crypto);
      const payloadKey = await createOpaqueRoutePayloadKeyV2(this.crypto);
      const lease = createOpaqueRouteLeaseV2({
        issuedAt,
        expiresAt: swiftISODate(new Date(Date.parse(issuedAt) + routeReplacementLeaseMilliseconds)),
        policy: candidate.localRoute.route.lease.policy
      });
      const createRequest = await makeOpaqueRouteCreateRequestV2({
        crypto: this.crypto,
        capabilities: clientCapabilities,
        lease,
        idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(this.crypto),
        nonce: await createOpaqueRouteProofNonceV2(this.crypto)
      });
      record = {
        relationshipID: relationship.relationshipID,
        relay: candidate.localRoute.relay,
        clientCapabilities,
        payloadKey,
        createRequest,
        localReceiveRoute: null,
        testingSendRoute: null,
        replacingRouteIDs: [candidate.localRoute.route.routeID],
        teardownRequest: null,
        teardownCapability: null,
        tombstone: null,
        lastFailure: null,
        createdAt: issuedAt,
        updatedAt: issuedAt
      };
      await this.saveMaintenanceRecord(runtime, record);
    }
    try {
      const status = await this.resumeRouteMaintenanceRecord(runtime, record, {
        at,
        persistAppliedRelationship
      });
      if (status === "complete") {
        await this.saveMaintenanceRecord(runtime, null);
      }
      return Object.freeze({ status, failure: null });
    } catch (error) {
      record = await this.loadMaintenanceRecord(runtime);
      if (record !== null) {
        record.lastFailure = boundedFailure(error);
        record.updatedAt = swiftISODate();
        await this.saveMaintenanceRecord(runtime, record);
      }
      return Object.freeze({ status: "pending", failure: boundedFailure(error) });
    }
  }

  async resumeRouteMaintenanceRecord(runtime, record, {
    at,
    persistAppliedRelationship
  }) {
    if (record.localReceiveRoute === null) {
      const relay = this.relayClientFactory(record.relay);
      if (typeof relay?.createOpaqueRoute !== "function") {
        throw new TypeError("Relay client must implement createOpaqueRoute(...).");
      }
      const route = await relay.createOpaqueRoute({
        request: record.createRequest,
        renewCapability: record.clientCapabilities.renewCapability
      });
      record.localReceiveRoute = await createLocalOpaqueReceiveRouteV2({
        crypto: this.crypto,
        relay: record.relay,
        route,
        clientCapabilities: record.clientCapabilities,
        payloadKey: record.payloadKey
      });
      record.testingSendRoute = await createOpaqueSendRouteV2({
        crypto: this.crypto,
        relay: record.relay,
        route,
        clientCapabilities: record.clientCapabilities,
        payloadKey: record.payloadKey,
        state: "testing"
      });
      await this.updateMaintenanceRecord(runtime, record);
    }

    let current = await runtime.relationshipSnapshot();
    let advertised = current.localAdvertisedRoutes.routes.find(({ routeID }) =>
      routeID.rawValue === record.clientCapabilities.routeID.rawValue) ?? null;
    if (advertised === null) {
      const issuedAt = transitionTimestamp(current.localAdvertisedRoutes.issuedAt, at);
      const nextRouteSet = await addTestingPairwiseRouteV2({
        crypto: this.crypto,
        pqc: this.pqc,
        current: current.localAdvertisedRoutes,
        route: record.testingSendRoute,
        issuedAt,
        ...relationshipSigningKeys(current)
      });
      const localReceiveRoutes = current.localReceiveRoutes.some(({ route }) =>
        route.routeID.rawValue === record.clientCapabilities.routeID.rawValue)
        ? current.localReceiveRoutes
        : [...current.localReceiveRoutes, record.localReceiveRoute];
      await runtime.prepareRouteSetUpdate({
        routeSet: nextRouteSet,
        localReceiveRoutes,
        clientTransactionId: await this.routeControlTransactionID(
          "testing",
          current.relationshipID,
          record.clientCapabilities.routeID.rawValue
        ),
        sentAt: issuedAt
      });
      await this.reconcileRelationship(runtime, current, persistAppliedRelationship);
      await runtime.resumeOutbound();
      return "testingPublished";
    }
    if (advertised.state === "testing") {
      await runtime.resumeOutbound();
      return "awaitingAuthenticatedProbe";
    }
    if (advertised.state === "revoked") {
      throw new BrowserMessagingAvailabilityError(
        "replacementRouteRevoked",
        "The replacement receive route was revoked before activation."
      );
    }
    if (advertised.state !== "active") {
      throw new BrowserMessagingAvailabilityError(
        "replacementRouteInvalid",
        "The replacement receive route has an invalid lifecycle state."
      );
    }

    for (const replacedRouteID of record.replacingRouteIDs) {
      current = await runtime.relationshipSnapshot();
      const replaced = current.localAdvertisedRoutes.routes.find(({ routeID }) =>
        routeID.rawValue === replacedRouteID.rawValue);
      if (replaced?.state === "draining" && Date.parse(replaced.drainAfter) <= at) {
        const issuedAt = transitionTimestamp(current.localAdvertisedRoutes.issuedAt, at);
        const nextRouteSet = await revokeDrainedPairwiseRouteV2({
          crypto: this.crypto,
          pqc: this.pqc,
          current: current.localAdvertisedRoutes,
          routeID: replacedRouteID,
          issuedAt,
          ...relationshipSigningKeys(current)
        });
        await runtime.prepareRouteSetUpdate({
          routeSet: nextRouteSet,
          localReceiveRoutes: current.localReceiveRoutes,
          clientTransactionId: await this.routeControlTransactionID(
            "revocation",
            current.relationshipID,
            replacedRouteID.rawValue
          ),
          sentAt: issuedAt
        });
        await this.reconcileRelationship(runtime, current, persistAppliedRelationship);
        await runtime.resumeOutbound();
      }
    }

    current = await runtime.relationshipSnapshot();
    const replacedRoutes = record.replacingRouteIDs.map(({ rawValue }) =>
      current.localAdvertisedRoutes.routes.find(({ routeID }) => routeID.rawValue === rawValue));
    if (replacedRoutes.some((route) => route?.state === "draining")) return "overlap";
    if (replacedRoutes.some((route) => route?.state !== "revoked")) {
      throw new BrowserMessagingAvailabilityError(
        "replacementTransitionInvalid",
        "The signed route set did not preserve the expected replacement transition."
      );
    }
    await runtime.resumeOutbound();
    const outbound = await runtime.listOutbound();
    for (const replacedRouteID of record.replacingRouteIDs) {
      const transactionID = await this.routeControlTransactionID(
        "revocation",
        current.relationshipID,
        replacedRouteID.rawValue
      );
      if (outbound.find(({ clientTransactionId }) => clientTransactionId === transactionID)?.status !==
          "relayAccepted") {
        return "revocationPublicationPending";
      }
    }

    const oldLocalRoutes = current.localReceiveRoutes.filter(({ route }) =>
      record.replacingRouteIDs.some(({ rawValue }) => rawValue === route.routeID.rawValue));
    if (oldLocalRoutes.length === 0) return "complete";
    if (oldLocalRoutes.length !== 1 || record.replacingRouteIDs.length !== 1) {
      throw new BrowserMessagingAvailabilityError(
        "replacementScopeInvalid",
        "Browser route replacement retires exactly one old receive route at a time."
      );
    }
    const oldLocalRoute = oldLocalRoutes[0];
    if (record.teardownRequest === null) {
      const authorizedAt = transitionTimestamp(current.localAdvertisedRoutes.issuedAt, at);
      record.teardownRequest = await makeOpaqueRouteTeardownRequestV2({
        crypto: this.crypto,
        capabilities: oldLocalRoute.clientCapabilities,
        current: oldLocalRoute.route,
        authorizedAt,
        idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(this.crypto),
        nonce: await createOpaqueRouteProofNonceV2(this.crypto)
      });
      record.teardownCapability = oldLocalRoute.clientCapabilities.teardownCapability;
      await this.updateMaintenanceRecord(runtime, record);
    }
    if (record.tombstone === null) {
      const relay = this.relayClientFactory(oldLocalRoute.relay);
      if (typeof relay?.teardownOpaqueRoute !== "function") {
        throw new TypeError("Relay client must implement teardownOpaqueRoute(...).");
      }
      record.tombstone = structuredClone(await relay.teardownOpaqueRoute({
        request: record.teardownRequest,
        teardownCapability: record.teardownCapability
      }));
      await this.updateMaintenanceRecord(runtime, record);
    }
    const retired = await runtime.finalizeLocalRouteRetirement({
      evidence: {
        request: record.teardownRequest,
        teardownCapability: record.teardownCapability,
        tombstone: record.tombstone
      },
      retiredAt: transitionTimestamp(current.localAdvertisedRoutes.issuedAt, at)
    });
    await this.reconcileRelationship(runtime, current, persistAppliedRelationship);
    return retired.retired || oldLocalRoutes.length === 0 ? "complete" : "pending";
  }

  async updateMaintenanceRecord(runtime, record) {
    const current = await this.loadMaintenanceRecord(runtime);
    if (current?.relationshipID !== record.relationshipID) {
      throw new TypeError("Route-maintenance record disappeared.");
    }
    const updatedAt = swiftISODate();
    await this.saveMaintenanceRecord(runtime, {
      ...structuredClone(record),
      lastFailure: null,
      updatedAt
    });
  }

  async loadMaintenanceRecord(runtime) {
    const stored = (await runtime.lifecycleSnapshot()).routeMaintenance;
    if (stored === null) return null;
    const validated = await validateMaintenanceJournal(this.crypto, {
      stateSchema: "org.noctweave.browser-route-maintenance.v2",
      version: 2,
      relationships: [stored],
      updatedAt: stored.updatedAt
    });
    return structuredClone(validated.relationships[0]);
  }

  async saveMaintenanceRecord(runtime, record) {
    if (record === null) {
      await runtime.updateLifecycle({ routeMaintenance: null });
      return null;
    }
    const validated = await validateMaintenanceJournal(this.crypto, {
      stateSchema: "org.noctweave.browser-route-maintenance.v2",
      version: 2,
      relationships: [record],
      updatedAt: record.updatedAt
    });
    const result = structuredClone(validated.relationships[0]);
    await runtime.updateLifecycle({ routeMaintenance: result });
    return result;
  }

  async routeControlTransactionID(kind, relationshipID, scope) {
    const digest = await this.crypto.sha256(encoder.encode(
      `Noctweave/browser-route-${kind}-transaction/v2\u0000${relationshipID}\u0000${scope}`
    ));
    return uuidFromDigest(digest);
  }

  async safetyNumber(relationship) {
    requireRelationshipID(relationship);
    const localFingerprint = relationship.localIdentity?.signingFingerprint;
    const peerPublicKey = decodeBase64(relationship.peerIdentity?.signingPublicKey);
    const peerFingerprint = base64(await this.crypto.sha256(peerPublicKey));
    peerPublicKey.fill(0);
    if (typeof localFingerprint !== "string" || localFingerprint.length === 0) {
      throw new TypeError("Relationship signing fingerprint is missing.");
    }
    const fingerprints = [localFingerprint, peerFingerprint].sort();
    const digest = await this.crypto.sha256(encoder.encode(
      `Noctweave/relationship-safety-number/v2\u0000${relationship.relationshipID.toLowerCase()}\u0000${fingerprints.join("\u0000")}`
    ));
    let numeric = 0n;
    for (const byte of digest.subarray(0, 25)) numeric = (numeric << 8n) | BigInt(byte);
    const digits = numeric.toString(10).padStart(60, "0").slice(-60);
    return Object.freeze({
      groups: Object.freeze(digits.match(/.{5}/gu)),
      display: digits.match(/.{5}/gu).join(" ")
    });
  }

  async teardownRelationshipRoutes(relationship, reason = "blocked", at = Date.now()) {
    const relationshipID = requireRelationshipID(relationship);
    if (!new Set(["blocked", "burned"]).has(reason) || !Number.isFinite(at)) {
      throw new TypeError("Relationship route teardown reason or time is invalid.");
    }
    if (reason === "burned") return this.attemptBurnRouteTeardowns(relationship, at);
    const runtime = await this.runtimeFor(relationship);
    const current = await runtime.relationshipSnapshot();
    const maintenance = await this.loadMaintenanceRecord(runtime);
    const receiveRoutes = [...current.localReceiveRoutes];
    if (maintenance !== null && maintenance.localReceiveRoute !== null &&
        maintenance.tombstone === null &&
        !receiveRoutes.some(({ route }) => route.routeID.rawValue ===
          maintenance.localReceiveRoute.route.routeID.rawValue)) {
      receiveRoutes.push(maintenance.localReceiveRoute);
    }
    let record = await this.loadTeardownRecord(runtime);
    if (record === null) {
      if (!Array.isArray(current.localReceiveRoutes) ||
          receiveRoutes.length > maximumTeardownRoutes) {
        throw new BrowserMessagingAvailabilityError(
          "teardownCapacityExceeded",
          "The bounded encrypted route-teardown journal is full."
        );
      }
      const createdAt = swiftISODate(new Date(at));
      const intents = [];
      for (const localRoute of receiveRoutes) {
        if (Date.parse(localRoute.route.lease.expiresAt) <= at) continue;
        const request = await makeOpaqueRouteTeardownRequestV2({
          crypto: this.crypto,
          capabilities: localRoute.clientCapabilities,
          current: localRoute.route,
          authorizedAt: createdAt,
          idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(this.crypto),
          nonce: await createOpaqueRouteProofNonceV2(this.crypto)
        });
        intents.push({
          relay: localRoute.relay,
          request,
          teardownCapability: localRoute.clientCapabilities.teardownCapability,
          status: "pending",
          lastFailure: null,
          tombstone: null,
          updatedAt: createdAt
        });
      }
      record = {
        relationshipID,
        reason,
        status: intents.length === 0 ? "complete" : "pending",
        intents,
        createdAt,
        updatedAt: createdAt
      };
      await this.saveTeardownRecord(runtime, record);
    }
    const resumed = await this.resumeRouteTeardowns({ relationship: current });
    if (resumed.complete && maintenance !== null) {
      await runtime.updateLifecycle({ routeMaintenance: null });
    }
    return resumed;
  }

  async attemptBurnRouteTeardowns(relationship, at = Date.now()) {
    const relationshipID = requireRelationshipID(relationship);
    const failures = [];
    for (const localRoute of relationship.localReceiveRoutes ?? []) {
      try {
        if (Date.parse(localRoute.route.lease.expiresAt) <= at) continue;
        const authorizedAt = swiftISODate(new Date(at));
        const request = await makeOpaqueRouteTeardownRequestV2({
          crypto: this.crypto,
          capabilities: localRoute.clientCapabilities,
          current: localRoute.route,
          authorizedAt,
          idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(this.crypto),
          nonce: await createOpaqueRouteProofNonceV2(this.crypto)
        });
        const relay = this.relayClientFactory(localRoute.relay);
        if (typeof relay?.teardownOpaqueRoute !== "function") {
          throw new TypeError("Relay client must implement teardownOpaqueRoute(...).");
        }
        const response = await relay.teardownOpaqueRoute({
          request,
          teardownCapability: localRoute.clientCapabilities.teardownCapability
        });
        if (response?.status !== "tornDown") {
          throw new Error("Relay did not confirm an opaque-route tombstone.");
        }
      } catch (error) {
        failures.push(`${relationshipID}:${boundedFailure(error)}`);
      }
    }
    return Object.freeze({
      complete: failures.length === 0,
      pendingRelationshipCount: 0,
      failures: Object.freeze(failures)
    });
  }

  async anchorRelationshipsForBurn(relationships) {
    if (!Array.isArray(relationships)) {
      throw new TypeError("Local burn requires relationship scopes.");
    }
    let terminal = 0;
    const failures = [];
    for (const relationship of relationships) {
      const relationshipID = requireRelationshipID(relationship);
      try {
        const stateKey = await this.storageKey("messages", relationshipID);
        const anchorKey = await this.storageKey("monotonic-anchor", relationshipID);
        const anchorStore = await this.stateAnchorStoreFactory?.({
          relationshipID,
          anchorKey,
          stateKey
        });
        if (!anchorStore) throw new Error("Relationship anchor store is unavailable.");
        if (typeof anchorStore.erasureStatus === "function") {
          const erasure = await anchorStore.erasureStatus({ anchorKey, relationshipID });
          if (erasure?.erased === true) {
            terminal += 1;
            continue;
          }
        }
        const runtime = await this.runtimeFor(relationship);
        await runtime.open();
        await runtime.updateLocalPolicy({
          ...relationship.localPolicy,
          consent: "blocked"
        });
        terminal += 1;
      } catch (error) {
        failures.push(`${relationshipID}:${boundedFailure(error)}`);
      }
    }
    if (failures.length > 0) {
      throw new BrowserMessagingAvailabilityError(
        "burnTerminalPolicyFailed",
        `${failures.length} relationship scope${failures.length === 1 ? "" : "s"} could not commit terminal burn policy: ${failures.join(", ")}.`
      );
    }
    return Object.freeze({ complete: true, terminal });
  }

  async destroyRollbackAnchors(relationships) {
    if (!Array.isArray(relationships)) {
      throw new TypeError("Rollback-anchor destruction requires relationships.");
    }
    if (this.stateAnchorStoreFactory === null) {
      throw new BrowserMessagingAvailabilityError(
        "rollbackAnchorDestructionUnavailable",
        "The host rollback coordinator is required for terminal relationship erasure."
      );
    }
    let destroyed = 0;
    const failures = [];
    for (const relationship of relationships) {
      const relationshipID = requireRelationshipID(relationship);
      try {
        const stateKey = await this.storageKey("messages", relationshipID);
        const anchorKey = await this.storageKey("monotonic-anchor", relationshipID);
        const anchorStore = await this.stateAnchorStoreFactory({
          relationshipID,
          anchorKey,
          stateKey
        });
        if (!anchorStore || typeof anchorStore.destroy !== "function") {
          throw new BrowserMessagingAvailabilityError(
            "rollbackAnchorUnavailable",
            "The host rollback coordinator cannot prove terminal relationship erasure."
          );
        }
        if (typeof anchorStore.erasureStatus === "function") {
          try {
            const erasure = await anchorStore.erasureStatus({ anchorKey, relationshipID });
            if (erasure?.erased === true && Object.keys(erasure).length === 1) {
              this.runtimes.delete(relationshipID);
              this.runtimePromises.delete(relationshipID);
              destroyed += 1;
              continue;
            }
          } catch {
            // Corrupt/missing ciphertext must not prevent the host from
            // installing its fixed-scope erasure tombstone below.
          }
        }
        const runtime = await this.runtimeFor(relationship);
        const result = await runtime.destroyRelationshipState();
        if (result?.destroyed !== true) {
          throw new Error("The host did not confirm atomic relationship-state destruction.");
        }
        this.runtimes.delete(relationshipID);
        this.runtimePromises.delete(relationshipID);
      } catch (error) {
        const code = error instanceof BrowserMessagingAvailabilityError &&
          error.code === "rollbackAnchorUnavailable"
          ? "rollbackAnchorDestructionUnavailable"
          : "rollbackAnchorDestructionFailed";
        failures.push({ code, failure: boundedFailure(error) });
        continue;
      }
      destroyed += 1;
    }
    if (failures.length > 0) {
      const code = failures.some(({ code }) => code === "rollbackAnchorDestructionUnavailable")
        ? "rollbackAnchorDestructionUnavailable"
        : "rollbackAnchorDestructionFailed";
      throw new BrowserMessagingAvailabilityError(
        code,
        `${failures.length} relationship rollback anchor${failures.length === 1 ? "" : "s"} could not be erased: ${failures.map(({ failure }) => failure).join(", ")}. The blocked encrypted vault was retained.`
      );
    }
    return Object.freeze({ complete: true, destroyed });
  }

  async resumeRouteTeardowns({ relationship = null, relationships = [], relationshipID = null } = {}) {
    const candidates = relationship === null ? relationships : [relationship];
    if (!Array.isArray(candidates)) throw new TypeError("Route teardown resume requires relationships.");
    const records = [];
    for (const candidate of candidates) {
      const candidateID = requireRelationshipID(candidate);
      if (relationshipID !== null && candidateID !== relationshipID) continue;
      const runtime = await this.runtimeFor(candidate);
      const record = await this.loadTeardownRecord(runtime);
      if (record === null) continue;
      for (const intent of record.intents) {
        if (intent.status === "complete") continue;
        try {
          const relay = this.relayClientFactory(intent.relay);
          if (typeof relay?.teardownOpaqueRoute !== "function") {
            throw new TypeError("Relay client must implement teardownOpaqueRoute(...).");
          }
          const response = await relay.teardownOpaqueRoute({
            request: intent.request,
            teardownCapability: intent.teardownCapability
          });
          if (response?.status !== "tornDown") {
            throw new Error("Relay did not confirm an opaque-route tombstone.");
          }
          intent.status = "complete";
          intent.lastFailure = null;
          intent.tombstone = structuredClone(response);
        } catch (error) {
          intent.status = "pending";
          intent.lastFailure = boundedFailure(error);
        }
        intent.updatedAt = swiftISODate();
        record.updatedAt = intent.updatedAt;
        record.status = record.intents.every(({ status }) => status === "complete")
          ? "complete"
          : "pending";
        await this.saveTeardownRecord(runtime, record);
      }
      records.push(record);
    }
    return Object.freeze({
      complete: records.every(({ status }) => status === "complete"),
      pendingRelationshipCount: records.filter(({ status }) => status !== "complete").length,
      failures: Object.freeze(records.flatMap(({ intents }) => intents
        .filter(({ status }) => status !== "complete")
        .map(({ lastFailure }) => lastFailure ?? "teardownPending")))
    });
  }

  async availabilityFor(relationship, at = Date.now()) {
    const runtime = await this.runtimeFor(relationship);
    const current = await runtime.relationshipSnapshot();
    const base = describeBrowserRelationshipAvailabilityV2(current, at);
    const teardown = await this.loadTeardownRecord(runtime);
    if (teardown === null) return Object.freeze({ ...base, routeTeardownState: null });
    const complete = teardown.status === "complete";
    return Object.freeze({
      ...base,
      canSend: false,
      canReceive: false,
      maintenanceState: complete ? "routesTornDown" : "routeTeardownPending",
      message: complete
        ? "Local receive routes were torn down. This relationship cannot be unblocked; create a fresh pairing."
        : "Local route teardown is pending and retryable. Messaging remains blocked.",
      routeTeardownState: teardown.status
    });
  }

  async loadTeardownRecord(runtime) {
    const stored = (await runtime.lifecycleSnapshot()).routeTeardown;
    if (stored === null) return null;
    return structuredClone(validateTeardownJournal({
      stateSchema: "org.noctweave.browser-route-teardown.v2",
      version: 2,
      relationships: [stored],
      updatedAt: stored.updatedAt
    }).relationships[0]);
  }

  async saveTeardownRecord(runtime, record) {
    if (record === null) {
      await runtime.updateLifecycle({ routeTeardown: null });
      return null;
    }
    const validated = validateTeardownJournal({
      stateSchema: "org.noctweave.browser-route-teardown.v2",
      version: 2,
      relationships: [record],
      updatedAt: record.updatedAt
    }).relationships[0];
    await runtime.updateLifecycle({ routeTeardown: validated });
    return structuredClone(validated);
  }

  async runtimeFor(relationship) {
    const relationshipID = requireRelationshipID(relationship);
    if (!this.runtimePromises.has(relationshipID)) {
      this.runtimePromises.set(relationshipID, (async () => {
        if (this.stateAnchorStoreFactory === null) {
          throw new BrowserMessagingAvailabilityError(
            "rollbackAnchorUnavailable",
            browserRollbackAnchorRequirement
          );
        }
        const stateKey = await this.storageKey("messages", relationshipID);
        const anchorKey = await this.storageKey("monotonic-anchor", relationshipID);
        const stateAnchorStore = await this.stateAnchorStoreFactory({
          relationshipID,
          anchorKey,
          stateKey
        });
        if (!stateAnchorStore || typeof stateAnchorStore.load !== "function" ||
            typeof stateAnchorStore.commit !== "function" ||
            typeof stateAnchorStore.destroy !== "function") {
          throw new BrowserMessagingAvailabilityError(
            "rollbackAnchorUnavailable",
            browserRollbackAnchorRequirement
          );
        }
        let runtimeStore = this.store;
        if (stateAnchorStore.encryptedStateStoreBackend !== undefined) {
          const backend = stateAnchorStore.encryptedStateStoreBackend;
          if (!backend || ["get", "set", "delete"].some((method) =>
            typeof backend[method] !== "function")) {
            throw new BrowserMessagingAvailabilityError(
              "rollbackAnchorUnavailable",
              "The host atomic relationship-state backend is malformed."
            );
          }
          runtimeStore = new EncryptedNoctweaveStore(backend, {
            crypto: this.store.crypto,
            key: await this.store.encryptionKey()
          });
        }
        const runtime = this.runtimeFactory({
          crypto: this.crypto,
          pqc: this.pqc,
          relationship,
          store: runtimeStore,
          stateKey,
          stateAnchorStore,
          anchorKey,
          relayClientFactory: this.relayClientFactory
        });
        for (const method of [
          "open",
          "prepareText",
          "prepareDeliveryReceipt",
          "prepareReadReceipt",
          "resumeOutbound",
          "syncReceive",
          "relationshipSnapshot",
          "lifecycleSnapshot",
          "updateLifecycle",
          "prepareEndpointPrekeyUpdate",
          "prepareRouteSetUpdate",
          "prepareRouteProbe",
          "finalizeLocalRouteRetirement",
          "updateLocalPolicy",
          "destroyRelationshipState",
          "listOutbound",
          "listReceived",
          "discard"
        ]) {
          if (typeof runtime?.[method] !== "function") {
            throw new TypeError(`Durable browser runtime must implement ${method}(...).`);
          }
        }
        this.runtimes.set(relationshipID, runtime);
        return runtime;
      })());
    }
    try {
      const runtime = await this.runtimePromises.get(relationshipID);
      return runtime;
    } catch (error) {
      this.runtimePromises.delete(relationshipID);
      throw error;
    }
  }

  async storageKey(purpose, ...scope) {
    const material = encoder.encode(`Noctweave/browser/${purpose}/v2\u0000${scope.join("\u0000")}`);
    const digest = await this.crypto.sha256(material);
    return `${purpose}-v2:${base64(digest)}`;
  }

  async reconcileRelationship(runtime, relationship, persistAppliedRelationship) {
    if (persistAppliedRelationship !== undefined &&
        typeof persistAppliedRelationship !== "function") {
      throw new TypeError("persistAppliedRelationship must be a function.");
    }
    const current = await runtime.relationshipSnapshot();
    if (JSON.stringify(current) !== JSON.stringify(relationship)) {
      if (persistAppliedRelationship === undefined) {
        throw new BrowserMessagingAvailabilityError(
          "relationshipPersistenceRequired",
          "Newer durable relationship state must be persisted before network progress."
        );
      }
      await persistAppliedRelationship({ relationship: current, received: Object.freeze([]) });
    }
    return current;
  }

  async prepareEnabledDeliveryReceipts(runtime) {
    const relationship = await runtime.relationshipSnapshot();
    if (relationship.localPolicy.consent !== "accepted" ||
        !relationship.localPolicy.deliveryReceiptsEnabled) {
      return Object.freeze({ enabled: false, prepared: 0 });
    }
    const received = await runtime.listReceived();
    const outbound = await runtime.listOutbound();
    const existingTransactions = new Set(outbound.map(({ clientTransactionId }) =>
      clientTransactionId));
    let prepared = 0;
    for (const item of received) {
      if (item.event?.kind !== "application") continue;
      const clientTransactionId = await this.receiptTransactionID(
        "delivery",
        relationship.relationshipID,
        item.event.id
      );
      if (existingTransactions.has(clientTransactionId)) continue;
      await runtime.prepareDeliveryReceipt({
        targetEventId: item.event.id,
        clientTransactionId
      });
      existingTransactions.add(clientTransactionId);
      prepared += 1;
    }
    if (prepared > 0) await runtime.resumeOutbound();
    return Object.freeze({ enabled: true, prepared });
  }

  async receiptTransactionID(kind, relationshipID, targetEventId) {
    const digest = await this.crypto.sha256(encoder.encode(
      `Noctweave/browser-${kind}-receipt-transaction/v2\u0000${relationshipID}\u0000${targetEventId}`
    ));
    const bytes = new Uint8Array(digest.subarray(0, 16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
}

export class BrowserMessagingAvailabilityError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "BrowserMessagingAvailabilityError";
    this.code = code;
  }
}

export function describeBrowserRelationshipAvailabilityV2(relationship, at = Date.now()) {
  requireRelationshipID(relationship);
  if (!Number.isFinite(at)) throw new TypeError("Relationship availability time is invalid.");
  const consent = relationship.localPolicy?.consent;
  const canSendByPolicy = relationshipAllowsUserSendingV2(relationship.localPolicy);
  const canReceiveByPolicy = relationshipAcceptsInboundEventsV2(relationship.localPolicy);
  const muted = relationshipIsMutedV2(relationship.localPolicy, at);
  const outboundRoutes = usablePairwiseRoutesV2(relationship.peerIdentity.sendRoutes, at);
  const localRoutes = relationship.localReceiveRoutes ?? [];
  const activeReceiveRoutes = localRoutes.filter(({ route, gapState }) =>
    gapState === null && Date.parse(route.lease.expiresAt) > at);
  const hasContinuityGap = localRoutes.some(({ gapState }) => gapState !== null);
  const expiries = [
    ...outboundRoutes.map(({ expiresAt }) => Date.parse(expiresAt)),
    ...activeReceiveRoutes.map(({ route }) => Date.parse(route.lease.expiresAt))
  ].filter(Number.isFinite);
  const nextRouteExpiry = expiries.length === 0 ? null : Math.min(...expiries);
  let maintenanceState = "current";
  let message = muted ? "Active pairwise routes; notifications are muted locally." : "Active pairwise routes.";
  if (consent === "blocked") {
    maintenanceState = "blocked";
    message = "Blocked locally. Sending and receiving are disabled for this relationship.";
  } else if (consent === "pendingRequest") {
    maintenanceState = "pendingRequest";
    message = "Message request is pending. Sending is disabled until you accept it locally.";
  } else if (hasContinuityGap) {
    maintenanceState = "continuityGap";
    message = "A receive-route continuity gap requires explicit recovery; synchronization is paused.";
  } else if (outboundRoutes.length === 0 && activeReceiveRoutes.length === 0) {
    maintenanceState = "routeExpired";
    message = "Both relationship directions lost usable routes. Fresh pairing is required.";
  } else if (activeReceiveRoutes.length === 0) {
    maintenanceState = "routeExpired";
    message = "The local receive route expired before authenticated overlap completed. Fresh pairing is required.";
  } else if (outboundRoutes.length === 0) {
    maintenanceState = "routeExpired";
    message = "The peer has no usable receive route. Local receiving remains available while awaiting an authenticated peer route update.";
  } else if (nextRouteExpiry - at <= routeMaintenanceWindowMilliseconds) {
    maintenanceState = "expiresSoon";
    const localExpiresSoon = activeReceiveRoutes.some(({ route }) =>
      Date.parse(route.lease.expiresAt) - at <= routeMaintenanceWindowMilliseconds);
    const peerExpiresSoon = outboundRoutes.some(({ expiresAt }) =>
      Date.parse(expiresAt) - at <= routeMaintenanceWindowMilliseconds);
    message = localExpiresSoon && peerExpiresSoon
      ? "Both directions expire soon. Local make-before-break rotation is active; the peer independently rotates its route."
      : localExpiresSoon
        ? "The local receive route expires soon. Durable make-before-break rotation is active."
        : "The peer receive route expires soon; its authenticated replacement is awaited.";
  }
  return Object.freeze({
    consent,
    muted,
    canSend: canSendByPolicy && outboundRoutes.length > 0,
    canReceive: canReceiveByPolicy && activeReceiveRoutes.length > 0,
    maintenanceState,
    message,
    activeOutboundRouteCount: outboundRoutes.length,
    activeReceiveRouteCount: activeReceiveRoutes.length,
    nextRouteExpiry: nextRouteExpiry === null ? null : new Date(nextRouteExpiry).toISOString()
  });
}

export function browserMessageTimelineV2({ outbound, received }) {
  if (!Array.isArray(outbound) || !Array.isArray(received)) {
    throw new TypeError("Browser message timeline requires outbound and received arrays.");
  }
  const timeline = [];
  for (const intent of outbound) {
    if (intent.event?.kind !== "application" || intent.event.content?.disposition !== "visible") continue;
    timeline.push(Object.freeze({
      direction: "outbound",
      eventID: intent.event.id,
      createdAt: intent.event.createdAt,
      text: safeDisplayText(intent.event.content.fallbackText ?? "Unsupported message"),
      contentKind: contentKind(intent.event.content.type),
      relationLabel: relationLabel(intent.event.relation, contentKind(intent.event.content.type)),
      deliveryState: intent.delivery?.state ?? "locallyPersisted",
      deliveryLabel: deliveryLabel(intent.delivery?.state ?? "locallyPersisted"),
      intentStatus: intent.status,
      clientTransactionId: intent.clientTransactionId
    }));
  }
  for (const item of received) {
    if (item.projection?.disposition !== "visible") continue;
    const text = item.projection.kind === "text"
      ? item.projection.text
      : item.projection.fallbackText ?? "Unsupported message";
    timeline.push(Object.freeze({
      direction: "inbound",
      eventID: item.event.id,
      createdAt: item.event.createdAt,
      text: safeDisplayText(text),
      contentKind: item.projection.kind,
      relationLabel: relationLabel(item.event.relation, item.projection.kind),
      deliveryState: null,
      deliveryLabel: "Received",
      intentStatus: null,
      clientTransactionId: null
    }));
  }
  timeline.sort((left, right) =>
    Date.parse(left.createdAt) - Date.parse(right.createdAt) ||
    left.eventID.localeCompare(right.eventID));
  return Object.freeze(timeline);
}

function validateMessageText(value) {
  if (typeof value !== "string") throw new TypeError("Message text is required.");
  const normalized = value.trim();
  if (normalized.length === 0 || encoder.encode(normalized).byteLength > maximumTextBytes) {
    throw new TypeError("Message text must contain 1 to 16384 UTF-8 bytes.");
  }
  return normalized;
}

function requireRelationshipID(relationship) {
  const relationshipID = relationship?.relationshipID;
  if (typeof relationshipID !== "string" || relationshipID.length === 0) {
    throw new TypeError("A pairwise relationship is required.");
  }
  return relationshipID;
}

function contentKind(type) {
  if (type?.authority === "org.noctweave" && type?.major === 1) {
    return new Set(["text", "attachment", "reaction", "retraction"]).has(type.name)
      ? type.name
      : "unsupported";
  }
  return "unsupported";
}

function relationLabel(relation, kind) {
  if (kind === "reaction") return "Reaction";
  if (kind === "retraction") return "Retraction; received copies may remain";
  return ({
    reply: "Reply",
    replacement: "Replacement event",
    reference: "Reference"
  })[relation?.kind] ?? null;
}

function deliveryLabel(value) {
  return ({
    locallyPersisted: "Saved locally",
    relayAccepted: "Relay accepted",
    peerStored: "Delivered",
    peerRead: "Read"
  })[value] ?? "Delivery state unavailable";
}

function safeDisplayText(value) {
  const text = typeof value === "string" ? value : "Unsupported message";
  return text.replace(unsafeDisplayControls, "�");
}

function boundedFailure(error) {
  if (error instanceof DurablePairwiseMessagingV2Error && typeof error.code === "string") {
    return error.code;
  }
  const message = error instanceof Error ? error.message : String(error);
  const sanitized = safeDisplayText(message).slice(0, 160);
  return sanitized || "Synchronization failed";
}

function validateTeardownJournal(value) {
  exactKeys(value, ["stateSchema", "version", "relationships", "updatedAt"], "Route teardown journal");
  if (value.stateSchema !== "org.noctweave.browser-route-teardown.v2" || value.version !== 2 ||
      !Array.isArray(value.relationships) || value.relationships.length > maximumTeardownRelationships) {
    throw new TypeError("Route teardown journal is invalid.");
  }
  const relationshipIDs = new Set();
  for (const record of value.relationships) {
    exactKeys(record, [
      "relationshipID",
      "reason",
      "status",
      "intents",
      "createdAt",
      "updatedAt"
    ], "Route teardown record");
    requireRelationshipID({ relationshipID: record.relationshipID });
    if (relationshipIDs.has(record.relationshipID) ||
        !new Set(["blocked", "burned"]).has(record.reason) ||
        !new Set(["pending", "complete"]).has(record.status) ||
        !Array.isArray(record.intents) || record.intents.length > maximumTeardownRoutes) {
      throw new TypeError("Route teardown record is invalid.");
    }
    relationshipIDs.add(record.relationshipID);
    canonicalTimestamp(record.createdAt, "Route teardown creation time");
    canonicalTimestamp(record.updatedAt, "Route teardown update time");
    const routeIDs = new Set();
    for (const intent of record.intents) {
      exactKeys(intent, [
        "relay",
        "request",
        "teardownCapability",
        "status",
        "lastFailure",
        "tombstone",
        "updatedAt"
      ], "Route teardown intent");
      if (!intent.request || typeof intent.request !== "object" || Array.isArray(intent.request) ||
          intent.request.version !== 2 || typeof intent.request.routeID?.rawValue !== "string" ||
          routeIDs.has(intent.request.routeID.rawValue) ||
          !new Set(["pending", "complete"]).has(intent.status) ||
          (intent.lastFailure !== null &&
            (typeof intent.lastFailure !== "string" || intent.lastFailure.length > 160)) ||
          typeof intent.teardownCapability?.rawValue !== "string") {
        throw new TypeError("Route teardown intent is invalid.");
      }
      routeIDs.add(intent.request.routeID.rawValue);
      if (intent.status === "complete") {
        const tombstone = validateOpaqueReceiveRouteV2(intent.tombstone);
        if (tombstone.status !== "tornDown" ||
            tombstone.routeID.rawValue !== intent.request.routeID.rawValue ||
            tombstone.lease.renewalSequence !== intent.request.renewalSequence) {
          throw new TypeError("Route teardown tombstone does not match its request.");
        }
      } else if (intent.tombstone !== null) {
        throw new TypeError("Pending route teardown cannot contain a tombstone.");
      }
      canonicalTimestamp(intent.updatedAt, "Route teardown intent update time");
    }
    if ((record.status === "complete") !==
        record.intents.every(({ status }) => status === "complete")) {
      throw new TypeError("Route teardown completion state is inconsistent.");
    }
  }
  canonicalTimestamp(value.updatedAt, "Route teardown journal update time");
  return value;
}

async function validateMaintenanceJournal(crypto, value) {
  exactKeys(value, ["stateSchema", "version", "relationships", "updatedAt"],
    "Route maintenance journal");
  if (value.stateSchema !== "org.noctweave.browser-route-maintenance.v2" ||
      value.version !== 2 || !Array.isArray(value.relationships) ||
      value.relationships.length > maximumMaintenanceRelationships) {
    throw new TypeError("Route maintenance journal is invalid.");
  }
  const relationshipIDs = new Set();
  for (const record of value.relationships) {
    exactKeys(record, [
      "relationshipID",
      "relay",
      "clientCapabilities",
      "payloadKey",
      "createRequest",
      "localReceiveRoute",
      "testingSendRoute",
      "replacingRouteIDs",
      "teardownRequest",
      "teardownCapability",
      "tombstone",
      "lastFailure",
      "createdAt",
      "updatedAt"
    ], "Route maintenance record");
    requireRelationshipID(record);
    if (relationshipIDs.has(record.relationshipID)) {
      throw new TypeError("Route maintenance relationships must be unique.");
    }
    relationshipIDs.add(record.relationshipID);
    validateRelayEndpoint(record.relay);
    const capabilities = validateOpaqueRouteClientCapabilityMaterialV2(
      record.clientCapabilities
    );
    validateOpaqueRoutePayloadKeyV2(record.payloadKey);
    const createRequest = await validateOpaqueRouteCreateRequestV2(crypto, record.createRequest);
    if (createRequest.routeID.rawValue !== capabilities.routeID.rawValue ||
        !Array.isArray(record.replacingRouteIDs) || record.replacingRouteIDs.length !== 1) {
      throw new TypeError("Route maintenance creation authority is inconsistent.");
    }
    const replacingIDs = new Set();
    for (const routeID of record.replacingRouteIDs) {
      exactKeys(routeID, ["rawValue"], "Replaced route ID");
      requireFixedBase64(routeID.rawValue, "Replaced route ID");
      if (routeID.rawValue === capabilities.routeID.rawValue || replacingIDs.has(routeID.rawValue)) {
        throw new TypeError("Route maintenance replacement scope is invalid.");
      }
      replacingIDs.add(routeID.rawValue);
    }
    if ((record.localReceiveRoute === null) !== (record.testingSendRoute === null)) {
      throw new TypeError("Route maintenance registration state is inconsistent.");
    }
    if (record.localReceiveRoute !== null) {
      const local = await validateLocalOpaqueReceiveRouteV2({
        crypto,
        route: record.localReceiveRoute
      });
      const testing = validateOpaqueSendRouteV2(record.testingSendRoute);
      if (local.route.routeID.rawValue !== capabilities.routeID.rawValue ||
          testing.routeID.rawValue !== capabilities.routeID.rawValue ||
          testing.state !== "testing") {
        throw new TypeError("Route maintenance registered route is inconsistent.");
      }
    }
    const hasTeardown = record.teardownRequest !== null ||
      record.teardownCapability !== null || record.tombstone !== null;
    if (hasTeardown) {
      if (record.teardownRequest === null || record.teardownCapability === null) {
        throw new TypeError("Route maintenance teardown state is incomplete.");
      }
      const request = await validateOpaqueRouteTeardownRequestV2(
        crypto,
        record.teardownRequest
      );
      exactKeys(record.teardownCapability, ["rawValue"], "Route teardown capability");
      requireFixedBase64(record.teardownCapability.rawValue, "Route teardown capability");
      if (!replacingIDs.has(request.routeID.rawValue)) {
        throw new TypeError("Route maintenance teardown targets another route.");
      }
      if (record.tombstone !== null) {
        const tombstone = validateOpaqueReceiveRouteV2(record.tombstone);
        if (tombstone.status !== "tornDown" ||
            tombstone.routeID.rawValue !== request.routeID.rawValue ||
            tombstone.lease.renewalSequence !== request.renewalSequence) {
          throw new TypeError("Route maintenance tombstone does not match its teardown.");
        }
      }
    }
    if (record.lastFailure !== null &&
        (typeof record.lastFailure !== "string" || record.lastFailure.length > 160)) {
      throw new TypeError("Route maintenance failure is invalid.");
    }
    canonicalTimestamp(record.createdAt, "Route maintenance creation time");
    canonicalTimestamp(record.updatedAt, "Route maintenance update time");
  }
  canonicalTimestamp(value.updatedAt, "Route maintenance journal update time");
  return value;
}

function routeReplacementCandidate(relationship, at) {
  const peerRoutes = usablePairwiseRoutesV2(relationship.peerIdentity.sendRoutes, at);
  const advertised = new Map(relationship.localAdvertisedRoutes.routes.map((route) =>
    [route.routeID.rawValue, route]));
  const eligible = relationship.localReceiveRoutes
    .filter(({ route, gapState }) =>
      gapState === null && advertised.get(route.routeID.rawValue)?.state === "active")
    .sort((left, right) =>
      Date.parse(left.route.lease.expiresAt) - Date.parse(right.route.lease.expiresAt));
  const active = eligible.filter(({ route }) => Date.parse(route.lease.expiresAt) > at);
  if (active.length === 0) {
    return {
      status: "routeExpired",
      failure: "The old receive route expired before make-before-break rotation completed; fresh pairing is required.",
      localRoute: null
    };
  }
  const localRoute = active[0];
  if (Date.parse(localRoute.route.lease.expiresAt) - at > routeMaintenanceWindowMilliseconds) {
    return null;
  }
  if (peerRoutes.length === 0) {
    return {
      status: "awaitingPeerRoute",
      failure: "The peer has no usable route on which to publish a replacement receive route.",
      localRoute: null
    };
  }
  return { status: "replacementNeeded", failure: null, localRoute };
}

function relationshipSigningKeys(relationship) {
  const ownerSigningPublicKey = relationship.localIdentity?.endpointBinding?.signingPublicKey;
  const ownerSigningSecretKey = relationship.localIdentity?.localEndpoint?.signing?.secretKey;
  if (typeof ownerSigningPublicKey !== "string" || typeof ownerSigningSecretKey !== "string") {
    throw new TypeError("Relationship-local route signing authority is missing.");
  }
  return { ownerSigningPublicKey, ownerSigningSecretKey };
}

function transitionTimestamp(previous, at) {
  if (!Number.isFinite(at)) throw new TypeError("Route transition time is invalid.");
  const previousMilliseconds = Date.parse(previous);
  if (!Number.isFinite(previousMilliseconds)) {
    throw new TypeError("Previous route transition time is invalid.");
  }
  return swiftISODate(new Date(Math.max(previousMilliseconds, at)));
}

function applicationVaultPersonaStateKey(vaultScopeID) {
  if (!/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u.test(
    vaultScopeID
  )) {
    throw new TypeError("Application vault scope is invalid.");
  }
  return `browser-persona-v2:${vaultScopeID}`;
}

function validateApplicationVaultAnchor(value) {
  exactKeys(value, [
    "version",
    "relationshipID",
    "generation",
    "stateDigest",
    "authenticationTag"
  ], "Application vault anchor");
  if (value.version !== 2 || value.relationshipID !== APPLICATION_VAULT_SLOT_SCOPE ||
      !Number.isSafeInteger(value.generation) || value.generation < 1) {
    throw new BrowserMessagingAvailabilityError(
      "vaultRollbackDetected",
      "The fixed application vault anchor is invalid."
    );
  }
  const stateDigest = decodeBase64(value.stateDigest);
  const authenticationTag = decodeBase64(value.authenticationTag);
  try {
    if (stateDigest.byteLength !== 32 || authenticationTag.byteLength !== 32) {
      throw new BrowserMessagingAvailabilityError(
        "vaultRollbackDetected",
        "The fixed application vault anchor is malformed."
      );
    }
  } finally {
    stateDigest.fill(0);
    authenticationTag.fill(0);
  }
  return value;
}

function validateApplicationVaultSlotRecord(value) {
  exactKeys(value, [
    "stateSchema",
    "version",
    "status",
    "vaultScopeID",
    "salt",
    "encryptedRecord",
    "createdAt",
    "updatedAt"
  ], "Application vault slot record");
  if (value.stateSchema !== APPLICATION_VAULT_SCHEMA || value.version !== 2 ||
      !new Set(["active", "burning", "burned"]).has(value.status)) {
    throw new BrowserMessagingAvailabilityError(
      "vaultRollbackDetected",
      "The fixed application vault record is invalid."
    );
  }
  applicationVaultPersonaStateKey(value.vaultScopeID);
  canonicalTimestamp(value.createdAt, "Application vault creation time");
  canonicalTimestamp(value.updatedAt, "Application vault update time");
  if (Date.parse(value.updatedAt) < Date.parse(value.createdAt)) {
    throw new BrowserMessagingAvailabilityError(
      "vaultRollbackDetected",
      "The fixed application vault time moved backwards."
    );
  }
  if (value.status === "active" || value.status === "burning") {
    const salt = decodeBase64(value.salt);
    try {
      if (salt.byteLength !== 16 || !value.encryptedRecord ||
          typeof value.encryptedRecord !== "object" || Array.isArray(value.encryptedRecord) ||
          encoder.encode(JSON.stringify(value.encryptedRecord)).byteLength > 12 * 1_024 * 1_024) {
        throw new BrowserMessagingAvailabilityError(
          "vaultRollbackDetected",
          "The active application vault payload is invalid."
        );
      }
    } finally {
      salt.fill(0);
    }
  } else if (value.salt !== null || value.encryptedRecord !== null) {
    throw new BrowserMessagingAvailabilityError(
      "vaultRollbackDetected",
      "A burned application vault retained live encrypted authority."
    );
  }
  return value;
}

function monotonicTimestamp(previous) {
  const prior = Date.parse(previous);
  if (!Number.isFinite(prior)) throw new TypeError("Previous application vault time is invalid.");
  return swiftISODate(new Date(Math.max(prior, Date.now())));
}

function uuidFromDigest(digest) {
  const bytes = new Uint8Array(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function requireFixedBase64(value, label) {
  const bytes = decodeBase64(value);
  if (bytes.byteLength !== 32 || bytes.every((byte) => byte === 0)) {
    bytes.fill(0);
    throw new TypeError(`${label} is invalid.`);
  }
  bytes.fill(0);
}

function validateRelayEndpoint(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Route maintenance relay endpoint is invalid.");
  }
  const allowed = new Set([
    "host",
    "port",
    "useTLS",
    "transport",
    "tlsCertificateFingerprintSHA256",
    "directorySigningPublicKey"
  ]);
  if (Object.keys(value).some((field) => !allowed.has(field)) ||
      typeof value.host !== "string" || value.host.length === 0 || value.host.length > 255 ||
      !Number.isInteger(value.port) || value.port < 1 || value.port > 65_535 ||
      typeof value.useTLS !== "boolean" ||
      !new Set(["tcp", "http", "websocket"]).has(value.transport)) {
    throw new TypeError("Route maintenance relay endpoint is invalid.");
  }
  if (value.tlsCertificateFingerprintSHA256 !== undefined) {
    requireFixedBase64(value.tlsCertificateFingerprintSHA256, "Relay TLS fingerprint");
  }
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new TypeError(`${label} fields do not match the current schema.`);
  }
}

function canonicalTimestamp(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || swiftISODate(new Date(milliseconds)) !== value) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function decodeBase64(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 16_384) {
    throw new TypeError("Relationship public key encoding is invalid.");
  }
  let bytes;
  try {
    bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  } catch {
    throw new TypeError("Relationship public key encoding is invalid.");
  }
  if (base64(bytes) !== value) {
    bytes.fill(0);
    throw new TypeError("Relationship public key encoding is not canonical.");
  }
  return bytes;
}
