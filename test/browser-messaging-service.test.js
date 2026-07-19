import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  EncryptedNoctweaveStore,
  MemoryNoctweaveStore,
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  WebCryptoPrimitives,
  base64,
  createContactPairingInvitationV2,
  createOpaqueReceiveRouteV2,
  createProtocolCapabilityManifest,
  decodeContactPairingInvitationV2,
  encodeContactPairingInvitationV2,
  prepareContactPairingParticipantV2,
  swiftISODate,
  teardownOpaqueReceiveRouteV2
} from "../src/index.js";
import {
  BrowserMessagingAvailabilityError,
  NoctweaveBrowserMessagingServiceV2,
  browserMessageTimelineV2,
  browserMessagingAttachmentBlocker,
  describeBrowserRelationshipAvailabilityV2
} from "../client/messaging-service.js";
import { runContactPairingConformanceV2 } from "../test-support/contact-pairing-conformance.js";

const relay = { host: "127.0.0.1", port: 9_339, useTLS: false, transport: "http" };

test("browser service sends through the durable runtime and stores only encrypted scoped records", async () => {
  const fixture = await pairedFixture();
  const backend = new MemoryNoctweaveStore();
  const store = encryptedStore(backend, 41);
  let acceptance = 0;
  const service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store,
    stateAnchorStoreFactory: testAnchorFactory(),
    relayClientFactory: () => ({
      enqueueOpaqueRoute: async ({ packet }) => enqueueReceipt(packet, ++acceptance)
    })
  });
  const result = await service.sendText({ relationship: fixture.alice, text: "  hello browser  " });

  assert.equal(result.snapshot.timeline.length, 1);
  assert.equal(result.snapshot.timeline[0].text, "hello browser");
  assert.equal(result.snapshot.timeline[0].deliveryState, "relayAccepted");
  assert.equal(result.snapshot.timeline[0].deliveryLabel, "Relay accepted");
  assert.equal(result.snapshot.timeline[0].direction, "outbound");
  const raw = [...backend.records.entries()];
  assert.equal(raw.length, 1);
  assert.equal(raw[0][0].includes(fixture.alice.relationshipID), false);
  assert.equal(JSON.stringify(raw).includes("hello browser"), false);
  assert.equal(raw[0][1].__noctweaveEncrypted, 1);
  const aliceSafetyNumber = await service.safetyNumber(fixture.alice);
  const bobSafetyNumber = await service.safetyNumber(fixture.bob);
  assert.equal(aliceSafetyNumber.display, bobSafetyNumber.display);
  assert.match(aliceSafetyNumber.display, /^\d{5}( \d{5}){11}$/);
  assert.equal(aliceSafetyNumber.display.includes(fixture.alice.localIdentity.signingFingerprint), false);
});

test("route blocking persists an exact encrypted teardown before I/O and retries after restart", async () => {
  const fixture = await pairedFixture();
  const backend = new MemoryNoctweaveStore();
  const store = encryptedStore(backend, 44);
  const anchorFactory = testAnchorFactory();
  const attempted = [];
  let fail = true;
  let service;
  const relayClientFactory = () => ({
    teardownOpaqueRoute: async (submission) => {
      const lifecycle = await service.runtimes.get(fixture.alice.relationshipID)
        .lifecycleSnapshot();
      assert.equal(lifecycle.routeTeardown.status, "pending");
      attempted.push(JSON.stringify(submission));
      if (fail) throw new Error("relay unavailable");
      return teardownOpaqueReceiveRouteV2({
        crypto: fixture.crypto,
        current: fixture.alice.localReceiveRoutes[0].route,
        request: submission.request,
        presentedCapability: submission.teardownCapability,
        confidentialTransport: true,
        receivedAt: submission.request.authorizedAt
      });
    }
  });
  service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store,
    stateAnchorStoreFactory: anchorFactory,
    relayClientFactory
  });
  const first = await service.teardownRelationshipRoutes(fixture.alice, "blocked");
  assert.equal(first.complete, false);
  assert.equal(first.failures.length, 1);
  const pending = await service.runtimes.get(fixture.alice.relationshipID).lifecycleSnapshot();
  assert.equal(pending.routeTeardown.status, "pending");
  assert.equal(JSON.stringify([...backend.records.values()]).includes(
    fixture.alice.localReceiveRoutes[0].clientCapabilities.teardownCapability.rawValue
  ), false);

  fail = false;
  const reopened = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(backend, 44),
    stateAnchorStoreFactory: anchorFactory,
    relayClientFactory
  });
  const resumed = await reopened.resumeRouteTeardowns({
    relationship: fixture.alice,
    relationshipID: fixture.alice.relationshipID
  });
  assert.equal(resumed.complete, true);
  assert.equal(attempted.length, 2);
  assert.equal(attempted[0], attempted[1]);
  const tornDown = await reopened.availabilityFor(fixture.alice);
  assert.equal(tornDown.routeTeardownState, "complete");
  assert.equal(tornDown.maintenanceState, "routesTornDown");
  assert.equal(tornDown.canReceive, false);
  assert.equal(tornDown.canSend, false);
});

test("make-before-break persists fresh route authority before relay creation and publishes testing state", async () => {
  const now = Date.now();
  const fixture = await pairedFixture(swiftISODate(new Date(now - (5 * 60 + 40) * 60_000)));
  const backend = new MemoryNoctweaveStore();
  const store = encryptedStore(backend, 46);
  let acceptance = 0;
  let createCalls = 0;
  const relayRoutes = new Map([[
    fixture.alice.localReceiveRoutes[0].route.routeID.rawValue,
    fixture.alice.localReceiveRoutes[0].route
  ]]);
  let service;
  service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store,
    stateAnchorStoreFactory: testAnchorFactory(),
    relayClientFactory: () => ({
      createOpaqueRoute: async ({ request, renewCapability }) => {
        const lifecycle = await service.runtimes.get(fixture.alice.relationshipID)
          .lifecycleSnapshot();
        assert.deepEqual(lifecycle.routeMaintenance.createRequest, request);
        createCalls += 1;
        const route = await createOpaqueReceiveRouteV2({
          crypto: fixture.crypto,
          request,
          presentedRenewCapability: renewCapability,
          confidentialTransport: true,
          receivedAt: request.lease.issuedAt
        });
        relayRoutes.set(route.routeID.rawValue, route);
        return route;
      },
      enqueueOpaqueRoute: async ({ packet }) => enqueueReceipt(packet, ++acceptance),
      teardownOpaqueRoute: async ({ request, teardownCapability }) => {
        const tombstone = await teardownOpaqueReceiveRouteV2({
          crypto: fixture.crypto,
          current: relayRoutes.get(request.routeID.rawValue),
          request,
          presentedCapability: teardownCapability,
          confidentialTransport: true,
          receivedAt: request.authorizedAt
        });
        relayRoutes.set(request.routeID.rawValue, tombstone);
        return tombstone;
      }
    })
  });
  let persisted = fixture.alice;
  const maintained = await service.maintainRelationship(fixture.alice, {
    at: now,
    persistAppliedRelationship: async ({ relationship }) => {
      persisted = structuredClone(relationship);
    }
  });
  assert.equal(createCalls, 1);
  assert.equal(maintained.routes, "testingPublished", JSON.stringify(maintained));
  assert.equal(persisted.localReceiveRoutes.length, 2);
  assert.equal(persisted.localAdvertisedRoutes.routes.some(({ state }) => state === "testing"), true);
  const lifecycle = await service.runtimes.get(fixture.alice.relationshipID).lifecycleSnapshot();
  const capability = lifecycle.routeMaintenance.clientCapabilities.teardownCapability.rawValue;
  assert.equal(JSON.stringify([...backend.records.values()]).includes(capability), false);
  const blocked = await service.teardownRelationshipRoutes(fixture.alice, "blocked", now);
  assert.equal(blocked.complete, true);
  const blockedLifecycle = await service.runtimes.get(fixture.alice.relationshipID)
    .lifecycleSnapshot();
  assert.equal(blockedLifecycle.routeTeardown.intents.length, 2);
  assert.equal(blockedLifecycle.routeMaintenance, null);
});

test("browser messaging fails closed without an embedding-host rollback anchor", async () => {
  const fixture = await pairedFixture();
  const service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(new MemoryNoctweaveStore(), 47),
    relayClientFactory: () => ({})
  });
  await assert.rejects(
    () => service.sendText({ relationship: fixture.alice, text: "not without anchor" }),
    (error) => error.code === "rollbackAnchorUnavailable" &&
      /Ordinary browser storage does not provide hardware rollback resistance/.test(error.message)
  );
  await assert.rejects(
    () => service.destroyRollbackAnchors([fixture.alice]),
    (error) => error.code === "rollbackAnchorDestructionUnavailable"
  );
});

test("persona burn destroys external relationship anchors idempotently across service restart", async () => {
  const fixture = await pairedFixture();
  const coordinator = new TestRelationshipAnchorStore();
  const factory = async () => coordinator;
  const options = {
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(new MemoryNoctweaveStore(), 48),
    stateAnchorStoreFactory: factory,
    relayClientFactory: () => ({})
  };
  const first = new NoctweaveBrowserMessagingServiceV2(options);
  const initial = await first.destroyRollbackAnchors([fixture.alice]);
  assert.deepEqual(initial, { complete: true, destroyed: 1 });
  const restarted = new NoctweaveBrowserMessagingServiceV2(options);
  const repeated = await restarted.destroyRollbackAnchors([fixture.alice]);
  assert.deepEqual(repeated, { complete: true, destroyed: 1 });
  assert.equal(coordinator.destroyCalls.length, 1);
  assert.equal(coordinator.destroyCalls[0].relationshipID, fixture.alice.relationshipID);
  assert.equal(coordinator.erased.size, 1);
});

test("persona burn retains the blocked vault when external anchor erasure fails", async () => {
  const fixture = await pairedFixture();
  const coordinator = new TestRelationshipAnchorStore();
  coordinator.failDestroy = true;
  const service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(new MemoryNoctweaveStore(), 49),
    stateAnchorStoreFactory: async () => coordinator,
    relayClientFactory: () => ({})
  });
  await assert.rejects(
    () => service.destroyRollbackAnchors([fixture.alice]),
    (error) => error.code === "rollbackAnchorDestructionFailed" &&
      /blocked encrypted vault was retained/.test(error.message)
  );
  const missingDestroy = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(new MemoryNoctweaveStore(), 50),
    stateAnchorStoreFactory: async () => ({ load() {}, commit() {} }),
    relayClientFactory: () => ({})
  });
  await assert.rejects(
    () => missingDestroy.destroyRollbackAnchors([fixture.alice]),
    (error) => error.code === "rollbackAnchorDestructionUnavailable"
  );
});

test("browser service synchronizes every healthy local route and keeps local-first runtime ownership", async () => {
  const fixture = await pairedFixture();
  const calls = [];
  const runtime = {
    open: async () => ({}),
    prepareText: async () => ({}),
    prepareDeliveryReceipt: async () => ({}),
    prepareReadReceipt: async () => ({}),
    resumeOutbound: async () => ({ completed: 0, intents: [] }),
    relationshipSnapshot: async () => fixture.alice,
    lifecycleSnapshot: async () => ({ routeMaintenance: null, routeTeardown: null }),
    updateLifecycle: async () => ({ routeMaintenance: null, routeTeardown: null }),
    prepareEndpointPrekeyUpdate: async () => ({}),
    prepareRouteSetUpdate: async () => ({}),
    prepareRouteProbe: async () => ({}),
    finalizeLocalRouteRetirement: async () => ({ retired: true }),
    updateLocalPolicy: async () => ({}),
    destroyRelationshipState: async () => ({ destroyed: true }),
    syncReceive: async ({ client, routeID, authorizedAt }) => {
      calls.push({ client, routeID, authorizedAt });
      return { received: [], hasMore: false, relayCommit: { status: "deferred" } };
    },
    listOutbound: async () => [],
    listReceived: async () => [],
    discard: async () => ({})
  };
  const service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(new MemoryNoctweaveStore(), 42),
    stateAnchorStoreFactory: testAnchorFactory(),
    relayClientFactory: (endpoint) => ({ endpoint }),
    runtimeFactory: () => runtime,
    webClientFactory: (options) => ({ ...options, syncOpaqueRoute() {}, commitOpaqueRoute() {} })
  });
  const synchronized = await service.syncReceiveRoutes(fixture.alice);

  assert.equal(calls.length, fixture.alice.localReceiveRoutes.length);
  assert.deepEqual(synchronized.outcomes.map(({ status }) => status), ["localCommitted"]);
  assert.equal(calls[0].routeID, fixture.alice.localReceiveRoutes[0].route.routeID.rawValue);
  assert.match(calls[0].authorizedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test("browser open reconciles newer durable relationship state before network progress", async () => {
  const fixture = await pairedFixture();
  const updated = structuredClone(fixture.alice);
  updated.localPolicy.mutedUntil = swiftISODate(new Date(Date.now() + 60_000));
  const runtime = {
    open: async () => ({}),
    prepareText: async () => ({}),
    prepareDeliveryReceipt: async () => ({}),
    prepareReadReceipt: async () => ({}),
    resumeOutbound: async () => ({ completed: 0, intents: [] }),
    relationshipSnapshot: async () => updated,
    lifecycleSnapshot: async () => ({ routeMaintenance: null, routeTeardown: null }),
    updateLifecycle: async () => ({ routeMaintenance: null, routeTeardown: null }),
    prepareEndpointPrekeyUpdate: async () => ({}),
    prepareRouteSetUpdate: async () => ({}),
    prepareRouteProbe: async () => ({}),
    finalizeLocalRouteRetirement: async () => ({ retired: true }),
    updateLocalPolicy: async () => ({}),
    destroyRelationshipState: async () => ({ destroyed: true }),
    syncReceive: async () => ({ received: [], hasMore: false, relayCommit: { status: "deferred" } }),
    listOutbound: async () => [],
    listReceived: async () => [],
    discard: async () => ({})
  };
  let persisted = null;
  let anchorRequest = null;
  let runtimeOptions = null;
  const anchorCoordinator = new TestRelationshipAnchorStore();
  const atomicStateBackend = new MemoryNoctweaveStore();
  anchorCoordinator.encryptedStateStoreBackend = atomicStateBackend;
  const personaStore = encryptedStore(new MemoryNoctweaveStore(), 45);
  const service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: personaStore,
    stateAnchorStoreFactory: async (request) => {
      anchorRequest = request;
      return anchorCoordinator;
    },
    relayClientFactory: () => ({}),
    runtimeFactory: (options) => {
      runtimeOptions = options;
      return runtime;
    }
  });
  await service.open(fixture.alice, {
    persistAppliedRelationship: async ({ relationship }) => {
      persisted = structuredClone(relationship);
    }
  });
  assert.deepEqual(persisted, updated);
  assert.equal(anchorRequest.relationshipID, fixture.alice.relationshipID);
  assert.notEqual(anchorRequest.anchorKey, anchorRequest.stateKey);
  assert.equal(anchorRequest.anchorKey.includes(fixture.alice.relationshipID), false);
  assert.equal(runtimeOptions.anchorKey, anchorRequest.anchorKey);
  assert.equal(runtimeOptions.stateAnchorStore, anchorCoordinator);
  assert.notEqual(runtimeOptions.store, personaStore);
  assert.equal(runtimeOptions.store.store, atomicStateBackend);
  assert.equal(await runtimeOptions.store.encryptionKey(), await personaStore.encryptionKey());
  await assert.rejects(
    () => service.open(fixture.alice),
    (error) => error.code === "relationshipPersistenceRequired"
  );
});

test("anchored block wins over a restored accepted aggregate projection", async () => {
  const fixture = await pairedFixture();
  const coordinator = new TestRelationshipAnchorStore();
  const backend = new MemoryNoctweaveStore();
  const service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(backend, 51),
    stateAnchorStoreFactory: async () => coordinator,
    relayClientFactory: () => ({})
  });
  const accepted = await service.open(fixture.alice);
  assert.equal(accepted.availability.consent, "accepted");
  const generation = [...coordinator.records.values()][0].generation;
  const blockedPolicy = { ...fixture.alice.localPolicy, consent: "blocked" };
  await service.updateRelationshipLocalPolicy(fixture.alice, blockedPolicy);
  assert.equal([...coordinator.records.values()][0].generation, generation + 1);

  // Simulate the crash window before the aggregate projection was saved: the
  // caller restarts with its old accepted relationship record.
  const restarted = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(backend, 51),
    stateAnchorStoreFactory: async () => coordinator,
    relayClientFactory: () => ({})
  });
  await assert.rejects(
    () => restarted.open(fixture.alice),
    (error) => error.code === "relationshipPersistenceRequired"
  );
  let corrected = null;
  const reopened = await restarted.open(fixture.alice, {
    persistAppliedRelationship: async ({ relationship }) => {
      corrected = structuredClone(relationship);
    }
  });
  assert.equal(corrected.localPolicy.consent, "blocked");
  assert.equal(reopened.availability.consent, "blocked");
  assert.equal(reopened.availability.canSend, false);
  await assert.rejects(
    () => restarted.updateRelationshipLocalPolicy(corrected, fixture.alice.localPolicy),
    (error) => error.code === "terminalPolicyRollback"
  );
});

test("blocked, expiring, and expired routes are represented honestly and fail closed", async () => {
  const fixture = await pairedFixture();
  const createdAt = Date.parse(fixture.alice.createdAt);
  const current = describeBrowserRelationshipAvailabilityV2(fixture.alice, createdAt);
  assert.equal(current.canSend, true);
  assert.equal(current.canReceive, true);

  const blocked = structuredClone(fixture.alice);
  blocked.localPolicy.consent = "blocked";
  const blockedState = describeBrowserRelationshipAvailabilityV2(blocked, createdAt);
  assert.equal(blockedState.maintenanceState, "blocked");
  assert.equal(blockedState.canSend, false);
  assert.equal(blockedState.canReceive, false);

  const expiry = Date.parse(fixture.alice.localReceiveRoutes[0].route.lease.expiresAt);
  const expiring = describeBrowserRelationshipAvailabilityV2(fixture.alice, expiry - 10 * 60_000);
  assert.equal(expiring.maintenanceState, "expiresSoon");
  const expired = describeBrowserRelationshipAvailabilityV2(fixture.alice, expiry + 1);
  assert.equal(expired.maintenanceState, "routeExpired");
  assert.equal(expired.canReceive, false);

  const service = new NoctweaveBrowserMessagingServiceV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    store: encryptedStore(new MemoryNoctweaveStore(), 43),
    stateAnchorStoreFactory: testAnchorFactory(),
    relayClientFactory: () => ({})
  });
  await assert.rejects(
    () => service.sendText({ relationship: blocked, text: "must not send", at: createdAt }),
    (error) => error instanceof BrowserMessagingAvailabilityError && error.code === "blocked"
  );
  await assert.rejects(
    () => service.prepareFile({ relationship: fixture.alice }),
    (error) => error.code === "attachmentUnavailable" &&
      error.message === browserMessagingAttachmentBlocker
  );
});

test("browser timeline renders authenticated fallback and receipt state without control spoofing", () => {
  const outbound = [{
    event: {
      id: "00000000-0000-4000-8000-000000000001",
      kind: "application",
      createdAt: "2026-07-18T12:00:00Z",
      content: {
        type: { authority: "example.test", name: "note", major: 1, minor: 0 },
        disposition: "visible",
        fallbackText: "safe\u202Eunsafe"
      },
      relation: { kind: "replacement", targetEventId: "00000000-0000-4000-8000-000000000009" }
    },
    status: "retryableFailure",
    clientTransactionId: "00000000-0000-4000-8000-000000000002",
    delivery: { state: "locallyPersisted" }
  }];
  const received = [{
    event: { id: "00000000-0000-4000-8000-000000000003", createdAt: "2026-07-18T12:01:00Z" },
    projection: { kind: "unsupported", disposition: "visible", fallbackText: "Authenticated fallback" }
  }, {
    event: { id: "00000000-0000-4000-8000-000000000004", createdAt: "2026-07-18T12:02:00Z" },
    projection: { kind: "readReceipt", disposition: "silent", fallbackText: null }
  }];
  const timeline = browserMessageTimelineV2({ outbound, received });

  assert.equal(timeline.length, 2);
  assert.equal(timeline[0].text, "safe�unsafe");
  assert.equal(timeline[0].deliveryLabel, "Saved locally");
  assert.equal(timeline[0].relationLabel, "Replacement event");
  assert.equal(timeline[1].text, "Authenticated fallback");
  assert.equal(JSON.stringify(timeline).includes("routeCapability"), false);
});

async function pairedFixture(createdAt = swiftISODate()) {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const crypto = new NoctweaveCryptoSuite({ pqc, webcrypto: new WebCryptoPrimitives() });
  const expiresAt = swiftISODate(new Date(Date.parse(createdAt) + 10 * 60_000));
  const made = await createContactPairingInvitationV2({ crypto, createdAt, expiresAt });
  const encoded = await encodeContactPairingInvitationV2({ crypto, invitation: made.invitation });
  const invitation = await decodeContactPairingInvitationV2({ crypto, encoded });
  const endpointCapabilities = createProtocolCapabilityManifest();
  const alice = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    relationshipPseudonym: "Alice for Bob",
    relay,
    createdAt,
    endpointCapabilities
  });
  const bob = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    relationshipPseudonym: "Bob for Alice",
    relay,
    createdAt,
    endpointCapabilities
  });
  const paired = await runContactPairingConformanceV2({
    crypto,
    pqc,
    pending: made.pending,
    invitation,
    offerer: alice,
    responder: bob,
    at: createdAt
  });
  return { crypto, pqc, alice: paired.offererRelationship, bob: paired.responderRelationship };
}

function encryptedStore(backend, marker) {
  return new EncryptedNoctweaveStore(backend, {
    crypto: globalThis.crypto,
    keyBytes: new Uint8Array(32).fill(marker)
  });
}

function enqueueReceipt(packet, marker) {
  const cursor = { rawValue: base64(new Uint8Array(68).fill((marker % 250) + 1)) };
  return { packetID: packet.packetID, acceptedCursor: cursor, highWatermark: cursor };
}

function testAnchorFactory() {
  // Test-only coordinator: this exercises the mandatory authenticated CAS
  // contract, but deliberately makes no production rollback-resistance claim.
  const coordinator = new TestRelationshipAnchorStore();
  return async () => coordinator;
}

class TestRelationshipAnchorStore {
  constructor() {
    this.records = new Map();
    this.erased = new Set();
    this.key = new Uint8Array(32).fill(0xb4);
    this.destroyCalls = [];
    this.failDestroy = false;
  }

  async load({ anchorKey, relationshipID, loadEncryptedState }) {
    if (this.erased.has(anchorKey)) throw new Error("relationship was erased");
    const anchor = this.records.get(anchorKey) ?? null;
    if (anchor !== null) {
      assert.equal(anchor.relationshipID, relationshipID);
      assert.equal(anchor.authenticationTag, await this.authenticationTag(anchor));
    }
    return {
      anchor: anchor === null ? null : structuredClone(anchor),
      state: await loadEncryptedState()
    };
  }

  async commit({
    anchorKey,
    relationshipID,
    expectedAnchor,
    nextGeneration,
    nextStateDigest,
    persistEncryptedState
  }) {
    if (this.erased.has(anchorKey)) throw new Error("relationship was erased");
    const current = this.records.get(anchorKey) ?? null;
    assert.equal(
      current === null ? null : JSON.stringify(current),
      expectedAnchor === null ? null : JSON.stringify(expectedAnchor)
    );
    assert.equal(nextGeneration, (current?.generation ?? 0) + 1);
    const unsigned = {
      version: 2,
      relationshipID,
      generation: nextGeneration,
      stateDigest: nextStateDigest
    };
    const anchor = {
      ...unsigned,
      authenticationTag: await this.authenticationTag(unsigned)
    };
    await persistEncryptedState();
    this.records.set(anchorKey, structuredClone(anchor));
    return anchor;
  }

  async destroy({ anchorKey, relationshipID, expectedAnchor, destroyEncryptedState }) {
    this.destroyCalls.push({ anchorKey, relationshipID });
    if (this.failDestroy) throw new Error("secure host erase failed");
    const current = this.records.get(anchorKey) ?? null;
    if (current !== null) assert.equal(current.relationshipID, relationshipID);
    assert.equal(
      current === null ? null : JSON.stringify(current),
      expectedAnchor === null ? null : JSON.stringify(expectedAnchor)
    );
    await destroyEncryptedState();
    this.records.delete(anchorKey);
    this.erased.add(anchorKey);
    return { destroyed: true };
  }

  async erasureStatus({ anchorKey }) {
    return { erased: this.erased.has(anchorKey) };
  }

  async authenticationTag(anchor) {
    const payload = new TextEncoder().encode(JSON.stringify({
      version: anchor.version,
      relationshipID: anchor.relationshipID,
      generation: anchor.generation,
      stateDigest: anchor.stateDigest
    }));
    const input = new Uint8Array(this.key.byteLength + payload.byteLength);
    input.set(this.key);
    input.set(payload, this.key.byteLength);
    return base64(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input)));
  }
}
