import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  DurablePairwiseMessagingRuntimeV2,
  DurablePairwiseMessagingV2Error,
  EncryptedNoctweaveStore,
  MemoryNoctweaveStore,
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  NoctweaveWebClient,
  WebCryptoPrimitives,
  addTestingPairwiseRouteV2,
  base64,
  canonicalJsonBytes,
  createContentTypeCapabilityV2,
  createContactPairingInvitationV2,
  createEncodedContent,
  createLocalOpaqueReceiveRouteV2,
  createOpaqueReceiveRouteV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePayloadKeyV2,
  createOpaqueRoutePolicyV2,
  createProtocolCapabilityManifest,
  createOpaqueSendRouteV2,
  defaultContentTypeCapabilities,
  encodeContactPairingInvitationV2,
  decodeContactPairingInvitationV2,
  derivePairwiseDirectV4Binding,
  opaqueRouteRecordDigestV2,
  opaqueRoutePacketAuthenticatedDataV2,
  opaqueRoutePacketOperationDigestV2,
  prepareContactPairingParticipantV2,
  sealOpaqueRouteBundleV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteSendAuthorizationV2,
  makeOpaqueRouteCreateRequestV2,
  makeOpaqueRouteTeardownRequestV2,
  promoteProbedPairwiseRouteV2,
  revokeDrainedPairwiseRouteV2,
  renewPairwiseDirectV4PrekeyIfNeeded,
  swiftISODate,
  swiftUUID,
  teardownOpaqueReceiveRouteV2,
  validateOpaqueRouteSyncResponseV2
} from "../src/index.js";
import { runContactPairingConformanceV2 } from "../test-support/contact-pairing-conformance.js";

const relayEndpoint = {
  host: "127.0.0.1",
  port: 9_339,
  useTLS: false,
  transport: "http"
};

test("runtime refuses plaintext storage", async () => {
  const fixture = await pairedFixture();
  assert.throws(() => new DurablePairwiseMessagingRuntimeV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    relationship: fixture.alice,
    store: new MemoryNoctweaveStore()
  }), /requires EncryptedNoctweaveStore/);
});

test("runtime refuses encrypted state without an independent relationship anchor", async () => {
  const fixture = await pairedFixture();
  assert.throws(() => new DurablePairwiseMessagingRuntimeV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    relationship: fixture.alice,
    store: encryptedStore(new ToggleMemoryStore(), 21)
  }), /requires a relationship-local rollback anchor store/);
});

test("secure anchor rejects rolled-back ciphertext and anchor generations", async () => {
  const fixture = await pairedFixture();
  const ciphertextBackend = new ToggleMemoryStore();
  const ciphertextStore = encryptedStore(ciphertextBackend, 22);
  const ciphertextRuntime = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store: ciphertextStore
  });
  await ciphertextRuntime.open();
  const encryptedKey = [...ciphertextBackend.records.keys()][0];
  const generationOneCiphertext = structuredClone(ciphertextBackend.records.get(encryptedKey));
  await ciphertextRuntime.prepareText({ text: "advance anchor", clientTransactionId: swiftUUID() });
  ciphertextBackend.records.set(encryptedKey, generationOneCiphertext);
  await assert.rejects(() => runtimeFor({
    fixture,
    relationship: fixture.alice,
    store: encryptedStore(ciphertextBackend, 22)
  }).open(), (error) => error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "rollbackDetected");

  const anchorBackend = new ToggleMemoryStore();
  const anchorStore = encryptedStore(anchorBackend, 23);
  const anchorRuntime = runtimeFor({ fixture, relationship: fixture.alice, store: anchorStore });
  await anchorRuntime.open();
  const anchorKey = `${stateKey(fixture.alice)}:anchor`;
  const generationOneAnchor = structuredClone(
    anchorBackend.testRelationshipAnchorStore.records.get(anchorKey)
  );
  await anchorRuntime.prepareText({ text: "advance ciphertext", clientTransactionId: swiftUUID() });
  anchorBackend.testRelationshipAnchorStore.records.set(anchorKey, generationOneAnchor);
  await assert.rejects(() => runtimeFor({
    fixture,
    relationship: fixture.alice,
    store: encryptedStore(anchorBackend, 23)
  }).open(), (error) => error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "rollbackDetected");
});

test("relationship burn atomically destroys ciphertext and its independent anchor", async () => {
  const fixture = await pairedFixture();
  const backend = new ToggleMemoryStore();
  const store = encryptedStore(backend, 24);
  const runtime = runtimeFor({ fixture, relationship: fixture.alice, store });
  await runtime.prepareText({ text: "ephemeral", clientTransactionId: swiftUUID() });
  const encryptedKey = [...backend.records.keys()][0];
  const anchorKey = `${stateKey(fixture.alice)}:anchor`;
  assert.ok(backend.records.has(encryptedKey));
  assert.ok(backend.testRelationshipAnchorStore.records.has(anchorKey));

  assert.deepEqual(await runtime.destroyRelationshipState(), { destroyed: true });
  assert.equal(backend.records.has(encryptedKey), false);
  assert.equal(backend.testRelationshipAnchorStore.records.has(anchorKey), false);
  await assert.rejects(() => runtime.open(), (error) =>
    error instanceof DurablePairwiseMessagingV2Error && error.code === "relationshipDestroyed");
});

test("relationship burn remains locally terminal after ciphertext loss", async () => {
  const fixture = await pairedFixture();
  const backend = new ToggleMemoryStore();
  const store = encryptedStore(backend, 26);
  const runtime = runtimeFor({ fixture, relationship: fixture.alice, store });
  await runtime.open();
  const encryptedKey = [...backend.records.keys()][0];
  const anchorKey = `${stateKey(fixture.alice)}:anchor`;
  backend.records.delete(encryptedKey);

  const reopened = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store: encryptedStore(backend, 26)
  });
  assert.deepEqual(await reopened.destroyRelationshipState(), { destroyed: true });
  assert.equal(backend.records.has(encryptedKey), false);
  assert.equal(backend.testRelationshipAnchorStore.records.has(anchorKey), false);
});

test("terminal relationship policy advances the anchor and cannot be rolled back", async () => {
  const fixture = await pairedFixture();
  const backend = new ToggleMemoryStore();
  const store = encryptedStore(backend, 25);
  const runtime = runtimeFor({ fixture, relationship: fixture.alice, store });
  await runtime.open();
  const anchorKey = `${stateKey(fixture.alice)}:anchor`;
  const anchorBefore = structuredClone(backend.testRelationshipAnchorStore.records.get(anchorKey));
  const stateBefore = await store.get(stateKey(fixture.alice));
  const blocked = { ...fixture.alice.localPolicy, consent: "blocked" };

  assert.deepEqual(await runtime.updateLocalPolicy(blocked), blocked);
  assert.equal((await runtime.relationshipSnapshot()).localPolicy.consent, "blocked");
  const anchorAfter = backend.testRelationshipAnchorStore.records.get(anchorKey);
  assert.equal(anchorAfter.generation, anchorBefore.generation + 1);
  assert.notDeepEqual(anchorAfter, anchorBefore);
  assert.notDeepEqual(await store.get(stateKey(fixture.alice)), stateBefore);
  await assert.rejects(
    () => runtime.updateLocalPolicy(fixture.alice.localPolicy),
    (error) => error instanceof DurablePairwiseMessagingV2Error &&
      error.code === "terminalPolicyRollback"
  );
});

test("prepare save failure performs zero relay I/O and advances no persisted ratchet", async () => {
  const fixture = await pairedFixture();
  const backend = new ToggleMemoryStore();
  const store = encryptedStore(backend, 1);
  let relayCreations = 0;
  const runtime = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store,
    relayClientFactory: () => {
      relayCreations += 1;
      throw new Error("network must not be reached");
    }
  });
  await runtime.open();
  const before = await store.get(stateKey(fixture.alice));
  const anchorKey = `${stateKey(fixture.alice)}:anchor`;
  const anchorBefore = structuredClone(backend.testRelationshipAnchorStore.records.get(anchorKey));
  backend.failWrites = true;

  await assert.rejects(
    () => runtime.prepareText({
      text: "persist me before transport",
      clientTransactionId: swiftUUID()
    }),
    /injected storage failure/
  );

  backend.failWrites = false;
  const after = await store.get(stateKey(fixture.alice));
  assert.equal(relayCreations, 0);
  assert.equal(before.sessions.length, 0);
  assert.equal(after.sessions.length, 0);
  assert.equal(after.intents.length, 0);
  assert.deepEqual(backend.testRelationshipAnchorStore.records.get(anchorKey), anchorBefore);
});

test("relay failure reopens with byte-identical envelope and packets", async () => {
  const fixture = await pairedFixture();
  const backend = new ToggleMemoryStore();
  const store = encryptedStore(backend, 2);
  const attempted = [];
  let fail = true;
  const relayClientFactory = () => ({
    enqueueOpaqueRoute: async ({ packet }) => {
      attempted.push(JSON.stringify(packet));
      if (fail) throw new Error("relay unavailable");
      return enqueueReceipt(packet, attempted.length);
    }
  });
  const runtime = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store,
    relayClientFactory
  });
  const prepared = await runtime.prepareText({
    text: "exact retry",
    clientTransactionId: swiftUUID()
  });
  const before = await store.get(stateKey(fixture.alice));
  const exactEnvelope = JSON.stringify(before.intents[0].directEnvelope);
  const exactPacket = JSON.stringify(before.intents[0].routeDeliveries[0].sealedBundle.packets[0]);

  const first = await runtime.resumeOutbound();
  assert.equal(first.completed, 0);
  assert.equal(first.intents[0].status, "retryableFailure");
  assert.equal(attempted[0], exactPacket);

  fail = false;
  const reopened = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store: encryptedStore(backend, 2),
    relayClientFactory
  });
  const persisted = await store.get(stateKey(fixture.alice));
  assert.equal(JSON.stringify(persisted.intents[0].directEnvelope), exactEnvelope);
  assert.equal(
    JSON.stringify(persisted.intents[0].routeDeliveries[0].sealedBundle.packets[0]),
    exactPacket
  );
  const resumed = await reopened.resumeOutbound();
  assert.equal(resumed.completed, 1);
  assert.equal(resumed.intents[0].status, "relayAccepted");
  assert.equal(resumed.intents[0].delivery.state, "relayAccepted");
  assert.equal(attempted[1], attempted[0]);
  assert.equal(resumed.intents[0].event.id, prepared.event.id);
});

test("transient relay failure remains retryable beyond eight attempts and recovers", async () => {
  const fixture = await pairedFixture();
  const store = encryptedStore(new ToggleMemoryStore(), 29);
  let available = false;
  const runtime = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store,
    relayClientFactory: () => ({
      enqueueOpaqueRoute: async ({ packet }) => {
        if (!available) throw new Error("relay offline");
        return enqueueReceipt(packet, 1);
      }
    })
  });
  await runtime.prepareText({ text: "eventual retry", clientTransactionId: swiftUUID() });
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const result = await runtime.resumeOutbound();
    assert.equal(result.completed, 0);
    assert.equal(result.intents[0].status, "retryableFailure");
  }
  assert.equal((await runtime.listOutbound())[0].attemptCount, 8);
  available = true;
  const recovered = await runtime.resumeOutbound();
  assert.equal(recovered.completed, 1);
  assert.equal(recovered.intents[0].status, "relayAccepted");
});

test("outbound attempts every route and accepts a complete fallback after partial first route", async () => {
  const fixture = await pairedFixture();
  const transitionAt = swiftISODate();
  const fallbackLocal = await createTestingReceiveRoute(fixture, transitionAt);
  const fallbackSend = await createOpaqueSendRouteV2({
    crypto: fixture.crypto,
    relay: relayEndpoint,
    route: fallbackLocal.route,
    clientCapabilities: fallbackLocal.clientCapabilities,
    payloadKey: fallbackLocal.payloadKey,
    state: "testing"
  });
  const testingSet = await addTestingPairwiseRouteV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    current: fixture.alice.peerIdentity.sendRoutes,
    route: fallbackSend,
    issuedAt: transitionAt,
    ownerSigningPublicKey: fixture.bob.localIdentity.endpointBinding.signingPublicKey,
    ownerSigningSecretKey: fixture.bob.localIdentity.localEndpoint.signing.secretKey
  });
  const overlapUntil = swiftISODate(new Date(Date.parse(transitionAt) + 60_000));
  const redundantSet = await promoteProbedPairwiseRouteV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    current: testingSet,
    routeID: fallbackSend.routeID,
    replacingRouteIDs: [fixture.alice.peerIdentity.sendRoutes.routes[0].routeID],
    testedAt: transitionAt,
    overlapUntil,
    issuedAt: transitionAt,
    ownerSigningPublicKey: fixture.bob.localIdentity.endpointBinding.signingPublicKey,
    ownerSigningSecretKey: fixture.bob.localIdentity.localEndpoint.signing.secretKey
  });
  const relationship = structuredClone(fixture.alice);
  relationship.peerIdentity.sendRoutes = redundantSet;
  const counts = new Map();
  let firstRouteID = null;
  const runtime = runtimeFor({
    fixture,
    relationship,
    store: encryptedStore(new ToggleMemoryStore(), 30),
    relayClientFactory: () => ({
      enqueueOpaqueRoute: async ({ packet }) => {
        const routeID = packet.routeID.rawValue;
        firstRouteID ??= routeID;
        const count = (counts.get(routeID) ?? 0) + 1;
        counts.set(routeID, count);
        if (routeID === firstRouteID && count > 1) throw new Error("first route offline");
        return enqueueReceipt(packet, count);
      }
    })
  });
  await runtime.prepareText({
    text: "x".repeat(512),
    clientTransactionId: swiftUUID(),
    sentAt: transitionAt
  });
  const result = await runtime.resumeOutbound({ authorizedAt: transitionAt });
  assert.equal(result.completed, 1);
  assert.equal(result.intents[0].status, "relayAccepted");
  assert.equal(counts.size, 2);
  assert.ok(counts.get(firstRouteID) >= 2);
  assert.ok([...counts.entries()].some(([routeID, count]) =>
    routeID !== firstRouteID && count >= 1));
});

test("restart durably refreshes only an expired send proof before relay I/O", async () => {
  const fixture = await pairedFixture();
  const backend = new ToggleMemoryStore();
  const store = encryptedStore(backend, 13);
  const initial = runtimeFor({ fixture, relationship: fixture.alice, store });
  await initial.prepareText({ text: "long offline retry", clientTransactionId: swiftUUID() });
  const before = await store.get(stateKey(fixture.alice));
  const original = before.intents[0].routeDeliveries[0].sealedBundle.packets[0];
  const originalPacketIDs = before.intents[0].routeDeliveries[0].sealedBundle.packets
    .map(({ packetID }) => packetID.rawValue);
  const retryAt = swiftISODate(new Date(
    Date.parse(original.authorization.authorizedAt) + 301_000
  ));
  let observedPersistedPacket = null;
  const alreadyAcceptedPacketIDs = new Set(originalPacketIDs);
  const reopenedStore = encryptedStore(backend, 13);
  const reopened = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store: reopenedStore,
    relayClientFactory: async () => {
      const persisted = await reopenedStore.get(stateKey(fixture.alice));
      observedPersistedPacket = persisted.intents[0]
        .routeDeliveries[0]
        .sealedBundle
        .packets[0];
      return {
        enqueueOpaqueRoute: async ({ packet }) => {
          assert.equal(alreadyAcceptedPacketIDs.has(packet.packetID.rawValue), true);
          return enqueueReceipt(packet, 13);
        }
      };
    }
  });

  const result = await reopened.resumeOutbound({ authorizedAt: retryAt });
  assert.equal(
    result.intents[0].status,
    "relayAccepted",
    JSON.stringify(result.intents[0])
  );
  assert.ok(observedPersistedPacket);
  assert.deepEqual(observedPersistedPacket.packetID, original.packetID);
  assert.equal(observedPersistedPacket.sealedFrame, original.sealedFrame);
  assert.equal(
    observedPersistedPacket.authorization.operationDigest,
    original.authorization.operationDigest
  );
  assert.notDeepEqual(observedPersistedPacket.authorization, original.authorization);
  assert.equal(observedPersistedPacket.authorization.authorizedAt, retryAt);
});

test("client transaction IDs are idempotent and conflicting reuse fails", async () => {
  const fixture = await pairedFixture();
  const store = encryptedStore(new ToggleMemoryStore(), 3);
  const runtime = runtimeFor({ fixture, relationship: fixture.alice, store });
  const transactionID = swiftUUID();
  const first = await runtime.prepareText({ text: "once", clientTransactionId: transactionID });
  const duplicate = await runtime.prepareText({ text: "once", clientTransactionId: transactionID });
  assert.equal(duplicate.id, first.id);
  assert.equal(duplicate.event.id, first.event.id);
  assert.equal((await runtime.listOutbound()).length, 1);
  await assert.rejects(
    () => runtime.prepareText({ text: "different", clientTransactionId: transactionID }),
    (error) => error instanceof DurablePairwiseMessagingV2Error &&
      error.code === "transactionConflict"
  );
});

test("a failed earlier counter blocks every later intent until exact retry succeeds", async () => {
  const fixture = await pairedFixture();
  const backend = new ToggleMemoryStore();
  const store = encryptedStore(backend, 4);
  let failFirst = true;
  const calls = [];
  const relayClientFactory = () => ({
    enqueueOpaqueRoute: async ({ packet }) => {
      calls.push(packet.packetID.rawValue);
      if (failFirst) throw new Error("first counter blocked");
      return enqueueReceipt(packet, calls.length);
    }
  });
  const runtime = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store,
    relayClientFactory
  });
  await runtime.prepareText({ text: "counter zero", clientTransactionId: swiftUUID() });
  await runtime.prepareText({ text: "counter one", clientTransactionId: swiftUUID() });
  const prepared = await store.get(stateKey(fixture.alice));
  assert.deepEqual(prepared.intents.map(({ directEnvelope }) => directEnvelope.messageCounter), [0, 1]);
  const firstPacketIDs = prepared.intents[0].routeDeliveries.flatMap(({ sealedBundle }) =>
    sealedBundle.packets.map(({ packetID }) => packetID.rawValue)
  );
  const secondPacketIDs = prepared.intents[1].routeDeliveries.flatMap(({ sealedBundle }) =>
    sealedBundle.packets.map(({ packetID }) => packetID.rawValue)
  );

  await runtime.resumeOutbound();
  assert.deepEqual(calls, [firstPacketIDs[0]]);
  failFirst = false;
  const resumed = await runtime.resumeOutbound();
  assert.deepEqual(calls.slice(1), [...firstPacketIDs, ...secondPacketIDs]);
  assert.deepEqual(resumed.intents.map(({ status }) => status), ["relayAccepted", "relayAccepted"]);
});

test("receive sync saves reassembly, session, event, and cursor before relay GC", async () => {
  const fixture = await pairedFixture();
  const aliceBackend = new ToggleMemoryStore();
  const aliceStore = encryptedStore(aliceBackend, 5);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  const outbound = await alice.prepareText({
    text: "local transaction before relay GC",
    clientTransactionId: swiftUUID()
  });
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  const packets = aliceState.intents[0].routeDeliveries[0].sealedBundle.packets;

  const bobBackend = new ToggleMemoryStore();
  const order = bobBackend.writeOrder;
  const bobStore = encryptedStore(bobBackend, 6);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.open();
  order.length = 0;
  const localRoute = fixture.bob.localReceiveRoutes[0];
  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: localRoute,
    packets
  });
  const relay = new NoctweaveRelayClient(relayEndpoint, {
    crypto: fixture.crypto,
    fetch: async () => { throw new Error("unexpected HTTP"); }
  });
  relay.syncOpaqueRoute = async () => batch;
  relay.commitOpaqueRoute = async ({ request }) => {
    order.push("relayCommit");
    return {
      committedCursor: request.cursor,
      highWatermark: request.cursor,
      retentionFloor: request.cursor
    };
  };
  const webClient = new NoctweaveWebClient({
    relay,
    store: new MemoryNoctweaveStore(),
    stateKey: "web-client-unused",
    crypto: fixture.crypto
  });

  const result = await bob.syncReceive({
    client: webClient,
    authorizedAt: swiftISODate()
  });
  assert.equal(result.received.length, 1);
  assert.equal(result.received[0].projection.kind, "text");
  assert.equal(result.received[0].projection.text, "local transaction before relay GC");
  assert.equal(result.received[0].event.id, outbound.event.id);
  assert.equal(result.relayCommit.status, "accepted");
  assert.equal(order.at(-1), "relayCommit");
  assert.ok(order.lastIndexOf("localSave") < order.lastIndexOf("relayCommit"));

  const persisted = await bobStore.get(stateKey(fixture.bob));
  assert.equal(persisted.receivedEvents.length, 1);
  assert.equal(persisted.receivedEvents[0].event.id, outbound.event.id);
  assert.equal(persisted.localReceiveRoutes[0].committedSequence, packets.length);
  assert.equal(persisted.sessions.length, 1);
});

test("authenticated malformed packet frames are durably quarantined before cursor advance", async () => {
  const fixture = await pairedFixture();
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 14);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  await alice.prepareText({ text: "terminal packet", clientTransactionId: swiftUUID() });
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  const original = aliceState.intents[0].routeDeliveries[0].sealedBundle.packets[0];
  const authorizedAt = swiftISODate();
  const malformed = await rewriteOpaquePacketAsMalformedFrame({
    fixture,
    packet: original,
    routeRevision: 0,
    authorizedAt
  });
  const bobBackend = new ToggleMemoryStore();
  const bobStore = encryptedStore(bobBackend, 15);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.open();
  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.bob.localReceiveRoutes[0],
    packets: [malformed]
  });
  let relayCommits = 0;
  const result = await bob.syncReceive({
    client: receiveWebClient({
      fixture,
      batch,
      onCommit: () => { relayCommits += 1; }
    }),
    authorizedAt
  });
  assert.equal(relayCommits, 1);
  assert.equal(result.received[0].kind, "quarantinedPacket");
  assert.equal(result.received[0].reason, "malformedFrame");
  const persisted = await bobStore.get(stateKey(fixture.bob));
  assert.equal(persisted.quarantinedPackets.length, 1);
  assert.equal(
    persisted.quarantinedPackets[0].packet.packetID.rawValue,
    malformed.packetID.rawValue
  );
  assert.equal(persisted.localReceiveRoutes[0].committedSequence, 1);
  assert.equal(persisted.receivedEvents.length, 0);
});

test("unknown direct sessions remain retryable and never authorize cursor GC", async () => {
  const fixture = await pairedFixture();
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 16);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  await alice.prepareText({ text: "bootstrap", clientTransactionId: swiftUUID() });
  await alice.prepareText({ text: "requires bootstrap", clientTransactionId: swiftUUID() });
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  const packets = aliceState.intents[1].routeDeliveries[0].sealedBundle.packets;
  const bobStore = encryptedStore(new ToggleMemoryStore(), 17);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.open();
  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.bob.localReceiveRoutes[0],
    packets
  });
  let relayCommits = 0;
  await assert.rejects(
    () => bob.syncReceive({
      client: receiveWebClient({
        fixture,
        batch,
        onCommit: () => { relayCommits += 1; }
      }),
      authorizedAt: swiftISODate()
    }),
    (error) => error instanceof DurablePairwiseMessagingV2Error &&
      error.code === "unknownSession"
  );
  const persisted = await bobStore.get(stateKey(fixture.bob));
  assert.equal(relayCommits, 0);
  assert.equal(persisted.localReceiveRoutes[0].committedSequence, 0);
  assert.equal(persisted.quarantinedPackets.length, 0);
  assert.equal(persisted.quarantinedEnvelopes.length, 0);
  assert.equal(persisted.sessions.length, 0);
});

test("receiver observation time rejects backdated and future-dated authenticated envelopes", async () => {
  const fixture = await pairedFixture();
  const sentAt = swiftISODate();
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 24);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  await alice.prepareText({
    text: "bounded delivery observation",
    clientTransactionId: swiftUUID(),
    sentAt
  });
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  const packets = aliceState.intents[0].routeDeliveries[0].sealedBundle.packets;
  const retentionMilliseconds = fixture.bob.localReceiveRoutes[0]
    .route.lease.policy.retentionBucket * 1_000;
  const observedTooLate = swiftISODate(new Date(Date.parse(sentAt) + retentionMilliseconds + 1_000));
  const bobBackend = new ToggleMemoryStore();
  const bobStore = encryptedStore(bobBackend, 25);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.open();
  const lateBatch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.bob.localReceiveRoutes[0],
    packets
  });
  let lateCommits = 0;
  await assert.rejects(() => bob.syncReceive({
    client: receiveWebClient({
      fixture,
      batch: lateBatch,
      onCommit: () => { lateCommits += 1; }
    }),
    authorizedAt: observedTooLate
  }), (error) => error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "invalidInboundFreshness");
  assert.equal(lateCommits, 0);
  assert.equal((await bobStore.get(stateKey(fixture.bob))).sessions.length, 0);

  const futureSentAt = swiftISODate(new Date(Date.now() + 6 * 60_000));
  const futureAliceStore = encryptedStore(new ToggleMemoryStore(), 26);
  const futureAlice = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store: futureAliceStore
  });
  await futureAlice.prepareText({
    text: "future attribution",
    clientTransactionId: swiftUUID(),
    sentAt: futureSentAt
  });
  const futureState = await futureAliceStore.get(stateKey(fixture.alice));
  const futureBatch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.bob.localReceiveRoutes[0],
    packets: futureState.intents[0].routeDeliveries[0].sealedBundle.packets
  });
  await assert.rejects(() => bob.syncReceive({
    client: receiveWebClient({ fixture, batch: futureBatch }),
    authorizedAt: swiftISODate()
  }), (error) => error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "invalidInboundFreshness");
});

test("prekey transition retains exact in-flight endpoint bindings", async () => {
  const fixture = await pairedFixture({ routeDurationMilliseconds: 9 * 86_400_000 });
  const originalBobBinding = structuredClone(fixture.bob.localIdentity.endpointBinding);
  const renewalAt = swiftISODate(new Date(
    Date.parse(originalBobBinding.prekeyBundle.signedPrekey.expiresAt) - 2 * 86_400_000
  ));
  const inFlightAt = swiftISODate(new Date(Date.parse(renewalAt) - 1_000));
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 27);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  await alice.prepareText({
    text: "sent before peer prekey publication",
    clientTransactionId: swiftUUID(),
    sentAt: inFlightAt
  });
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  const inFlightPackets = aliceState.intents[0].routeDeliveries[0].sealedBundle.packets;

  const renewedIdentity = structuredClone(fixture.bob.localIdentity);
  assert.equal(await renewPairwiseDirectV4PrekeyIfNeeded({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    localIdentity: renewedIdentity,
    now: Date.parse(renewalAt)
  }), true);
  const bobStore = encryptedStore(new ToggleMemoryStore(), 28);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.prepareEndpointPrekeyUpdate({
    endpointBinding: renewedIdentity.endpointBinding,
    localIdentity: renewedIdentity,
    clientTransactionId: swiftUUID(),
    sentAt: renewalAt
  });
  const transitioned = await bobStore.get(stateKey(fixture.bob));
  assert.equal(transitioned.localEndpointBindings.length, 2);
  assert.deepEqual(transitioned.localEndpointBindings[0], renewedIdentity.endpointBinding);
  assert.deepEqual(transitioned.localEndpointBindings[1], originalBobBinding);
  assert.deepEqual(transitioned.localIdentity, renewedIdentity);
  assert.equal(
    transitioned.intents[0].directEnvelope.senderBindingDigest,
    transitioned.sessions[0].endpointSession.localBindingReferenceDigest
  );
  const successorBinding = await derivePairwiseDirectV4Binding({
    crypto: fixture.crypto,
    localIdentity: renewedIdentity,
    peerIdentity: fixture.bob.peerIdentity
  });
  assert.equal(
    transitioned.intents[0].directEnvelope.senderBindingDigest,
    successorBinding.localBindingReferenceDigest
  );
  assert.notEqual(
    originalBobBinding.prekeyBundle.signedPrekey.id,
    renewedIdentity.endpointBinding.prekeyBundle.signedPrekey.id
  );
  assert.notEqual(transitioned.sessions[0].sessionId, aliceState.intents[0].directEnvelope.sessionId);
  assert.notEqual(transitioned.sessions[0].rootKey, aliceState.sessions[0].rootKey);

  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: transitioned.localReceiveRoutes[0],
    packets: inFlightPackets
  });
  const result = await bob.syncReceive({
    client: receiveWebClient({ fixture, batch }),
    authorizedAt: renewalAt
  });
  assert.equal(result.received[0].projection.text, "sent before peer prekey publication");
});

test("unknown negotiated application content is retained with authenticated fallback", async () => {
  const fixture = await pairedFixture();
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 8);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  const content = createEncodedContent({
    type: { authority: "example.noctweave", name: "note", major: 1, minor: 0 },
    payload: new Uint8Array([1, 2, 3]),
    fallbackText: "Unsupported private note",
    disposition: "visible"
  });
  await alice.prepareApplication({
    content,
    clientTransactionId: swiftUUID()
  });
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  const packets = aliceState.intents[0].routeDeliveries[0].sealedBundle.packets;
  const bobStore = encryptedStore(new ToggleMemoryStore(), 9);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.open();
  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.bob.localReceiveRoutes[0],
    packets
  });
  const client = receiveWebClient({ fixture, batch });

  const result = await bob.syncReceive({ client, authorizedAt: swiftISODate() });
  assert.equal(result.received[0].projection.kind, "unsupported");
  assert.equal(result.received[0].projection.fallbackText, "Unsupported private note");
  const received = await bob.listReceived();
  assert.equal(received[0].event.content.type.authority, "example.noctweave");
  assert.equal(received[0].event.content.payload, content.payload);
});

test("signed route controls persist relationship effects and probe the exact testing route", async () => {
  const fixture = await pairedFixture();
  const transitionAt = swiftISODate();
  const testing = await createTestingReceiveRoute(fixture, transitionAt);
  const testingSendRoute = await createOpaqueSendRouteV2({
    crypto: fixture.crypto,
    relay: relayEndpoint,
    route: testing.route,
    clientCapabilities: testing.clientCapabilities,
    payloadKey: testing.payloadKey,
    state: "testing"
  });
  const nextRouteSet = await addTestingPairwiseRouteV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    current: fixture.alice.localAdvertisedRoutes,
    route: testingSendRoute,
    issuedAt: transitionAt,
    ownerSigningPublicKey: fixture.alice.localIdentity.endpointBinding.signingPublicKey,
    ownerSigningSecretKey: fixture.alice.localIdentity.localEndpoint.signing.secretKey
  });
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 18);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  const published = await alice.prepareRouteSetUpdate({
    routeSet: nextRouteSet,
    localReceiveRoutes: [...fixture.alice.localReceiveRoutes, testing],
    clientTransactionId: swiftUUID(),
    sentAt: transitionAt
  });
  assert.equal(published.event.kind, "control");
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  assert.equal(aliceState.localAdvertisedRoutes.revision, nextRouteSet.revision);
  const packets = aliceState.intents[0].routeDeliveries[0].sealedBundle.packets;

  const bobStore = encryptedStore(new ToggleMemoryStore(), 19);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.open();
  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.bob.localReceiveRoutes[0],
    packets
  });
  let persistedEffect = null;
  const received = await bob.syncReceive({
    client: receiveWebClient({ fixture, batch }),
    authorizedAt: transitionAt,
    persistAppliedRelationship: async ({ relationship, received: outcomes }) => {
      const runtimeState = await bobStore.get(stateKey(fixture.bob));
      assert.equal(runtimeState.peerIdentity.sendRoutes.revision, nextRouteSet.revision);
      assert.equal(outcomes[0].kind, "control");
      persistedEffect = relationship;
    }
  });
  assert.equal(received.received[0].projection.controlKind, "routeSetUpdate");
  assert.equal(received.appliedRelationship.peerIdentity.sendRoutes.revision, nextRouteSet.revision);
  assert.equal(persistedEffect.peerIdentity.sendRoutes.revision, nextRouteSet.revision);
  assert.equal(
    (await bob.relationshipSnapshot()).peerIdentity.sendRoutes.revision,
    nextRouteSet.revision
  );

  await bob.prepareRouteProbe({
    routeID: testingSendRoute.routeID,
    routeSetRevision: nextRouteSet.revision,
    clientTransactionId: swiftUUID(),
    sentAt: transitionAt
  });
  const bobState = await bobStore.get(stateKey(fixture.bob));
  const probeDelivery = bobState.intents[0].routeDeliveries[0];
  assert.equal(probeDelivery.route.routeID.rawValue, testingSendRoute.routeID.rawValue);
  assert.equal(probeDelivery.route.state, "testing");

  const oldRoute = fixture.bob.peerIdentity.sendRoutes.routes[0];
  const wrongSource = await sealOpaqueRouteBundleV2({
    crypto: fixture.crypto,
    payload: canonicalJsonBytes(bobState.intents[0].directEnvelope),
    routeRevision: oldRoute.routeRevision,
    paddingBucket: oldRoute.policy.paddingBucket,
    payloadKey: oldRoute.payloadKey,
    sendAuthority: {
      routeID: oldRoute.routeID,
      sendCapability: oldRoute.sendCapability
    },
    authorizedAt: transitionAt
  });
  const aliceBeforeProbe = await aliceStore.get(stateKey(fixture.alice));
  const oldBatch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: aliceBeforeProbe.localReceiveRoutes[0],
    packets: wrongSource.packets
  });
  let wrongSourceCommits = 0;
  await assert.rejects(() => alice.syncReceive({
    client: receiveWebClient({
      fixture,
      batch: oldBatch,
      onCommit: () => { wrongSourceCommits += 1; }
    }),
    routeID: oldRoute.routeID,
    authorizedAt: transitionAt
  }), (error) => error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "invalidControlTransition");
  assert.equal(wrongSourceCommits, 0);

  const aliceTestingState = await aliceStore.get(stateKey(fixture.alice));
  const testingLocalRoute = aliceTestingState.localReceiveRoutes.find(({ route }) =>
    route.routeID.rawValue === testingSendRoute.routeID.rawValue
  );
  const probeBatch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: testingLocalRoute,
    packets: probeDelivery.sealedBundle.packets
  });
  const sourceBound = await alice.syncReceive({
    client: receiveWebClient({ fixture, batch: probeBatch }),
    routeID: testingSendRoute.routeID,
    authorizedAt: transitionAt
  });
  assert.equal(sourceBound.received[0].projection.controlKind, "routeProbe");
  assert.equal(
    sourceBound.received[0].projection.sourceRouteID.rawValue,
    testingSendRoute.routeID.rawValue
  );

  const overlapUntil = swiftISODate(new Date(Date.parse(transitionAt) + 60_000));
  const promoted = await promoteProbedPairwiseRouteV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    current: nextRouteSet,
    routeID: testingSendRoute.routeID,
    replacingRouteIDs: [fixture.alice.localAdvertisedRoutes.routes[0].routeID],
    testedAt: transitionAt,
    overlapUntil,
    issuedAt: transitionAt,
    ownerSigningPublicKey: fixture.alice.localIdentity.endpointBinding.signingPublicKey,
    ownerSigningSecretKey: fixture.alice.localIdentity.localEndpoint.signing.secretKey
  });
  await alice.prepareRouteSetUpdate({
    routeSet: promoted,
    localReceiveRoutes: [...fixture.alice.localReceiveRoutes, testing],
    clientTransactionId: swiftUUID(),
    sentAt: transitionAt
  });
  const revoked = await revokeDrainedPairwiseRouteV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    current: promoted,
    routeID: fixture.alice.localAdvertisedRoutes.routes[0].routeID,
    issuedAt: overlapUntil,
    ownerSigningPublicKey: fixture.alice.localIdentity.endpointBinding.signingPublicKey,
    ownerSigningSecretKey: fixture.alice.localIdentity.localEndpoint.signing.secretKey
  });
  await alice.prepareRouteSetUpdate({
    routeSet: revoked,
    localReceiveRoutes: [...fixture.alice.localReceiveRoutes, testing],
    clientTransactionId: swiftUUID(),
    sentAt: overlapUntil
  });
  const oldLocal = fixture.alice.localReceiveRoutes[0];
  const teardownAt = swiftISODate(new Date(Date.parse(overlapUntil) + 1_000));
  const teardownRequest = await makeOpaqueRouteTeardownRequestV2({
    crypto: fixture.crypto,
    capabilities: oldLocal.clientCapabilities,
    current: oldLocal.route,
    authorizedAt: teardownAt,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(fixture.crypto),
    nonce: await createOpaqueRouteProofNonceV2(fixture.crypto)
  });
  const tombstone = await teardownOpaqueReceiveRouteV2({
    crypto: fixture.crypto,
    current: oldLocal.route,
    request: teardownRequest,
    presentedCapability: oldLocal.clientCapabilities.teardownCapability,
    confidentialTransport: true,
    receivedAt: teardownAt
  });
  await assert.rejects(() => alice.finalizeLocalRouteRetirement({
    evidence: {
      request: teardownRequest,
      teardownCapability: oldLocal.clientCapabilities.teardownCapability,
      tombstone: {
        ...tombstone,
        lastTransitionDigest: base64(new Uint8Array(32).fill(0x4d))
      }
    },
    retiredAt: teardownAt
  }), (error) => error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "invalidRouteRetirement");
  const retired = await alice.finalizeLocalRouteRetirement({
    evidence: {
      request: teardownRequest,
      teardownCapability: oldLocal.clientCapabilities.teardownCapability,
      tombstone
    },
    retiredAt: teardownAt
  });
  assert.equal(retired.retired, true);
  assert.deepEqual(
    retired.relationship.localReceiveRoutes.map(({ route }) => route.routeID.rawValue),
    [testingSendRoute.routeID.rawValue]
  );

  // A later rotation prunes the old revoked route from the current snapshot.
  // Its compact retirement record must remain independently authenticated.
  const successorAt = swiftISODate(new Date(Date.parse(teardownAt) + 1_000));
  const successorLocal = await createTestingReceiveRoute(fixture, successorAt);
  const successorSend = await createOpaqueSendRouteV2({
    crypto: fixture.crypto,
    relay: relayEndpoint,
    route: successorLocal.route,
    clientCapabilities: successorLocal.clientCapabilities,
    payloadKey: successorLocal.payloadKey,
    state: "testing"
  });
  const prunedRouteSet = await addTestingPairwiseRouteV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    current: revoked,
    route: successorSend,
    issuedAt: successorAt,
    ownerSigningPublicKey: fixture.alice.localIdentity.endpointBinding.signingPublicKey,
    ownerSigningSecretKey: fixture.alice.localIdentity.localEndpoint.signing.secretKey
  });
  assert.equal(prunedRouteSet.routes.some(({ routeID }) =>
    routeID.rawValue === oldLocal.route.routeID.rawValue), false);
  await alice.prepareRouteSetUpdate({
    routeSet: prunedRouteSet,
    localReceiveRoutes: [...retired.relationship.localReceiveRoutes, successorLocal],
    clientTransactionId: swiftUUID(),
    sentAt: successorAt
  });
  const repeated = await alice.finalizeLocalRouteRetirement({
    evidence: {
      request: teardownRequest,
      teardownCapability: oldLocal.clientCapabilities.teardownCapability,
      tombstone
    },
    retiredAt: successorAt
  });
  assert.equal(repeated.retired, false);
});

test("route probes reject an actual source route that is not currently testing", async () => {
  const fixture = await pairedFixture();
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 27);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  const activePeerRoute = fixture.alice.peerIdentity.sendRoutes.routes[0];
  await alice.prepareRouteProbe({
    routeID: activePeerRoute.routeID,
    routeSetRevision: fixture.alice.peerIdentity.sendRoutes.revision,
    clientTransactionId: swiftUUID()
  });
  const aliceState = await aliceStore.get(stateKey(fixture.alice));
  const bobStore = encryptedStore(new ToggleMemoryStore(), 28);
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  await bob.open();
  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.bob.localReceiveRoutes[0],
    packets: aliceState.intents[0].routeDeliveries[0].sealedBundle.packets
  });
  let relayCommits = 0;
  await assert.rejects(() => bob.syncReceive({
    client: receiveWebClient({
      fixture,
      batch,
      onCommit: () => { relayCommits += 1; }
    }),
    authorizedAt: swiftISODate()
  }), (error) => error instanceof DurablePairwiseMessagingV2Error &&
    error.code === "invalidControlTransition");
  assert.equal(relayCommits, 0);
});

test("the extensible application runtime refuses security controls", async () => {
  const fixture = await pairedFixture();
  const store = encryptedStore(new ToggleMemoryStore(), 10);
  const runtime = runtimeFor({ fixture, relationship: fixture.alice, store });
  await runtime.open();
  const control = createEncodedContent({
    type: { authority: "org.noctweave.control", name: "future", major: 2, minor: 0 },
    payload: new Uint8Array([1]),
    disposition: "silent"
  });
  await assert.rejects(
    () => runtime.prepareApplication({
      content: control,
      eventKind: "control",
      clientTransactionId: swiftUUID()
    }),
    /accepts only application and receipt events/
  );
  const persisted = await store.get(stateKey(fixture.alice));
  assert.equal(persisted.intents.length, 0);
  assert.equal(persisted.sessions.length, 0);
});

test("only authenticated peer receipts advance peerStored and peerRead", async () => {
  const fixture = await pairedFixture();
  const aliceStore = encryptedStore(new ToggleMemoryStore(), 11);
  const bobStore = encryptedStore(new ToggleMemoryStore(), 12);
  const alice = runtimeFor({ fixture, relationship: fixture.alice, store: aliceStore });
  const bob = runtimeFor({ fixture, relationship: fixture.bob, store: bobStore });
  const sent = await alice.prepareText({
    text: "receipt state machine",
    clientTransactionId: swiftUUID()
  });
  const alicePrepared = await aliceStore.get(stateKey(fixture.alice));
  const messagePackets = alicePrepared.intents[0].routeDeliveries[0].sealedBundle.packets;
  await alice.resumeOutbound();
  await deliverPackets({
    fixture,
    runtime: bob,
    store: bobStore,
    relationship: fixture.bob,
    packets: messagePackets
  });

  await bob.prepareDeliveryReceipt({
    targetEventId: sent.event.id,
    clientTransactionId: swiftUUID()
  });
  await bob.prepareReadReceipt({
    targetEventId: sent.event.id,
    clientTransactionId: swiftUUID()
  });
  const bobPrepared = await bobStore.get(stateKey(fixture.bob));
  const deliveryPackets = bobPrepared.intents[0].routeDeliveries[0].sealedBundle.packets;
  const readPackets = bobPrepared.intents[1].routeDeliveries[0].sealedBundle.packets;

  await deliverPackets({
    fixture,
    runtime: alice,
    store: aliceStore,
    relationship: fixture.alice,
    packets: deliveryPackets
  });
  assert.equal((await alice.listOutbound())[0].delivery.state, "peerStored");
  await deliverPackets({
    fixture,
    runtime: alice,
    store: aliceStore,
    relationship: fixture.alice,
    packets: readPackets
  });
  assert.equal((await alice.listOutbound())[0].delivery.state, "peerRead");
});

test("retry exhaustion stays retryable and explicit discard releases ordering", async () => {
  const fixture = await pairedFixture();
  const store = encryptedStore(new ToggleMemoryStore(), 7);
  const runtime = runtimeFor({
    fixture,
    relationship: fixture.alice,
    store,
    relayClientFactory: () => ({
      enqueueOpaqueRoute: async () => { throw new Error("offline"); }
    })
  });
  const transactionID = swiftUUID();
  await runtime.prepareText({ text: "bounded failure", clientTransactionId: transactionID });
  for (let attempt = 0; attempt < 8; attempt += 1) await runtime.resumeOutbound();
  const failed = (await runtime.listOutbound())[0];
  assert.equal(failed.status, "retryableFailure");
  assert.equal(failed.attemptCount, 8);
  const discarded = await runtime.discard(transactionID);
  assert.equal(discarded.status, "discarded");
});

function runtimeFor({ fixture, relationship, store, relayClientFactory }) {
  return new DurablePairwiseMessagingRuntimeV2({
    crypto: fixture.crypto,
    pqc: fixture.pqc,
    relationship,
    store,
    stateAnchorStore: store.testRelationshipAnchorStore,
    relayClientFactory: relayClientFactory ?? (() => ({
      enqueueOpaqueRoute: async ({ packet }) => enqueueReceipt(packet, 1)
    }))
  });
}

function stateKey(relationship) {
  return `pairwise-runtime-v2:${relationship.relationshipID}`;
}

function encryptedStore(backend, marker) {
  const store = new EncryptedNoctweaveStore(backend, {
    crypto: globalThis.crypto,
    keyBytes: new Uint8Array(32).fill(marker)
  });
  backend.testRelationshipAnchorStore ??= new TestRelationshipAnchorStore();
  store.testRelationshipAnchorStore = backend.testRelationshipAnchorStore;
  return store;
}

function enqueueReceipt(packet, marker) {
  const cursor = {
    rawValue: base64(new Uint8Array(68).fill((marker % 250) + 1))
  };
  return {
    packetID: packet.packetID,
    acceptedCursor: cursor,
    highWatermark: cursor
  };
}

function receiveWebClient({ fixture, batch, onCommit = () => {} }) {
  const relay = new NoctweaveRelayClient(relayEndpoint, {
    crypto: fixture.crypto,
    fetch: async () => { throw new Error("unexpected HTTP"); }
  });
  relay.syncOpaqueRoute = async () => batch;
  relay.commitOpaqueRoute = async ({ request }) => {
    onCommit(request);
    return {
      committedCursor: request.cursor,
      highWatermark: request.cursor,
      retentionFloor: request.cursor
    };
  };
  return new NoctweaveWebClient({
    relay,
    store: new MemoryNoctweaveStore(),
    stateKey: "web-client-unused",
    crypto: fixture.crypto
  });
}

async function rewriteOpaquePacketAsMalformedFrame({
  fixture,
  packet,
  routeRevision,
  authorizedAt
}) {
  const sealed = Uint8Array.from(Buffer.from(packet.sealedFrame, "base64"));
  const oldNonce = sealed.slice(0, 12);
  const ciphertext = sealed.slice(12);
  const localRoute = fixture.bob.localReceiveRoutes[0];
  const key = Uint8Array.from(Buffer.from(localRoute.payloadKey.rawValue, "base64"));
  const aad = opaqueRoutePacketAuthenticatedDataV2({
    routeID: packet.routeID,
    packetID: packet.packetID,
    routeRevision,
    paddingBucket: sealed.byteLength
  });
  const plaintext = await fixture.crypto.aesGcmDecrypt({
    key,
    nonce: oldNonce,
    ciphertext,
    additionalData: aad
  });
  plaintext[0] ^= 0xff;
  const nonce = await fixture.crypto.randomBytes(12);
  const encrypted = await fixture.crypto.aesGcmEncrypt({
    key,
    nonce,
    plaintext,
    additionalData: aad
  });
  const rewritten = new Uint8Array(nonce.byteLength + encrypted.byteLength);
  rewritten.set(nonce, 0);
  rewritten.set(encrypted, nonce.byteLength);
  const sealedFrame = base64(rewritten);
  const operationDigest = await opaqueRoutePacketOperationDigestV2({
    crypto: fixture.crypto,
    routeID: packet.routeID,
    packetID: packet.packetID,
    sealedFrame
  });
  const sendRoute = fixture.alice.peerIdentity.sendRoutes.routes.find(({ routeID }) =>
    routeID.rawValue === packet.routeID.rawValue
  );
  assert.ok(sendRoute);
  const authorization = await makeOpaqueRouteSendAuthorizationV2({
    crypto: fixture.crypto,
    sendAuthority: {
      routeID: sendRoute.routeID,
      sendCapability: sendRoute.sendCapability
    },
    operationDigest,
    authorizedAt,
    nonce: await createOpaqueRouteProofNonceV2(fixture.crypto)
  });
  oldNonce.fill(0);
  ciphertext.fill(0);
  plaintext.fill(0);
  key.fill(0);
  return {
    routeID: packet.routeID,
    packetID: packet.packetID,
    sealedFrame,
    authorization
  };
}

async function deliverPackets({ fixture, runtime, store, relationship, packets }) {
  const state = await store.get(stateKey(relationship));
  const localReceiveRoute = state?.localReceiveRoutes?.[0] ?? relationship.localReceiveRoutes[0];
  const batch = await syncBatch({
    crypto: fixture.crypto,
    localReceiveRoute,
    packets
  });
  return runtime.syncReceive({
    client: receiveWebClient({ fixture, batch }),
    authorizedAt: swiftISODate()
  });
}

async function syncBatch({ crypto, localReceiveRoute, packets }) {
  let sequence = localReceiveRoute.committedSequence;
  let previousRecordDigest = localReceiveRoute.committedRecordDigest;
  const records = [];
  for (const packet of packets) {
    sequence += 1;
    const recordDigest = await opaqueRouteRecordDigestV2({
      crypto,
      previousRecordDigest,
      sequence,
      routeRevision: localReceiveRoute.route.lease.renewalSequence,
      packet
    });
    records.push({
      sequence,
      previousRecordDigest,
      recordDigest,
      routeRevision: localReceiveRoute.route.lease.renewalSequence,
      packet
    });
    previousRecordDigest = recordDigest;
  }
  const cursor = { rawValue: base64(new Uint8Array(68).fill(0x71)) };
  const zeroCursor = { rawValue: base64(new Uint8Array(68).fill(0x01)) };
  return validateOpaqueRouteSyncResponseV2({
    crypto,
    request: {
      routeID: localReceiveRoute.route.routeID,
      limit: 256
    },
    response: {
      packets: records,
      startsAfterSequence: localReceiveRoute.committedSequence,
      startsAfterRecordDigest: localReceiveRoute.committedRecordDigest,
      nextSequence: sequence,
      nextRecordDigest: previousRecordDigest,
      highWatermarkSequence: sequence,
      retentionFloorSequence: 0,
      nextCursor: cursor,
      highWatermark: cursor,
      retentionFloor: zeroCursor,
      hasMore: false
    }
  });
}

class TestRelationshipAnchorStore {
  constructor() {
    this.records = new Map();
    this.key = new Uint8Array(32).fill(0xa7);
  }

  async load({ anchorKey, relationshipID, loadEncryptedState }) {
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
    const current = this.records.get(anchorKey) ?? null;
    assert.equal(
      current === null ? null : JSON.stringify(current),
      expectedAnchor === null ? null : JSON.stringify(expectedAnchor),
      "anchor compare-and-swap"
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

  async destroy({
    anchorKey,
    relationshipID,
    expectedAnchor,
    destroyEncryptedState
  }) {
    const current = this.records.get(anchorKey) ?? null;
    assert.equal(current?.relationshipID, relationshipID);
    if (expectedAnchor !== null) {
      assert.equal(JSON.stringify(current), JSON.stringify(expectedAnchor), "anchor destroy compare-and-swap");
    }
    await destroyEncryptedState();
    this.records.delete(anchorKey);
    return { destroyed: true };
  }

  async authenticationTag(anchor) {
    const unsigned = {
      version: anchor.version,
      relationshipID: anchor.relationshipID,
      generation: anchor.generation,
      stateDigest: anchor.stateDigest
    };
    const payload = canonicalJsonBytes(unsigned);
    const input = new Uint8Array(this.key.byteLength + payload.byteLength);
    input.set(this.key, 0);
    input.set(payload, this.key.byteLength);
    return base64(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input)));
  }
}

class ToggleMemoryStore extends MemoryNoctweaveStore {
  constructor() {
    super();
    this.failWrites = false;
    this.writeOrder = [];
  }

  async set(key, value) {
    if (this.failWrites) throw new Error("injected storage failure");
    this.writeOrder.push("localSave");
    return super.set(key, value);
  }
}

async function createTestingReceiveRoute(fixture, issuedAt) {
  const clientCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(fixture.crypto);
  const lease = createOpaqueRouteLeaseV2({
    issuedAt,
    expiresAt: swiftISODate(new Date(Date.parse(issuedAt) + 6 * 60 * 60 * 1_000)),
    policy: createOpaqueRoutePolicyV2({
      paddingBucket: 4_096,
      retentionBucket: 3_600,
      quotaBucket: 64
    })
  });
  const request = await makeOpaqueRouteCreateRequestV2({
    crypto: fixture.crypto,
    capabilities: clientCapabilities,
    lease,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(fixture.crypto),
    nonce: await createOpaqueRouteProofNonceV2(fixture.crypto)
  });
  const route = await createOpaqueReceiveRouteV2({
    crypto: fixture.crypto,
    request,
    presentedRenewCapability: clientCapabilities.renewCapability,
    confidentialTransport: true,
    receivedAt: issuedAt
  });
  return createLocalOpaqueReceiveRouteV2({
    crypto: fixture.crypto,
    relay: relayEndpoint,
    route,
    clientCapabilities,
    payloadKey: await createOpaqueRoutePayloadKeyV2(fixture.crypto)
  });
}

async function pairedFixture({ routeDurationMilliseconds = 6 * 60 * 60 * 1_000 } = {}) {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const webcrypto = new WebCryptoPrimitives();
  const crypto = new NoctweaveCryptoSuite({ pqc, webcrypto });
  const createdAt = swiftISODate();
  const expiresAt = swiftISODate(new Date(Date.parse(createdAt) + 10 * 60_000));
  const made = await createContactPairingInvitationV2({ crypto, createdAt, expiresAt });
  const encoded = await encodeContactPairingInvitationV2({ crypto, invitation: made.invitation });
  const invitation = await decodeContactPairingInvitationV2({ crypto, encoded });
  const endpointCapabilities = createProtocolCapabilityManifest({
    contentTypes: [
      ...defaultContentTypeCapabilities,
      createContentTypeCapabilityV2({
        authority: "example.noctweave",
        name: "note",
        majorVersions: [1]
      })
    ]
  });
  const routeExpiresAt = swiftISODate(new Date(Date.parse(createdAt) + routeDurationMilliseconds));
  const alice = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    relationshipPseudonym: "Alice for Bob",
    relay: relayEndpoint,
    createdAt,
    routeExpiresAt,
    endpointCapabilities
  });
  const bob = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    relationshipPseudonym: "Bob for Alice",
    relay: relayEndpoint,
    createdAt,
    routeExpiresAt,
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
  return {
    crypto,
    pqc,
    alice: paired.offererRelationship,
    bob: paired.responderRelationship
  };
}
