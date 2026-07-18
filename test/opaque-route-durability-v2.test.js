import assert from "node:assert/strict";
import test from "node:test";
import { NoctweaveWebClient } from "../src/client.js";
import { WebCryptoPrimitives } from "../src/crypto/webcrypto.js";
import { base64 } from "../src/crypto/swift-canonical.js";
import {
  createOpaqueRoutePacketReassemblerV2,
  createOpaqueRoutePayloadKeyV2,
  opaqueRoutePacketMaximumFragmentPayloadBytesV2,
  restoreOpaqueRoutePacketReassemblerV2,
  sealOpaqueRouteBundleV2
} from "../src/opaque-route-packet-v2.js";
import {
  createOpaqueReceiveRouteV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteCreateRequestV2
} from "../src/opaque-route-v2.js";
import {
  opaqueRouteRecordDigestV2,
  validateOpaqueRouteSyncResponseV2
} from "../src/opaque-route-relay-v2.js";
import {
  OpaqueRouteGapV2Error,
  createLocalOpaqueReceiveRouteV2,
  updateLocalOpaqueReceiveRouteReassemblerV2,
  validateLocalOpaqueReceiveRouteV2
} from "../src/pairwise-opaque-route-v2.js";
import { NoctweaveRelayClient } from "../src/relay-client.js";
import { MemoryNoctweaveStore } from "../src/storage.js";

const authorizedAt = "2026-07-18T12:00:00Z";
const relayEndpoint = {
  host: "127.0.0.1",
  port: 9_339,
  useTLS: false,
  transport: "http"
};

test("local save failure authorizes zero relay cursor commits", async () => {
  const fixture = await receiveFixture();
  let relayCommitCount = 0;
  const client = webClient(fixture.crypto, {
    commitOpaqueRoute: async () => {
      relayCommitCount += 1;
      return commitResponse(fixture.batch.nextCursor);
    }
  });

  await assert.rejects(
    () => client.commitOpaqueRoute({
      localReceiveRoute: fixture.localReceiveRoute,
      batch: fixture.batch,
      persistLocalState: async () => {
        throw new Error("local storage unavailable");
      }
    }, { authorizedAt }),
    /local storage unavailable/
  );
  assert.equal(relayCommitCount, 0);

  await assert.rejects(
    () => client.commitOpaqueRoute({
      localReceiveRoute: fixture.localReceiveRoute,
      batch: fixture.batch,
      durablyProcessed: true
    }, { authorizedAt }),
    /requires a local persistence transaction callback/
  );
  assert.equal(relayCommitCount, 0);
});

test("saved cursor survives reload when best-effort relay commit fails", async () => {
  const fixture = await receiveFixture();
  let persisted;
  const client = webClient(fixture.crypto, {
    commitOpaqueRoute: async () => {
      throw new Error("relay unavailable");
    }
  });

  const result = await client.commitOpaqueRoute({
    localReceiveRoute: fixture.localReceiveRoute,
    batch: fixture.batch,
    persistLocalState: async ({ localReceiveRoute }) => {
      persisted = JSON.parse(JSON.stringify(localReceiveRoute));
    }
  }, { authorizedAt });

  assert.equal(result.relayCommit.status, "deferred");
  assert.equal(result.relayCommit.response, null);
  const reloaded = await validateLocalOpaqueReceiveRouteV2({
    crypto: fixture.crypto,
    route: persisted
  });
  assert.equal(reloaded.committedSequence, fixture.batch.nextSequence);
  assert.equal(reloaded.committedRecordDigest, fixture.batch.nextRecordDigest);
  assert.deepEqual(reloaded.committedCursor, fixture.batch.nextCursor);
});

test("successful opaque-route processing persists before relay commit", async () => {
  const fixture = await receiveFixture();
  const order = [];
  const client = webClient(fixture.crypto, {
    commitOpaqueRoute: async () => {
      order.push("relayCommit");
      return commitResponse(fixture.batch.nextCursor);
    }
  });

  const result = await client.commitOpaqueRoute({
    localReceiveRoute: fixture.localReceiveRoute,
    batch: fixture.batch,
    persistLocalState: async ({ kind, localReceiveRoute }) => {
      order.push("localCommit");
      assert.equal(kind, "cursorAdvance");
      assert.equal(localReceiveRoute.committedSequence, 1);
    }
  }, { authorizedAt });

  assert.deepEqual(order, ["localCommit", "relayCommit"]);
  assert.equal(result.relayCommit.status, "accepted");
  assert.deepEqual(result.relayCommit.response, commitResponse(fixture.batch.nextCursor));
});

test("partial bundles persist inside a local route and complete after exact restore", async () => {
  const fixture = await localRouteFixture();
  const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(4_096);
  const payload = patternedBytes(capacity + 19);
  const bundle = await sealOpaqueRouteBundleV2({
    crypto: fixture.crypto,
    payload,
    routeRevision: 0,
    paddingBucket: 4_096,
    payloadKey: fixture.payloadKey,
    routeCapabilities: fixture.clientCapabilities,
    authorizedAt
  });

  const partial = await updateLocalOpaqueReceiveRouteReassemblerV2({
    crypto: fixture.crypto,
    localReceiveRoute: fixture.localReceiveRoute,
    update: (reassembler) => reassembler.consume({
      crypto: fixture.crypto,
      packet: bundle.packets[0],
      payloadKey: fixture.payloadKey,
      routeRevision: 0
    })
  });
  assert.equal(partial.result.status, "accepted");
  assert.equal(partial.localReceiveRoute.reassembler.maximumBufferedBytes, 1_024 * 1_024);
  assert.equal(partial.localReceiveRoute.reassembler.pendingBundles.length, 1);

  const restoredRoute = await validateLocalOpaqueReceiveRouteV2({
    crypto: fixture.crypto,
    route: JSON.parse(JSON.stringify(partial.localReceiveRoute))
  });
  const completed = await updateLocalOpaqueReceiveRouteReassemblerV2({
    crypto: fixture.crypto,
    localReceiveRoute: restoredRoute,
    update: (reassembler) => reassembler.consume({
      crypto: fixture.crypto,
      packet: bundle.packets[1],
      payloadKey: fixture.payloadKey,
      routeRevision: 0
    })
  });
  assert.equal(completed.result.status, "complete");
  assert.deepEqual(completed.result.bundle.payload, payload);
  assert.equal(completed.localReceiveRoute.reassembler.pendingBundles.length, 0);
  assert.equal(completed.localReceiveRoute.reassembler.completedBundles.length, 1);

  const unknown = structuredClone(completed.localReceiveRoute.reassembler);
  unknown.legacy = true;
  assert.throws(() => restoreOpaqueRoutePacketReassemblerV2(unknown), (error) =>
    error?.code === "invalidReassemblyState"
  );
});

test("reassembly pressure retires the deterministic oldest bundle", async () => {
  const crypto = new WebCryptoPrimitives();
  const routeCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(4_096);
  const bundles = [];
  for (let index = 0; index < 3; index += 1) {
    bundles.push(await sealOpaqueRouteBundleV2({
      crypto,
      payload: patternedBytes(capacity + 1, index + 1),
      routeRevision: 4,
      paddingBucket: 4_096,
      payloadKey,
      routeCapabilities,
      authorizedAt
    }));
  }
  const reassembler = createOpaqueRoutePacketReassemblerV2({
    maximumBufferedBundles: 2,
    maximumBufferedBytes: 10_000
  });
  for (const bundle of bundles.slice(0, 2)) {
    assert.equal((await reassembler.consume({
      crypto,
      packet: bundle.packets[0],
      payloadKey,
      routeRevision: 4
    })).status, "accepted");
  }
  await assert.rejects(
    () => reassembler.consume({
      crypto,
      packet: bundles[2].packets[0],
      payloadKey,
      routeRevision: 4
    }),
    (error) => error?.code === "reassemblyCapacityExceeded"
  );

  assert.deepEqual(reassembler.discardOldestPendingBundle(), bundles[0].bundleID);
  assert.equal((await reassembler.consume({
    crypto,
    packet: bundles[2].packets[0],
    payloadKey,
    routeRevision: 4
  })).status, "accepted");

  const restored = restoreOpaqueRoutePacketReassemblerV2(
    JSON.parse(JSON.stringify(reassembler.snapshot())),
    { routeID: routeCapabilities.routeID }
  );
  assert.deepEqual(
    restored.snapshot().pendingBundles.map(({ bundleID }) => bundleID),
    [bundles[1].bundleID, bundles[2].bundleID]
  );
  assert.deepEqual(
    restored.snapshot().completedBundles.map(({ bundleID }) => bundleID),
    [bundles[0].bundleID]
  );
  assert.equal((await restored.consume({
    crypto,
    packet: bundles[0].packets[0],
    payloadKey,
    routeRevision: 4
  })).status, "duplicate");
});

test("verified cursor gaps become durable terminal local route state", async () => {
  const fixture = await receiveFixture();
  const gapBatch = Object.freeze({
    ...fixture.batch,
    startsAfterSequence: 1,
    retentionFloorSequence: 1
  });
  let persisted;
  const client = webClient(fixture.crypto, {
    syncOpaqueRoute: async () => gapBatch
  });

  await assert.rejects(
    () => client.syncOpaqueRoute(fixture.localReceiveRoute, {
      authorizedAt,
      persistLocalState: async ({ kind, localReceiveRoute }) => {
        assert.equal(kind, "routeGap");
        persisted = JSON.parse(JSON.stringify(localReceiveRoute));
      }
    }),
    (error) => error instanceof OpaqueRouteGapV2Error && error.gapState.reason === "retentionExpired"
  );
  const reloaded = await validateLocalOpaqueReceiveRouteV2({
    crypto: fixture.crypto,
    route: persisted
  });
  assert.equal(reloaded.gapState.reason, "retentionExpired");
  assert.equal(reloaded.gapState.expectedSequence, 0);
  assert.equal(reloaded.gapState.observedSequence, 1);
});

function webClient(crypto, methods) {
  const relay = new NoctweaveRelayClient("https://relay.example", {
    crypto,
    fetch: async () => {
      throw new Error("unexpected network request");
    }
  });
  Object.assign(relay, methods);
  return new NoctweaveWebClient({
    relay,
    store: new MemoryNoctweaveStore(),
    crypto
  });
}

async function receiveFixture() {
  const fixture = await localRouteFixture();
  const bundle = await sealOpaqueRouteBundleV2({
    crypto: fixture.crypto,
    payload: new TextEncoder().encode("durable opaque route batch"),
    routeRevision: 0,
    paddingBucket: 4_096,
    payloadKey: fixture.payloadKey,
    routeCapabilities: fixture.clientCapabilities,
    authorizedAt
  });
  const zeroDigest = base64(new Uint8Array(32));
  const recordDigest = await opaqueRouteRecordDigestV2({
    crypto: fixture.crypto,
    previousRecordDigest: zeroDigest,
    sequence: 1,
    routeRevision: 0,
    packet: bundle.packets[0]
  });
  const cursor = { rawValue: base64(new Uint8Array(68).fill(0x51)) };
  const batch = await validateOpaqueRouteSyncResponseV2({
    crypto: fixture.crypto,
    request: { routeID: fixture.clientCapabilities.routeID, limit: 16 },
    response: {
      packets: [{
        sequence: 1,
        previousRecordDigest: zeroDigest,
        recordDigest,
        routeRevision: 0,
        packet: bundle.packets[0]
      }],
      startsAfterSequence: 0,
      startsAfterRecordDigest: zeroDigest,
      nextSequence: 1,
      nextRecordDigest: recordDigest,
      highWatermarkSequence: 1,
      retentionFloorSequence: 0,
      nextCursor: cursor,
      highWatermark: cursor,
      retentionFloor: cursor,
      hasMore: false
    }
  });
  return { ...fixture, batch };
}

async function localRouteFixture() {
  const crypto = new WebCryptoPrimitives();
  const clientCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const lease = createOpaqueRouteLeaseV2({
    issuedAt: authorizedAt,
    expiresAt: "2026-07-18T13:00:00Z",
    policy: createOpaqueRoutePolicyV2({
      paddingBucket: 4_096,
      retentionBucket: 3_600,
      quotaBucket: 64
    })
  });
  const request = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities: clientCapabilities,
    lease,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const route = await createOpaqueReceiveRouteV2({
    crypto,
    request,
    presentedRenewCapability: clientCapabilities.renewCapability,
    confidentialTransport: true,
    receivedAt: authorizedAt
  });
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const localReceiveRoute = await createLocalOpaqueReceiveRouteV2({
    crypto,
    relay: relayEndpoint,
    route,
    clientCapabilities,
    payloadKey
  });
  return { crypto, clientCapabilities, route, payloadKey, localReceiveRoute };
}

function commitResponse(cursor) {
  return Object.freeze({
    committedCursor: cursor,
    highWatermark: cursor,
    retentionFloor: cursor
  });
}

function patternedBytes(length, offset = 0) {
  return Uint8Array.from({ length }, (_, index) => (index + offset) & 0xff);
}
