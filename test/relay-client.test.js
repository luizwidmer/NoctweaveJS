import assert from "node:assert/strict";
import test from "node:test";
import {
  MemoryNoctweaveStore,
  NoctweaveRelayClient,
  NoctweaveWebClient,
  WebCryptoPrimitives,
  base64,
  createOpaqueReceiveRouteV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePayloadKeyV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteCommitRequestV2,
  makeOpaqueRouteCreateRequestV2,
  makeOpaqueRouteRenewRequestV2,
  makeOpaqueRouteSyncRequestV2,
  makeOpaqueRouteTeardownRequestV2,
  normalizeRelayClientPolicy,
  relayClientPolicyLimits,
  relayRequests,
  renewOpaqueReceiveRouteV2,
  sealOpaqueRouteBundleV2,
  swiftISODate,
  teardownOpaqueReceiveRouteV2
} from "../src/index.js";

test("relay client posts bounded authenticated requests", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ type: "info", relayInfo: { relayName: "Test" } }));
  };
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch,
    authToken: "secret"
  });

  const response = await client.info();

  assert.equal(response.type, "info");
  assert.equal(calls[0].url, "https://relay.example/relay");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.referrerPolicy, "no-referrer");
  assert.equal(calls[0].init.cache, "no-store");
  assert.deepEqual(JSON.parse(calls[0].init.body), { type: "info", authToken: "secret" });
});

test("relay client runs the exact opaque route lifecycle", async () => {
  const crypto = new WebCryptoPrimitives();
  const capabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const issuedAt = "2026-07-16T12:34:56Z";
  const lease = createOpaqueRouteLeaseV2({
    issuedAt,
    expiresAt: "2026-07-16T13:34:56Z",
    policy: createOpaqueRoutePolicyV2({
      paddingBucket: 4_096,
      retentionBucket: 3_600,
      quotaBucket: 64
    })
  });
  const createTransition = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities,
    lease,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const requests = [];
  let route;
  let packet;
  const cursor = { rawValue: base64(new Uint8Array(68).fill(0x61)) };
  const fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    requests.push(request);
    switch (request.type) {
    case "createOpaqueRouteV2":
      route = await createOpaqueReceiveRouteV2({
        crypto,
        request: request.createOpaqueRouteV2.transition,
        presentedRenewCapability: request.createOpaqueRouteV2.renewCapability,
        confidentialTransport: true,
        receivedAt: issuedAt
      });
      return jsonResponse({ type: "opaqueRouteV2", opaqueRouteV2: route });
    case "renewOpaqueRouteV2":
      route = await renewOpaqueReceiveRouteV2({
        crypto,
        current: route,
        request: request.renewOpaqueRouteV2.transition,
        presentedCapability: request.renewOpaqueRouteV2.renewCapability,
        confidentialTransport: true,
        receivedAt: issuedAt
      });
      return jsonResponse({ type: "opaqueRouteV2", opaqueRouteV2: route });
    case "appendOpaqueRouteV2":
      packet = request.appendOpaqueRouteV2.packet;
      return jsonResponse({
        type: "opaqueRouteAppendV2",
        opaqueRouteAppendV2: {
          packetID: packet.packetID,
          acceptedCursor: cursor,
          highWatermark: cursor
        }
      });
    case "syncOpaqueRouteV2":
      return jsonResponse({
        type: "opaqueRouteSyncV2",
        opaqueRouteSyncV2: {
          packets: [{ routeRevision: 1, packet }],
          nextCursor: cursor,
          highWatermark: cursor,
          retentionFloor: cursor,
          hasMore: false
        }
      });
    case "commitOpaqueRouteV2":
      return jsonResponse({
        type: "opaqueRouteCommitV2",
        opaqueRouteCommitV2: {
          committedCursor: request.commitOpaqueRouteV2.request.cursor,
          highWatermark: cursor,
          retentionFloor: cursor
        }
      });
    case "teardownOpaqueRouteV2":
      route = await teardownOpaqueReceiveRouteV2({
        crypto,
        current: route,
        request: request.teardownOpaqueRouteV2.transition,
        presentedCapability: request.teardownOpaqueRouteV2.teardownCapability,
        confidentialTransport: true,
        receivedAt: "2026-07-16T12:35:00Z"
      });
      return jsonResponse({ type: "opaqueRouteV2", opaqueRouteV2: route });
    default:
      throw new Error(`Unexpected request: ${request.type}`);
    }
  };
  const client = new NoctweaveRelayClient("https://relay.example", { fetch, crypto });

  const created = await client.createOpaqueRoute({
    transition: createTransition,
    renewCapability: capabilities.renewCapability
  });
  const renewTransition = await makeOpaqueRouteRenewRequestV2({
    crypto,
    capabilities,
    current: created.opaqueRouteV2,
    newExpiry: "2026-07-16T14:34:56Z",
    authorizedAt: issuedAt,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const renewed = await client.renewOpaqueRoute({
    transition: renewTransition,
    renewCapability: capabilities.renewCapability
  });
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const bundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload: new TextEncoder().encode("opaque route payload"),
    routeRevision: 1,
    paddingBucket: 4_096,
    payloadKey,
    routeCapabilities: capabilities,
    authorizedAt: issuedAt
  });
  await client.enqueueOpaqueRoute({
    packet: bundle.packets[0],
    sendCapability: capabilities.sendCapability
  });
  const syncRequest = await makeOpaqueRouteSyncRequestV2({
    crypto,
    capabilities,
    limit: 16,
    authorizedAt: issuedAt
  });
  const synced = await client.syncOpaqueRoute({
    request: syncRequest,
    readCredential: capabilities.readCredential
  });
  const commitRequest = await makeOpaqueRouteCommitRequestV2({
    crypto,
    capabilities,
    cursor: synced.opaqueRouteSyncV2.nextCursor,
    authorizedAt: issuedAt
  });
  await client.commitOpaqueRoute({
    request: commitRequest,
    readCredential: capabilities.readCredential
  });
  const teardownTransition = await makeOpaqueRouteTeardownRequestV2({
    crypto,
    capabilities,
    current: renewed.opaqueRouteV2,
    authorizedAt: "2026-07-16T12:35:00Z",
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const tornDown = await client.teardownOpaqueRoute({
    transition: teardownTransition,
    teardownCapability: capabilities.teardownCapability
  });

  assert.equal(tornDown.opaqueRouteV2.status, "tornDown");
  assert.equal(synced.opaqueRouteSyncV2.packets.length, 1);
  assert.deepEqual(requests.map(({ type }) => type), [
    "createOpaqueRouteV2",
    "renewOpaqueRouteV2",
    "appendOpaqueRouteV2",
    "syncOpaqueRouteV2",
    "commitOpaqueRouteV2",
    "teardownOpaqueRouteV2"
  ]);
  for (const request of requests) {
    assert.equal(JSON.stringify(request).includes(capabilities.readCredential.rawValue),
      ["syncOpaqueRouteV2", "commitOpaqueRouteV2"].includes(request.type));
  }
});

test("relay request surface rejects operations outside the current protocol before transport", async () => {
  let called = false;
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch: async () => {
      called = true;
      return jsonResponse({ type: "ok" });
    }
  });

  await assert.rejects(
    () => client.send({ type: "retiredOperation", retiredOperation: {} }),
    /not part of the current/
  );
  await assert.rejects(
    () => client.send({ type: "custom", payload: {} }),
    /not part of the current/
  );
  assert.equal(called, false);
  assert.deepEqual(Object.keys(relayRequests), [
    "health",
    "info",
    "createOpaqueRoute",
    "renewOpaqueRoute",
    "teardownOpaqueRoute",
    "enqueueOpaqueRoute",
    "syncOpaqueRoute",
    "commitOpaqueRoute",
    "uploadAttachment",
    "fetchAttachment"
  ]);
});

test("web client exposes only current opaque route synchronization", () => {
  const web = new NoctweaveWebClient({
    relay: "https://relay.example",
    store: new MemoryNoctweaveStore(),
    crypto: new WebCryptoPrimitives(),
    fetch: async () => jsonResponse({ type: "ok" })
  });

  for (const method of [
    "createOpaqueRoute",
    "renewOpaqueRoute",
    "teardownOpaqueRoute",
    "enqueueOpaqueRoute",
    "syncOpaqueRoute",
    "commitOpaqueRoute"
  ]) {
    assert.equal(typeof web[method], "function");
  }
});

test("relay health fallback preserves redirect and credential isolation", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (calls.length === 1) throw new TypeError("POST health unavailable");
    return new Response("ok");
  };
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  assert.deepEqual(await client.health(), { type: "ok" });
  assert.equal(calls[1].url, "https://relay.example/health");
  assert.equal(calls[1].init.redirect, "error");
  assert.equal(calls[1].init.credentials, "omit");
});

test("tcp endpoint fails explicitly in web client", async () => {
  const client = new NoctweaveRelayClient("127.0.0.1:9339", {
    fetch: async () => jsonResponse({})
  });
  await assert.rejects(() => client.health(), /not raw TCP/);
});

test("relay client redacts HTTP and invalid JSON bodies", async () => {
  const failed = new NoctweaveRelayClient("https://relay.example", {
    fetch: async () => new Response("relay-secret-token", { status: 500 })
  });
  await assert.rejects(() => failed.info(), (error) => {
    assert.match(error.message, /Relay returned HTTP 500/);
    assert.doesNotMatch(error.message, /relay-secret-token/);
    return true;
  });
  const malformed = new NoctweaveRelayClient("https://relay.example", {
    fetch: async () => new Response("not-json-secret")
  });
  await assert.rejects(() => malformed.info(), (error) => {
    assert.match(error.message, /invalid JSON/);
    assert.doesNotMatch(error.message, /not-json-secret/);
    return true;
  });
});

test("relay client rejects invalid policy, authentication, and endpoint inputs", () => {
  assert.throws(
    () => new NoctweaveRelayClient("https://relay.example", {
      timeoutMs: 0,
      fetch: async () => jsonResponse({})
    }),
    /Relay timeout/
  );
  assert.throws(
    () => new NoctweaveRelayClient("https://relay.example", {
      authToken: "x".repeat(4_097),
      fetch: async () => jsonResponse({})
    }),
    /authentication token/
  );
  assert.throws(
    () => new NoctweaveRelayClient(
      { host: "relay.example/path", port: 443, useTLS: true, transport: "http" },
      { fetch: async () => jsonResponse({}) }
    )
  );
  assert.throws(
    () => normalizeRelayClientPolicy({
      maxResponseBytes: relayClientPolicyLimits.maximumResponseBytes + 1
    }),
    /response budget/
  );
});

test("relay client enforces bounded response and request allocation", async () => {
  const oversized = new Uint8Array(1_000_001).fill(0x61);
  const responseClient = new NoctweaveRelayClient("https://relay.example", {
    fetch: async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(oversized);
        controller.close();
      }
    }))
  });
  await assert.rejects(() => responseClient.info(), /response exceeds client size limit/);

  let called = false;
  const requestClient = new NoctweaveRelayClient("https://relay.example", {
    fetch: async () => {
      called = true;
      return jsonResponse({ type: "ok" });
    }
  });
  await assert.rejects(
    () => requestClient.send(relayRequests.uploadAttachment({ payload: "x".repeat(600_000) })),
    /request exceeds client size limit/
  );
  assert.equal(called, false);
});

test("relay client rejects unbounded fetch implementations", async () => {
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      text: async () => JSON.stringify({ type: "info" })
    })
  });
  await assert.rejects(() => client.info(), /must expose a streaming response body/);
});

function jsonResponse(value, init) {
  return new Response(JSON.stringify(value), init);
}
