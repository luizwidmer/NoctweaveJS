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
  opaqueRouteRecordDigestV2,
  relayClientPolicyDefaults,
  relayClientPolicyLimits,
  relayRequests,
  rendezvousRelayTransportV2,
  renewOpaqueReceiveRouteV2,
  sealOpaqueRouteBundleV2,
  swiftISODate,
  teardownOpaqueReceiveRouteV2
} from "../src/index.js";

test("relay client posts bounded authenticated requests", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    const request = JSON.parse(init.body);
    return jsonResponse(relaySuccess(request, { relayInfo: { relayName: "Test" } }));
  };
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch,
    authToken: "secret"
  });

  const response = await client.info();

  assert.deepEqual(response, { relayInfo: { relayName: "Test" } });
  assert.equal(calls[0].url, "https://relay.example/relay");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.referrerPolicy, "no-referrer");
  assert.equal(calls[0].init.cache, "no-store");
  const request = JSON.parse(calls[0].init.body);
  assert.deepEqual(
    { ...request, requestID: "<dynamic>" },
    {
      requestID: "<dynamic>",
      module: "nw.core",
      version: 2,
      method: "info",
      body: {},
      authToken: "secret"
    }
  );
});

test("relay client requires exact correlated responses and bounded error codes", async () => {
  const mismatched = new NoctweaveRelayClient("https://relay.example", {
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      return jsonResponse(relaySuccess({
        ...request,
        requestID: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
      }, { relayInfo: {} }));
    }
  });
  await assert.rejects(() => mismatched.info(), /does not correlate/);

  const rejected = new NoctweaveRelayClient("https://relay.example", {
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      return jsonResponse({
        requestID: request.requestID,
        module: request.module,
        version: request.version,
        method: request.method,
        status: "error",
        body: null,
        error: { code: "rate-limited", message: "private relay detail", retryable: true }
      });
    }
  });
  await assert.rejects(() => rejected.info(), (error) => {
    assert.equal(error.code, "rate-limited");
    assert.equal(error.retryable, true);
    assert.doesNotMatch(error.message, /private relay detail/);
    return true;
  });
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
  const initialRecordDigest = base64(new Uint8Array(32));
  const fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    requests.push(request);
    switch (`${request.module}/${request.method}`) {
    case "nw.opaque-route/create":
      route = await createOpaqueReceiveRouteV2({
        crypto,
        request: request.body.request,
        presentedRenewCapability: request.body.renewCapability,
        confidentialTransport: true,
        receivedAt: issuedAt
      });
      return jsonResponse(relaySuccess(request, { route }));
    case "nw.opaque-route/renew":
      route = await renewOpaqueReceiveRouteV2({
        crypto,
        current: route,
        request: request.body.request,
        presentedCapability: request.body.renewCapability,
        confidentialTransport: true,
        receivedAt: issuedAt
      });
      return jsonResponse(relaySuccess(request, { route }));
    case "nw.opaque-route/append":
      packet = request.body.packet;
      return jsonResponse(relaySuccess(request, {
        receipt: {
          packetID: packet.packetID,
          acceptedCursor: cursor,
          highWatermark: cursor
        }
      }));
    case "nw.opaque-route/sync":
      const recordDigest = await opaqueRouteRecordDigestV2({
        crypto,
        previousRecordDigest: initialRecordDigest,
        sequence: 1,
        routeRevision: 1,
        packet
      });
      return jsonResponse(relaySuccess(request, {
        batch: {
          packets: [{
            sequence: 1,
            previousRecordDigest: initialRecordDigest,
            recordDigest,
            routeRevision: 1,
            packet
          }],
          startsAfterSequence: 0,
          startsAfterRecordDigest: initialRecordDigest,
          nextSequence: 1,
          nextRecordDigest: recordDigest,
          highWatermarkSequence: 1,
          retentionFloorSequence: 0,
          nextCursor: cursor,
          highWatermark: cursor,
          retentionFloor: cursor,
          hasMore: false
        }
      }));
    case "nw.opaque-route/commit":
      return jsonResponse(relaySuccess(request, {
        commit: {
          committedCursor: request.body.request.cursor,
          highWatermark: cursor,
          retentionFloor: cursor
        }
      }));
    case "nw.opaque-route/teardown":
      route = await teardownOpaqueReceiveRouteV2({
        crypto,
        current: route,
        request: request.body.request,
        presentedCapability: request.body.teardownCapability,
        confidentialTransport: true,
        receivedAt: "2026-07-16T12:35:00Z"
      });
      return jsonResponse(relaySuccess(request, { route }));
    default:
      throw new Error(`Unexpected request: ${request.module}/${request.method}`);
    }
  };
  const client = new NoctweaveRelayClient("https://relay.example", { fetch, crypto });

  const created = await client.createOpaqueRoute({
    request: createTransition,
    renewCapability: capabilities.renewCapability
  });
  const renewTransition = await makeOpaqueRouteRenewRequestV2({
    crypto,
    capabilities,
    current: created,
    newExpiry: "2026-07-16T14:34:56Z",
    authorizedAt: issuedAt,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const renewed = await client.renewOpaqueRoute({
    request: renewTransition,
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
    cursor: synced.nextCursor,
    authorizedAt: issuedAt
  });
  await client.commitOpaqueRoute({
    request: commitRequest,
    readCredential: capabilities.readCredential
  });
  const teardownTransition = await makeOpaqueRouteTeardownRequestV2({
    crypto,
    capabilities,
    current: renewed,
    authorizedAt: "2026-07-16T12:35:00Z",
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const tornDown = await client.teardownOpaqueRoute({
    request: teardownTransition,
    teardownCapability: capabilities.teardownCapability
  });

  assert.equal(tornDown.status, "tornDown");
  assert.equal(synced.packets.length, 1);
  assert.deepEqual(requests.map(({ method }) => method), [
    "create",
    "renew",
    "append",
    "sync",
    "commit",
    "teardown"
  ]);
  for (const request of requests) {
    assert.equal(JSON.stringify(request).includes(capabilities.readCredential.rawValue),
      ["sync", "commit"].includes(request.method));
  }
});

test("relay client runs the identity-blind rendezvous transport lifecycle", async () => {
  const registration = rendezvousRegistration();
  const lane = registration.lanes[0];
  const frame = {
    frameId: opaqueValue(0x31, 16),
    sequence: 1,
    ciphertext: base64(new Uint8Array(4_096).fill(0x32))
  };
  const append = {
    routeCapability: registration.routeCapability,
    laneId: lane.laneId,
    publishCapability: lane.publishCapability,
    frame
  };
  const sync = {
    routeCapability: registration.routeCapability,
    laneId: lane.laneId,
    readCapability: lane.readCapability,
    afterSequence: 0,
    maxCount: null
  };
  const deletion = {
    routeCapability: registration.routeCapability,
    laneId: lane.laneId,
    deleteCapability: lane.deleteCapability
  };
  const requests = [];
  const fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    requests.push(request);
    if (request.method === "sync") {
      return jsonResponse(relaySuccess(request, {
        batch: {
          frames: [frame],
          highWatermark: 1,
          nextSequence: 1,
          hasMore: false
        }
      }));
    }
    return jsonResponse(relaySuccess(request, {}));
  };
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  assert.equal(await client.registerRendezvousTransportV2(registration), undefined);
  assert.equal(await client.appendRendezvousTransportV2(append), undefined);
  assert.deepEqual(await client.syncRendezvousTransportV2(sync), {
    frames: [frame],
    highWatermark: 1,
    nextSequence: 1,
    hasMore: false
  });
  assert.equal(await client.deleteRendezvousTransportV2(deletion), undefined);
  assert.deepEqual(requests.map(({ module, version, method }) => ({ module, version, method })), [
    { module: "nw.rendezvous-transport", version: 2, method: "register" },
    { module: "nw.rendezvous-transport", version: 2, method: "append" },
    { module: "nw.rendezvous-transport", version: 2, method: "sync" },
    { module: "nw.rendezvous-transport", version: 2, method: "delete" }
  ]);
  const visible = JSON.stringify(requests).toLowerCase();
  for (const forbidden of [
    "purpose", "generation", "identity", "fingerprint", "contact", "relationship",
    "endpoint", "inbox", "provider", "publickey"
  ]) {
    assert.equal(visible.includes(forbidden), false, forbidden);
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
    /current protocol fields/
  );
  await assert.rejects(
    () => client.send({ type: "custom", payload: {} }),
    /current protocol fields/
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
    "registerRendezvousTransportV2",
    "appendRendezvousTransportV2",
    "syncRendezvousTransportV2",
    "deleteRendezvousTransportV2",
    "uploadAttachment",
    "fetchAttachment"
  ]);
});

test("attachment upload requires an exact bounded encrypted payload", () => {
  const payload = {
    nonce: base64(new Uint8Array(12).fill(0x11)),
    ciphertext: base64(Uint8Array.of(0x22)),
    tag: base64(new Uint8Array(16).fill(0x33))
  };
  const input = {
    attachmentId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
    chunkIndex: 0,
    payload
  };
  const request = relayRequests.uploadAttachment(input);
  assert.deepEqual(request.body.payload, payload);

  assert.throws(
    () => relayRequests.uploadAttachment({
      ...input,
      payload: { ...payload, legacy: true }
    }),
    /exactly its current protocol fields/
  );
  const { tag: _tag, ...missingTag } = payload;
  assert.throws(
    () => relayRequests.uploadAttachment({ ...input, payload: missingTag }),
    /exactly its current protocol fields/
  );
  assert.throws(
    () => relayRequests.uploadAttachment({
      ...input,
      payload: { ...payload, nonce: base64(new Uint8Array(11).fill(0x11)) }
    }),
    /invalid encoding or length/
  );
  assert.throws(
    () => relayRequests.uploadAttachment({
      ...input,
      payload: { ...payload, ciphertext: "" }
    }),
    /must be base64/
  );
  assert.throws(
    () => relayRequests.uploadAttachment({
      ...input,
      payload: {
        ...payload,
        ciphertext: base64(new Uint8Array(128 * 1_024).fill(0x22))
      }
    }),
    /protocol size limit/
  );
});

test("web client exposes current opaque route and rendezvous transport operations", () => {
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
    "commitOpaqueRoute",
    "registerRendezvousTransportV2",
    "appendRendezvousTransportV2",
    "syncRendezvousTransportV2",
    "deleteRendezvousTransportV2"
  ]) {
    assert.equal(typeof web[method], "function");
  }
});

test("relay health uses only the exact modular relay endpoint", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    throw new TypeError("relay unavailable");
  };
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  await assert.rejects(() => client.health(), /relay unavailable/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://relay.example/relay");
  assert.equal(calls[0].init.method, "POST");
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

test("relay client rejects duplicate response fields before envelope validation", async () => {
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      return new Response(
        `{"requestID":"${request.requestID}","module":"nw.core","version":2,` +
        `"method":"info","status":"success","\\u0073tatus":"error",` +
        '"body":{},"error":null}'
      );
    }
  });
  await assert.rejects(() => client.info(), /invalid JSON/);
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
  const maximumLaneBase64Bytes = 4 * Math.ceil(
    rendezvousRelayTransportV2.maximumCiphertextBytesPerLane / 3
  );
  assert.ok(relayClientPolicyDefaults.maxResponseBytes > maximumLaneBase64Bytes + 64 * 1_024);
  const oversized = new Uint8Array(relayClientPolicyDefaults.maxResponseBytes + 1).fill(0x61);
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
    policy: { maxRequestBytes: 1_024 },
    fetch: async () => {
      called = true;
      return jsonResponse({ type: "ok" });
    }
  });
  await assert.rejects(
    () => requestClient.send(relayRequests.uploadAttachment({
      attachmentId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
      chunkIndex: 0,
      payload: {
        nonce: base64(new Uint8Array(12).fill(0x11)),
        ciphertext: base64(new Uint8Array(2_048).fill(0x22)),
        tag: base64(new Uint8Array(16).fill(0x33))
      }
    })),
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

function relaySuccess(request, body) {
  return {
    requestID: request.requestID,
    module: request.module,
    version: request.version,
    method: request.method,
    status: "success",
    body,
    error: null
  };
}

function rendezvousRegistration() {
  return {
    version: 2,
    routeCapability: opaqueValue(0x21, 32),
    expiresAt: swiftISODate(new Date(Date.now() + (5 * 60 * 1_000))),
    lanes: [
      rendezvousLane(0x22, 0x23, 0x24, 0x25),
      rendezvousLane(0x26, 0x27, 0x28, 0x29)
    ]
  };
}

function rendezvousLane(lane, publish, read, deletion) {
  return {
    laneId: opaqueValue(lane, 32),
    publishCapability: opaqueValue(publish, 32),
    readCapability: opaqueValue(read, 32),
    deleteCapability: opaqueValue(deletion, 32)
  };
}

function opaqueValue(repeatedByte, length) {
  return { rawValue: base64(new Uint8Array(length).fill(repeatedByte)) };
}
