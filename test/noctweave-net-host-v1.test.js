import assert from "node:assert/strict";
import test from "node:test";
import {
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  base64,
  createNoctweaveNetHostPutV1,
  noctweaveNetHostReleaseDigest,
  relayRequests,
  validateNoctweaveNetHostPutBody,
  verifyNoctweaveNetHostingReceiptV1
} from "../src/index.js";

const encoder = new TextEncoder();

test("Noctweave Net host put material is content-addressed, bounded, and random", async () => {
  const primitives = new WebCryptoPrimitives();
  const payload = encoder.encode("<h1>Noctweb</h1>");
  const prepared = await createNoctweaveNetHostPutV1({
    crypto: primitives,
    payload,
    ttlSeconds: 3_600
  });

  assert.match(prepared.request.objectID, /^[0-9a-f]{64}$/u);
  assert.equal(prepared.request.payload, base64(payload));
  assert.equal(prepared.byteCount, payload.byteLength);
  assert.equal(prepared.releaseCapability.byteLength, 32);
  assert.equal(prepared.idempotencyKey.byteLength, 32);
  assert.equal(
    prepared.request.releaseCapabilityDigest,
    base64(await noctweaveNetHostReleaseDigest(primitives, prepared.releaseCapability))
  );
  assert.deepEqual(
    relayRequests.putNetHostObject(prepared.request).body,
    prepared.request
  );
  assert.throws(
    () => validateNoctweaveNetHostPutBody({
      ...prepared.request,
      payload: base64(new Uint8Array(1_024 * 1_024 + 1))
    }),
    /size bound/u
  );
});

test("relay client hosts, verifies, checks, and releases exact Noctweave Net bytes", async () => {
  const primitives = new WebCryptoPrimitives();
  const signingKey = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  );
  const signingPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", signingKey.publicKey)
  );
  const payload = encoder.encode("<main id=\"root\"></main>");
  const calls = [];
  let releaseCapability;

  const fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    calls.push(request);
    switch (request.method) {
    case "put": {
      const receipt = await signedReceipt(
        signingKey.privateKey,
        signingPublicKey,
        request.body.objectID,
        payload.byteLength
      );
      return response(relaySuccess(request, { receipt }));
    }
    case "get": {
      const receipt = await signedReceipt(
        signingKey.privateKey,
        signingPublicKey,
        request.body.objectID,
        payload.byteLength
      );
      return response(relaySuccess(request, {
        object: { receipt, payload: base64(payload) }
      }));
    }
    case "has":
      return response(relaySuccess(request, {
        presence: {
          objectID: request.body.objectID,
          present: true,
          expiresAt: "2026-07-26T11:00:00Z"
        }
      }));
    case "release":
      releaseCapability = request.body.releaseCapability;
      return response(relaySuccess(request, {
        release: { objectID: request.body.objectID, released: true }
      }));
    default:
      throw new Error("Unexpected relay method.");
    }
  };
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch,
    authToken: "host-access-password",
    crypto: primitives,
    policy: {
      maxRequestBytes: 2 * 1_024 * 1_024,
      maxResponseBytes: 2 * 1_024 * 1_024
    }
  });

  const hosted = await client.putNetHostObject({ payload, ttlSeconds: 3_600 });
  assert.equal(hosted.receipt.objectID, hosted.objectID);
  assert.equal(calls[0].authToken, "host-access-password");
  assert.equal(calls[0].body.releaseCapabilityDigest.length, 44);
  assert.equal(calls[0].body.idempotencyKey.length, 44);

  const fetched = await client.getNetHostObject(hosted.objectID);
  assert.deepEqual(fetched.payload, payload);
  assert.equal(await verifyNoctweaveNetHostingReceiptV1(fetched.receipt), true);

  const presence = await client.hasNetHostObject(hosted.objectID);
  assert.equal(presence.present, true);

  const released = await client.releaseNetHostObject({
    objectID: hosted.objectID,
    releaseCapability: hosted.releaseCapability
  });
  assert.equal(released.released, true);
  assert.equal(releaseCapability, base64(hosted.releaseCapability));
});

test("default client budget carries the maximum host object and rejects a forged put receipt", async () => {
  const primitives = new WebCryptoPrimitives();
  const signingKey = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  );
  const signingPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", signingKey.publicKey)
  );
  const payload = new Uint8Array(1_024 * 1_024);
  const fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    const receipt = await signedReceipt(
      signingKey.privateKey,
      signingPublicKey,
      request.body.objectID,
      payload.byteLength
    );
    return response(relaySuccess(request, { receipt }));
  };
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch,
    authToken: "host-access-password",
    crypto: primitives
  });

  const hosted = await client.putNetHostObject(
    { payload, ttlSeconds: 3_600 },
    { expectedHostSigningPublicKey: signingPublicKey }
  );
  assert.equal(hosted.receipt.byteCount, payload.byteLength);

  const forgedClient = new NoctweaveRelayClient("https://relay.example", {
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      const receipt = await signedReceipt(
        signingKey.privateKey,
        signingPublicKey,
        request.body.objectID,
        encoder.encode("forged").byteLength
      );
      receipt.signature = base64(new Uint8Array(64));
      return response(relaySuccess(request, { receipt }));
    },
    authToken: "host-access-password",
    crypto: primitives
  });
  await assert.rejects(
    forgedClient.putNetHostObject({ payload: encoder.encode("forged"), ttlSeconds: 3_600 }),
    /receipt verification failed/u
  );
});

async function signedReceipt(privateKey, publicKey, objectID, byteCount) {
  const storedAt = "2026-07-26T10:00:00Z";
  const expiresAt = "2026-07-26T11:00:00Z";
  const signingPayload = concatenate(
    encoder.encode("org.noctweave.net/hosting-receipt/v1"),
    Uint8Array.of(0),
    encoder.encode(objectID),
    uint64(byteCount),
    uint64(Date.parse(storedAt) / 1_000),
    uint64(Date.parse(expiresAt) / 1_000)
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, signingPayload)
  );
  return {
    objectID,
    byteCount,
    storedAt,
    expiresAt,
    signingPublicKey: base64(publicKey),
    signatureAlgorithm: "Ed25519",
    signature: base64(signature)
  };
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

function response(value) {
  const body = JSON.stringify(value);
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(body).byteLength)
    }
  });
}

function uint64(value) {
  let remaining = BigInt(value);
  const output = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function concatenate(...values) {
  const output = new Uint8Array(values.reduce((count, value) => count + value.byteLength, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}
