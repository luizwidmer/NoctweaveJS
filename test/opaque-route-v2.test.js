import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  OpaqueRouteV2Error,
  authorizeOpaqueRouteUseV2,
  createOpaqueReceiveRouteV2,
  createOpaqueRouteAuthorizationReplayLedgerV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteCreateRequestV2,
  makeOpaqueRouteRenewRequestV2,
  makeOpaqueRouteTeardownRequestV2,
  makeOpaqueRouteUseAuthorizationV2,
  opaqueRouteTransitionDigestV2,
  renewOpaqueReceiveRouteV2,
  teardownOpaqueReceiveRouteV2,
  validateOpaqueReceiveRouteV2,
  validateOpaqueRouteAuthorizationReplayLedgerV2
} from "../src/opaque-route-v2.js";
import { WebCryptoPrimitives } from "../src/crypto/webcrypto.js";
import { base64, canonicalJson } from "../src/crypto/swift-canonical.js";

const vectors = JSON.parse(readFileSync(
  new URL("../../NoctweaveDocumentation/test_vectors/rendezvous_opaque_v2.json", import.meta.url),
  "utf8"
));
const routeVector = vectors.opaqueRouteCreate;
const issuedAt = routeVector.issuedAt;
const receivedAt = "2026-07-16T12:01:00Z";
const expiresAt = routeVector.expiresAt;

test("opaque route creation keeps four authorities independent and relay state digest-only", async () => {
  const crypto = testCrypto();
  const fixture = await createFixture(crypto);
  const request = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities: fixture.capabilities,
    lease: fixture.lease,
    idempotencyKey: fixture.idempotencyKey,
    nonce: fixture.nonce
  });
  const route = await createOpaqueReceiveRouteV2({
    crypto,
    request,
    presentedRenewCapability: fixture.capabilities.renewCapability,
    confidentialTransport: true,
    receivedAt
  });

  const rawAuthorities = [
    fixture.capabilities.sendCapability.rawValue,
    fixture.capabilities.readCredential.rawValue,
    fixture.capabilities.renewCapability.rawValue,
    fixture.capabilities.teardownCapability.rawValue
  ];
  assert.equal(new Set(rawAuthorities).size, 4);
  assert.equal(route.status, "active");
  assert.equal(route.tornDownAt, null);
  assert.equal(route.routeID.rawValue, fixture.capabilities.routeID.rawValue);
  assert.deepEqual(validateOpaqueReceiveRouteV2(route), route);
  const missingTornDownAt = structuredClone(route);
  delete missingTornDownAt.tornDownAt;
  assert.throws(
    () => validateOpaqueReceiveRouteV2(missingTornDownAt),
    /current protocol fields/
  );
  assert.throws(
    () => validateOpaqueReceiveRouteV2({ ...route, tornDownAt: issuedAt }),
    (error) => error instanceof OpaqueRouteV2Error && error.code === "invalidRequest"
  );

  const relayProjection = JSON.stringify(route);
  for (const authority of rawAuthorities) {
    assert.equal(relayProjection.includes(authority), false);
  }
  for (const forbidden of ["identity", "generation", "endpoint", "relationship", "provider", "owner", "account", "reusableaddress"]) {
    assert.equal(relayProjection.toLowerCase().includes(forbidden), false, forbidden);
  }
  assert.equal(request.lease.policy.transportRequirement, "confidentialAuthenticated");

  const retry = await createOpaqueReceiveRouteV2({
    crypto,
    request: structuredClone(request),
    presentedRenewCapability: fixture.capabilities.renewCapability,
    existing: route,
    confidentialTransport: true,
    receivedAt
  });
  assert.deepEqual(retry, route);
  await assert.rejects(
    () => createOpaqueReceiveRouteV2({
      crypto,
      request,
      presentedRenewCapability: fixture.capabilities.renewCapability,
      confidentialTransport: false,
      receivedAt
    }),
    (error) => error instanceof OpaqueRouteV2Error && error.code === "confidentialTransportRequired"
  );
});

test("opaque route transition digests use the Swift sorted-JSON projection", async () => {
  const crypto = testCrypto();
  const fixture = await createFixture(crypto);
  const request = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities: fixture.capabilities,
    lease: fixture.lease,
    idempotencyKey: fixture.idempotencyKey,
    nonce: fixture.nonce
  });
  const digest = await opaqueRouteTransitionDigestV2(crypto, request);
  assert.equal(
    Buffer.from(digest).toString("hex"),
    routeVector.expectedTransitionDigestHex
  );
  assert.equal(
    Buffer.from(request.authorization.mac, "base64").toString("hex"),
    routeVector.expectedAuthorizationMACHex
  );

  const unsigned = structuredClone(request);
  delete unsigned.authorization;
  const canonical = canonicalJson(unsigned);
  assert.equal(canonical.startsWith("{\"idempotencyKey\":{\"rawValue\":"), true);
  assert.equal(canonical.includes("\"transportRequirement\":\"confidentialAuthenticated\""), true);
});

test("opaque route renewals are ordered and teardown leaves a non-resurrectable tombstone", async () => {
  const crypto = testCrypto();
  const fixture = await createFixture(crypto);
  const createRequest = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities: fixture.capabilities,
    lease: fixture.lease,
    idempotencyKey: fixture.idempotencyKey,
    nonce: fixture.nonce
  });
  const created = await createOpaqueReceiveRouteV2({
    crypto,
    request: createRequest,
    presentedRenewCapability: fixture.capabilities.renewCapability,
    confidentialTransport: true,
    receivedAt
  });
  const renewalTime = "2026-07-16T12:10:00Z";
  const renewRequest = await makeOpaqueRouteRenewRequestV2({
    crypto,
    capabilities: fixture.capabilities,
    current: created,
    newExpiry: "2026-07-16T14:00:00Z",
    authorizedAt: renewalTime,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const renewed = await renewOpaqueReceiveRouteV2({
    crypto,
    current: created,
    request: renewRequest,
    presentedCapability: fixture.capabilities.renewCapability,
    confidentialTransport: true,
    receivedAt: renewalTime
  });
  assert.equal(renewed.lease.renewalSequence, 1);
  assert.equal(renewed.lease.expiresAt, "2026-07-16T14:00:00Z");
  assert.deepEqual(await renewOpaqueReceiveRouteV2({
    crypto,
    current: renewed,
    request: renewRequest,
    presentedCapability: fixture.capabilities.renewCapability,
    confidentialTransport: true,
    receivedAt: renewalTime
  }), renewed);

  const teardownTime = "2026-07-16T12:11:00Z";
  const teardownRequest = await makeOpaqueRouteTeardownRequestV2({
    crypto,
    capabilities: fixture.capabilities,
    current: renewed,
    authorizedAt: teardownTime,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const tombstone = await teardownOpaqueReceiveRouteV2({
    crypto,
    current: renewed,
    request: teardownRequest,
    presentedCapability: fixture.capabilities.teardownCapability,
    confidentialTransport: true,
    receivedAt: teardownTime
  });
  assert.equal(tombstone.status, "tornDown");
  assert.equal(tombstone.tornDownAt, teardownTime);
  await assert.rejects(
    () => createOpaqueReceiveRouteV2({
      crypto,
      request: createRequest,
      presentedRenewCapability: fixture.capabilities.renewCapability,
      existing: tombstone,
      confidentialTransport: true,
      receivedAt
    }),
    (error) => error.code === "routeTornDown"
  );
});

test("send and read proofs are least-privilege, time-bounded, and replay-safe after persistence", async () => {
  const crypto = testCrypto();
  const fixture = await createFixture(crypto);
  const request = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities: fixture.capabilities,
    lease: fixture.lease,
    idempotencyKey: fixture.idempotencyKey,
    nonce: fixture.nonce
  });
  const route = await createOpaqueReceiveRouteV2({
    crypto,
    request,
    presentedRenewCapability: fixture.capabilities.renewCapability,
    confidentialTransport: true,
    receivedAt
  });
  const operationDigest = base64(new Uint8Array(32).fill(0x91));
  const proof = await makeOpaqueRouteUseAuthorizationV2({
    crypto,
    capabilities: fixture.capabilities,
    authority: "send",
    operationDigest,
    authorizedAt: receivedAt,
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  const ledger = await authorizeOpaqueRouteUseV2({
    crypto,
    current: route,
    proof,
    operationDigest,
    presentedCredential: fixture.capabilities.sendCapability,
    authority: "send",
    confidentialTransport: true,
    receivedAt,
    replayLedger: createOpaqueRouteAuthorizationReplayLedgerV2()
  });
  assert.equal(ledger.consumedDigests.length, 1);
  const restored = validateOpaqueRouteAuthorizationReplayLedgerV2(JSON.parse(JSON.stringify(ledger)));
  await assert.rejects(
    () => authorizeOpaqueRouteUseV2({
      crypto,
      current: route,
      proof,
      operationDigest,
      presentedCredential: fixture.capabilities.sendCapability,
      authority: "send",
      confidentialTransport: true,
      receivedAt,
      replayLedger: restored
    }),
    (error) => error.code === "authorizationReplay"
  );
  await assert.rejects(
    () => authorizeOpaqueRouteUseV2({
      crypto,
      current: route,
      proof,
      operationDigest,
      presentedCredential: fixture.capabilities.readCredential,
      authority: "read",
      confidentialTransport: true,
      receivedAt,
      replayLedger: createOpaqueRouteAuthorizationReplayLedgerV2()
    }),
    (error) => error.code === "invalidAuthorization"
  );
});

async function createFixture(crypto) {
  const capabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const policy = createOpaqueRoutePolicyV2({
    paddingBucket: routeVector.paddingBucket,
    retentionBucket: routeVector.retentionBucket,
    quotaBucket: routeVector.quotaBucket
  });
  return {
    capabilities,
    lease: createOpaqueRouteLeaseV2({ issuedAt, expiresAt, policy }),
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  };
}

function testCrypto() {
  const webcrypto = new WebCryptoPrimitives();
  let sequence = 1;
  return {
    randomBytes(length) {
      const output = new Uint8Array(length);
      output.fill(sequence);
      sequence += 1;
      return output;
    },
    sha256: (data) => webcrypto.sha256(data),
    hmacSha256: (input) => webcrypto.hmacSha256(input)
  };
}
