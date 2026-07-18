#!/usr/bin/env node
import {
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  advanceLocalOpaqueReceiveRouteV2,
  assertOpaqueRouteSyncContinuityV2,
  createLocalOpaqueReceiveRouteV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePayloadKeyV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteCommitRequestV2,
  makeOpaqueRouteCreateRequestV2,
  makeOpaqueRouteSyncRequestV2,
  makeOpaqueRouteTeardownRequestV2,
  sealOpaqueRouteBundleV2,
  swiftISODate
} from "../src/index.js";

const options = parseArgs(process.argv.slice(2));
const endpoint = options.relay ?? "http://127.0.0.1:9339";
const crypto = new WebCryptoPrimitives();
const client = new NoctweaveRelayClient(endpoint, {
  authToken: options.authToken,
  timeoutMs: Number(options.timeoutMs ?? 8_000),
  crypto
});

console.log(`Relay: ${endpoint}`);
console.log(`Health: ${JSON.stringify(await client.health())}`);
const info = await client.info();
console.log(`Info: ${info.relayInfo?.relayName ?? "unknown"}`);

const createdAt = new Date();
const createdAtValue = swiftISODate(createdAt);
const expiresAt = swiftISODate(new Date(createdAt.getTime() + 60 * 60 * 1_000));
const capabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
const lease = createOpaqueRouteLeaseV2({
  issuedAt: createdAtValue,
  expiresAt,
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
const created = await client.createOpaqueRoute({
  request: createTransition,
  renewCapability: capabilities.renewCapability
});
console.log(`Created opaque route: ${created.status}`);

const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
let localReceiveRoute = await createLocalOpaqueReceiveRouteV2({
  crypto,
  relay: client.endpoint,
  route: created,
  clientCapabilities: capabilities,
  payloadKey
});
const bundle = await sealOpaqueRouteBundleV2({
  crypto,
  payload: new TextEncoder().encode(options.text ?? `Noctweave route smoke ${createdAtValue}`),
  routeRevision: 0,
  paddingBucket: lease.policy.paddingBucket,
  payloadKey,
  routeCapabilities: capabilities,
  authorizedAt: createdAtValue
});
for (const packet of bundle.packets) {
  await client.enqueueOpaqueRoute({ packet, sendCapability: capabilities.sendCapability });
}
console.log(`Enqueued packets: ${bundle.packets.length}`);

const syncRequest = await makeOpaqueRouteSyncRequestV2({
  crypto,
  capabilities,
  limit: 16
});
const synced = await client.syncOpaqueRoute({
  request: syncRequest,
  readCredential: capabilities.readCredential
});
assertOpaqueRouteSyncContinuityV2({
  batch: synced,
  localReceiveRoute,
  detectedAt: swiftISODate()
});
console.log(`Synced packets: ${synced.packets.length}`);

// This protocol smoke runner has no application database. It still advances
// the local candidate before authorizing relay garbage collection. Production
// clients must durably persist this candidate, its reassembly snapshot, and
// batch effects atomically before sending the commit request; use
// NoctweaveWebClient.commitOpaqueRoute for that transaction boundary.
localReceiveRoute = await advanceLocalOpaqueReceiveRouteV2({
  crypto,
  localReceiveRoute,
  batch: synced,
  detectedAt: swiftISODate()
});
const commitRequest = await makeOpaqueRouteCommitRequestV2({
  crypto,
  capabilities,
  cursor: synced.nextCursor
});
await client.commitOpaqueRoute({
  request: commitRequest,
  readCredential: capabilities.readCredential
});
console.log(`Committed opaque route sequence: ${localReceiveRoute.committedSequence}`);

const teardownTransition = await makeOpaqueRouteTeardownRequestV2({
  crypto,
  capabilities,
  current: created,
  authorizedAt: swiftISODate(),
  idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
  nonce: await createOpaqueRouteProofNonceV2(crypto)
});
const tornDown = await client.teardownOpaqueRoute({
  request: teardownTransition,
  teardownCapability: capabilities.teardownCapability
});
console.log(`Tore down opaque route: ${tornDown.status}`);

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(`Expected a value after ${flag}.`);
    }
    const key = flag.slice(2).replace(/-([a-z])/g, (_, character) => character.toUpperCase());
    parsed[key] = value;
    index += 1;
  }
  return parsed;
}
