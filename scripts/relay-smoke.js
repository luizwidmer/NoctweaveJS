#!/usr/bin/env node
import {
  NoctweaveRelayClient,
  WebCryptoPrimitives,
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
console.log(`Info: ${info.relayInfo?.relayName ?? info.type ?? "unknown"}`);

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
  transition: createTransition,
  renewCapability: capabilities.renewCapability
});
console.log(`Created opaque route: ${created.opaqueRouteV2.status}`);

const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
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
console.log(`Synced packets: ${synced.opaqueRouteSyncV2.packets.length}`);

const commitRequest = await makeOpaqueRouteCommitRequestV2({
  crypto,
  capabilities,
  cursor: synced.opaqueRouteSyncV2.nextCursor
});
await client.commitOpaqueRoute({
  request: commitRequest,
  readCredential: capabilities.readCredential
});
console.log("Committed opaque route cursor: ok");

const teardownTransition = await makeOpaqueRouteTeardownRequestV2({
  crypto,
  capabilities,
  current: created.opaqueRouteV2,
  authorizedAt: swiftISODate(),
  idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
  nonce: await createOpaqueRouteProofNonceV2(crypto)
});
const tornDown = await client.teardownOpaqueRoute({
  transition: teardownTransition,
  teardownCapability: capabilities.teardownCapability
});
console.log(`Tore down opaque route: ${tornDown.opaqueRouteV2.status}`);

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
