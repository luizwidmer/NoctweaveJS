#!/usr/bin/env node
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  PairingLobbyHostSessionV1,
  PairingLobbyRequesterSessionV1,
  WebCryptoPrimitives,
  createContactPairingInvitationV2,
  decodeNoctweavePairingLinkV1,
  encodeNoctweavePairingLinkV1,
  swiftISODate,
  verifyPairingLobbyListingV1
} from "../src/index.js";

const options = parseArgs(process.argv.slice(2));
const endpoint = options.relay ?? "http://127.0.0.1:9340";
const authToken = options.authToken ?? process.env.NOCTWEAVE_RELAY_AUTH_TOKEN;
const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
const crypto = new NoctweaveCryptoSuite({
  pqc,
  webcrypto: new WebCryptoPrimitives()
});
const relay = new NoctweaveRelayClient(endpoint, {
  authToken,
  crypto,
  timeoutMs: Number(options.timeoutMs ?? 10_000)
});

let host;
let requester;
let hostSubscription;
let requesterSubscription;
let listingAcquired = false;

try {
  const info = await relay.info();
  const modules = info.relayInfo?.protocolCapabilities?.modules ?? [];
  if (!modules.some((module) =>
    module.module === "nw.pairing-lobby" && module.versions.includes(1))) {
    throw new Error("Relay does not advertise nw.pairing-lobby@1.");
  }

  host = await PairingLobbyHostSessionV1.create({ crypto });
  await relay.createRealtimeRouteV1(host.requestRouteCreateRequest);
  const acquired = await relay.acquirePairingLobbyV1(host.leaseAcquireRequest);
  listingAcquired = true;
  hostSubscription = await relay.subscribeRealtimeRouteV1(
    host.requestRouteSubscribeRequest()
  );

  const leases = await relay.listPairingLobbyV1();
  const lease = leases.find((candidate) => candidate.leaseID === acquired.leaseID);
  if (!lease) throw new Error("Acquired pairing listing was not returned by list.");
  const listing = await verifyPairingLobbyListingV1(crypto, lease);
  if (listing.badge.displayText !== host.badge.displayText) {
    throw new Error("Verified relay listing changed the host comparison badge.");
  }

  requester = await PairingLobbyRequesterSessionV1.create({
    crypto,
    listing: lease
  });
  await relay.createRealtimeRouteV1(requester.responseRouteCreateRequest);
  requesterSubscription = await relay.subscribeRealtimeRouteV1(
    requester.responseRouteSubscribeRequest()
  );
  await relay.appendRealtimeRouteV1(requester.requestAppendRequest);

  const hostBatch = await relay.syncRealtimeRouteV1({
    routeCapability: host.announcement.requestRouteCapability,
    subscriptionCapability: hostSubscription.subscriptionCapability,
    afterSequence: 0,
    maxRecords: 8
  });
  if (hostBatch.records.length !== 1) {
    throw new Error(`Expected one pairing request, received ${hostBatch.records.length}.`);
  }
  const pending = await host.openRequest(hostBatch.records[0].payload);

  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 5 * 60 * 1_000);
  const invitation = (await createContactPairingInvitationV2({
    crypto,
    createdAt: swiftISODate(createdAt),
    expiresAt: swiftISODate(expiresAt)
  })).invitation;
  const pairingLink = await encodeNoctweavePairingLinkV1({
    crypto,
    relay: endpoint,
    invitation
  });
  const decision = await host.decisionAppendRequest({
    pending,
    decision: "accepted",
    pairingLink
  });
  await relay.appendRealtimeRouteV1(decision);

  const requesterBatch = await relay.syncRealtimeRouteV1({
    routeCapability: requester.request.responseRouteCapability,
    subscriptionCapability: requesterSubscription.subscriptionCapability,
    afterSequence: 0,
    maxRecords: 8
  });
  if (requesterBatch.records.length !== 1) {
    throw new Error(`Expected one pairing response, received ${requesterBatch.records.length}.`);
  }
  const response = await requester.openResponse(requesterBatch.records[0].payload);
  if (response.decision !== "accepted" || response.pairingLink !== pairingLink) {
    throw new Error("Encrypted pairing decision did not reproduce the exact one-use link.");
  }
  const decodedLink = await decodeNoctweavePairingLinkV1({
    crypto,
    encoded: response.pairingLink
  });

  console.log(JSON.stringify({
    endpoint,
    listingCount: leases.length,
    hostBadge: host.badge.displayText,
    requesterBadge: requester.requesterBadge.displayText,
    requestRecords: hostBatch.records.length,
    responseRecords: requesterBatch.records.length,
    decision: response.decision,
    pairingRelayTransport: decodedLink.relay.transport,
    plaintextLinkVisibleInRelayRecord: Buffer.from(decision.payload, "base64")
      .includes(Buffer.from(pairingLink))
  }, null, 2));
} finally {
  if (hostSubscription && host) {
    await ignoreFailure(relay.unsubscribeRealtimeRouteV1({
      routeCapability: host.announcement.requestRouteCapability,
      subscriptionCapability: hostSubscription.subscriptionCapability
    }));
  }
  if (requesterSubscription && requester) {
    await ignoreFailure(relay.unsubscribeRealtimeRouteV1({
      routeCapability: requester.request.responseRouteCapability,
      subscriptionCapability: requesterSubscription.subscriptionCapability
    }));
  }
  if (listingAcquired && host) {
    await ignoreFailure(relay.releasePairingLobbyV1(host.leaseReleaseRequest));
  }
  host?.dispose();
  requester?.dispose();
}

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(`Expected a value after ${flag}.`);
    }
    const key = flag.slice(2).replace(/-([a-z])/g, (_, character) =>
      character.toUpperCase());
    parsed[key] = value;
    index += 1;
  }
  return parsed;
}

async function ignoreFailure(promise) {
  try {
    await promise;
  } catch {
    // Expiry or relay shutdown is already a terminal cleanup boundary.
  }
}
