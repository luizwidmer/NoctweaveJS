import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveBrowserPairingService,
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  WebCryptoPrimitives,
  browserPersonaStateSchema,
  defaultRelationshipPseudonymV2,
  createOpaqueReceiveRouteV2,
  createProtocolCapabilityManifest,
  parseBrowserRelayEndpoint,
  validateBrowserDisplayName,
  validateBrowserPersonaState
} from "../src/index.js";

test("browser personas are keyless UI containers and each pairing mints fresh authority", async () => {
  const service = await pairingService();
  const persona = service.createPersona({
    displayName: "  Alice   Example  ",
    createdAt: "2026-07-16T12:00:00Z"
  });
  assert.equal(persona.stateSchema, browserPersonaStateSchema);
  assert.equal(persona.displayName, "Alice Example");
  assert.deepEqual(persona.relationships, []);
  for (const forbidden of [
    "signing",
    "agreement",
    "access",
    "networkAddress",
    "identityGenerationId"
  ]) {
    assert.equal(Object.hasOwn(persona, forbidden), false, forbidden);
  }
  const first = await service.preparePairingParticipant({
    persona,
    relay: "https://relay.example",
    createdAt: "2026-07-16T12:00:00Z"
  });
  const second = await service.preparePairingParticipant({
    persona,
    relay: "https://relay.example",
    createdAt: "2026-07-16T12:00:01Z"
  });
  assert.equal(first.localIdentity.displayName, defaultRelationshipPseudonymV2);
  assert.notEqual(first.localIdentity.displayName, persona.displayName);
  assert.notEqual(first.localIdentity.signing.publicKey, second.localIdentity.signing.publicKey);
  assert.notEqual(
    first.localReceiveRoute.clientCapabilities.routeID.rawValue,
    second.localReceiveRoute.clientCapabilities.routeID.rawValue
  );

  const peerPersona = service.createPersona({
    displayName: "Bob Example",
    createdAt: "2026-07-16T12:00:00Z"
  });
  const made = await service.createPairingInvitation({
    createdAt: "2026-07-16T12:00:00Z",
    expiresAt: "2026-07-16T12:10:00Z"
  });
  const peer = await service.preparePairingParticipant({
    persona: peerPersona,
    relay: "https://relay.example",
    relationshipLabel: "Bob for Alice",
    createdAt: "2026-07-16T12:00:00Z"
  });
  const completed = await service.establishPairing({
    persona,
    pending: made.pending,
    invitation: made.invitation,
    localParticipant: first,
    peerParticipant: peer,
    at: "2026-07-16T12:01:00Z"
  });
  assert.equal(completed.persona.relationships.length, 1);
  assert.equal(completed.persona.relationships[0].relationshipID, completed.relationship.relationshipID);
  assert.equal(completed.persona.relationships[0].peerIdentity.displayName, "Bob for Alice");
});

test("browser relay verification requires current opaque-route delivery", async () => {
  const service = await pairingService({
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: testRelayInfo() })
    })
  });
  const verified = await service.verifyRelay("https://relay.example");
  assert.equal(verified.endpoint.transport, "http");
  assert.equal(verified.endpoint.useTLS, true);

  const incompatible = await pairingService({
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({
        type: "info",
        relayInfo: {
          ...testRelayInfo(),
          protocolCapabilities: {
            ...createProtocolCapabilityManifest(),
            modules: createProtocolCapabilityManifest().modules.filter(({ module }) => module !== "nw.opaque-route")
          }
        }
      })
    })
  });
  await assert.rejects(() => incompatible.verifyRelay("https://relay.example"), /opaque route v2/);
});

test("browser persona schema rejects non-current global identity state", () => {
  const foreignState = {
    stateSchema: "nw.browser-global-identity",
    architectureVersion: 2,
    displayName: "Alice",
    identityGenerationId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
    networkAddress: "reusable-address"
  };
  assert.throws(() => validateBrowserPersonaState(foreignState), /fields do not match|unsupported/);
  const extended = {
    stateSchema: browserPersonaStateSchema,
    version: 2,
    displayName: "Alice",
    relationships: [],
    pendingPairings: [],
    createdAt: "2026-07-16T12:00:00Z",
    networkAddress: "forbidden"
  };
  assert.throws(() => validateBrowserPersonaState(extended), /fields do not match/);
  assert.deepEqual(parseBrowserRelayEndpoint("wss://relay.example"), {
    host: "relay.example",
    port: 443,
    useTLS: true,
    transport: "websocket"
  });
  assert.throws(() => parseBrowserRelayEndpoint("tcp://relay.example"), /requires an HTTP/);
  assert.throws(() => validateBrowserDisplayName("   "), /Display name/);
});

async function pairingService(options = {}) {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const crypto = new NoctweaveCryptoSuite({ pqc, webcrypto: new WebCryptoPrimitives() });
  const relayClientFactory = options.relayClientFactory ?? (() => ({
    createOpaqueRoute: async ({ transition, renewCapability }) => ({
      type: "opaqueRouteV2",
      opaqueRouteV2: await createOpaqueReceiveRouteV2({
        crypto,
        request: transition,
        presentedRenewCapability: renewCapability,
        confidentialTransport: true,
        receivedAt: transition.lease.issuedAt
      })
    })
  }));
  return new NoctweaveBrowserPairingService({
    pqc,
    crypto,
    ...options,
    relayClientFactory
  });
}

function testRelayInfo() {
  const capabilities = createProtocolCapabilityManifest();
  return {
    kind: "standard",
    protocolCapabilities: {
      ...capabilities,
      modules: [
        ...capabilities.modules,
        { module: "nw.opaque-route", versions: [2], status: "stable", limits: {} }
      ]
    }
  };
}
