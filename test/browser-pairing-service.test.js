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

test("browser personas persist independent crash-resumable pairing machines", async () => {
  const service = await pairingService();
  let offererPersona = service.createPersona({
    displayName: "  Alice   Example  ",
    createdAt: "2026-07-16T12:00:00Z"
  });
  assert.equal(offererPersona.stateSchema, browserPersonaStateSchema);
  assert.equal(offererPersona.displayName, "Alice Example");
  assert.deepEqual(offererPersona.relationships, []);
  for (const forbidden of [
    "signing",
    "agreement",
    "access",
    "networkAddress"
  ]) {
    assert.equal(Object.hasOwn(offererPersona, forbidden), false, forbidden);
  }
  const first = await service.preparePairingParticipant({
    persona: offererPersona,
    relay: "https://relay.example",
    createdAt: "2026-07-16T12:00:00Z"
  });
  const second = await service.preparePairingParticipant({
    persona: offererPersona,
    relay: "https://relay.example",
    createdAt: "2026-07-16T12:00:01Z"
  });
  assert.equal(first.localIdentity.relationshipPseudonym, defaultRelationshipPseudonymV2);
  assert.notEqual(first.localIdentity.relationshipPseudonym, offererPersona.displayName);
  assert.notEqual(first.localIdentity.signing.publicKey, second.localIdentity.signing.publicKey);
  assert.notEqual(
    first.localReceiveRoute.clientCapabilities.routeID.rawValue,
    second.localReceiveRoute.clientCapabilities.routeID.rawValue
  );

  let responderPersona = service.createPersona({
    displayName: "Bob Example",
    createdAt: "2026-07-16T12:00:00Z"
  });
  const offerer = await service.prepareOffererPairing({
    persona: offererPersona,
    relay: "https://relay.example",
    relationshipPseudonym: "Alice for Bob",
    createdAt: "2026-07-16T12:00:00Z",
    expiresAt: "2026-07-16T12:10:00Z"
  });
  offererPersona = persisted(offerer.persona);
  const responder = await service.prepareResponderPairing({
    persona: responderPersona,
    invitation: offerer.invitation,
    relay: "https://relay.example",
    relationshipPseudonym: "Bob for Alice",
    at: "2026-07-16T12:01:00Z"
  });
  responderPersona = persisted(responder.persona);
  assert.equal(service.establishPairing, undefined);
  assert.equal(offerer.pairingID, responder.pairingID);
  assert.equal(offererPersona.pendingPairings.length, 1);
  assert.equal(responderPersona.pendingPairings.length, 1);

  const offererPrivate = offererPersona.pendingPairings[0].participant.localIdentity.signing.secretKey;
  const responderPrivate = responderPersona.pendingPairings[0].participant.localIdentity.signing.secretKey;
  assert.equal(JSON.stringify(offererPersona).includes(responderPrivate), false);
  assert.equal(JSON.stringify(responderPersona).includes(offererPrivate), false);
  assert.equal(JSON.stringify(responder.outboundTransportFrames).includes("Bob for Alice"), false);
  assert.equal(typeof responder.outboundTransportFrames[0].frame.ciphertext, "string");

  await assert.rejects(
    () => service.processPairingFrame({
      persona: responderPersona,
      pairingID: responder.pairingID,
      transportFrame: responder.outboundTransportFrames[0].frame,
      at: "2026-07-16T12:01:00Z"
    }),
    /authentication failed|decryptionFailed|invalidDirection/
  );

  ({ senderPersona: responderPersona, receiverPersona: offererPersona } = await deliverBrowserOutbox({
    service,
    senderPersona: responderPersona,
    receiverPersona: offererPersona,
    pairingID: offerer.pairingID,
    at: "2026-07-16T12:01:00Z"
  }));
  const replayedOpen = responder.outboundTransportFrames[0].frame;
  await assert.rejects(
    () => service.processPairingFrame({
      persona: offererPersona,
      pairingID: offerer.pairingID,
      transportFrame: replayedOpen,
      at: "2026-07-16T12:01:00Z"
    }),
    /sequence is unexpected/
  );
  ({ senderPersona: offererPersona, receiverPersona: responderPersona } = await deliverBrowserOutbox({
    service,
    senderPersona: offererPersona,
    receiverPersona: responderPersona,
    pairingID: offerer.pairingID,
    at: "2026-07-16T12:01:00Z"
  }));
  ({ senderPersona: responderPersona, receiverPersona: offererPersona } = await deliverBrowserOutbox({
    service,
    senderPersona: responderPersona,
    receiverPersona: offererPersona,
    pairingID: offerer.pairingID,
    at: "2026-07-16T12:01:00Z"
  }));
  ({ senderPersona: offererPersona, receiverPersona: responderPersona } = await deliverBrowserOutbox({
    service,
    senderPersona: offererPersona,
    receiverPersona: responderPersona,
    pairingID: offerer.pairingID,
    at: "2026-07-16T12:01:00Z"
  }));

  const tampered = persisted(offererPersona);
  tampered.pendingPairings[0].session.transcriptDigest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  await assert.rejects(
    () => service.resumePairing({ persona: tampered, pairingID: offerer.pairingID }),
    /invalid/
  );

  const offererFinal = await service.finalizePairing({
    persona: offererPersona,
    pairingID: offerer.pairingID,
    at: "2026-07-16T12:01:00Z"
  });
  const responderFinal = await service.finalizePairing({
    persona: responderPersona,
    pairingID: responder.pairingID,
    at: "2026-07-16T12:01:00Z"
  });
  assert.equal(offererFinal.persona.pendingPairings.length, 0);
  assert.equal(responderFinal.persona.pendingPairings.length, 0);
  assert.equal(offererFinal.persona.relationships.length, 1);
  assert.equal(responderFinal.persona.relationships.length, 1);
  assert.equal(offererFinal.relationship.relationshipID, responderFinal.relationship.relationshipID);
  assert.equal(offererFinal.relationship.peerIdentity.relationshipPseudonym, "Bob for Alice");
  assert.equal(JSON.stringify(offererFinal.relationship).includes(offererPersona.displayName), false);
});

test("browser pairing cancellation removes persisted private pairing state", async () => {
  const service = await pairingService();
  const persona = service.createPersona({
    displayName: "Alice",
    createdAt: "2026-07-16T12:00:00Z"
  });
  const prepared = await service.prepareOffererPairing({
    persona,
    relay: "https://relay.example",
    createdAt: "2026-07-16T12:00:00Z",
    expiresAt: "2026-07-16T12:10:00Z"
  });
  assert.equal(prepared.persona.pendingPairings.length, 1);
  const cancelled = await service.cancelPairing({
    persona: persisted(prepared.persona),
    pairingID: prepared.pairingID,
    at: "2026-07-16T12:01:00Z"
  });
  assert.equal(cancelled.receipt.phase, "cancelled");
  assert.equal(cancelled.persona.pendingPairings.length, 0);
  assert.equal(cancelled.rendezvousDeletionRequests.length, 2);
});

test("browser relay verification requires current opaque-route delivery", async () => {
  const service = await pairingService({
    relayClientFactory: () => ({
      health: async () => ({}),
      info: async () => ({ relayInfo: testRelayInfo() })
    })
  });
  const verified = await service.verifyRelay("https://relay.example");
  assert.equal(verified.endpoint.transport, "http");
  assert.equal(verified.endpoint.useTLS, true);

  const incompatible = await pairingService({
    relayClientFactory: () => ({
      health: async () => ({}),
      info: async () => ({
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
    globalProtocolID: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
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
    createOpaqueRoute: async ({ request, renewCapability }) => (
      createOpaqueReceiveRouteV2({
        crypto,
        request,
        presentedRenewCapability: renewCapability,
        confidentialTransport: true,
        receivedAt: request.lease.issuedAt
      })
    ),
    registerRendezvousTransportV2: async () => undefined
  }));
  return new NoctweaveBrowserPairingService({
    pqc,
    crypto,
    ...options,
    relayClientFactory
  });
}

async function deliverBrowserOutbox({
  service,
  senderPersona: senderValue,
  receiverPersona: receiverValue,
  pairingID,
  at
}) {
  let senderPersona = persisted(senderValue);
  let receiverPersona = persisted(receiverValue);
  const resumed = await service.resumePairing({ persona: senderPersona, pairingID });
  for (const outbound of resumed.outboundTransportFrames) {
    const processed = await service.processPairingFrame({
      persona: receiverPersona,
      pairingID,
      transportFrame: outbound.frame,
      at
    });
    receiverPersona = persisted(processed.persona);
    const acknowledged = await service.acknowledgePairingOutbound({
      persona: senderPersona,
      pairingID,
      frameIDs: [outbound.frame.frameId.rawValue]
    });
    senderPersona = persisted(acknowledged.persona);
  }
  return { senderPersona, receiverPersona };
}

function persisted(value) {
  return JSON.parse(JSON.stringify(value));
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
