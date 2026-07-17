import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  WebCryptoPrimitives,
  base64,
  certifiedEndpointAuthorizationDigest,
  createContactPairingInvitationV2,
  createContentTypeId,
  createEncodedContent,
  createEndpointRemovalProofV4,
  createNativeInboundSession,
  createNativeOutboundSession,
  decryptNativeApplicationEnvelope,
  decryptNativeEnvelope,
  derivePairwiseDirectV4Binding,
  encryptNativeApplicationEnvelope,
  encryptNativeTextEnvelope,
  establishContactPairingV2,
  findPairwiseRelationshipForEnvelope,
  pairwiseConversationKey,
  prepareContactPairingParticipantV2,
  renewPairwiseDirectV4PrekeyIfNeeded,
  swiftISODate
} from "../src/index.js";

const createdAt = "2026-07-16T12:00:00Z";
const openedAt = "2026-07-16T12:01:00Z";
const expiresAt = "2026-07-16T12:10:00Z";
const relay = { host: "127.0.0.1", port: 9_339, useTLS: false, transport: "http" };

test("direct-v4 uses only rendezvous-established pairwise identity state", async () => {
  const fixture = await paired("Alice for Bob", "Bob for Alice");
  const { crypto, pqc, alice, bob } = fixture;
  const outbound = await createNativeOutboundSession({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    now: Date.parse(openedAt)
  });
  const envelope = await encryptNativeTextEnvelope({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    conversation: outbound.conversation,
    text: "pairwise direct-v4 survives restart",
    bootstrap: outbound.bootstrap,
    sentAt: openedAt
  });
  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    peerIdentity: bob.peerIdentity,
    bootstrap: envelope.bootstrap,
    now: Date.parse(openedAt)
  });
  const restarted = structuredClone(inbound);
  assert.equal(await decryptNativeEnvelope({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    peerIdentity: bob.peerIdentity,
    conversation: restarted,
    envelope
  }), "pairwise direct-v4 survives restart");
  assert.equal(outbound.conversation.relationshipID, alice.relationshipID);
  assert.equal(restarted.relationshipID, bob.relationshipID);
  assert.equal(pairwiseConversationKey(alice.peerIdentity).includes(alice.relationshipID), true);
  assert.equal(
    await findPairwiseRelationshipForEnvelope({ crypto, relationships: [bob], envelope }),
    bob
  );
});

test("typed application payloads remain extensible while authenticated known semantics fail closed", async () => {
  const { crypto, pqc, alice, bob } = await paired("Typed Alice", "Typed Bob");
  const outbound = await createNativeOutboundSession({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    now: Date.parse(openedAt)
  });
  const custom = createEncodedContent({
    type: createContentTypeId({ authority: "org.example", name: "poll", major: 1, minor: 0 }),
    payload: new TextEncoder().encode('{"question":"Tea?"}'),
    fallbackText: "Unsupported poll",
    disposition: "visible"
  });
  const envelope = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    conversation: outbound.conversation,
    content: custom,
    bootstrap: outbound.bootstrap,
    sentAt: openedAt
  });
  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    peerIdentity: bob.peerIdentity,
    bootstrap: envelope.bootstrap,
    now: Date.parse(openedAt)
  });
  const decoded = await decryptNativeApplicationEnvelope({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    peerIdentity: bob.peerIdentity,
    conversation: inbound,
    envelope
  });
  assert.equal(decoded.projection.kind, "unsupported");
  assert.equal(decoded.projection.fallbackText, "Unsupported poll");
  assert.equal(decoded.event.content.payload, custom.payload);
});

test("authenticated-header tampering never advances a receive ratchet", async () => {
  const { crypto, pqc, alice, bob } = await paired("Alice", "Bob");
  const outbound = await createNativeOutboundSession({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    now: Date.parse(openedAt)
  });
  const envelope = await encryptNativeTextEnvelope({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    conversation: outbound.conversation,
    text: "ratchet stays atomic",
    bootstrap: outbound.bootstrap,
    sentAt: openedAt
  });
  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    peerIdentity: bob.peerIdentity,
    bootstrap: envelope.bootstrap,
    now: Date.parse(openedAt)
  });
  const before = structuredClone(inbound.receiveChain);
  const tampered = structuredClone(envelope);
  tampered.negotiatedCapabilitiesDigest = base64(new Uint8Array(32).fill(0x7f));
  await assert.rejects(() => decryptNativeEnvelope({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    peerIdentity: bob.peerIdentity,
    conversation: inbound,
    envelope: tampered
  }), /endpoint session/);
  assert.deepEqual(inbound.receiveChain, before);
});

test("prekey renewal retains an in-flight pairwise bootstrap without creating reusable public state", async () => {
  const { crypto, pqc, alice, bob } = await paired("Alice", "Bob");
  const original = bob.localIdentity.certifiedGenerationEndpoint.prekeyBundle.signedPrekey;
  const authorization = await certifiedEndpointAuthorizationDigest({
    crypto,
    endpoint: bob.localIdentity.certifiedGenerationEndpoint
  });
  const renewalTime = Date.parse(original.expiresAt) - 2 * 86_400_000;
  const outbound = await createNativeOutboundSession({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    now: renewalTime - 1
  });
  assert.equal(await renewPairwiseDirectV4PrekeyIfNeeded({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    now: renewalTime
  }), true);
  assert.equal(bob.localIdentity.localEndpoint.prekeys.retiredSignedPrekeys.length, 1);
  assert.equal(await certifiedEndpointAuthorizationDigest({
    crypto,
    endpoint: bob.localIdentity.certifiedGenerationEndpoint
  }), authorization);
  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    peerIdentity: bob.peerIdentity,
    bootstrap: outbound.bootstrap,
    now: renewalTime
  });
  assert.equal(inbound.id, outbound.conversation.id);
});

test("endpoint revocation is relationship-local and fails closed", async () => {
  const { crypto, pqc, alice, bob } = await paired("Alice", "Bob");
  const revocation = await createEndpointRemovalProofV4({
    crypto,
    pqc,
    localIdentity: bob.localIdentity,
    issuedAt: swiftISODate(new Date(Date.parse(openedAt) + 1_000))
  });
  alice.peerIdentity = { ...alice.peerIdentity, endpointRevocation: revocation };
  await assert.rejects(() => createNativeOutboundSession({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    now: Date.parse(openedAt) + 2_000
  }), /revoked/);
});

test("separate pairings cannot correlate a local persona through keys, handles, or routes", async () => {
  const first = await paired("Alice", "Bob");
  const second = await paired("Alice", "Carol");
  assert.notEqual(first.alice.relationshipID, second.alice.relationshipID);
  assert.notEqual(
    first.alice.localIdentity.signing.publicKey,
    second.alice.localIdentity.signing.publicKey
  );
  assert.notEqual(
    first.alice.localEndpointHandle.rawValue,
    second.alice.localEndpointHandle.rawValue
  );
  assert.notEqual(
    first.alice.localReceiveRoutes[0].clientCapabilities.routeID.rawValue,
    second.alice.localReceiveRoutes[0].clientCapabilities.routeID.rawValue
  );
  const firstBinding = await derivePairwiseDirectV4Binding({
    crypto: first.crypto,
    localIdentity: first.alice.localIdentity,
    peerIdentity: first.alice.peerIdentity
  });
  const secondBinding = await derivePairwiseDirectV4Binding({
    crypto: second.crypto,
    localIdentity: second.alice.localIdentity,
    peerIdentity: second.alice.peerIdentity
  });
  assert.notEqual(firstBinding.localCertificateReferenceDigest, secondBinding.localCertificateReferenceDigest);
});

async function paired(localName, peerName) {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const crypto = new NoctweaveCryptoSuite({ pqc, webcrypto: new WebCryptoPrimitives() });
  const invitation = await createContactPairingInvitationV2({ crypto, createdAt, expiresAt });
  const offerer = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    displayName: localName,
    relay,
    createdAt
  });
  const responder = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    displayName: peerName,
    relay,
    createdAt
  });
  const established = await establishContactPairingV2({
    crypto,
    pqc,
    pending: invitation.pending,
    invitation: invitation.invitation,
    offerer,
    responder,
    at: openedAt
  });
  return {
    crypto,
    pqc,
    alice: structuredClone(established.offererRelationship),
    bob: structuredClone(established.responderRelationship)
  };
}
