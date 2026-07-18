import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  WebCryptoPrimitives,
  base64,
  createContactPairingInvitationV2,
  createContentTypeCapabilityV2,
  createContentTypeId,
  createEncodedContent,
  createNativeInboundSession,
  createNativeOutboundSession,
  createProtocolCapabilityManifest,
  decryptNativeApplicationEnvelope,
  decryptNativeEnvelope,
  derivePairwiseDirectV4Binding,
  defaultContentTypeCapabilities,
  encryptNativeApplicationEnvelope,
  encryptNativeTextEnvelope,
  findPairwiseRelationshipForEnvelope,
  pairwiseConversationKey,
  prepareContactPairingParticipantV2,
  relationshipEndpointAuthorizationDigestV4,
  renewPairwiseDirectV4PrekeyIfNeeded,
} from "../src/index.js";
import { createReadReceiptEncodedContent } from "../src/architecture-v2.js";
import { runContactPairingConformanceV2 } from "../test-support/contact-pairing-conformance.js";

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
  assert.equal(outbound.conversation.id, alice.relationshipID.toLowerCase());
  assert.deepEqual(Object.keys(outbound.conversation.endpointSession).sort(), [
    "localBindingReferenceDigest",
    "localEndpointHandle",
    "peerBindingReferenceDigest",
    "peerEndpointHandle",
    "relationshipID"
  ]);
  assert.equal(restarted.relationshipID, bob.relationshipID);
  assert.equal(pairwiseConversationKey(alice.peerIdentity).includes(alice.relationshipID), true);
  assert.equal(
    await findPairwiseRelationshipForEnvelope({ crypto, relationships: [bob], envelope }),
    bob
  );
});

test("typed application payloads remain extensible while authenticated known semantics fail closed", async () => {
  const customType = createContentTypeId({ authority: "org.example", name: "poll", major: 1, minor: 0 });
  const endpointCapabilities = createProtocolCapabilityManifest({
    contentTypes: [
      ...defaultContentTypeCapabilities.filter(({ authority, name }) =>
        authority !== "org.noctweave.receipt" || name !== "read"),
      createContentTypeCapabilityV2({
        authority: customType.authority,
        name: customType.name,
        majorVersions: [customType.major]
      })
    ]
  });
  const { crypto, pqc, alice, bob } = await paired(
    "Typed Alice",
    "Typed Bob",
    { endpointCapabilities }
  );
  const outbound = await createNativeOutboundSession({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    now: Date.parse(openedAt)
  });
  const custom = createEncodedContent({
    type: customType,
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

  const beforeRejectedSend = structuredClone(outbound.conversation.sendChain);
  await assert.rejects(() => encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: createContentTypeId({
        authority: "org.example",
        name: "unadvertised",
        major: 1,
        minor: 0
      }),
      payload: new Uint8Array([1]),
      fallbackText: "Unsupported extension",
      disposition: "visible"
    }),
    sentAt: openedAt
  }), /did not advertise org\.example\/unadvertised:1\.0/);
  await assert.rejects(() => encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    conversation: outbound.conversation,
    eventKind: "receipt",
    content: createReadReceiptEncodedContent(decoded.event.id),
    sentAt: openedAt
  }), /did not advertise org\.noctweave\.receipt\/read:1\.0/);
  assert.deepEqual(outbound.conversation.sendChain, beforeRejectedSend);
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
  const original = bob.localIdentity.endpointBinding.prekeyBundle.signedPrekey;
  const authorization = await relationshipEndpointAuthorizationDigestV4({
    crypto,
    endpointBinding: bob.localIdentity.endpointBinding
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
  assert.equal(await relationshipEndpointAuthorizationDigestV4({
    crypto,
    endpointBinding: bob.localIdentity.endpointBinding
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

test("relationship endpoint binding tampering fails closed", async () => {
  const { crypto, pqc, alice, bob } = await paired("Alice", "Bob");
  alice.peerIdentity.endpointBinding.authoritySignature = base64(new Uint8Array(3_309).fill(0x7f));
  await assert.rejects(() => createNativeOutboundSession({
    crypto,
    pqc,
    localIdentity: alice.localIdentity,
    peerIdentity: alice.peerIdentity,
    now: Date.parse(openedAt)
  }), /signature failed verification/);

  const retired = await paired("Retired Alice", "Retired Bob");
  const bundle = retired.alice.peerIdentity.endpointBinding.prekeyBundle;
  bundle[["identity", "Fingerprint"].join("")] = bundle.relationshipSigningKeyDigest;
  delete bundle.relationshipSigningKeyDigest;
  await assert.rejects(() => createNativeOutboundSession({
    crypto: retired.crypto,
    pqc: retired.pqc,
    localIdentity: retired.alice.localIdentity,
    peerIdentity: retired.alice.peerIdentity,
    now: Date.parse(openedAt)
  }), /fields do not match the current protocol/);
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
  assert.notEqual(firstBinding.localBindingReferenceDigest, secondBinding.localBindingReferenceDigest);
});

async function paired(localName, peerName, {
  endpointCapabilities = createProtocolCapabilityManifest()
} = {}) {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const crypto = new NoctweaveCryptoSuite({ pqc, webcrypto: new WebCryptoPrimitives() });
  const invitation = await createContactPairingInvitationV2({ crypto, createdAt, expiresAt });
  const offerer = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    relationshipPseudonym: localName,
    relay,
    endpointCapabilities,
    createdAt
  });
  const responder = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    relationshipPseudonym: peerName,
    relay,
    endpointCapabilities,
    createdAt
  });
  const established = await runContactPairingConformanceV2({
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
