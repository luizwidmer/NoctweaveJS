import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import { canonicalEnvelopeBytes } from "../src/crypto/noctweave-native-message.js";
import {
  NoctweaveOQSWasmAdapter,
  WebCryptoPrimitives,
  base64,
  canonicalJsonBytes,
  certifiedEndpointAuthorizationDigest,
  contactFromNativeOffer,
  createContentTypeId,
  createEncodedContent,
  createInstallationEndpointRevocationV4,
  createProtocolCapabilityManifest,
  createNativeInboundSession,
  createNativeOutboundSession,
  decryptNativeApplicationEnvelope,
  decryptNativeEnvelope,
  deriveNativeDirectV4Binding,
  derivePairwiseInstallationBindingV4,
  directV4ConversationId,
  encryptNativeApplicationEnvelope,
  encryptNativeTextEnvelope,
  inboxIdForAccessPublicKey,
  makeNativeContactOffer,
  nativeAuthenticatedDataBytes,
  prepareNativeDirectV4Identity,
  renewNativeDirectV4PrekeyIfNeeded,
  standardContentTypes,
  swiftUUID,
  verifyCertifiedNativeContactOffer,
  verifyNativeContactOffer
} from "../src/index.js";

const relay = { host: "127.0.0.1", port: 9339, useTLS: false, transport: "http" };

test("direct-v4 renews endpoint prekeys without changing stable authorization", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Bob" });
  const aliceContact = contactFromNativeOffer(alice.contactOffer);
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const originalEndpoint = bob.certifiedInstallationEndpoint;
  const originalPrekey = originalEndpoint.prekeyBundle.signedPrekey;
  const originalAuthorizationDigest = await certifiedEndpointAuthorizationDigest({
    crypto,
    endpoint: originalEndpoint
  });
  const renewalTime = Date.parse(originalPrekey.expiresAt) - 2 * 86_400_000;
  const outbound = await createNativeOutboundSession({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    now: renewalTime - 1
  });

  assert.equal(await renewNativeDirectV4PrekeyIfNeeded({
    crypto,
    pqc,
    identity: bob,
    now: renewalTime
  }), true);
  assert.notEqual(bob.localInstallation.prekeys.signedPrekeyId, originalPrekey.id);
  assert.equal(bob.localInstallation.prekeys.retiredSignedPrekeys.length, 1);
  assert.equal(await certifiedEndpointAuthorizationDigest({
    crypto,
    endpoint: bob.certifiedInstallationEndpoint
  }), originalAuthorizationDigest);

  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    identity: bob,
    contact: aliceContact,
    kemCiphertext: base64(outbound.kemCiphertext),
    prekey: outbound.prekey,
    now: renewalTime
  });
  assert.equal(inbound.id, outbound.conversation.id);

  const renewedOffer = makeNativeContactOffer({ pqc, identity: bob, relayEndpoint: relay });
  await verifyCertifiedNativeContactOffer({ crypto, pqc, offer: renewedOffer, now: renewalTime });
  const tamperedOffer = structuredClone(renewedOffer);
  tamperedOffer.preferredInstallationEndpoint.prekeyPackageSignature = base64(
    new Uint8Array(3_309)
  );
  await assert.rejects(
    verifyCertifiedNativeContactOffer({ crypto, pqc, offer: tamperedOffer, now: renewalTime }),
    /signature/
  );
  await assert.rejects(
    createNativeInboundSession({
      crypto,
      pqc,
      identity: bob,
      contact: aliceContact,
      kemCiphertext: base64(outbound.kemCiphertext),
      prekey: outbound.prekey,
      now: Date.parse(originalPrekey.expiresAt)
    }),
    /expired or unknown/
  );
});

test("direct-v4 uses a certified local endpoint and survives persisted-session restart", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Bob" });
  const aliceContact = contactFromNativeOffer(alice.contactOffer);
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const reboundInboxOffer = makeNativeContactOffer({
    pqc,
    identity: { ...alice, inboxId: bob.inboxId },
    relayEndpoint: relay
  });
  await assert.rejects(
    verifyNativeContactOffer({ crypto, pqc, offer: reboundInboxOffer }),
    /inbox does not match its access key/
  );

  const outbound = await createNativeOutboundSession({ crypto, pqc, identity: alice, contact: bobContact });
  const envelope = await encryptNativeTextEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    text: "direct v4 after restart",
    kemCiphertext: outbound.kemCiphertext,
    prekey: outbound.prekey,
    eventId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
    clientTransactionId: "11111111-2222-4333-8444-555555555555",
    sentAt: "2026-07-16T12:34:56Z"
  });

  assert.equal(envelope.authenticatedContext.purpose, "directV4");
  assert.equal(envelope.authenticatedContext.directV4.payloadFormat, "nw.wire-payload.v2");
  assert.notEqual(envelope.senderFingerprint, alice.signingFingerprint);
  assert.notEqual(envelope.senderFingerprint, alice.localInstallation.signingFingerprint);
  assert.equal(envelope.prekey.id, bob.localInstallation.prekeys.signedPrekeyId);

  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    identity: bob,
    contact: aliceContact,
    kemCiphertext: envelope.kemCiphertext,
    prekey: envelope.prekey
  });
  const restartedConversation = JSON.parse(JSON.stringify(inbound));
  assert.equal(
    await decryptNativeEnvelope({
      crypto,
      pqc,
      identity: bob,
      contact: aliceContact,
      conversation: restartedConversation,
      envelope
    }),
    "direct v4 after restart"
  );
  assert.equal(
    restartedConversation.endpointSession.peerInstallationHandle.rawValue,
    envelope.senderFingerprint
  );
});

test("direct-v4 preserves typed application content and fails closed for malformed known types", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Typed Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Typed Bob" });
  const aliceContact = contactFromNativeOffer(alice.contactOffer);
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const outbound = await createNativeOutboundSession({ crypto, pqc, identity: alice, contact: bobContact });
  const customType = createContentTypeId({
    authority: "org.example",
    name: "poll",
    major: 1,
    minor: 0
  });
  const custom = createEncodedContent({
    type: customType,
    payload: new TextEncoder().encode('{"question":"Tea?"}'),
    fallbackText: "Unsupported poll",
    disposition: "visible"
  });
  const first = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: custom,
    kemCiphertext: outbound.kemCiphertext,
    prekey: outbound.prekey
  });
  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    identity: bob,
    contact: aliceContact,
    kemCiphertext: first.kemCiphertext,
    prekey: first.prekey
  });
  const decodedCustom = await decryptNativeApplicationEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: first
  });
  assert.equal(decodedCustom.projection.kind, "unsupported");
  assert.equal(decodedCustom.projection.fallbackText, "Unsupported poll");
  assert.equal(decodedCustom.event.content.payload, custom.payload);

  const silent = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: customType,
      payload: new Uint8Array([1]),
      disposition: "silent"
    })
  });
  const silentInbound = structuredClone(inbound);
  const decodedSilent = await decryptNativeApplicationEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact, conversation: silentInbound, envelope: silent
  });
  assert.equal(decodedSilent.projection.disposition, "silent");
  const wrapperInbound = structuredClone(inbound);
  assert.equal(await decryptNativeEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact, conversation: wrapperInbound, envelope: silent
  }), null);
  Object.assign(inbound, silentInbound);

  const descriptor = {
    id: swiftUUID(),
    mimeType: "image/png",
    byteCount: 65_537,
    sha256: base64(new Uint8Array(32).fill(0x42)),
    chunkCount: 2,
    chunkSize: 65_536
  };
  const attachmentReplyTarget = swiftUUID();
  const attachment = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: standardContentTypes.attachment,
      payload: canonicalJsonBytes(descriptor),
      fallbackText: "Image",
      disposition: "visible"
    }),
    relation: { kind: "reply", targetEventId: attachmentReplyTarget }
  });
  const decodedAttachment = await decryptNativeApplicationEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: attachment
  });
  assert.equal(decodedAttachment.projection.kind, "attachment");
  assert.deepEqual(decodedAttachment.projection.descriptor, descriptor);
  assert.equal(decodedAttachment.event.relation.targetEventId, attachmentReplyTarget);

  const malformedText = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: standardContentTypes.text,
      payload: new TextEncoder().encode("real text"),
      fallbackText: "different text",
      disposition: "visible"
    })
  });
  const receiveBeforeMalformed = structuredClone(inbound.receiveChain);
  await assert.rejects(
    decryptNativeApplicationEnvelope({
      crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: malformedText
    }),
    (error) => error?.reason === "unsupportedPayload"
  );
  assert.deepEqual(inbound.receiveChain, receiveBeforeMalformed);

  const afterMalformed = await encryptNativeTextEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    text: "valid after quarantined content"
  });
  assert.equal(await decryptNativeEnvelope({
    crypto,
    pqc,
    identity: bob,
    contact: aliceContact,
    conversation: inbound,
    envelope: afterMalformed
  }), "valid after quarantined content");
  assert.equal(Object.keys(inbound.receiveChain.skippedMessageKeys).length, 1);
});

test("direct-v4 authenticates private relation targets, truthful tombstones, and silent receipts", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Relations Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Relations Bob" });
  const aliceContact = contactFromNativeOffer(alice.contactOffer);
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const outbound = await createNativeOutboundSession({ crypto, pqc, identity: alice, contact: bobContact });
  const targetEventId = "11111111-2222-4333-8444-555555555555";

  const reaction = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: standardContentTypes.reaction,
      payload: canonicalJsonBytes({ value: "👍" }),
      fallbackText: "Reacted 👍 to a message",
      disposition: "visible"
    }),
    relation: { kind: "reaction", targetEventId },
    kemCiphertext: outbound.kemCiphertext,
    prekey: outbound.prekey
  });
  assert.equal(JSON.stringify(reaction).includes(targetEventId), false);
  const inbound = await createNativeInboundSession({
    crypto,
    pqc,
    identity: bob,
    contact: aliceContact,
    kemCiphertext: reaction.kemCiphertext,
    prekey: reaction.prekey
  });
  const decodedReaction = await decryptNativeApplicationEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: reaction
  });
  assert.equal(decodedReaction.event.relation.targetEventId, targetEventId);
  assert.deepEqual(decodedReaction.projection, {
    kind: "reaction",
    value: "👍",
    targetEventId,
    disposition: "visible",
    fallbackText: "Reacted 👍 to a message"
  });

  const replacement = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: standardContentTypes.text,
      payload: new TextEncoder().encode("corrected"),
      fallbackText: "corrected",
      disposition: "visible"
    }),
    relation: { kind: "replacement", targetEventId }
  });
  const decodedReplacement = await decryptNativeApplicationEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: replacement
  });
  assert.equal(decodedReplacement.projection.text, "corrected");
  assert.equal(decodedReplacement.event.relation.kind, "replacement");

  const tombstone = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: standardContentTypes.retraction,
      payload: canonicalJsonBytes({ reason: "duplicate", scope: "received-copies-may-remain" }),
      fallbackText: "Message retracted; received copies may remain",
      disposition: "visible"
    }),
    relation: { kind: "retraction", targetEventId }
  });
  const decodedTombstone = await decryptNativeApplicationEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: tombstone
  });
  assert.equal(decodedTombstone.projection.kind, "retraction");
  assert.equal(decodedTombstone.projection.scope, "received-copies-may-remain");
  assert.match(decodedTombstone.projection.fallbackText, /received copies may remain/);

  for (const [type, expectedKind] of [
    [standardContentTypes.deliveryReceipt, "deliveryReceipt"],
    [standardContentTypes.readReceipt, "readReceipt"]
  ]) {
    const receipt = await encryptNativeApplicationEnvelope({
      crypto,
      pqc,
      identity: alice,
      contact: bobContact,
      conversation: outbound.conversation,
      eventKind: "receipt",
      content: createEncodedContent({
        type,
        payload: canonicalJsonBytes({ targetEventId }),
        disposition: "silent"
      })
    });
    assert.equal(JSON.stringify(receipt).includes(targetEventId), false);
    const decodedReceipt = await decryptNativeApplicationEnvelope({
      crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: receipt
    });
    assert.equal(decodedReceipt.kind, "receipt");
    assert.equal(decodedReceipt.projection.kind, expectedKind);
    assert.equal(decodedReceipt.projection.targetEventId, targetEventId);
    const compatibilityInbound = structuredClone(inbound);
    const duplicateReceipt = await encryptNativeApplicationEnvelope({
      crypto,
      pqc,
      identity: alice,
      contact: bobContact,
      conversation: outbound.conversation,
      eventKind: "receipt",
      content: createEncodedContent({
        type,
        payload: canonicalJsonBytes({ targetEventId }),
        disposition: "silent"
      })
    });
    assert.equal(await decryptNativeEnvelope({
      crypto,
      pqc,
      identity: bob,
      contact: aliceContact,
      conversation: compatibilityInbound,
      envelope: duplicateReceipt
    }), null);
    Object.assign(inbound, compatibilityInbound);
  }

  const malformed = await encryptNativeApplicationEnvelope({
    crypto,
    pqc,
    identity: alice,
    contact: bobContact,
    conversation: outbound.conversation,
    content: createEncodedContent({
      type: standardContentTypes.reaction,
      payload: new TextEncoder().encode('{ "value": "👍" }'),
      fallbackText: "Reacted 👍 to a message",
      disposition: "visible"
    }),
    relation: { kind: "reaction", targetEventId }
  });
  const beforeMalformed = structuredClone(inbound.receiveChain);
  await assert.rejects(
    decryptNativeApplicationEnvelope({
      crypto, pqc, identity: bob, contact: aliceContact, conversation: inbound, envelope: malformed
    }),
    (error) => error?.reason === "unsupportedPayload"
  );
  assert.deepEqual(inbound.receiveChain, beforeMalformed);
});

test("aged endpoints reopen established sessions but cannot bootstrap a new session", async () => {
  const { crypto, pqc } = await primitives();
  const issuedAt = new Date(Date.now() - 9 * 86_400_000).toISOString();
  const issuanceTime = Date.parse(issuedAt);
  const alice = await makeV4Identity({
    crypto, pqc, displayName: "Aged Alice", issuedAt, verificationNow: issuanceTime
  });
  const bob = await makeV4Identity({
    crypto, pqc, displayName: "Aged Bob", issuedAt, verificationNow: issuanceTime
  });
  const aliceContact = contactFromNativeOffer(alice.contactOffer);
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const outbound = await createNativeOutboundSession({
    crypto, pqc, identity: alice, contact: bobContact, now: issuanceTime
  });
  const first = await encryptNativeTextEnvelope({
    crypto, pqc, identity: alice, contact: bobContact,
    conversation: outbound.conversation, text: "establish while fresh",
    kemCiphertext: outbound.kemCiphertext, prekey: outbound.prekey,
    sentAt: issuedAt
  });
  const inbound = await createNativeInboundSession({
    crypto, pqc, identity: bob, contact: aliceContact,
    kemCiphertext: first.kemCiphertext, prekey: first.prekey, now: issuanceTime
  });
  assert.equal(await decryptNativeEnvelope({
    crypto, pqc, identity: bob, contact: aliceContact,
    conversation: inbound, envelope: first
  }), "establish while fresh");

  const restartedAlice = structuredClone(alice);
  const restartedBob = structuredClone(bob);
  await prepareNativeDirectV4Identity({ crypto, pqc, identity: restartedAlice });
  await prepareNativeDirectV4Identity({ crypto, pqc, identity: restartedBob });
  const restartedOutbound = structuredClone(outbound.conversation);
  const restartedInbound = structuredClone(inbound);
  const followup = await encryptNativeTextEnvelope({
    crypto, pqc, identity: restartedAlice, contact: bobContact,
    conversation: restartedOutbound, text: "established after endpoint age"
  });
  assert.equal(await decryptNativeEnvelope({
    crypto, pqc, identity: restartedBob, contact: aliceContact,
    conversation: restartedInbound, envelope: followup
  }), "established after endpoint age");

  await assert.rejects(
    createNativeOutboundSession({ crypto, pqc, identity: restartedAlice, contact: bobContact }),
    /expired/
  );
  await assert.rejects(
    createNativeInboundSession({
      crypto, pqc, identity: restartedBob, contact: aliceContact,
      kemCiphertext: first.kemCiphertext, prekey: first.prekey
    }),
    /expired/
  );
});

test("direct-v4 rejects authenticated-context tampering without advancing the ratchet", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Bob" });
  const aliceContact = contactFromNativeOffer(alice.contactOffer);
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const outbound = await createNativeOutboundSession({ crypto, pqc, identity: alice, contact: bobContact });
  const envelope = await encryptNativeTextEnvelope({
    crypto, pqc, identity: alice, contact: bobContact,
    conversation: outbound.conversation, text: "tamper resistant",
    kemCiphertext: outbound.kemCiphertext, prekey: outbound.prekey
  });
  const inbound = await createNativeInboundSession({
    crypto, pqc, identity: bob, contact: aliceContact,
    kemCiphertext: envelope.kemCiphertext, prekey: envelope.prekey
  });
  const before = structuredClone(inbound.receiveChain);
  const mutations = [
    (direct) => { direct.senderCertificateDigest = base64(new Uint8Array(32)); },
    (direct) => { direct.negotiatedCapabilitiesDigest = base64(new Uint8Array(32)); },
    (direct) => { direct.cipherSuite = "nw.direct-v4.downgraded"; }
  ];
  for (const mutate of mutations) {
    const tampered = structuredClone(envelope);
    mutate(tampered.authenticatedContext.directV4);
    tampered.signature = base64(pqc.sign(
      canonicalEnvelopeBytes(tampered),
      Buffer.from(alice.localInstallation.signing.secretKey, "base64")
    ));
    await assert.rejects(
      decryptNativeEnvelope({
        crypto, pqc, identity: bob, contact: aliceContact,
        conversation: inbound, envelope: tampered
      }),
      /authenticated context/
    );
    assert.deepEqual(inbound.receiveChain, before);
  }
});

test("direct-v4 refuses missing modules, version gaps, altered limits, and legacy downgrade", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Bob" });
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const defaultCapabilities = bobContact.preferredInstallationEndpoint.capabilities;

  bobContact.preferredInstallationEndpoint.capabilities = {
    ...defaultCapabilities,
    modules: defaultCapabilities.modules.filter(({ module }) => module !== "nw.events")
  };
  await assert.rejects(
    createNativeOutboundSession({ crypto, pqc, identity: alice, contact: bobContact }),
    /requires nw\.events/
  );

  bobContact.preferredInstallationEndpoint.capabilities = {
    ...defaultCapabilities,
    modules: defaultCapabilities.modules.map((module) => module.module === "nw.events"
      ? { ...module, versions: [3] }
      : module)
  };
  await assert.rejects(
    createNativeOutboundSession({ crypto, pqc, identity: alice, contact: bobContact }),
    /no shared nw\.events version/
  );

  bobContact.preferredInstallationEndpoint.capabilities = defaultCapabilities;
  const outbound = await createNativeOutboundSession({
    crypto, pqc, identity: alice, contact: bobContact
  });
  bobContact.preferredInstallationEndpoint.capabilities = {
    ...defaultCapabilities,
    modules: defaultCapabilities.modules.map((module) => module.module === "nw.events"
      ? { ...module, limits: { maxContentPayloadBytes: 1_024 } }
      : module)
  };
  await assert.rejects(
    encryptNativeTextEnvelope({
      crypto, pqc, identity: alice, contact: bobContact,
      conversation: outbound.conversation, text: "transcript changed"
    }),
    /capability transcript/
  );

  await assert.rejects(
    createNativeOutboundSession({
      crypto,
      pqc,
      identity: alice,
      contact: { ...bobContact, preferredInstallationEndpoint: undefined }
    }),
    /legacy fallback is forbidden/
  );
  await assert.rejects(
    createNativeOutboundSession({
      crypto,
      pqc,
      identity: alice,
      contact: { ...bobContact, version: 3 }
    }),
    /legacy fallback is forbidden/
  );
});

test("direct-v4 endpoint revocation fails closed", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Bob" });
  const aliceContact = contactFromNativeOffer(alice.contactOffer);
  aliceContact.endpointRevocation = await createInstallationEndpointRevocationV4({
    crypto,
    pqc,
    identity: alice,
    issuedAt: new Date(Date.parse(alice.certifiedInstallationEndpoint.issuedAt) + 1_000).toISOString()
  });
  await assert.rejects(
    createNativeOutboundSession({ crypto, pqc, identity: bob, contact: aliceContact }),
    /revoked/
  );
});

test("direct-v4 pairwise handles and certificate references are unlinkable across contacts", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Bob" });
  const carol = await makeV4Identity({ crypto, pqc, displayName: "Carol" });
  const aliceBob = await deriveNativeDirectV4Binding({
    crypto, identity: alice, contact: contactFromNativeOffer(bob.contactOffer)
  });
  const bobAlice = await deriveNativeDirectV4Binding({
    crypto, identity: bob, contact: contactFromNativeOffer(alice.contactOffer)
  });
  const aliceCarol = await deriveNativeDirectV4Binding({
    crypto, identity: alice, contact: contactFromNativeOffer(carol.contactOffer)
  });

  assert.equal(aliceBob.relationshipId, bobAlice.relationshipId);
  assert.equal(aliceBob.localInstallationHandle.rawValue, bobAlice.peerInstallationHandle.rawValue);
  assert.equal(aliceBob.localCertificateReferenceDigest, bobAlice.peerCertificateReferenceDigest);
  assert.notEqual(aliceBob.relationshipId, aliceCarol.relationshipId);
  assert.notEqual(aliceBob.localInstallationHandle.rawValue, aliceCarol.localInstallationHandle.rawValue);
  assert.notEqual(aliceBob.localCertificateReferenceDigest, aliceCarol.localCertificateReferenceDigest);
});

test("direct-v4 relay context contains no global endpoint or identity material", async () => {
  const { crypto, pqc } = await primitives();
  const alice = await makeV4Identity({ crypto, pqc, displayName: "Alice" });
  const bob = await makeV4Identity({ crypto, pqc, displayName: "Bob" });
  const bobContact = contactFromNativeOffer(bob.contactOffer);
  const outbound = await createNativeOutboundSession({ crypto, pqc, identity: alice, contact: bobContact });
  const envelope = await encryptNativeTextEnvelope({
    crypto, pqc, identity: alice, contact: bobContact,
    conversation: outbound.conversation, text: "opaque context",
    kemCiphertext: outbound.kemCiphertext, prekey: outbound.prekey
  });
  const relayContext = JSON.stringify(envelope.authenticatedContext);
  assert.equal(
    envelope.authenticatedContext.directV4.cipherSuite,
    outbound.conversation.endpointSession.cipherSuite
  );
  assert.equal(
    envelope.authenticatedContext.directV4.negotiatedCapabilitiesDigest,
    outbound.conversation.endpointSession.negotiatedCapabilitiesDigest
  );
  for (const forbidden of [
    alice.signing.publicKey,
    alice.localInstallation.signing.publicKey,
    alice.localInstallation.agreement.publicKey,
    alice.certifiedInstallationEndpoint.prekeyBundle.signedPrekey.publicKey,
    alice.localInstallation.id,
    alice.identityGenerationId,
    alice.signingFingerprint,
    "preferredInstallationEndpoint",
    "prekeyBundle",
    "identityAuthorityPublicKey",
    "signingPublicKey",
    "agreementPublicKey",
    "installationId"
  ]) {
    assert.equal(relayContext.includes(forbidden), false, forbidden);
  }
});

test("direct-v4 pairwise binding matches the shared Swift and JavaScript vector", async () => {
  const crypto = new WebCryptoPrimitives();
  const vector = JSON.parse(await readFile(new URL(
    "../../NoctweaveDocumentation/test_vectors/direct_v4_pairwise_binding.json",
    import.meta.url
  )));
  const localEndpoint = vectorEndpoint(vector.local, vector.issuedAt);
  const peerEndpoint = vectorEndpoint(vector.peer, vector.issuedAt);
  const binding = await derivePairwiseInstallationBindingV4({
    crypto,
    localIdentityGenerationId: vector.local.identityGenerationId,
    localIdentitySigningPublicKey: repeatedBase64(vector.local.identitySigningByte, 1_952),
    localEndpoint,
    peerIdentityGenerationId: vector.peer.identityGenerationId,
    peerIdentitySigningPublicKey: repeatedBase64(vector.peer.identitySigningByte, 1_952),
    peerEndpoint
  });
  assert.deepEqual(binding, {
    relationshipId: vector.expected.relationshipId,
    localInstallationHandle: { rawValue: vector.expected.localInstallationHandle },
    peerInstallationHandle: { rawValue: vector.expected.peerInstallationHandle },
    localCertificateReferenceDigest: vector.expected.localCertificateReferenceDigest,
    peerCertificateReferenceDigest: vector.expected.peerCertificateReferenceDigest,
    cipherSuite: vector.expected.cipherSuite,
    negotiatedCapabilitiesDigest: vector.expected.negotiatedCapabilitiesDigest
  });
  assert.equal(
    await directV4ConversationId({ crypto, localEndpoint, peerEndpoint, binding }),
    vector.wire.conversationId
  );

  const authenticatedContext = {
    purpose: "directV4",
    directV4: {
      version: 4,
      payloadFormat: "nw.wire-payload.v2",
      cipherSuite: vector.expected.cipherSuite,
      negotiatedCapabilitiesDigest: vector.expected.negotiatedCapabilitiesDigest,
      eventId: vector.wire.eventId,
      senderInstallationHandle: binding.localInstallationHandle.rawValue,
      senderCertificateDigest: binding.localCertificateReferenceDigest,
      recipientInstallationHandle: binding.peerInstallationHandle.rawValue,
      senderManifestEpoch: vector.local.manifestEpoch,
      recipientManifestEpoch: vector.peer.manifestEpoch,
      recipientCertificateDigest: binding.peerCertificateReferenceDigest
    }
  };
  const aad = nativeAuthenticatedDataBytes({
    conversationId: vector.wire.conversationId,
    sessionId: vector.wire.sessionId,
    authenticatedContext,
    messageCounter: vector.wire.messageCounter
  });
  const signable = canonicalEnvelopeBytes({
    id: vector.wire.envelopeId,
    conversationId: vector.wire.conversationId,
    sessionId: vector.wire.sessionId,
    senderFingerprint: binding.localInstallationHandle.rawValue,
    sentAt: vector.wire.sentAt,
    messageCounter: vector.wire.messageCounter,
    authenticatedContext,
    payload: {
      nonce: repeatedBase64(vector.wire.nonceByte, 12),
      ciphertext: repeatedBase64(vector.wire.ciphertextByte, vector.wire.ciphertextCount),
      tag: repeatedBase64(vector.wire.tagByte, 16)
    },
    signature: ""
  });
  const signatureDigest = base64(await crypto.sha256(signable));
  assert.equal(base64(aad), vector.wire.aadCanonicalBase64);
  assert.equal(signatureDigest, vector.wire.signatureCanonicalSHA256);
});

test("contact decoding keeps legacy v2 and v3 explicit and rejects incomplete v4", async () => {
  const { crypto, pqc } = await primitives();
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  const unsignedV2 = {
    agreementPublicKey: base64(agreement.publicKey),
    displayName: "Legacy v2",
    fingerprint: base64(await crypto.sha256(signing.publicKey)),
    inboxId: "legacy-v2-inbox",
    relay,
    signingPublicKey: base64(signing.publicKey),
    version: 2
  };
  const offerV2 = {
    ...unsignedV2,
    signature: base64(pqc.sign(canonicalJsonBytes(unsignedV2), signing.secretKey))
  };
  await verifyNativeContactOffer({ crypto, pqc, offer: offerV2 });

  const access = pqc.generateSigningKeypair();
  const unsignedV3 = { ...unsignedV2, version: 3, inboxAccessPublicKey: base64(access.publicKey) };
  const offerV3 = {
    ...unsignedV3,
    signature: base64(pqc.sign(canonicalJsonBytes(unsignedV3), signing.secretKey))
  };
  await verifyNativeContactOffer({ crypto, pqc, offer: offerV3 });
  await assert.rejects(
    verifyNativeContactOffer({ crypto, pqc, offer: { ...offerV3, version: 4 } }),
    /Certified contact offer is malformed/
  );
  await assert.rejects(
    verifyNativeContactOffer({ crypto, pqc, offer: { ...offerV2, version: 3 } }),
    /version is inconsistent/
  );
});

async function primitives() {
  return {
    crypto: new WebCryptoPrimitives(),
    pqc: await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory)
  };
}

async function makeV4Identity({ crypto, pqc, displayName, issuedAt, verificationNow }) {
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  const access = pqc.generateSigningKeypair();
  const identity = {
    architectureVersion: 2,
    identityGenerationId: swiftUUID(),
    displayName,
    signing: serializeKeypair(signing),
    agreement: serializeKeypair(agreement),
    access: serializeKeypair(access),
    inboxId: await inboxIdForAccessPublicKey({ crypto, publicKey: access.publicKey }),
    accessFingerprint: base64(await crypto.sha256(access.publicKey)),
    signingFingerprint: base64(await crypto.sha256(signing.publicKey))
  };
  await prepareNativeDirectV4Identity({ crypto, pqc, identity, issuedAt });
  identity.contactOffer = makeNativeContactOffer({ pqc, identity, relayEndpoint: relay });
  if (verificationNow == null) {
    await verifyNativeContactOffer({ crypto, pqc, offer: identity.contactOffer });
  } else {
    await verifyCertifiedNativeContactOffer({
      crypto, pqc, offer: identity.contactOffer, now: verificationNow
    });
  }
  return identity;
}

function serializeKeypair(keypair) {
  return { publicKey: base64(keypair.publicKey), secretKey: base64(keypair.secretKey) };
}

function vectorEndpoint(value, issuedAt) {
  const capabilities = createProtocolCapabilityManifest();
  return {
    identityGenerationId: value.identityGenerationId,
    identityAuthorityPublicKey: repeatedBase64(value.identitySigningByte, 1_952),
    manifestEpoch: value.manifestEpoch,
    manifestDigest: repeatedBase64(value.manifestDigestByte, 32),
    installationId: value.installationId,
    signingPublicKey: repeatedBase64(value.endpointSigningByte, 1_952),
    agreementPublicKey: repeatedBase64(value.endpointAgreementByte, 1_184),
    capabilities,
    prekeyBundle: {
      version: 2,
      identityFingerprint: repeatedBase64(value.endpointSigningByte, 32),
      signedPrekey: {
        id: value.signedPrekeyId,
        publicKey: repeatedBase64(value.signedPrekeyByte, 1_184),
        issuedAt,
        signature: repeatedBase64(value.signatureByte, 3_309)
      },
      oneTimePrekeys: [],
      createdAt: issuedAt
    },
    issuedAt,
    authoritySignature: repeatedBase64(value.signatureByte, 3_309),
    possessionSignature: repeatedBase64(value.signatureByte, 3_309)
  };
}

function repeatedBase64(value, count) {
  return Buffer.alloc(count, value).toString("base64");
}
