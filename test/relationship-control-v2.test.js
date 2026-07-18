import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveOQSWasmAdapter,
  RelationshipControlV2Error,
  WebCryptoPrimitives,
  authenticatedRelationshipControlV2SignableBytes,
  base64,
  canonicalJsonBytes,
  createApplicationWirePayloadV2,
  createAuthenticatedRelationshipControlV2,
  createContentTypeId,
  createConversationEvent,
  createPairwiseRouteSetV2,
  createOpaqueSendRouteV2,
  createRelationshipControlWirePayloadV2,
  createRelationshipEndpointPrekeyUpdateV2,
  createRelationshipRouteProbeV2,
  createRelationshipRouteSetUpdateV2,
  createTextEncodedContent,
  decodeKnownRelationshipControlV2,
  prepareContactPairingParticipantV2,
  relationshipControlDispositionV2,
  relationshipControlKindsV2,
  validateAuthenticatedRelationshipControlV2,
  validateWirePayloadV2,
  verifyAuthenticatedRelationshipControlV2
} from "../src/index.js";

const relationshipID = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE";
const eventID = "11111111-2222-4333-8444-555555555555";
const nonce = "99999999-8888-4777-8666-555555555555";
const issuedAt = "2026-07-17T12:00:00Z";
const relay = { host: "127.0.0.1", port: 9_339, useTLS: false, transport: "http" };

test("relationship controls use one exact independently authenticated frame", async () => {
  const fixture = await controlFixture();
  const applicationWire = createApplicationWirePayloadV2(createConversationEvent({
    id: eventID,
    clientTransactionId: nonce,
    conversationId: relationshipID.toLowerCase(),
    authorEndpointHandle: fixture.participant.localEndpointHandle,
    createdAt: issuedAt,
    kind: "application",
    content: createTextEncodedContent("exact application branch")
  }));
  assert.deepEqual(Object.keys(applicationWire), ["version", "kind", "application", "control"]);
  assert.equal(applicationWire.control, null);
  assert.throws(
    () => validateWirePayloadV2({
      version: applicationWire.version,
      kind: applicationWire.kind,
      application: applicationWire.application
    }),
    /exactly its current protocol fields/
  );
  const payloads = {
    routeSetUpdate: createRelationshipRouteSetUpdateV2({
      relationshipID,
      routeSet: fixture.routeSet
    }),
    routeProbe: createRelationshipRouteProbeV2({
      relationshipID,
      routeID: fixture.routeSet.routes[0].routeID,
      routeSetRevision: fixture.routeSet.revision,
      nonce
    }),
    endpointPrekeyUpdate: createRelationshipEndpointPrekeyUpdateV2({
      relationshipID,
      endpointBinding: fixture.participant.localIdentity.endpointBinding
    })
  };

  for (const [kind, payload] of Object.entries(payloads)) {
    const control = createAuthenticatedRelationshipControlV2({
      pqc: fixture.pqc,
      kind,
      payload,
      relationshipID,
      eventID,
      senderEndpointHandle: fixture.participant.localEndpointHandle,
      issuedAt,
      nonce,
      senderSigningSecretKey: fixture.signing.secretKey
    });
    assert.deepEqual(Object.keys(control), [
      "version",
      "type",
      "relationshipID",
      "eventID",
      "senderEndpointHandle",
      "issuedAt",
      "nonce",
      "encodedPayload",
      "signature"
    ]);
    assert.deepEqual(control.type, relationshipControlKindsV2[kind]);
    assert.equal(verifyAuthenticatedRelationshipControlV2({
      pqc: fixture.pqc,
      control,
      relationshipID,
      eventID,
      senderEndpointHandle: fixture.participant.localEndpointHandle,
      senderSigningPublicKey: fixture.signing.publicKey
    }), true);
    assert.deepEqual(decodeKnownRelationshipControlV2(control), { kind, value: payload });

    const wirePayload = createRelationshipControlWirePayloadV2(control);
    assert.deepEqual(Object.keys(wirePayload), ["version", "kind", "application", "control"]);
    assert.equal(wirePayload.application, null);
    const disposition = relationshipControlDispositionV2({
      pqc: fixture.pqc,
      wirePayload,
      relationshipID,
      eventID,
      senderEndpointHandle: fixture.participant.localEndpointHandle,
      sentAt: issuedAt,
      receivedAt: issuedAt,
      senderSigningPublicKey: fixture.signing.publicKey
    });
    assert.equal(disposition.kind, "control");
    assert.deepEqual(disposition.control, { kind, value: payload });
    assert.equal(disposition.event.kind, "control");
    assert.equal(disposition.event.content.disposition, "silent");
  }
});

test("unknown authenticated controls quarantine while malformed known controls fail closed", async () => {
  const fixture = await controlFixture();
  const probe = createRelationshipRouteProbeV2({
    relationshipID,
    routeID: fixture.routeSet.routes[0].routeID,
    routeSetRevision: fixture.routeSet.revision,
    nonce
  });
  const known = createAuthenticatedRelationshipControlV2({
    pqc: fixture.pqc,
    kind: "routeProbe",
    payload: probe,
    relationshipID,
    eventID,
    senderEndpointHandle: fixture.participant.localEndpointHandle,
    issuedAt,
    nonce,
    senderSigningSecretKey: fixture.signing.secretKey
  });

  const unknown = resignControl({
    pqc: fixture.pqc,
    secretKey: fixture.signing.secretKey,
    control: {
      ...known,
      type: createContentTypeId({
        authority: "org.noctweave.control",
        name: "futureRelationshipControl",
        major: 2,
        minor: 0
      })
    }
  });
  assert.equal(decodeKnownRelationshipControlV2(unknown), null);
  const quarantined = relationshipControlDispositionV2({
    pqc: fixture.pqc,
    wirePayload: createRelationshipControlWirePayloadV2(unknown),
    relationshipID,
    eventID,
    senderEndpointHandle: fixture.participant.localEndpointHandle,
    sentAt: issuedAt,
    receivedAt: issuedAt,
    senderSigningPublicKey: fixture.signing.publicKey
  });
  assert.equal(quarantined.kind, "quarantinedControl");
  assert.equal(quarantined.quarantine.event.kind, "control");
  assert.match(quarantined.quarantine.reason, /futureRelationshipControl/);

  const wrongScope = {
    ...probe,
    relationshipID: "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF"
  };
  const malformedKnown = resignControl({
    pqc: fixture.pqc,
    secretKey: fixture.signing.secretKey,
    control: {
      ...known,
      encodedPayload: base64(canonicalJsonBytes(wrongScope))
    }
  });
  assert.throws(
    () => decodeKnownRelationshipControlV2(malformedKnown),
    (error) => error instanceof RelationshipControlV2Error && error.code === "invalidKnownControl"
  );
  assert.throws(() => relationshipControlDispositionV2({
    pqc: fixture.pqc,
    wirePayload: createRelationshipControlWirePayloadV2(malformedKnown),
    relationshipID,
    eventID,
    senderEndpointHandle: fixture.participant.localEndpointHandle,
    sentAt: issuedAt,
    receivedAt: issuedAt,
    senderSigningPublicKey: fixture.signing.publicKey
  }), /Known relationship control payload is invalid/);

  assert.throws(() => validateAuthenticatedRelationshipControlV2({
    ...known,
    encodedPayload: base64(new Uint8Array((48 * 1_024) + 1))
  }), /outside its bounds/);

  const extra = structuredClone(createRelationshipControlWirePayloadV2(known));
  extra.unexpectedField = null;
  assert.throws(() => validateWirePayloadV2(extra), /exactly its current protocol fields/);
  assert.equal(verifyAuthenticatedRelationshipControlV2({
    pqc: fixture.pqc,
    control: known,
    relationshipID: "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF",
    eventID,
    senderEndpointHandle: fixture.participant.localEndpointHandle,
    senderSigningPublicKey: fixture.signing.publicKey
  }), false);
});

async function controlFixture() {
  const crypto = new WebCryptoPrimitives();
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const participant = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    relationshipPseudonym: "one relationship",
    relay,
    createdAt: issuedAt,
    routeExpiresAt: "2026-07-17T13:00:00Z"
  });
  const signing = participant.localIdentity.localEndpoint.signing;
  const sendRoute = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: participant.localReceiveRoute.route,
    clientCapabilities: participant.localReceiveRoute.clientCapabilities,
    payloadKey: participant.localReceiveRoute.payloadKey
  });
  const routeSet = createPairwiseRouteSetV2({
    pqc,
    relationshipID,
    ownerEndpointHandle: participant.localEndpointHandle,
    activeRoutes: [sendRoute],
    issuedAt,
    ownerSigningPublicKey: signing.publicKey,
    ownerSigningSecretKey: signing.secretKey
  });
  return { crypto, pqc, participant, routeSet, signing };
}

function resignControl({ pqc, secretKey, control }) {
  const provisional = validateAuthenticatedRelationshipControlV2({
    ...control,
    signature: base64(new Uint8Array(3_309))
  });
  const key = Uint8Array.from(atob(secretKey), (character) => character.charCodeAt(0));
  try {
    return validateAuthenticatedRelationshipControlV2({
      ...provisional,
      signature: base64(pqc.sign(authenticatedRelationshipControlV2SignableBytes(provisional), key))
    });
  } finally {
    key.fill(0);
  }
}
