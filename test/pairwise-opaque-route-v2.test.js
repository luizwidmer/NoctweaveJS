import assert from "node:assert/strict";
import { inspect } from "node:util";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveOQSWasmAdapter,
  PairwiseOpaqueRouteV2Error,
  WebCryptoPrimitives,
  addTestingPairwiseRouteV2,
  base64,
  contactIntroductionV2SignableBytes,
  createContactIntroductionV2,
  createOpaqueReceiveRouteV2,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePayloadKeyV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  createPairwiseSendRouteV2,
  createPairwiseRouteSetV2,
  derivePairwiseRelationshipIDV2,
  makeOpaqueRouteCreateRequestV2,
  markPairwiseRouteTestedV2,
  pairwiseRouteSetV2Digest,
  pairwiseRouteSetV2SignableBytes,
  prepareNativeDirectV4Identity,
  swiftUUID,
  promotePairwiseRouteV2,
  revokeDrainedPairwiseRouteV2,
  usablePairwiseRoutesV2,
  validateContactIntroductionV2,
  validatePairwiseSendRouteV2,
  validatePairwiseRouteSetV2,
  verifyCertifiedGenerationEndpointV4,
  verifyContactIntroductionV2,
  verifyPairwiseRouteSetV2
} from "../src/index.js";

const issuedAt = "2026-07-16T12:00:00Z";
const routeExpiresAt = "2026-07-16T13:00:00Z";
const introductionExpiresAt = "2026-07-16T12:05:00Z";
const relay = { host: "127.0.0.1", port: 9_339, useTLS: false, transport: "http" };

test("pairwise send routes disclose only send and payload authority and redact inspection", async () => {
  const crypto = new WebCryptoPrimitives();
  const local = await createLocalReceiveRoute(crypto);
  const route = await createPairwiseSendRouteV2({
    crypto,
    relay,
    opaqueRoute: local.opaqueRoute,
    clientCapabilities: local.clientCapabilities,
    payloadKey: local.payloadKey
  });

  assert.deepEqual(Object.keys(route).sort(), [
    "drainAfter",
    "expiresAt",
    "payloadKey",
    "policy",
    "priority",
    "relay",
    "revokedAt",
    "routeID",
    "routeRevision",
    "sendCapability",
    "state",
    "testedAt",
    "validFrom"
  ]);
  assert.equal(String(route), "PairwiseSendRouteV2(<redacted>)");
  assert.equal(inspect(route), "PairwiseSendRouteV2(<redacted>)");
  assert.equal(inspect(route.sendCapability).includes(route.sendCapability.rawValue), false);
  assert.equal(inspect(route.payloadKey).includes(route.payloadKey.rawValue), false);
  assert.equal(route.state, "active");
  assert.equal(route.testedAt, issuedAt);
  assert.equal(route.drainAfter, null);
  assert.equal(route.revokedAt, null);
  assert.equal(route.routeRevision, local.opaqueRoute.lease.renewalSequence);
  const projection = JSON.stringify(route);
  for (const field of ["readCredential", "renewCapability", "teardownCapability"]) {
    assert.equal(projection.includes(field), false, field);
  }
  for (const secret of [
    local.clientCapabilities.readCredential.rawValue,
    local.clientCapabilities.renewCapability.rawValue,
    local.clientCapabilities.teardownCapability.rawValue
  ]) {
    assert.equal(projection.includes(secret), false);
  }
  assert.equal(projection.includes(local.clientCapabilities.sendCapability.rawValue), true);
  assert.equal(projection.includes(local.payloadKey.rawValue), true);
  assert.deepEqual(validatePairwiseSendRouteV2(JSON.parse(projection)), JSON.parse(projection));

  const unknownField = JSON.parse(projection);
  unknownField.readCredential = local.clientCapabilities.readCredential;
  assert.throws(
    () => validatePairwiseSendRouteV2(unknownField),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidRoute"
  );
  const missingLifecycle = JSON.parse(projection);
  delete missingLifecycle.testedAt;
  assert.throws(
    () => validatePairwiseSendRouteV2(missingLifecycle),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidRoute"
  );
  const insecure = JSON.parse(projection);
  insecure.relay = { host: "192.168.1.8", port: 9_339, useTLS: false, transport: "http" };
  assert.throws(
    () => validatePairwiseSendRouteV2(insecure),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidRoute"
  );
});

test("pairwise route projection proves all local authorities and fresh routes do not correlate", async () => {
  const crypto = new WebCryptoPrimitives();
  const first = await createLocalReceiveRoute(crypto);
  const second = await createLocalReceiveRoute(crypto);
  const firstRoute = await createPairwiseSendRouteV2({
    crypto,
    relay,
    opaqueRoute: first.opaqueRoute,
    clientCapabilities: first.clientCapabilities,
    payloadKey: first.payloadKey
  });
  const secondRoute = await createPairwiseSendRouteV2({
    crypto,
    relay,
    opaqueRoute: second.opaqueRoute,
    clientCapabilities: second.clientCapabilities,
    payloadKey: second.payloadKey
  });
  assert.notEqual(firstRoute.routeID.rawValue, secondRoute.routeID.rawValue);
  assert.notEqual(firstRoute.sendCapability.rawValue, secondRoute.sendCapability.rawValue);
  assert.notEqual(firstRoute.payloadKey.rawValue, secondRoute.payloadKey.rawValue);

  const mismatched = structuredClone(first.clientCapabilities);
  mismatched.readCredential = second.clientCapabilities.readCredential;
  await assert.rejects(
    createPairwiseSendRouteV2({
      crypto,
      relay,
      opaqueRoute: first.opaqueRoute,
      clientCapabilities: mismatched,
      payloadKey: first.payloadKey
    }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidRoute"
  );
});

test("contact introductions bind one active route to one rendezvous and exact lifetime", async () => {
  const { crypto, pqc } = await primitives();
  const relationship = await createRelationshipAuthority({ crypto, pqc });
  const local = await createLocalReceiveRoute(crypto);
  const receiveRoute = await createPairwiseSendRouteV2({
    crypto,
    relay,
    opaqueRoute: local.opaqueRoute,
    clientCapabilities: local.clientCapabilities,
    payloadKey: local.payloadKey
  });
  const rendezvousTranscriptDigest = await crypto.sha256(
    new TextEncoder().encode("one authenticated rendezvous")
  );
  const receiveRoutes = await createInitialRouteSet({
    crypto,
    pqc,
    relationship,
    activeRoutes: [receiveRoute],
    relationshipID: await derivePairwiseRelationshipIDV2({
      crypto,
      rendezvousTranscriptDigest
    })
  });
  const introduction = await createContactIntroductionV2({
    crypto,
    pqc,
    ...introductionAuthority(relationship),
    receiveRoutes,
    rendezvousTranscriptDigest,
    issuedAt,
    expiresAt: introductionExpiresAt
  });

  assert.deepEqual(Object.keys(introduction), [
    "version",
    "displayName",
    "relationshipGenerationID",
    "relationshipSigningPublicKey",
    "relationshipAgreementPublicKey",
    "endpointSetCheckpoint",
    "preferredEndpoint",
    "receiveRoutes",
    "rendezvousTranscriptDigest",
    "issuedAt",
    "expiresAt",
    "signature"
  ]);
  assert.equal(introduction.relationshipGenerationID, relationship.identityGenerationId);
  assert.equal(introduction.receiveRoutes.routes[0].routeID.rawValue, receiveRoute.routeID.rawValue);
  assert.equal(inspect(introduction.receiveRoutes.routes[0]), "PairwiseSendRouteV2(<redacted>)");
  const canonical = new TextDecoder().decode(contactIntroductionV2SignableBytes(introduction));
  assert.equal(canonical.includes("\"relationshipGenerationID\""), true);
  assert.equal(Object.hasOwn(JSON.parse(canonical), "signature"), false);
  assert.deepEqual(await verifyContactIntroductionV2({
    crypto,
    pqc,
    introduction: JSON.parse(JSON.stringify(introduction)),
    rendezvousTranscriptDigest,
    at: "2026-07-16T12:02:00Z"
  }), introduction);

  const wrongDigest = new Uint8Array(rendezvousTranscriptDigest);
  wrongDigest[0] ^= 0xff;
  await assert.rejects(
    verifyContactIntroductionV2({
      crypto,
      pqc,
      introduction,
      rendezvousTranscriptDigest: wrongDigest,
      at: "2026-07-16T12:02:00Z"
    }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "wrongRendezvous"
  );
  await assert.rejects(
    verifyContactIntroductionV2({
      crypto,
      pqc,
      introduction,
      rendezvousTranscriptDigest,
      at: introductionExpiresAt
    }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "expiredIntroduction"
  );

  const invalidSignature = structuredClone(introduction);
  invalidSignature.signature = base64(new Uint8Array(3_309));
  await assert.rejects(
    verifyContactIntroductionV2({
      crypto,
      pqc,
      introduction: invalidSignature,
      rendezvousTranscriptDigest,
      at: "2026-07-16T12:02:00Z"
    }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidSignature"
  );
});

test("contact introductions reject unknown, non-current, and overbroad route state", async () => {
  const { crypto, pqc } = await primitives();
  const relationship = await createRelationshipAuthority({ crypto, pqc });
  const local = await createLocalReceiveRoute(crypto);
  const receiveRoute = await createPairwiseSendRouteV2({
    crypto,
    relay,
    opaqueRoute: local.opaqueRoute,
    clientCapabilities: local.clientCapabilities,
    payloadKey: local.payloadKey
  });
  const digest = await crypto.sha256(new TextEncoder().encode("strict current introduction"));
  const receiveRoutes = await createInitialRouteSet({
    crypto,
    pqc,
    relationship,
    activeRoutes: [receiveRoute],
    relationshipID: await derivePairwiseRelationshipIDV2({
      crypto,
      rendezvousTranscriptDigest: digest
    })
  });
  const introduction = await createContactIntroductionV2({
    crypto,
    pqc,
    ...introductionAuthority(relationship),
    receiveRoutes,
    rendezvousTranscriptDigest: digest,
    issuedAt,
    expiresAt: introductionExpiresAt
  });

  const unknownTopLevel = structuredClone(introduction);
  unknownTopLevel.inboxId = "stable-routing-identifier-must-not-exist";
  assert.throws(
    () => validateContactIntroductionV2(unknownTopLevel, { pqc }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  const unknownRouteField = structuredClone(introduction);
  unknownRouteField.receiveRoutes.routes[0].renewCapability = local.clientCapabilities.renewCapability;
  assert.throws(
    () => validateContactIntroductionV2(unknownRouteField, { pqc }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  const mismatchedCheckpoint = structuredClone(introduction);
  mismatchedCheckpoint.endpointSetCheckpoint.epoch += 1;
  assert.throws(
    () => validateContactIntroductionV2(mismatchedCheckpoint, { pqc }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  const drainingRoute = structuredClone(introduction);
  drainingRoute.receiveRoutes.routes[0].state = "draining";
  assert.throws(
    () => validateContactIntroductionV2(drainingRoute, { pqc }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  const tooLong = structuredClone(introduction);
  tooLong.expiresAt = "2026-07-16T12:10:01Z";
  assert.throws(
    () => validateContactIntroductionV2(tooLong, { pqc }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  const endpointUnknown = structuredClone(introduction);
  endpointUnknown.preferredEndpoint.previousEndpoint = "legacy";
  assert.throws(
    () => validateContactIntroductionV2(endpointUnknown, { pqc }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  const unsignedRouteSet = structuredClone(introduction);
  unsignedRouteSet.receiveRoutes.signature = base64(new Uint8Array(3_309));
  assert.throws(
    () => validateContactIntroductionV2(unsignedRouteSet, { pqc }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  const wrongRelationshipRoutes = await createInitialRouteSet({
    crypto,
    pqc,
    relationship,
    activeRoutes: [receiveRoute]
  });
  await assert.rejects(
    createContactIntroductionV2({
      crypto,
      pqc,
      ...introductionAuthority(relationship),
      receiveRoutes: wrongRelationshipRoutes,
      rendezvousTranscriptDigest: digest,
      issuedAt,
      expiresAt: introductionExpiresAt
    }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
  await assert.rejects(
    createContactIntroductionV2({
      crypto,
      pqc,
      identity: relationship,
      receiveRoutes,
      rendezvousTranscriptDigest: digest,
      issuedAt,
      expiresAt: introductionExpiresAt
    }),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction"
  );
});

test("pairwise route sets enforce signed make-before-break replacement", async () => {
  const { crypto, pqc } = await primitives();
  const relationship = await createRelationshipAuthority({ crypto, pqc });
  const originalLocal = await createLocalReceiveRoute(crypto);
  const replacementLocal = await createLocalReceiveRoute(crypto);
  const original = await createPairwiseSendRouteV2({
    crypto,
    relay,
    opaqueRoute: originalLocal.opaqueRoute,
    clientCapabilities: originalLocal.clientCapabilities,
    payloadKey: originalLocal.payloadKey
  });
  const replacement = await createPairwiseSendRouteV2({
    crypto,
    relay,
    opaqueRoute: replacementLocal.opaqueRoute,
    clientCapabilities: replacementLocal.clientCapabilities,
    payloadKey: replacementLocal.payloadKey,
    state: "testing"
  });
  const keys = endpointSigningKeys(relationship);
  const initial = await createInitialRouteSet({
    crypto,
    pqc,
    relationship,
    activeRoutes: [original]
  });
  assert.equal(verifyPairwiseRouteSetV2({
    pqc,
    routeSet: initial,
    ownerSigningPublicKey: keys.ownerSigningPublicKey
  }), true);
  assert.equal(Object.hasOwn(JSON.parse(new TextDecoder().decode(
    pairwiseRouteSetV2SignableBytes(initial)
  )), "previousDigest"), false);

  const added = await addTestingPairwiseRouteV2({
    crypto,
    pqc,
    current: initial,
    route: replacement,
    issuedAt: "2026-07-16T12:01:00Z",
    ...keys
  });
  assert.equal(added.revision, 1);
  assert.equal(added.previousDigest, await pairwiseRouteSetV2Digest(crypto, initial));
  assert.equal(Object.hasOwn(JSON.parse(new TextDecoder().decode(
    pairwiseRouteSetV2SignableBytes(added)
  )), "previousDigest"), true);
  await assert.rejects(
    promotePairwiseRouteV2({
      crypto,
      pqc,
      current: added,
      routeID: replacement.routeID,
      replacingRouteIDs: [original.routeID],
      issuedAt: "2026-07-16T12:02:00Z",
      overlapUntil: "2026-07-16T12:10:00Z",
      ...keys
    }),
    (error) => error?.code === "invalidTransition"
  );

  const tested = await markPairwiseRouteTestedV2({
    crypto,
    pqc,
    current: added,
    routeID: replacement.routeID,
    testedAt: "2026-07-16T12:02:00Z",
    ...keys
  });
  const promoted = await promotePairwiseRouteV2({
    crypto,
    pqc,
    current: tested,
    routeID: replacement.routeID,
    replacingRouteIDs: [original.routeID],
    issuedAt: "2026-07-16T12:03:00Z",
    overlapUntil: "2026-07-16T12:10:00Z",
    ...keys
  });
  assert.equal(promoted.routes.find((route) =>
    route.routeID.rawValue === original.routeID.rawValue
  ).state, "draining");
  assert.equal(promoted.routes.find((route) =>
    route.routeID.rawValue === replacement.routeID.rawValue
  ).state, "active");
  assert.equal(usablePairwiseRoutesV2(promoted, "2026-07-16T12:05:00Z").length, 2);

  const revoked = await revokeDrainedPairwiseRouteV2({
    crypto,
    pqc,
    current: promoted,
    routeID: original.routeID,
    issuedAt: "2026-07-16T12:10:00Z",
    ...keys
  });
  assert.equal(revoked.revision, 4);
  assert.equal(usablePairwiseRoutesV2(revoked, "2026-07-16T12:10:00Z").length, 1);
  assert.equal(verifyPairwiseRouteSetV2({
    pqc,
    routeSet: revoked,
    ownerSigningPublicKey: keys.ownerSigningPublicKey
  }), true);

  const unknown = structuredClone(revoked);
  unknown.routeOwner = "global-profile";
  assert.throws(() => validatePairwiseRouteSetV2(unknown), (error) => error?.code === "invalidState");
  const badSignature = structuredClone(revoked);
  badSignature.signature = base64(new Uint8Array(3_309));
  assert.equal(verifyPairwiseRouteSetV2({
    pqc,
    routeSet: badSignature,
    ownerSigningPublicKey: keys.ownerSigningPublicKey
  }), false);
});

async function createInitialRouteSet({
  crypto,
  pqc,
  relationship,
  activeRoutes,
  relationshipID = swiftUUID()
}) {
  const keys = endpointSigningKeys(relationship);
  return createPairwiseRouteSetV2({
    pqc,
    relationshipID,
    ownerEndpointHandle: { rawValue: base64(await crypto.randomBytes(32)) },
    activeRoutes,
    issuedAt,
    ...keys
  });
}

function endpointSigningKeys(relationship) {
  return {
    ownerSigningPublicKey: relationship.certifiedGenerationEndpoint.signingPublicKey,
    ownerSigningSecretKey: relationship.localEndpoint.signing.secretKey
  };
}

async function createLocalReceiveRoute(crypto) {
  const clientCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const lease = createOpaqueRouteLeaseV2({
    issuedAt,
    expiresAt: routeExpiresAt,
    policy: createOpaqueRoutePolicyV2({
      paddingBucket: 4_096,
      retentionBucket: 3_600,
      quotaBucket: 64
    })
  });
  const request = await makeOpaqueRouteCreateRequestV2({
    crypto,
    capabilities: clientCapabilities,
    lease,
    idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
    nonce: await createOpaqueRouteProofNonceV2(crypto)
  });
  return {
    clientCapabilities,
    opaqueRoute: await createOpaqueReceiveRouteV2({
      crypto,
      request,
      presentedRenewCapability: clientCapabilities.renewCapability,
      confidentialTransport: true,
      receivedAt: issuedAt
    }),
    payloadKey: await createOpaqueRoutePayloadKeyV2(crypto)
  };
}

async function primitives() {
  return {
    crypto: new WebCryptoPrimitives(),
    pqc: await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory)
  };
}

async function createRelationshipAuthority({ crypto, pqc }) {
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  const relationship = {
    architectureVersion: 2,
    identityGenerationId: swiftUUID(),
    displayName: "Ephemeral Alice",
    signing: serializeKeypair(signing),
    agreement: serializeKeypair(agreement),
    signingFingerprint: base64(await crypto.sha256(signing.publicKey))
  };
  // The direct-v4 certificate builder is reused only to mint a certificate
  // graph for this freshly generated relationship authority in the fixture.
  await prepareNativeDirectV4Identity({ crypto, pqc, identity: relationship, issuedAt });
  await verifyCertifiedGenerationEndpointV4({
    crypto,
    pqc,
    identityGenerationId: relationship.identityGenerationId,
    identitySigningPublicKey: relationship.signing.publicKey,
    endpointSetCheckpoint: relationship.endpointSetCheckpoint,
    preferredEndpoint: relationship.certifiedGenerationEndpoint,
    now: issuedAt
  });
  return relationship;
}

function introductionAuthority(relationship) {
  return {
    displayName: relationship.displayName,
    relationshipGenerationID: relationship.identityGenerationId,
    relationshipSigningPublicKey: relationship.signing.publicKey,
    relationshipSigningSecretKey: relationship.signing.secretKey,
    relationshipAgreementPublicKey: relationship.agreement.publicKey,
    endpointSetCheckpoint: relationship.endpointSetCheckpoint,
    preferredEndpoint: relationship.certifiedGenerationEndpoint
  };
}

function serializeKeypair(keypair) {
  return { publicKey: base64(keypair.publicKey), secretKey: base64(keypair.secretKey) };
}
