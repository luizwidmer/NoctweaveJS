import assert from "node:assert/strict";
import { inspect } from "node:util";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveOQSWasmAdapter,
  PairwiseOpaqueRouteV2Error,
  WebCryptoPrimitives,
  addTestingPairwiseRouteV2,
  advanceLocalOpaqueReceiveRouteV2,
  assertOpaqueRouteSyncContinuityV2,
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
  createLocalOpaqueReceiveRouteV2,
  createOpaqueSendRouteV2,
  createPairwiseRouteSetV2,
  derivePairwiseRelationshipIDV2,
  makeOpaqueRouteCreateRequestV2,
  opaqueRouteRecordDigestV2,
  markPairwiseRouteTestedV2,
  pairwiseRouteSetV2Digest,
  pairwiseRouteSetV2SignableBytes,
  preparePairwiseDirectV4Identity,
  promoteProbedPairwiseRouteV2,
  swiftUUID,
  promotePairwiseRouteV2,
  revokeDrainedPairwiseRouteV2,
  sealOpaqueRouteBundleV2,
  usablePairwiseRoutesV2,
  validateContactIntroductionV2,
  validateOpaqueRouteSyncResponseV2,
  validateOpaqueSendRouteV2,
  validatePairwiseRouteSetV2,
  verifyRelationshipEndpointBindingV4,
  verifyContactIntroductionV2,
  verifyPairwiseRouteSetV2,
  verifyPairwiseRouteSetV2Throwing
} from "../src/index.js";

const issuedAt = "2026-07-16T12:00:00Z";
const routeExpiresAt = "2026-07-16T13:00:00Z";
const introductionExpiresAt = "2026-07-16T12:05:00Z";
const relay = { host: "127.0.0.1", port: 9_339, useTLS: false, transport: "http" };

test("opaque send routes disclose only send and payload authority and redact inspection", async () => {
  const crypto = new WebCryptoPrimitives();
  const local = await createLocalReceiveRoute(crypto);
  const route = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: local.route,
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
  assert.equal(String(route), "OpaqueSendRouteV2(<redacted>)");
  assert.equal(inspect(route), "OpaqueSendRouteV2(<redacted>)");
  assert.equal(inspect(route.sendCapability).includes(route.sendCapability.rawValue), false);
  assert.equal(inspect(route.payloadKey).includes(route.payloadKey.rawValue), false);
  assert.equal(route.state, "active");
  assert.equal(route.testedAt, issuedAt);
  assert.equal(route.drainAfter, null);
  assert.equal(route.revokedAt, null);
  assert.equal(route.routeRevision, local.route.lease.renewalSequence);
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
  assert.deepEqual(validateOpaqueSendRouteV2(JSON.parse(projection)), JSON.parse(projection));

  const unknownField = JSON.parse(projection);
  unknownField.readCredential = local.clientCapabilities.readCredential;
  assert.throws(
    () => validateOpaqueSendRouteV2(unknownField),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidRoute"
  );
  const missingLifecycle = JSON.parse(projection);
  delete missingLifecycle.testedAt;
  assert.throws(
    () => validateOpaqueSendRouteV2(missingLifecycle),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidRoute"
  );
  const insecure = JSON.parse(projection);
  insecure.relay = { host: "192.168.1.8", port: 9_339, useTLS: false, transport: "http" };
  assert.throws(
    () => validateOpaqueSendRouteV2(insecure),
    (error) => error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidRoute"
  );
});

test("local receive routes persist verified sequence and record-digest continuity", async () => {
  const crypto = new WebCryptoPrimitives();
  const raw = await createLocalReceiveRoute(crypto);
  const local = await createLocalOpaqueReceiveRouteV2({ crypto, relay, ...raw });
  const bundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload: new TextEncoder().encode("ordered opaque route payload"),
    routeRevision: 0,
    paddingBucket: 4_096,
    payloadKey: raw.payloadKey,
    sendAuthority: {
      routeID: raw.clientCapabilities.routeID,
      sendCapability: raw.clientCapabilities.sendCapability
    },
    authorizedAt: issuedAt
  });
  const packet = bundle.packets[0];
  const zeroDigest = base64(new Uint8Array(32));
  const recordDigest = await opaqueRouteRecordDigestV2({
    crypto,
    previousRecordDigest: zeroDigest,
    sequence: 1,
    routeRevision: 0,
    packet
  });
  const cursor = { rawValue: base64(new Uint8Array(68).fill(0x41)) };
  const batch = await validateOpaqueRouteSyncResponseV2({
    crypto,
    request: { routeID: raw.clientCapabilities.routeID, limit: 16 },
    response: {
      packets: [{
        sequence: 1,
        previousRecordDigest: zeroDigest,
        recordDigest,
        routeRevision: 0,
        packet
      }],
      startsAfterSequence: 0,
      startsAfterRecordDigest: zeroDigest,
      nextSequence: 1,
      nextRecordDigest: recordDigest,
      highWatermarkSequence: 1,
      retentionFloorSequence: 0,
      nextCursor: cursor,
      highWatermark: cursor,
      retentionFloor: cursor,
      hasMore: false
    }
  });
  assert.equal(
    assertOpaqueRouteSyncContinuityV2({ batch, localReceiveRoute: local, detectedAt: issuedAt }),
    batch
  );
  const advanced = await advanceLocalOpaqueReceiveRouteV2({
    crypto,
    localReceiveRoute: local,
    batch,
    commitResponse: {
      committedCursor: cursor,
      highWatermark: cursor,
      retentionFloor: cursor
    },
    detectedAt: issuedAt
  });
  assert.equal(advanced.committedSequence, 1);
  assert.equal(advanced.committedRecordDigest, recordDigest);
  assert.deepEqual(advanced.committedCursor, cursor);
  assert.equal(advanced.gapState, null);

  assert.throws(() => assertOpaqueRouteSyncContinuityV2({
    batch,
    localReceiveRoute: advanced,
    detectedAt: issuedAt
  }), (error) => {
    assert.equal(error.code, "routeGapDetected");
    assert.equal(error.gapState.reason, "cursorRegression");
    assert.equal(error.localReceiveRoute.gapState.reason, "cursorRegression");
    return true;
  });
});

test("opaque route sync rejects omitted, reordered, and digest-substituted records", async () => {
  const crypto = new WebCryptoPrimitives();
  const raw = await createLocalReceiveRoute(crypto);
  const bundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload: new TextEncoder().encode("gap proof"),
    routeRevision: 0,
    paddingBucket: 4_096,
    payloadKey: raw.payloadKey,
    sendAuthority: {
      routeID: raw.clientCapabilities.routeID,
      sendCapability: raw.clientCapabilities.sendCapability
    },
    authorizedAt: issuedAt
  });
  const packet = bundle.packets[0];
  const zeroDigest = base64(new Uint8Array(32));
  const recordDigest = await opaqueRouteRecordDigestV2({
    crypto,
    previousRecordDigest: zeroDigest,
    sequence: 1,
    routeRevision: 0,
    packet
  });
  const cursor = { rawValue: base64(new Uint8Array(68).fill(0x42)) };
  const response = {
    packets: [{
      sequence: 1,
      previousRecordDigest: zeroDigest,
      recordDigest,
      routeRevision: 0,
      packet
    }],
    startsAfterSequence: 0,
    startsAfterRecordDigest: zeroDigest,
    nextSequence: 1,
    nextRecordDigest: recordDigest,
    highWatermarkSequence: 1,
    retentionFloorSequence: 0,
    nextCursor: cursor,
    highWatermark: cursor,
    retentionFloor: cursor,
    hasMore: false
  };
  const validate = (candidate) => validateOpaqueRouteSyncResponseV2({
    crypto,
    request: { routeID: raw.clientCapabilities.routeID, limit: 16 },
    response: candidate
  });
  await assert.rejects(() => validate({
    ...response,
    packets: [{ ...response.packets[0], sequence: 2 }],
    nextSequence: 2,
    highWatermarkSequence: 2
  }), /gap, mismatch, or duplicate/);
  await assert.rejects(() => validate({
    ...response,
    packets: [{ ...response.packets[0], recordDigest: base64(new Uint8Array(32).fill(7)) }],
    nextRecordDigest: base64(new Uint8Array(32).fill(7))
  }), /record digest is invalid/);
  await assert.rejects(() => validate({ ...response, packets: [], nextSequence: 1 }),
    /continuation does not match/);
});

test("pairwise route projection proves all local authorities and fresh routes do not correlate", async () => {
  const crypto = new WebCryptoPrimitives();
  const first = await createLocalReceiveRoute(crypto);
  const second = await createLocalReceiveRoute(crypto);
  const firstRoute = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: first.route,
    clientCapabilities: first.clientCapabilities,
    payloadKey: first.payloadKey
  });
  const secondRoute = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: second.route,
    clientCapabilities: second.clientCapabilities,
    payloadKey: second.payloadKey
  });
  assert.notEqual(firstRoute.routeID.rawValue, secondRoute.routeID.rawValue);
  assert.notEqual(firstRoute.sendCapability.rawValue, secondRoute.sendCapability.rawValue);
  assert.notEqual(firstRoute.payloadKey.rawValue, secondRoute.payloadKey.rawValue);

  const mismatched = structuredClone(first.clientCapabilities);
  mismatched.readCredential = second.clientCapabilities.readCredential;
  await assert.rejects(
    createOpaqueSendRouteV2({
      crypto,
      relay,
      route: first.route,
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
  const receiveRoute = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: local.route,
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
    "relationshipPseudonym",
    "relationshipSigningPublicKey",
    "relationshipAgreementPublicKey",
    "endpointBinding",
    "receiveRoutes",
    "rendezvousTranscriptDigest",
    "issuedAt",
    "expiresAt",
    "signature"
  ]);
  assert.equal(introduction.relationshipPseudonym, relationship.relationshipPseudonym);
  assert.equal(introduction.receiveRoutes.routes[0].routeID.rawValue, receiveRoute.routeID.rawValue);
  assert.equal(inspect(introduction.receiveRoutes.routes[0]), "OpaqueSendRouteV2(<redacted>)");
  const canonical = new TextDecoder().decode(contactIntroductionV2SignableBytes(introduction));
  assert.equal(canonical.includes("\"relationshipPseudonym\""), true);
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
  const receiveRoute = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: local.route,
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
  unknownTopLevel.reusableAddress = "stable-routing-identifier-must-not-exist";
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
  endpointUnknown.endpointBinding.previousEndpoint = "legacy";
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
  const original = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: originalLocal.route,
    clientCapabilities: originalLocal.clientCapabilities,
    payloadKey: originalLocal.payloadKey
  });
  const replacement = await createOpaqueSendRouteV2({
    crypto,
    relay,
    route: replacementLocal.route,
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
  const unavailablePQC = { verify: () => { throw new Error("PQC runtime unavailable"); } };
  assert.throws(() => verifyPairwiseRouteSetV2Throwing({
    pqc: unavailablePQC,
    routeSet: initial,
    ownerSigningPublicKey: keys.ownerSigningPublicKey
  }), /PQC runtime unavailable/);
  assert.equal(verifyPairwiseRouteSetV2({
    pqc: unavailablePQC,
    routeSet: initial,
    ownerSigningPublicKey: keys.ownerSigningPublicKey
  }), false);
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

  const probePromoted = await promoteProbedPairwiseRouteV2({
    crypto,
    pqc,
    current: added,
    routeID: replacement.routeID,
    replacingRouteIDs: [original.routeID],
    testedAt: "2026-07-16T12:02:00Z",
    issuedAt: "2026-07-16T12:02:00Z",
    overlapUntil: "2026-07-16T12:10:00Z",
    ...keys
  });
  assert.equal(probePromoted.revision, 2);
  assert.equal(probePromoted.previousDigest, await pairwiseRouteSetV2Digest(crypto, added));
  assert.equal(probePromoted.routes.find((route) =>
    route.routeID.rawValue === replacement.routeID.rawValue
  ).testedAt, "2026-07-16T12:02:00Z");
  assert.equal(probePromoted.routes.find((route) =>
    route.routeID.rawValue === original.routeID.rawValue
  ).state, "draining");
  assert.equal(usablePairwiseRoutesV2(probePromoted, "2026-07-16T12:05:00Z").length, 2);
  assert.equal(verifyPairwiseRouteSetV2({
    pqc,
    routeSet: probePromoted,
    ownerSigningPublicKey: keys.ownerSigningPublicKey
  }), true);
  for (const invalid of [
    {
      replacingRouteIDs: [original.routeID, original.routeID],
      testedAt: "2026-07-16T12:02:00Z"
    },
    {
      replacingRouteIDs: [original.routeID],
      testedAt: "2026-07-16T12:03:00Z"
    },
    {
      replacingRouteIDs: [replacement.routeID],
      testedAt: "2026-07-16T12:02:00Z"
    }
  ]) {
    await assert.rejects(promoteProbedPairwiseRouteV2({
      crypto,
      pqc,
      current: added,
      routeID: replacement.routeID,
      replacingRouteIDs: invalid.replacingRouteIDs,
      testedAt: invalid.testedAt,
      issuedAt: "2026-07-16T12:02:00Z",
      overlapUntil: "2026-07-16T12:10:00Z",
      ...keys
    }), (error) => error?.code === "invalidTransition");
  }
  await assert.rejects(promoteProbedPairwiseRouteV2({
    crypto,
    pqc,
    current: probePromoted,
    routeID: replacement.routeID,
    replacingRouteIDs: [original.routeID],
    testedAt: "2026-07-16T12:03:00Z",
    issuedAt: "2026-07-16T12:03:00Z",
    overlapUntil: "2026-07-16T12:10:00Z",
    ...keys
  }), (error) => error?.code === "invalidTransition");

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
    ownerSigningPublicKey: relationship.endpointBinding.signingPublicKey,
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
    route: await createOpaqueReceiveRouteV2({
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
    version: 2,
    scope: "pairwise",
    id: swiftUUID(),
    relationshipPseudonym: "Ephemeral Alice",
    signing: serializeKeypair(signing),
    agreement: serializeKeypair(agreement),
    signingFingerprint: base64(await crypto.sha256(signing.publicKey)),
    createdAt: issuedAt
  };
  await preparePairwiseDirectV4Identity({
    crypto,
    pqc,
    localIdentity: relationship,
    issuedAt
  });
  await verifyRelationshipEndpointBindingV4({
    crypto,
    pqc,
    authoritySigningPublicKey: relationship.signing.publicKey,
    endpointBinding: relationship.endpointBinding,
    now: issuedAt
  });
  return relationship;
}

function introductionAuthority(relationship) {
  return {
    relationshipPseudonym: relationship.relationshipPseudonym,
    relationshipSigningPublicKey: relationship.signing.publicKey,
    relationshipSigningSecretKey: relationship.signing.secretKey,
    relationshipAgreementPublicKey: relationship.agreement.publicKey,
    endpointBinding: relationship.endpointBinding
  };
}

function serializeKeypair(keypair) {
  return { publicKey: base64(keypair.publicKey), secretKey: base64(keypair.secretKey) };
}
