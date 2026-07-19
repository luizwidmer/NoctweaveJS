import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  OpaqueRoutePacketReassemblerV2,
  OpaqueRoutePacketV2Error,
  createOpaqueRouteBundleIdV2,
  createOpaqueRoutePacketIdV2,
  createOpaqueRoutePacketReassemblerV2,
  createOpaqueRoutePayloadKeyV2,
  noctweaveOpaqueRoutePacketsV2,
  opaqueRouteBundleDigestV2,
  opaqueRoutePacketMaximumFragmentPayloadBytesV2,
  opaqueRoutePacketOperationDigestV2,
  opaqueRoutePacketSendAuthorizationExpiredV2,
  openOpaqueRoutePacketV2,
  refreshOpaqueRoutePacketSendAuthorizationV2,
  sealOpaqueRouteBundleV2,
  validateOpaqueRoutePacketV2,
  validateOpaqueRouteSealedBundleV2
} from "../src/opaque-route-packet-v2.js";
import {
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteUseAuthorizationV2,
  verifyOpaqueRouteAuthorizationProofV2
} from "../src/opaque-route-v2.js";
import { WebCryptoPrimitives } from "../src/crypto/webcrypto.js";
import { base64 } from "../src/crypto/swift-canonical.js";

const authorizedAt = "2026-07-16T12:00:00Z";

test("frozen Swift packet vector matches the JavaScript codec", async () => {
  const vector = JSON.parse(await readFile(new URL(
    "../../NoctweaveDocumentation/test_vectors/opaque_route_packet_v2.json",
    import.meta.url
  ), "utf8"));
  const crypto = testCrypto();
  const routeID = Object.freeze({ rawValue: vector.routeId });
  const packetID = Object.freeze({ rawValue: vector.packetId });
  const payloadKey = Object.freeze({ rawValue: vector.payloadKey });
  const packet = Object.freeze({
    routeID,
    packetID,
    sealedFrame: vector.sealedFrame,
    authorization: Object.freeze({
      authority: vector.authorization.authority,
      nonce: Object.freeze({ rawValue: vector.authorization.nonce }),
      operationDigest: vector.operationDigest,
      authorizedAt: vector.authorization.authorizedAt,
      mac: vector.authorization.mac
    })
  });

  assert.equal(vector.version, 2);
  assert.equal(Buffer.from(vector.sealedFrame, "base64").byteLength, vector.paddingBucket);
  assert.equal(await opaqueRoutePacketOperationDigestV2({
    crypto,
    routeID,
    packetID,
    sealedFrame: vector.sealedFrame
  }), vector.operationDigest);
  assert.deepEqual(await validateOpaqueRoutePacketV2({ crypto, packet }), packet);
  assert.equal(await verifyOpaqueRouteAuthorizationProofV2({
    crypto,
    proof: packet.authorization,
    expectedAuthority: "send",
    routeID,
    operationDigest: vector.operationDigest,
    secret: Object.freeze({ rawValue: vector.sendCapability })
  }), true);

  const fragment = await openOpaqueRoutePacketV2({
    crypto,
    packet,
    payloadKey,
    routeRevision: vector.routeRevision
  });
  assert.equal(fragment.routeID.rawValue, vector.routeId);
  assert.equal(fragment.packetID.rawValue, vector.packetId);
  assert.equal(fragment.bundleID.rawValue, vector.bundleId);
  assert.equal(fragment.bundleDigest, vector.expected.bundleDigest);
  assert.equal(fragment.fragmentIndex, vector.expected.fragmentIndex);
  assert.equal(fragment.fragmentCount, vector.expected.fragmentCount);
  assert.equal(fragment.totalPayloadBytes, vector.expected.totalPayloadBytes);
  assert.deepEqual(fragment.payload, new Uint8Array(Buffer.from(vector.payload, "base64")));
  assert.equal(await opaqueRouteBundleDigestV2({
    crypto,
    bundleID: fragment.bundleID,
    payload: fragment.payload
  }), vector.expected.bundleDigest);

  const reassembler = createOpaqueRoutePacketReassemblerV2();
  const completed = await reassembler.consume({
    crypto,
    packet,
    payloadKey,
    routeRevision: vector.routeRevision
  });
  assert.equal(completed.status, "complete");
  assert.equal(completed.bundle.bundleDigest, vector.expected.bundleDigest);
  assert.deepEqual(completed.bundle.payload, fragment.payload);

  await assert.rejects(
    () => openOpaqueRoutePacketV2({
      crypto,
      packet,
      payloadKey,
      routeRevision: vector.routeRevision + 1
    }),
    packetError("decryptionFailed")
  );
  await assert.rejects(
    () => openOpaqueRoutePacketV2({
      crypto,
      packet,
      payloadKey: createFixedValue(0x23),
      routeRevision: vector.routeRevision
    }),
    packetError("decryptionFailed")
  );

  const wrongRouteID = createFixedValue(0x12);
  const wrongCapabilities = Object.freeze({
    routeID: wrongRouteID,
    sendCapability: Object.freeze({ rawValue: vector.sendCapability }),
    readCredential: createFixedValue(0x44),
    renewCapability: createFixedValue(0x55),
    teardownCapability: createFixedValue(0x66)
  });
  const wrongRouteDigest = await opaqueRoutePacketOperationDigestV2({
    crypto,
    routeID: wrongRouteID,
    packetID,
    sealedFrame: vector.sealedFrame
  });
  const wrongRoutePacket = Object.freeze({
    routeID: wrongRouteID,
    packetID,
    sealedFrame: vector.sealedFrame,
    authorization: await makeOpaqueRouteUseAuthorizationV2({
      crypto,
      capabilities: wrongCapabilities,
      authority: "send",
      operationDigest: wrongRouteDigest,
      authorizedAt: vector.authorization.authorizedAt,
      nonce: await createOpaqueRouteProofNonceV2(crypto)
    })
  });
  await assert.rejects(
    () => openOpaqueRoutePacketV2({
      crypto,
      packet: wrongRoutePacket,
      payloadKey,
      routeRevision: vector.routeRevision
    }),
    packetError("decryptionFailed")
  );
});

test("opaque route packet codec is exported from the public package surface", async () => {
  const api = await import("../src/index.js");
  assert.equal(api.sealOpaqueRouteBundleV2, sealOpaqueRouteBundleV2);
  assert.equal(api.OpaqueRoutePacketReassemblerV2, OpaqueRoutePacketReassemblerV2);
});

test("opaque route packet constants and identifiers match the Swift profile", async () => {
  const crypto = testCrypto();
  assert.deepEqual(noctweaveOpaqueRoutePacketsV2.paddingBuckets, [4_096, 16_384, 65_536]);
  assert.equal(opaqueRoutePacketMaximumFragmentPayloadBytesV2(4_096), 3_946);
  assert.equal(opaqueRoutePacketMaximumFragmentPayloadBytesV2(16_384), 16_234);
  assert.equal(opaqueRoutePacketMaximumFragmentPayloadBytesV2(65_536), 65_386);

  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const packetID = await createOpaqueRoutePacketIdV2(crypto);
  const bundleID = await createOpaqueRouteBundleIdV2(crypto);
  for (const value of [payloadKey, packetID, bundleID]) {
    assert.equal(Buffer.from(value.rawValue, "base64").byteLength, 32);
    assert.equal(Buffer.from(value.rawValue, "base64").some((octet) => octet !== 0), true);
  }
  assert.notEqual(payloadKey.rawValue, packetID.rawValue);
  assert.notEqual(packetID.rawValue, bundleID.rawValue);
});

test("each padding bucket seals a relay-minimal packet with exact route proof binding", async () => {
  for (const paddingBucket of noctweaveOpaqueRoutePacketsV2.paddingBuckets) {
    const crypto = testCrypto();
    const routeCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
    const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
    assert.notEqual(payloadKey.rawValue, routeCapabilities.sendCapability.rawValue);
    const payload = Uint8Array.of(1, 2, 3, 4, 5);
    const bundle = await sealOpaqueRouteBundleV2({
      crypto,
      payload,
      routeRevision: 7,
      paddingBucket,
      payloadKey,
      sendAuthority: sendOnly(routeCapabilities),
      authorizedAt
    });
    const validated = await validateOpaqueRouteSealedBundleV2({ crypto, bundle });
    assert.deepEqual(validated, bundle);
    assert.equal(bundle.packets.length, 1);
    const packet = bundle.packets[0];
    assert.deepEqual(
      Object.keys(packet).sort(),
      ["authorization", "packetID", "routeID", "sealedFrame"].sort()
    );
    assert.equal(Buffer.from(packet.sealedFrame, "base64").byteLength, paddingBucket);
    assert.equal(packet.authorization.authority, "send");
    assert.equal(await verifyOpaqueRouteAuthorizationProofV2({
      crypto,
      proof: packet.authorization,
      expectedAuthority: "send",
      routeID: routeCapabilities.routeID,
      operationDigest: packet.authorization.operationDigest,
      secret: routeCapabilities.sendCapability
    }), true);
    const fragment = await openOpaqueRoutePacketV2({
      crypto,
      packet,
      payloadKey,
      routeRevision: 7
    });
    assert.deepEqual(fragment.payload, payload);
    assert.equal(fragment.fragmentIndex, 0);
    assert.equal(fragment.fragmentCount, 1);
    assert.equal(fragment.bundleDigest, bundle.bundleDigest);
  }
});

test("packet sealing accepts exactly route ID and send capability", async () => {
  const crypto = testCrypto();
  const capabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const sendAuthority = sendOnly(capabilities);
  assert.deepEqual(Object.keys(sendAuthority).sort(), ["routeID", "sendCapability"]);
  const bundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload: Uint8Array.of(1, 2, 3),
    routeRevision: 0,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority,
    authorizedAt
  });
  assert.equal(bundle.packets[0].routeID.rawValue, capabilities.routeID.rawValue);
  await assert.rejects(
    () => sealOpaqueRouteBundleV2({
      crypto,
      payload: Uint8Array.of(1),
      routeRevision: 0,
      paddingBucket: 4_096,
      payloadKey,
      sendAuthority: {
        ...sendAuthority,
        readCredential: capabilities.readCredential
      },
      authorizedAt
    }),
    /send authority/
  );
});

test("past- and future-skewed send proofs refresh without changing packet ciphertext", async () => {
  const crypto = testCrypto();
  const capabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const sendAuthority = sendOnly(capabilities);
  const bundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload: Uint8Array.of(4, 5, 6),
    routeRevision: 0,
    paddingBucket: 4_096,
    payloadKey: await createOpaqueRoutePayloadKeyV2(crypto),
    sendAuthority,
    authorizedAt
  });
  const original = bundle.packets[0];
  const earlierRetryAt = "2026-07-16T11:54:59Z";
  assert.equal(opaqueRoutePacketSendAuthorizationExpiredV2({
    packet: original,
    at: earlierRetryAt
  }), true);
  const futureSkewRefreshed = await refreshOpaqueRoutePacketSendAuthorizationV2({
    crypto,
    packet: original,
    sendAuthority,
    authorizedAt: earlierRetryAt
  });
  assert.deepEqual(futureSkewRefreshed.packetID, original.packetID);
  assert.equal(futureSkewRefreshed.sealedFrame, original.sealedFrame);
  assert.equal(futureSkewRefreshed.authorization.authorizedAt, earlierRetryAt);
  const retryAt = "2026-07-16T12:05:01Z";
  assert.equal(opaqueRoutePacketSendAuthorizationExpiredV2({
    packet: original,
    at: retryAt
  }), true);
  const refreshed = await refreshOpaqueRoutePacketSendAuthorizationV2({
    crypto,
    packet: original,
    sendAuthority,
    authorizedAt: retryAt
  });
  assert.deepEqual(refreshed.packetID, original.packetID);
  assert.equal(refreshed.sealedFrame, original.sealedFrame);
  assert.equal(
    refreshed.authorization.operationDigest,
    original.authorization.operationDigest
  );
  assert.notDeepEqual(refreshed.authorization, original.authorization);
  assert.equal(refreshed.authorization.authorizedAt, retryAt);
  assert.equal(await verifyOpaqueRouteAuthorizationProofV2({
    crypto,
    proof: refreshed.authorization,
    expectedAuthority: "send",
    routeID: refreshed.routeID,
    operationDigest: refreshed.authorization.operationDigest,
    secret: capabilities.sendCapability
  }), true);
  const stillFresh = await refreshOpaqueRoutePacketSendAuthorizationV2({
    crypto,
    packet: refreshed,
    sendAuthority,
    authorizedAt: retryAt
  });
  assert.deepEqual(stillFresh, refreshed);
});

test("fragmentation reassembles out of order and exact repeats remain duplicates", async () => {
  const crypto = testCrypto();
  const routeCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(4_096);
  const payload = patternedBytes(capacity * 2 + 17);
  const bundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload,
    routeRevision: 12,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt
  });
  assert.equal(bundle.packets.length, 3);
  const reassembler = createOpaqueRoutePacketReassemblerV2();
  assert.equal((await reassembler.consume({
    crypto,
    packet: bundle.packets[2],
    payloadKey,
    routeRevision: 12
  })).status, "accepted");
  assert.equal((await reassembler.consume({
    crypto,
    packet: bundle.packets[2],
    payloadKey,
    routeRevision: 12
  })).status, "duplicate");
  assert.equal((await reassembler.consume({
    crypto,
    packet: bundle.packets[0],
    payloadKey,
    routeRevision: 12
  })).status, "accepted");
  const complete = await reassembler.consume({
    crypto,
    packet: bundle.packets[1],
    payloadKey,
    routeRevision: 12
  });
  assert.equal(complete.status, "complete");
  assert.deepEqual(complete.bundle.payload, payload);
  assert.equal(reassembler.pendingBundleCount, 0);
  assert.equal(reassembler.bufferedPayloadBytes, 0);
  assert.equal((await reassembler.consume({
    crypto,
    packet: bundle.packets[0],
    payloadKey,
    routeRevision: 12
  })).status, "duplicate");
});

test("AAD and relay-projection tampering fail closed", async () => {
  const crypto = testCrypto();
  const routeCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const bundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload: patternedBytes(128),
    routeRevision: 19,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt
  });
  const packet = bundle.packets[0];
  await assert.rejects(
    () => openOpaqueRoutePacketV2({ crypto, packet, payloadKey, routeRevision: 20 }),
    packetError("decryptionFailed")
  );
  await assert.rejects(
    () => openOpaqueRoutePacketV2({
      crypto,
      packet,
      payloadKey: createFixedValue(0xee),
      routeRevision: 19
    }),
    packetError("decryptionFailed")
  );

  const changedSealed = Buffer.from(packet.sealedFrame, "base64");
  changedSealed[100] ^= 0x80;
  await assert.rejects(
    () => validateOpaqueRoutePacketV2({
      crypto,
      packet: { ...packet, sealedFrame: changedSealed.toString("base64") }
    }),
    packetError("invalidPacket")
  );

  const changedPacketID = await createOpaqueRoutePacketIdV2(crypto);
  const changedOperationDigest = await opaqueRoutePacketOperationDigestV2({
    crypto,
    routeID: packet.routeID,
    packetID: changedPacketID,
    sealedFrame: packet.sealedFrame
  });
  const rebound = {
    ...packet,
    packetID: changedPacketID,
    authorization: await makeOpaqueRouteUseAuthorizationV2({
      crypto,
      capabilities: routeCapabilities,
      authority: "send",
      operationDigest: changedOperationDigest,
      authorizedAt,
      nonce: await createOpaqueRouteProofNonceV2(crypto)
    })
  };
  await assert.rejects(
    () => openOpaqueRoutePacketV2({ crypto, packet: rebound, payloadKey, routeRevision: 19 }),
    packetError("decryptionFailed")
  );
});

test("reassembly rejects packet IDs, bundles, and capacity conflicts", async () => {
  const crypto = testCrypto();
  const routeCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(4_096);
  const bundleID = await createOpaqueRouteBundleIdV2(crypto);
  const first = await sealOpaqueRouteBundleV2({
    crypto,
    payload: patternedBytes(capacity + 1),
    routeRevision: 5,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt,
    bundleID
  });
  const conflictingBundle = await sealOpaqueRouteBundleV2({
    crypto,
    payload: patternedBytes(capacity + 2, 9),
    routeRevision: 5,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt,
    bundleID
  });
  const reassembler = new OpaqueRoutePacketReassemblerV2();
  assert.equal((await reassembler.consume({
    crypto,
    packet: first.packets[0],
    payloadKey,
    routeRevision: 5
  })).status, "accepted");
  await assert.rejects(
    () => reassembler.consume({
      crypto,
      packet: conflictingBundle.packets[0],
      payloadKey,
      routeRevision: 5
    }),
    packetError("bundleConflict")
  );

  const other = await sealOpaqueRouteBundleV2({
    crypto,
    payload: patternedBytes(capacity + 3, 21),
    routeRevision: 5,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt
  });
  const reusedID = first.packets[0].packetID;
  const conflictingOperationDigest = await opaqueRoutePacketOperationDigestV2({
    crypto,
    routeID: other.packets[0].routeID,
    packetID: reusedID,
    sealedFrame: other.packets[0].sealedFrame
  });
  const conflictingPacketID = {
    ...other.packets[0],
    packetID: reusedID,
    authorization: await makeOpaqueRouteUseAuthorizationV2({
      crypto,
      capabilities: routeCapabilities,
      authority: "send",
      operationDigest: conflictingOperationDigest,
      authorizedAt,
      nonce: await createOpaqueRouteProofNonceV2(crypto)
    })
  };
  await assert.rejects(
    () => reassembler.consume({
      crypto,
      packet: conflictingPacketID,
      payloadKey,
      routeRevision: 5
    }),
    packetError("packetIdentifierConflict")
  );

  const bounded = createOpaqueRoutePacketReassemblerV2({ maximumBufferedBundles: 1 });
  assert.equal((await bounded.consume({
    crypto,
    packet: first.packets[0],
    payloadKey,
    routeRevision: 5
  })).status, "accepted");
  await assert.rejects(
    () => bounded.consume({
      crypto,
      packet: other.packets[0],
      payloadKey,
      routeRevision: 5
    }),
    packetError("reassemblyCapacityExceeded")
  );
  assert.throws(
    () => createOpaqueRoutePacketReassemblerV2({ maximumBufferedBundles: 0 }),
    packetError("reassemblyCapacityExceeded")
  );
});

test("same fragment bytes are idempotent while aggregate buffered bytes stay bounded", async () => {
  const crypto = testCrypto();
  const routeCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  const payload = patternedBytes(4_000);
  const bundleID = await createOpaqueRouteBundleIdV2(crypto);
  const firstEncoding = await sealOpaqueRouteBundleV2({
    crypto,
    payload,
    routeRevision: 3,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt,
    bundleID
  });
  const secondEncoding = await sealOpaqueRouteBundleV2({
    crypto,
    payload,
    routeRevision: 3,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt,
    bundleID
  });
  const reassembler = createOpaqueRoutePacketReassemblerV2({
    maximumBufferedBundles: 2,
    maximumBufferedBytes: 5_000
  });
  assert.equal((await reassembler.consume({
    crypto,
    packet: firstEncoding.packets[0],
    payloadKey,
    routeRevision: 3
  })).status, "accepted");
  assert.equal((await reassembler.consume({
    crypto,
    packet: secondEncoding.packets[0],
    payloadKey,
    routeRevision: 3
  })).status, "duplicate");

  const other = await sealOpaqueRouteBundleV2({
    crypto,
    payload: patternedBytes(4_000, 77),
    routeRevision: 3,
    paddingBucket: 4_096,
    payloadKey,
    sendAuthority: sendOnly(routeCapabilities),
    authorizedAt
  });
  await assert.rejects(
    () => reassembler.consume({
      crypto,
      packet: other.packets[0],
      payloadKey,
      routeRevision: 3
    }),
    packetError("reassemblyCapacityExceeded")
  );
});

test("empty and over-fragmented payloads are rejected before sealing", async () => {
  const crypto = testCrypto();
  const routeCapabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
  const payloadKey = await createOpaqueRoutePayloadKeyV2(crypto);
  await assert.rejects(
    () => sealOpaqueRouteBundleV2({
      crypto,
      payload: new Uint8Array(),
      routeRevision: 1,
      paddingBucket: 4_096,
      payloadKey,
      sendAuthority: sendOnly(routeCapabilities),
      authorizedAt
    }),
    packetError("emptyPayload")
  );
  const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(4_096);
  await assert.rejects(
    () => sealOpaqueRouteBundleV2({
      crypto,
      payload: new Uint8Array(capacity * noctweaveOpaqueRoutePacketsV2.maximumFragmentCount + 1),
      routeRevision: 1,
      paddingBucket: 4_096,
      payloadKey,
      sendAuthority: sendOnly(routeCapabilities),
      authorizedAt
    }),
    packetError("fragmentCountExceeded")
  );
});

test("operation and bundle digests are domain separated", async () => {
  const crypto = testCrypto();
  const routeID = createFixedValue(0x11);
  const packetID = createFixedValue(0x22);
  const bundleID = createFixedValue(0x33);
  const sealedFrame = base64(new Uint8Array(4_096).fill(0x44));
  const operationDigest = await opaqueRoutePacketOperationDigestV2({
    crypto,
    routeID,
    packetID,
    sealedFrame
  });
  const bundleDigest = await opaqueRouteBundleDigestV2({
    crypto,
    bundleID,
    payload: Uint8Array.of(1, 2, 3)
  });
  assert.equal(Buffer.from(operationDigest, "base64").byteLength, 32);
  assert.equal(Buffer.from(bundleDigest, "base64").byteLength, 32);
  assert.notEqual(operationDigest, bundleDigest);
});

function testCrypto() {
  const webcrypto = new WebCryptoPrimitives();
  let sequence = 1;
  return {
    randomBytes(length) {
      const output = new Uint8Array(length);
      output.fill(sequence & 0xff);
      sequence += 1;
      return output;
    },
    sha256: (data) => webcrypto.sha256(data),
    hmacSha256: (input) => webcrypto.hmacSha256(input),
    aesGcmEncrypt: (input) => webcrypto.aesGcmEncrypt(input),
    aesGcmDecrypt: (input) => webcrypto.aesGcmDecrypt(input)
  };
}

function patternedBytes(length, offset = 0) {
  return Uint8Array.from({ length }, (_, index) => (index + offset) & 0xff);
}

function createFixedValue(octet) {
  return Object.freeze({ rawValue: base64(new Uint8Array(32).fill(octet)) });
}

function sendOnly(capabilities) {
  return Object.freeze({
    routeID: capabilities.routeID,
    sendCapability: capabilities.sendCapability
  });
}

function packetError(code) {
  return (error) => error instanceof OpaqueRoutePacketV2Error && error.code === code;
}
