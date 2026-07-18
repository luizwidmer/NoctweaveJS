import { bytes } from "./crypto/webcrypto.js";
import {
  concatBytes,
  cryptoRandomBytes,
  cryptoSha256,
  encodeBase64,
  equalBytes,
  freezeWire,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireNonzeroFixedBase64,
  requireRecord,
  uint16Bytes,
  uint32Bytes,
  uint64Bytes
} from "./private-v2.js";
import {
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteUseAuthorizationV2,
  validateOpaqueRouteAuthorizationProofV2,
  validateOpaqueRouteClientCapabilityMaterialV2
} from "./opaque-route-v2.js";

const encoder = new TextEncoder();
const inspectSymbol = Symbol.for("nodejs.util.inspect.custom");
const frameMagic = Uint8Array.of(0x4e, 0x57, 0x52, 0x50); // NWRP
const paddingBuckets = new Set([4_096, 16_384, 65_536]);
const frameHeaderBytes = 90;
const reassemblerStateFields = Object.freeze([
  "maximumBufferedBundles",
  "maximumBufferedBytes",
  "pendingBundles",
  "packetDigests",
  "completedBundles"
]);
const pendingBundleFields = Object.freeze([
  "bundleID",
  "routeID",
  "routeRevision",
  "paddingBucket",
  "bundleDigest",
  "fragmentCount",
  "totalPayloadBytes",
  "fragments",
  "packetIDs"
]);
const persistedFragmentFields = Object.freeze(["index", "payload"]);
const persistedPacketDigestFields = Object.freeze(["packetID", "digest"]);
const completedBundleFields = Object.freeze([
  "bundleID",
  "routeID",
  "routeRevision",
  "bundleDigest"
]);

export const noctweaveOpaqueRoutePacketsV2 = Object.freeze({
  version: 2,
  payloadKeyBytes: 32,
  identifierBytes: 32,
  digestBytes: 32,
  nonceBytes: 12,
  authenticationTagBytes: 16,
  minimumRandomPaddingBytes: 32,
  maximumFragmentCount: 4_096,
  maximumBundleBytes: 64 * 1_024 * 1_024,
  paddingBuckets: Object.freeze([...paddingBuckets])
});

export class OpaqueRoutePacketV2Error extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "OpaqueRoutePacketV2Error";
    this.code = code;
  }
}

export function opaqueRoutePacketMaximumFragmentPayloadBytesV2(paddingBucket) {
  const bucket = validatePaddingBucket(paddingBucket);
  return bucket
    - noctweaveOpaqueRoutePacketsV2.nonceBytes
    - noctweaveOpaqueRoutePacketsV2.authenticationTagBytes
    - frameHeaderBytes
    - noctweaveOpaqueRoutePacketsV2.minimumRandomPaddingBytes;
}

export async function createOpaqueRoutePayloadKeyV2(crypto) {
  return freezeWire({ rawValue: encodeBase64(await nonzeroRandom(crypto)) });
}

export async function createOpaqueRoutePacketIdV2(crypto) {
  return freezeWire({ rawValue: encodeBase64(await nonzeroRandom(crypto)) });
}

export async function createOpaqueRouteBundleIdV2(crypto) {
  return freezeWire({ rawValue: encodeBase64(await nonzeroRandom(crypto)) });
}

export function validateOpaqueRoutePayloadKeyV2(value) {
  return validateIdentifier(value, "Opaque route payload key");
}

export function validateOpaqueRoutePacketIdV2(value) {
  return validateIdentifier(value, "Opaque route packet identifier");
}

export function validateOpaqueRouteBundleIdV2(value) {
  return validateIdentifier(value, "Opaque route bundle identifier");
}

export async function opaqueRoutePacketOperationDigestV2({
  crypto,
  routeID,
  packetID,
  sealedFrame
}) {
  const route = validateIdentifier(routeID, "Opaque route ID");
  const packet = validateOpaqueRoutePacketIdV2(packetID);
  const sealed = requireBase64(sealedFrame, undefined, "Opaque route sealed frame");
  return encodeBase64(await packetDigest(
    crypto,
    "org.noctweave.opaque-route.packet-operation/v2",
    [
      requireBase64(route.rawValue, 32, "Opaque route ID"),
      requireBase64(packet.rawValue, 32, "Opaque route packet identifier"),
      sealed
    ]
  ));
}

export async function opaqueRouteBundleDigestV2({ crypto, bundleID, payload }) {
  const bundle = validateOpaqueRouteBundleIdV2(bundleID);
  const cleartext = bytes(payload, "Opaque route bundle payload");
  return encodeBase64(await packetDigest(
    crypto,
    "org.noctweave.opaque-route.bundle/v2",
    [
      requireBase64(bundle.rawValue, 32, "Opaque route bundle identifier"),
      uint64Bytes(cleartext.byteLength),
      cleartext
    ]
  ));
}

export function opaqueRoutePacketAuthenticatedDataV2({
  routeID,
  packetID,
  routeRevision,
  paddingBucket
}) {
  const route = validateIdentifier(routeID, "Opaque route ID");
  const packet = validateOpaqueRoutePacketIdV2(packetID);
  const revision = validateRouteRevision(routeRevision);
  const bucket = validatePaddingBucket(paddingBucket);
  return concatBytes(
    encoder.encode("org.noctweave.opaque-route.packet-aad/v2"),
    Uint8Array.of(0),
    requireBase64(route.rawValue, 32, "Opaque route ID"),
    requireBase64(packet.rawValue, 32, "Opaque route packet identifier"),
    uint64Bytes(revision),
    uint32Bytes(bucket)
  );
}

export function validateOpaqueRoutePacketShapeV2(value) {
  requireExactRecord(value, [
    "routeID",
    "packetID",
    "sealedFrame",
    "authorization"
  ], [], "Opaque route packet");
  const routeID = validateIdentifier(value.routeID, "Opaque route ID");
  const packetID = validateOpaqueRoutePacketIdV2(value.packetID);
  const sealedBytes = requireBase64(
    value.sealedFrame,
    undefined,
    "Opaque route sealed frame"
  );
  validatePaddingBucket(sealedBytes.byteLength);
  const authorization = validateOpaqueRouteAuthorizationProofV2(value.authorization);
  if (authorization.authority !== "send") {
    throw new OpaqueRoutePacketV2Error(
      "invalidPacket",
      "Opaque route packet requires send authorization."
    );
  }
  return freezeWire({
    routeID,
    packetID,
    sealedFrame: value.sealedFrame,
    authorization
  });
}

export async function validateOpaqueRoutePacketV2({ crypto, packet: value }) {
  const packet = validateOpaqueRoutePacketShapeV2(value);
  const operationDigest = await opaqueRoutePacketOperationDigestV2({
    crypto,
    routeID: packet.routeID,
    packetID: packet.packetID,
    sealedFrame: packet.sealedFrame
  });
  if (packet.authorization.operationDigest !== operationDigest) {
    throw new OpaqueRoutePacketV2Error(
      "invalidPacket",
      "Opaque route packet authorization is not bound to its relay projection."
    );
  }
  return packet;
}

export async function sealOpaqueRouteBundleV2({
  crypto,
  payload,
  routeRevision,
  paddingBucket,
  payloadKey: payloadKeyValue,
  routeCapabilities: routeCapabilitiesValue,
  authorizedAt = new Date(),
  bundleID: bundleIDValue = undefined
}) {
  const cleartext = bytes(payload, "Opaque route bundle payload");
  if (cleartext.byteLength === 0) {
    throw new OpaqueRoutePacketV2Error("emptyPayload");
  }
  if (cleartext.byteLength > noctweaveOpaqueRoutePacketsV2.maximumBundleBytes) {
    throw new OpaqueRoutePacketV2Error("payloadTooLarge");
  }
  const revision = validateRouteRevision(routeRevision);
  const bucket = validatePaddingBucket(paddingBucket);
  const payloadKey = validateOpaqueRoutePayloadKeyV2(payloadKeyValue);
  const routeCapabilities = validateOpaqueRouteClientCapabilityMaterialV2(
    routeCapabilitiesValue
  );
  const authorizationTime = requireCanonicalTimestamp(
    authorizedAt,
    "Opaque route authorization time"
  );
  const bundleID = bundleIDValue === undefined
    ? await createOpaqueRouteBundleIdV2(crypto)
    : validateOpaqueRouteBundleIdV2(bundleIDValue);
  const fragmentCapacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(bucket);
  const fragmentCount = Math.ceil(cleartext.byteLength / fragmentCapacity);
  if (fragmentCount > noctweaveOpaqueRoutePacketsV2.maximumFragmentCount) {
    throw new OpaqueRoutePacketV2Error("fragmentCountExceeded");
  }
  const bundleDigest = await opaqueRouteBundleDigestV2({
    crypto,
    bundleID,
    payload: cleartext
  });
  const packets = [];
  const packetIDs = new Set();

  for (let index = 0; index < fragmentCount; index += 1) {
    const lower = index * fragmentCapacity;
    const upper = Math.min(cleartext.byteLength, lower + fragmentCapacity);
    const fragment = cleartext.subarray(lower, upper);
    let packetID;
    do {
      packetID = await createOpaqueRoutePacketIdV2(crypto);
    } while (packetIDs.has(packetID.rawValue));
    packetIDs.add(packetID.rawValue);

    const frame = await encodeFrame({
      crypto,
      bundleID,
      bundleDigest,
      fragmentIndex: index,
      fragmentCount,
      totalPayloadBytes: cleartext.byteLength,
      fragment,
      paddingBucket: bucket
    });
    const nonce = await cryptoRandomBytes(crypto, noctweaveOpaqueRoutePacketsV2.nonceBytes);
    const additionalData = opaqueRoutePacketAuthenticatedDataV2({
      routeID: routeCapabilities.routeID,
      packetID,
      routeRevision: revision,
      paddingBucket: bucket
    });
    let ciphertextAndTag;
    try {
      if (typeof crypto?.aesGcmEncrypt !== "function") {
        throw new TypeError("An AES-256-GCM implementation is required.");
      }
      ciphertextAndTag = bytes(await crypto.aesGcmEncrypt({
        key: requireBase64(payloadKey.rawValue, 32, "Opaque route payload key"),
        nonce,
        plaintext: frame,
        additionalData
      }), "Opaque route AES-GCM output");
    } catch (error) {
      if (error instanceof TypeError) throw error;
      throw new OpaqueRoutePacketV2Error("invalidPacket");
    }
    if (ciphertextAndTag.byteLength !== frame.byteLength + 16) {
      throw new OpaqueRoutePacketV2Error("invalidPacket");
    }
    const sealedFrame = encodeBase64(concatBytes(nonce, ciphertextAndTag));
    const operationDigest = await opaqueRoutePacketOperationDigestV2({
      crypto,
      routeID: routeCapabilities.routeID,
      packetID,
      sealedFrame
    });
    const authorization = await makeOpaqueRouteUseAuthorizationV2({
      crypto,
      capabilities: routeCapabilities,
      authority: "send",
      operationDigest,
      authorizedAt: authorizationTime,
      nonce: await createOpaqueRouteProofNonceV2(crypto)
    });
    const packet = await validateOpaqueRoutePacketV2({
      crypto,
      packet: {
        routeID: routeCapabilities.routeID,
        packetID,
        sealedFrame,
        authorization
      }
    });
    packets.push(packet);
  }

  return freezeWire({
    bundleID,
    bundleDigest,
    routeRevision: revision,
    paddingBucket: bucket,
    packets
  });
}

export async function validateOpaqueRouteSealedBundleV2({ crypto, bundle: value }) {
  requireExactRecord(value, [
    "bundleID",
    "bundleDigest",
    "routeRevision",
    "paddingBucket",
    "packets"
  ], [], "Opaque route sealed bundle");
  const bundleID = validateOpaqueRouteBundleIdV2(value.bundleID);
  requireBase64(value.bundleDigest, 32, "Opaque route bundle digest");
  const routeRevision = validateRouteRevision(value.routeRevision);
  const paddingBucket = validatePaddingBucket(value.paddingBucket);
  if (!Array.isArray(value.packets) || value.packets.length === 0 ||
      value.packets.length > noctweaveOpaqueRoutePacketsV2.maximumFragmentCount) {
    throw new OpaqueRoutePacketV2Error("invalidBundle");
  }
  const packets = [];
  const packetIDs = new Set();
  let routeID;
  for (const candidate of value.packets) {
    const packet = await validateOpaqueRoutePacketV2({ crypto, packet: candidate });
    const bucket = requireBase64(
      packet.sealedFrame,
      undefined,
      "Opaque route sealed frame"
    ).byteLength;
    if (bucket !== paddingBucket ||
        (routeID !== undefined && routeID !== packet.routeID.rawValue) ||
        packetIDs.has(packet.packetID.rawValue)) {
      throw new OpaqueRoutePacketV2Error("invalidBundle");
    }
    routeID = packet.routeID.rawValue;
    packetIDs.add(packet.packetID.rawValue);
    packets.push(packet);
  }
  return freezeWire({
    bundleID,
    bundleDigest: value.bundleDigest,
    routeRevision,
    paddingBucket,
    packets
  });
}

export async function openOpaqueRoutePacketV2({
  crypto,
  packet: packetValue,
  payloadKey,
  routeRevision
}) {
  const packet = await validateOpaqueRoutePacketV2({ crypto, packet: packetValue });
  return openValidatedPacket({
    crypto,
    packet,
    payloadKey: validateOpaqueRoutePayloadKeyV2(payloadKey),
    routeRevision: validateRouteRevision(routeRevision)
  });
}

export class OpaqueRoutePacketReassemblerV2 {
  static defaultMaximumBufferedBundles = 64;
  static defaultMaximumBufferedBytes = 1 * 1_024 * 1_024;
  static maximumRecentCompletedBundles = 1_024;

  constructor({
    maximumBufferedBundles = OpaqueRoutePacketReassemblerV2.defaultMaximumBufferedBundles,
    maximumBufferedBytes = OpaqueRoutePacketReassemblerV2.defaultMaximumBufferedBytes
  } = {}) {
    if (!Number.isSafeInteger(maximumBufferedBundles) || maximumBufferedBundles <= 0 ||
        maximumBufferedBundles > 256 || !Number.isSafeInteger(maximumBufferedBytes) ||
        maximumBufferedBytes <= 0 ||
        maximumBufferedBytes > noctweaveOpaqueRoutePacketsV2.maximumBundleBytes) {
      throw new OpaqueRoutePacketV2Error("reassemblyCapacityExceeded");
    }
    this.maximumBufferedBundles = maximumBufferedBundles;
    this.maximumBufferedBytes = maximumBufferedBytes;
    this.pending = new Map();
    this.pendingOrder = [];
    this.packetDigests = new Map();
    this.completed = new Map();
    this.completedOrder = [];
    this.bufferedBytes = 0;
  }

  /**
   * Restores the exact bounded state emitted by snapshot(). Array order is
   * protocol state: pending bundles are oldest-first and completed bundles are
   * bounded replay tombstones in retirement order.
   */
  static restore(value, { routeID } = {}) {
    try {
      requireExactRecord(
        value,
        reassemblerStateFields,
        [],
        "Opaque route reassembler state"
      );
      const maximumBufferedBundles = requireInteger(
        value.maximumBufferedBundles,
        "Opaque route maximum buffered bundles",
        1,
        256
      );
      const maximumBufferedBytes = requireInteger(
        value.maximumBufferedBytes,
        "Opaque route maximum buffered bytes",
        1,
        noctweaveOpaqueRoutePacketsV2.maximumBundleBytes
      );
      if (!Array.isArray(value.pendingBundles) ||
          value.pendingBundles.length > maximumBufferedBundles ||
          !Array.isArray(value.packetDigests) ||
          value.packetDigests.length > Math.min(
            maximumBufferedBundles * noctweaveOpaqueRoutePacketsV2.maximumFragmentCount,
            maximumBufferedBytes + maximumBufferedBundles
          ) ||
          !Array.isArray(value.completedBundles) ||
          value.completedBundles.length > this.maximumRecentCompletedBundles) {
        throw new TypeError("Opaque route reassembler collections exceed protocol bounds.");
      }

      const expectedRouteID = routeID === undefined
        ? null
        : validateOpaqueRouteIdentifierForState(routeID, "Opaque route identifier").rawValue;
      const restored = new OpaqueRoutePacketReassemblerV2({
        maximumBufferedBundles,
        maximumBufferedBytes
      });
      const pendingPacketIDs = new Set();

      for (const candidate of value.pendingBundles) {
        requireExactRecord(candidate, pendingBundleFields, [], "Persisted pending bundle");
        const bundleID = validateOpaqueRouteBundleIdV2(candidate.bundleID);
        const route = validateOpaqueRouteIdentifierForState(
          candidate.routeID,
          "Persisted pending route identifier"
        );
        if (expectedRouteID !== null && route.rawValue !== expectedRouteID) {
          throw new TypeError("Persisted pending bundle belongs to another opaque route.");
        }
        const routeRevision = validateRouteRevision(candidate.routeRevision);
        const paddingBucket = validatePaddingBucket(candidate.paddingBucket);
        const bundleDigest = canonicalDigest(
          candidate.bundleDigest,
          "Persisted pending bundle digest"
        );
        const fragmentCount = requireInteger(
          candidate.fragmentCount,
          "Persisted opaque route fragment count",
          1,
          noctweaveOpaqueRoutePacketsV2.maximumFragmentCount
        );
        const totalPayloadBytes = requireInteger(
          candidate.totalPayloadBytes,
          "Persisted opaque route total payload bytes",
          1,
          maximumBufferedBytes
        );
        const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(paddingBucket);
        if (Math.ceil(totalPayloadBytes / capacity) !== fragmentCount ||
            !Array.isArray(candidate.fragments) || candidate.fragments.length === 0 ||
            candidate.fragments.length > fragmentCount ||
            !Array.isArray(candidate.packetIDs) ||
            candidate.packetIDs.length !== candidate.fragments.length) {
          throw new TypeError("Persisted pending bundle fragment metadata is inconsistent.");
        }

        const fragments = new Map();
        for (const persisted of candidate.fragments) {
          requireExactRecord(
            persisted,
            persistedFragmentFields,
            [],
            "Persisted opaque route fragment"
          );
          const index = requireInteger(
            persisted.index,
            "Persisted opaque route fragment index",
            0,
            fragmentCount - 1
          );
          const expectedBytes = index === fragmentCount - 1
            ? totalPayloadBytes - (fragmentCount - 1) * capacity
            : capacity;
          const payload = decodeBoundedPersistedPayload(
            persisted.payload,
            maximumBufferedBytes,
            expectedBytes
          );
          if (fragments.has(index)) {
            throw new TypeError("Persisted fragment indexes must be unique.");
          }
          fragments.set(index, payload);
          restored.bufferedBytes += payload.byteLength;
          if (restored.bufferedBytes > maximumBufferedBytes) {
            throw new TypeError("Persisted fragments exceed the reassembly byte budget.");
          }
        }

        const packetIDs = new Set();
        for (const packetIDValue of candidate.packetIDs) {
          const packetID = validateOpaqueRoutePacketIdV2(packetIDValue).rawValue;
          if (packetIDs.has(packetID) || pendingPacketIDs.has(packetID)) {
            throw new TypeError("Persisted packet identifiers must be unique.");
          }
          packetIDs.add(packetID);
          pendingPacketIDs.add(packetID);
        }
        if (restored.pending.has(bundleID.rawValue)) {
          throw new TypeError("Persisted pending bundle identifiers must be unique.");
        }
        restored.pending.set(bundleID.rawValue, {
          routeID: route.rawValue,
          routeRevision,
          paddingBucket,
          bundleDigest,
          fragmentCount,
          totalPayloadBytes,
          fragments,
          packetIDs
        });
        restored.pendingOrder.push(bundleID.rawValue);
      }

      for (const candidate of value.packetDigests) {
        requireExactRecord(
          candidate,
          persistedPacketDigestFields,
          [],
          "Persisted opaque route packet digest"
        );
        const packetID = validateOpaqueRoutePacketIdV2(candidate.packetID).rawValue;
        const digest = canonicalDigest(candidate.digest, "Persisted packet digest");
        if (restored.packetDigests.has(packetID)) {
          throw new TypeError("Persisted packet digest identifiers must be unique.");
        }
        restored.packetDigests.set(packetID, digest);
      }
      if (!sameStringSet(new Set(restored.packetDigests.keys()), pendingPacketIDs)) {
        throw new TypeError("Persisted packet digests must match pending fragments exactly.");
      }

      for (const candidate of value.completedBundles) {
        requireExactRecord(
          candidate,
          completedBundleFields,
          [],
          "Persisted completed opaque route bundle"
        );
        const bundleID = validateOpaqueRouteBundleIdV2(candidate.bundleID);
        const route = validateOpaqueRouteIdentifierForState(
          candidate.routeID,
          "Persisted completed route identifier"
        );
        if (expectedRouteID !== null && route.rawValue !== expectedRouteID) {
          throw new TypeError("Persisted completed bundle belongs to another opaque route.");
        }
        if (restored.pending.has(bundleID.rawValue) || restored.completed.has(bundleID.rawValue)) {
          throw new TypeError("Persisted terminal bundle identifiers must be unique.");
        }
        restored.completed.set(bundleID.rawValue, {
          routeID: route.rawValue,
          routeRevision: validateRouteRevision(candidate.routeRevision),
          bundleDigest: canonicalDigest(
            candidate.bundleDigest,
            "Persisted completed bundle digest"
          )
        });
        restored.completedOrder.push(bundleID.rawValue);
      }
      return restored;
    } catch (error) {
      if (error instanceof OpaqueRoutePacketV2Error &&
          error.code === "reassemblyCapacityExceeded") throw error;
      throw new OpaqueRoutePacketV2Error(
        "invalidReassemblyState",
        "Persisted opaque route reassembly state is invalid.",
        error
      );
    }
  }

  get pendingBundleCount() {
    return this.pending.size;
  }

  get bufferedPayloadBytes() {
    return this.bufferedBytes;
  }

  snapshot() {
    const pendingBundles = this.pendingOrder.map((bundleKey) => {
      const state = this.pending.get(bundleKey);
      if (state === undefined) {
        throw new OpaqueRoutePacketV2Error("invalidReassemblyState");
      }
      return {
        bundleID: { rawValue: bundleKey },
        routeID: { rawValue: state.routeID },
        routeRevision: state.routeRevision,
        paddingBucket: state.paddingBucket,
        bundleDigest: state.bundleDigest,
        fragmentCount: state.fragmentCount,
        totalPayloadBytes: state.totalPayloadBytes,
        fragments: [...state.fragments.entries()]
          .sort(([left], [right]) => left - right)
          .map(([index, payload]) => ({ index, payload: encodeBase64(payload) })),
        packetIDs: [...state.packetIDs]
          .sort(compareEncodedIdentifiers)
          .map((rawValue) => ({ rawValue }))
      };
    });
    const packetDigests = [...this.packetDigests.entries()]
      .sort(([left], [right]) => compareEncodedIdentifiers(left, right))
      .map(([rawValue, digest]) => ({ packetID: { rawValue }, digest }));
    const completedBundles = this.completedOrder.map((bundleKey) => {
      const state = this.completed.get(bundleKey);
      if (state === undefined) {
        throw new OpaqueRoutePacketV2Error("invalidReassemblyState");
      }
      return {
        bundleID: { rawValue: bundleKey },
        routeID: { rawValue: state.routeID },
        routeRevision: state.routeRevision,
        bundleDigest: state.bundleDigest
      };
    });
    const snapshot = freezeWire({
      maximumBufferedBundles: this.maximumBufferedBundles,
      maximumBufferedBytes: this.maximumBufferedBytes,
      pendingBundles,
      packetDigests,
      completedBundles
    });
    // Refuse to serialize an object whose mutable internals were corrupted.
    OpaqueRoutePacketReassemblerV2.restore(snapshot);
    return snapshot;
  }

  toJSON() {
    return this.snapshot();
  }

  toString() {
    return "OpaqueRoutePacketReassemblerV2(<redacted>)";
  }

  [inspectSymbol]() {
    return this.toString();
  }

  async consume({ crypto, packet: packetValue, payloadKey, routeRevision }) {
    const packet = await validateOpaqueRoutePacketV2({ crypto, packet: packetValue });
    const packetKey = packet.packetID.rawValue;
    const packetDigestValue = packet.authorization.operationDigest;
    const priorPacketDigest = this.packetDigests.get(packetKey);
    if (priorPacketDigest !== undefined) {
      if (priorPacketDigest !== packetDigestValue) {
        throw new OpaqueRoutePacketV2Error("packetIdentifierConflict");
      }
      return freezeWire({ status: "duplicate" });
    }

    const fragment = await openValidatedPacket({
      crypto,
      packet,
      payloadKey: validateOpaqueRoutePayloadKeyV2(payloadKey),
      routeRevision: validateRouteRevision(routeRevision)
    });
    const bundleKey = fragment.bundleID.rawValue;
    const completed = this.completed.get(bundleKey);
    if (completed !== undefined) {
      if (completed.routeID !== fragment.routeID.rawValue ||
          completed.routeRevision !== fragment.routeRevision ||
          completed.bundleDigest !== fragment.bundleDigest) {
        throw new OpaqueRoutePacketV2Error("bundleConflict");
      }
      return freezeWire({ status: "duplicate" });
    }

    let state = this.pending.get(bundleKey);
    if (state !== undefined) {
      if (state.routeID !== fragment.routeID.rawValue ||
          state.routeRevision !== fragment.routeRevision ||
          state.paddingBucket !== fragment.paddingBucket ||
          state.bundleDigest !== fragment.bundleDigest ||
          state.fragmentCount !== fragment.fragmentCount ||
          state.totalPayloadBytes !== fragment.totalPayloadBytes) {
        throw new OpaqueRoutePacketV2Error("bundleConflict");
      }
      const existing = state.fragments.get(fragment.fragmentIndex);
      if (existing !== undefined) {
        if (!equalBytes(existing, fragment.payload)) {
          throw new OpaqueRoutePacketV2Error("fragmentConflict");
        }
        return freezeWire({ status: "duplicate" });
      }
      if (fragment.payload.byteLength > this.maximumBufferedBytes - this.bufferedBytes) {
        throw new OpaqueRoutePacketV2Error("reassemblyCapacityExceeded");
      }
      state.fragments.set(fragment.fragmentIndex, fragment.payload);
      state.packetIDs.add(packetKey);
    } else {
      if (this.pending.size >= this.maximumBufferedBundles ||
          fragment.totalPayloadBytes > this.maximumBufferedBytes ||
          fragment.payload.byteLength > this.maximumBufferedBytes - this.bufferedBytes) {
        throw new OpaqueRoutePacketV2Error("reassemblyCapacityExceeded");
      }
      state = {
        routeID: fragment.routeID.rawValue,
        routeRevision: fragment.routeRevision,
        paddingBucket: fragment.paddingBucket,
        bundleDigest: fragment.bundleDigest,
        fragmentCount: fragment.fragmentCount,
        totalPayloadBytes: fragment.totalPayloadBytes,
        fragments: new Map([[fragment.fragmentIndex, fragment.payload]]),
        packetIDs: new Set([packetKey])
      };
      this.pending.set(bundleKey, state);
      this.pendingOrder.push(bundleKey);
    }
    this.packetDigests.set(packetKey, packetDigestValue);
    this.bufferedBytes += fragment.payload.byteLength;

    if (state.fragments.size !== state.fragmentCount) {
      return freezeWire({ status: "accepted" });
    }
    const parts = [];
    for (let index = 0; index < state.fragmentCount; index += 1) {
      const part = state.fragments.get(index);
      if (part === undefined) {
        throw new OpaqueRoutePacketV2Error("malformedFrame");
      }
      parts.push(part);
    }
    const reassembled = concatBytes(...parts);
    if (reassembled.byteLength !== state.totalPayloadBytes) {
      this.discardPendingBundle({ rawValue: bundleKey });
      throw new OpaqueRoutePacketV2Error("malformedFrame");
    }
    const digest = await opaqueRouteBundleDigestV2({
      crypto,
      bundleID: fragment.bundleID,
      payload: reassembled
    });
    if (digest !== state.bundleDigest) {
      this.discardPendingBundle({ rawValue: bundleKey });
      throw new OpaqueRoutePacketV2Error("bundleDigestMismatch");
    }
    const bundle = freezeWire({
      routeID: fragment.routeID,
      routeRevision: state.routeRevision,
      bundleID: fragment.bundleID,
      bundleDigest: state.bundleDigest,
      payload: reassembled
    });
    this.removePending(bundleKey);
    this.rememberCompleted(bundle);
    return freezeWire({ status: "complete", bundle });
  }

  removePending(bundleKey) {
    const removed = this.pending.get(bundleKey);
    if (removed === undefined) return;
    this.pending.delete(bundleKey);
    const orderIndex = this.pendingOrder.indexOf(bundleKey);
    if (orderIndex >= 0) this.pendingOrder.splice(orderIndex, 1);
    for (const part of removed.fragments.values()) {
      this.bufferedBytes -= part.byteLength;
    }
    for (const packetID of removed.packetIDs) {
      this.packetDigests.delete(packetID);
    }
  }

  /** Drops unreachable partial plaintext while retaining replay tombstones. */
  discardPendingBundles() {
    this.pending.clear();
    this.pendingOrder.length = 0;
    this.packetDigests.clear();
    this.bufferedBytes = 0;
  }

  /** Deterministically evicts and retires the oldest incomplete bundle. */
  discardOldestPendingBundle() {
    const oldest = this.pendingOrder[0];
    if (oldest === undefined || !this.discardPendingBundle({ rawValue: oldest })) return null;
    return freezeWire({ rawValue: oldest });
  }

  /** Retires one incomplete bundle so later matching fragments are duplicates. */
  discardPendingBundle(bundleIDValue) {
    const bundleID = validateOpaqueRouteBundleIdV2(bundleIDValue);
    const state = this.pending.get(bundleID.rawValue);
    if (state === undefined) return false;
    this.removePending(bundleID.rawValue);
    this.rememberTerminalBundle(bundleID.rawValue, state);
    return true;
  }

  rememberCompleted(bundle) {
    this.rememberTerminalBundle(bundle.bundleID.rawValue, {
      routeID: bundle.routeID.rawValue,
      routeRevision: bundle.routeRevision,
      bundleDigest: bundle.bundleDigest
    });
  }

  rememberTerminalBundle(key, state) {
    this.completed.set(key, {
      routeID: state.routeID,
      routeRevision: state.routeRevision,
      bundleDigest: state.bundleDigest
    });
    this.completedOrder.push(key);
    if (this.completedOrder.length > OpaqueRoutePacketReassemblerV2.maximumRecentCompletedBundles) {
      this.completed.delete(this.completedOrder.shift());
    }
  }
}

export function createOpaqueRoutePacketReassemblerV2(options = {}) {
  return new OpaqueRoutePacketReassemblerV2(options);
}

export function restoreOpaqueRoutePacketReassemblerV2(value, options = {}) {
  return OpaqueRoutePacketReassemblerV2.restore(value, options);
}

export function validateOpaqueRoutePacketReassemblerStateV2(value, options = {}) {
  return restoreOpaqueRoutePacketReassemblerV2(value, options).snapshot();
}

async function openValidatedPacket({ crypto, packet, payloadKey, routeRevision }) {
  const sealed = requireBase64(packet.sealedFrame, undefined, "Opaque route sealed frame");
  const bucket = validatePaddingBucket(sealed.byteLength);
  const nonce = sealed.subarray(0, noctweaveOpaqueRoutePacketsV2.nonceBytes);
  const ciphertextAndTag = sealed.subarray(noctweaveOpaqueRoutePacketsV2.nonceBytes);
  let plaintext;
  try {
    if (typeof crypto?.aesGcmDecrypt !== "function") {
      throw new TypeError("An AES-256-GCM implementation is required.");
    }
    plaintext = bytes(await crypto.aesGcmDecrypt({
      key: requireBase64(payloadKey.rawValue, 32, "Opaque route payload key"),
      nonce,
      ciphertext: ciphertextAndTag,
      additionalData: opaqueRoutePacketAuthenticatedDataV2({
        routeID: packet.routeID,
        packetID: packet.packetID,
        routeRevision,
        paddingBucket: bucket
      })
    }), "Opaque route decrypted frame");
  } catch (error) {
    if (error instanceof TypeError && typeof crypto?.aesGcmDecrypt !== "function") throw error;
    throw new OpaqueRoutePacketV2Error("decryptionFailed");
  }
  return decodeFragment({
    frame: plaintext,
    routeID: packet.routeID,
    packetID: packet.packetID,
    routeRevision,
    paddingBucket: bucket
  });
}

async function encodeFrame({
  crypto,
  bundleID,
  bundleDigest,
  fragmentIndex,
  fragmentCount,
  totalPayloadBytes,
  fragment,
  paddingBucket
}) {
  const bucket = validatePaddingBucket(paddingBucket);
  const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(bucket);
  if (!Number.isSafeInteger(fragmentCount) || fragmentCount <= 0 ||
      fragmentCount > noctweaveOpaqueRoutePacketsV2.maximumFragmentCount ||
      !Number.isSafeInteger(fragmentIndex) || fragmentIndex < 0 ||
      fragmentIndex >= fragmentCount || !Number.isSafeInteger(totalPayloadBytes) ||
      totalPayloadBytes <= 0 ||
      totalPayloadBytes > noctweaveOpaqueRoutePacketsV2.maximumBundleBytes ||
      fragment.byteLength > capacity) {
    throw new OpaqueRoutePacketV2Error("invalidBundle");
  }
  const frameBytes = bucket
    - noctweaveOpaqueRoutePacketsV2.nonceBytes
    - noctweaveOpaqueRoutePacketsV2.authenticationTagBytes;
  const header = concatBytes(
    frameMagic,
    uint16Bytes(noctweaveOpaqueRoutePacketsV2.version),
    requireBase64(bundleID.rawValue, 32, "Opaque route bundle identifier"),
    requireBase64(bundleDigest, 32, "Opaque route bundle digest"),
    uint32Bytes(fragmentIndex),
    uint32Bytes(fragmentCount),
    uint64Bytes(totalPayloadBytes),
    uint32Bytes(fragment.byteLength),
    fragment
  );
  const paddingCount = frameBytes - header.byteLength;
  if (paddingCount < noctweaveOpaqueRoutePacketsV2.minimumRandomPaddingBytes) {
    throw new OpaqueRoutePacketV2Error("invalidBundle");
  }
  const frame = concatBytes(header, await cryptoRandomBytes(crypto, paddingCount));
  if (frame.byteLength !== frameBytes) {
    throw new OpaqueRoutePacketV2Error("invalidBundle");
  }
  return frame;
}

function decodeFragment({ frame, routeID, packetID, routeRevision, paddingBucket }) {
  const bucket = validatePaddingBucket(paddingBucket);
  const expectedFrameBytes = bucket
    - noctweaveOpaqueRoutePacketsV2.nonceBytes
    - noctweaveOpaqueRoutePacketsV2.authenticationTagBytes;
  if (frame.byteLength !== expectedFrameBytes || !equalBytes(frame.subarray(0, 4), frameMagic)) {
    throw new OpaqueRoutePacketV2Error("malformedFrame");
  }
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  let offset = 4;
  const version = view.getUint16(offset, false);
  offset += 2;
  if (version !== noctweaveOpaqueRoutePacketsV2.version) {
    throw new OpaqueRoutePacketV2Error("malformedFrame");
  }
  const bundleID = freezeWire({ rawValue: encodeBase64(frame.subarray(offset, offset + 32)) });
  offset += 32;
  const bundleDigest = encodeBase64(frame.subarray(offset, offset + 32));
  offset += 32;
  const fragmentIndex = view.getUint32(offset, false);
  offset += 4;
  const fragmentCount = view.getUint32(offset, false);
  offset += 4;
  const totalPayloadBig = view.getBigUint64(offset, false);
  offset += 8;
  if (totalPayloadBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new OpaqueRoutePacketV2Error("malformedFrame");
  }
  const totalPayloadBytes = Number(totalPayloadBig);
  const fragmentBytes = view.getUint32(offset, false);
  offset += 4;
  if (fragmentBytes > frame.byteLength - offset ||
      frame.byteLength - offset - fragmentBytes <
        noctweaveOpaqueRoutePacketsV2.minimumRandomPaddingBytes) {
    throw new OpaqueRoutePacketV2Error("malformedFrame");
  }
  try {
    validateOpaqueRouteBundleIdV2(bundleID);
  } catch {
    throw new OpaqueRoutePacketV2Error("malformedFrame");
  }
  const payload = new Uint8Array(frame.subarray(offset, offset + fragmentBytes));
  const fragment = {
    routeID,
    packetID,
    routeRevision,
    paddingBucket: bucket,
    bundleID,
    bundleDigest,
    fragmentIndex,
    fragmentCount,
    totalPayloadBytes,
    payload
  };
  validateFragment(fragment);
  return freezeWire(fragment);
}

function validateFragment(fragment) {
  requireBase64(fragment.bundleDigest, 32, "Opaque route bundle digest");
  if (!Number.isSafeInteger(fragment.fragmentCount) || fragment.fragmentCount <= 0 ||
      fragment.fragmentCount > noctweaveOpaqueRoutePacketsV2.maximumFragmentCount ||
      !Number.isSafeInteger(fragment.fragmentIndex) || fragment.fragmentIndex < 0 ||
      fragment.fragmentIndex >= fragment.fragmentCount ||
      !Number.isSafeInteger(fragment.totalPayloadBytes) || fragment.totalPayloadBytes <= 0 ||
      fragment.totalPayloadBytes > noctweaveOpaqueRoutePacketsV2.maximumBundleBytes) {
    throw new OpaqueRoutePacketV2Error("malformedFrame");
  }
  const capacity = opaqueRoutePacketMaximumFragmentPayloadBytesV2(fragment.paddingBucket);
  const expectedCount = Math.ceil(fragment.totalPayloadBytes / capacity);
  const expectedBytes = fragment.fragmentIndex === expectedCount - 1
    ? fragment.totalPayloadBytes - (expectedCount - 1) * capacity
    : capacity;
  if (fragment.fragmentCount !== expectedCount || fragment.payload.byteLength !== expectedBytes) {
    throw new OpaqueRoutePacketV2Error("malformedFrame");
  }
}

async function packetDigest(crypto, domain, components) {
  return cryptoSha256(crypto, concatBytes(
    encoder.encode(domain),
    Uint8Array.of(0),
    ...components.flatMap((component) => [uint64Bytes(component.byteLength), component])
  ));
}

function validateIdentifier(value, label) {
  requireExactRecord(value, ["rawValue"], [], label);
  const rawValue = encodeBase64(requireNonzeroFixedBase64(
    value.rawValue,
    noctweaveOpaqueRoutePacketsV2.identifierBytes,
    label
  ));
  return freezeWire({ rawValue });
}

function validateOpaqueRouteIdentifierForState(value, label) {
  return validateIdentifier(value, label);
}

function canonicalDigest(value, label) {
  return encodeBase64(requireBase64(
    value,
    noctweaveOpaqueRoutePacketsV2.digestBytes,
    label
  ));
}

function decodeBoundedPersistedPayload(value, maximumBytes, expectedBytes) {
  const maximumEncodedLength = Math.ceil(maximumBytes / 3) * 4 + 4;
  if (typeof value !== "string" || value.length === 0 || value.length > maximumEncodedLength) {
    throw new TypeError("Persisted opaque route fragment exceeds the reassembly byte budget.");
  }
  return new Uint8Array(requireBase64(
    value,
    expectedBytes,
    "Persisted opaque route fragment payload"
  ));
}

function sameStringSet(left, right) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function compareEncodedIdentifiers(leftValue, rightValue) {
  const left = requireBase64(
    leftValue,
    noctweaveOpaqueRoutePacketsV2.identifierBytes,
    "Opaque route identifier"
  );
  const right = requireBase64(
    rightValue,
    noctweaveOpaqueRoutePacketsV2.identifierBytes,
    "Opaque route identifier"
  );
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function validatePaddingBucket(value) {
  if (!paddingBuckets.has(value)) {
    throw new OpaqueRoutePacketV2Error("invalidPacket", "Invalid opaque route padding bucket.");
  }
  return value;
}

function validateRouteRevision(value) {
  return requireInteger(
    value,
    "Opaque route revision",
    0,
    Number.MAX_SAFE_INTEGER
  );
}

async function nonzeroRandom(crypto) {
  while (true) {
    const candidate = await cryptoRandomBytes(
      crypto,
      noctweaveOpaqueRoutePacketsV2.identifierBytes
    );
    if (candidate.some((octet) => octet !== 0)) return candidate;
  }
}
