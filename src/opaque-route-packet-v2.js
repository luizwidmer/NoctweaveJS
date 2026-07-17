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
const frameMagic = Uint8Array.of(0x4e, 0x57, 0x52, 0x50); // NWRP
const paddingBuckets = new Set([4_096, 16_384, 65_536]);
const frameHeaderBytes = 90;

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

export async function validateOpaqueRoutePacketV2({ crypto, packet: value }) {
  requireRecord(value, "Opaque route packet");
  const routeID = validateIdentifier(value.routeID, "Opaque route ID");
  const packetID = validateOpaqueRoutePacketIdV2(value.packetID);
  const sealedBytes = requireBase64(
    value.sealedFrame,
    undefined,
    "Opaque route sealed frame"
  );
  validatePaddingBucket(sealedBytes.byteLength);
  const authorization = validateOpaqueRouteAuthorizationProofV2(value.authorization);
  const operationDigest = await opaqueRoutePacketOperationDigestV2({
    crypto,
    routeID,
    packetID,
    sealedFrame: value.sealedFrame
  });
  if (authorization.authority !== "send" || authorization.operationDigest !== operationDigest) {
    throw new OpaqueRoutePacketV2Error(
      "invalidPacket",
      "Opaque route packet authorization is not bound to its relay projection."
    );
  }
  return freezeWire({
    routeID,
    packetID,
    sealedFrame: value.sealedFrame,
    authorization
  });
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
  requireRecord(value, "Opaque route sealed bundle");
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
  static defaultMaximumBufferedBytes = 64 * 1_024 * 1_024;
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
    this.packetDigests = new Map();
    this.completed = new Map();
    this.completedOrder = [];
    this.bufferedBytes = 0;
  }

  get pendingBundleCount() {
    return this.pending.size;
  }

  get bufferedPayloadBytes() {
    return this.bufferedBytes;
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
      this.removePending(bundleKey);
      throw new OpaqueRoutePacketV2Error("malformedFrame");
    }
    const digest = await opaqueRouteBundleDigestV2({
      crypto,
      bundleID: fragment.bundleID,
      payload: reassembled
    });
    if (digest !== state.bundleDigest) {
      this.removePending(bundleKey);
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
    for (const part of removed.fragments.values()) {
      this.bufferedBytes -= part.byteLength;
    }
    for (const packetID of removed.packetIDs) {
      this.packetDigests.delete(packetID);
    }
  }

  rememberCompleted(bundle) {
    const key = bundle.bundleID.rawValue;
    this.completed.set(key, {
      routeID: bundle.routeID.rawValue,
      routeRevision: bundle.routeRevision,
      bundleDigest: bundle.bundleDigest
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
  requireRecord(value, label);
  const rawValue = encodeBase64(requireNonzeroFixedBase64(
    value.rawValue,
    noctweaveOpaqueRoutePacketsV2.identifierBytes,
    label
  ));
  return freezeWire({ rawValue });
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
