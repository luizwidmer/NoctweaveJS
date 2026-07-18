import {
  rendezvousOfferDigestV2,
  validateRendezvousFrameV2,
  validateRendezvousOfferV2,
  validateRendezvousOpenV2
} from "./rendezvous-v2.js";
import { base64, canonicalJsonBytes } from "./crypto/swift-canonical.js";
import { bytes } from "./crypto/webcrypto.js";
import { parseExactJSON } from "./strict-json.js";
import {
  concatBytes,
  cryptoHmacSha256,
  cryptoRandomBytes,
  encodeBase64,
  equalBytes,
  freezeWire,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireNonzeroFixedBase64,
  timestampMilliseconds,
  uint32Bytes,
  uint64Bytes
} from "./private-v2.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const inspectSymbol = Symbol.for("nodejs.util.inspect.custom");
const constructionToken = Symbol("RendezvousRelayAdapterV2");
const directions = new Set(["offererToResponder", "responderToOfferer"]);
const roles = new Set(["offerer", "responder"]);
const magic = Uint8Array.of(0x4e, 0x57, 0x52, 0x32);
const framingBytes = 9;
const transportOverhead = 28;

export const rendezvousRelayTransportV2 = Object.freeze({
  version: 2,
  capabilityBytes: 32,
  laneIDBytes: 32,
  frameIDBytes: 16,
  laneCount: 2,
  maximumLifetimeSeconds: 10 * 60,
  maximumFramesPerLane: 32,
  maximumCiphertextBytesPerLane: 2_097_152,
  maximumSyncFrames: 32,
  allowedCiphertextByteCounts: Object.freeze([4_096, 16_384, 65_536, 131_072])
});

export const rendezvousRelayDirectionsV2 = Object.freeze({
  offererToResponder: "offererToResponder",
  responderToOfferer: "responderToOfferer"
});

export class RendezvousRelayAdapterV2Error extends Error {
  constructor(code, message = code, options) {
    super(message, options);
    this.name = "RendezvousRelayAdapterV2Error";
    this.code = code;
  }
}

export function rendezvousRelayOutboundDirectionV2(role) {
  requireRole(role);
  return role === "offerer" ? "offererToResponder" : "responderToOfferer";
}

export function rendezvousRelayInboundDirectionV2(role) {
  requireRole(role);
  return role === "offerer" ? "responderToOfferer" : "offererToResponder";
}

export function validateRendezvousRelayLaneRegistrationV2(value) {
  requireExactRecord(value, [
    "laneId",
    "publishCapability",
    "readCapability",
    "deleteCapability"
  ], [], "Rendezvous relay lane registration");
  return freezeWire({
    laneId: validateOpaqueValue(value.laneId, 32, "Rendezvous relay lane ID"),
    publishCapability: validateOpaqueValue(
      value.publishCapability,
      32,
      "Rendezvous relay publish capability"
    ),
    readCapability: validateOpaqueValue(
      value.readCapability,
      32,
      "Rendezvous relay read capability"
    ),
    deleteCapability: validateOpaqueValue(
      value.deleteCapability,
      32,
      "Rendezvous relay delete capability"
    )
  });
}

export function validateRegisterRendezvousTransportV2Request(value, { at } = {}) {
  requireExactRecord(value, [
    "version",
    "routeCapability",
    "expiresAt",
    "lanes"
  ], [], "Rendezvous relay registration request");
  if (value.version !== rendezvousRelayTransportV2.version ||
      !Array.isArray(value.lanes) || value.lanes.length !== rendezvousRelayTransportV2.laneCount) {
    throw new TypeError("Rendezvous relay registration request is invalid.");
  }
  const routeCapability = validateOpaqueValue(
    value.routeCapability,
    32,
    "Rendezvous relay route capability"
  );
  const expiresAt = requireCanonicalTimestamp(value.expiresAt, "Rendezvous relay expiry");
  const lanes = value.lanes.map(validateRendezvousRelayLaneRegistrationV2);
  if (new Set(lanes.map(({ laneId }) => laneId.rawValue)).size !== lanes.length) {
    throw new TypeError("Rendezvous relay lane IDs must be distinct.");
  }
  const authorities = [routeCapability.rawValue, ...lanes.flatMap((lane) => [
    lane.publishCapability.rawValue,
    lane.readCapability.rawValue,
    lane.deleteCapability.rawValue
  ])];
  if (new Set(authorities).size !== authorities.length) {
    throw new TypeError("Rendezvous relay bearer capabilities must be independent.");
  }
  if (at !== undefined) {
    const now = instantMilliseconds(at, "Rendezvous relay registration time");
    const expiry = timestampMilliseconds(expiresAt);
    if (expiry <= now || expiry > Math.floor(now / 1_000) * 1_000 +
        rendezvousRelayTransportV2.maximumLifetimeSeconds * 1_000) {
      throw new TypeError("Rendezvous relay expiry is outside its lifetime bound.");
    }
  }
  return freezeWire({ version: 2, routeCapability, expiresAt, lanes });
}

export function validateRendezvousRelayCiphertextFrameV2(value) {
  requireExactRecord(value, ["frameId", "sequence", "ciphertext"], [],
    "Rendezvous relay ciphertext frame");
  const frameId = validateOpaqueValue(value.frameId, 16, "Rendezvous relay frame ID");
  const sequence = requireInteger(
    value.sequence,
    "Rendezvous relay frame sequence",
    1,
    rendezvousRelayTransportV2.maximumFramesPerLane
  );
  const ciphertext = requireBase64(value.ciphertext, undefined, "Rendezvous relay ciphertext");
  if (!rendezvousRelayTransportV2.allowedCiphertextByteCounts.includes(ciphertext.byteLength)) {
    throw new TypeError("Rendezvous relay ciphertext does not use a fixed transport bucket.");
  }
  return freezeWire({ frameId, sequence, ciphertext: value.ciphertext });
}

export function validateAppendRendezvousTransportV2Request(value) {
  requireExactRecord(value, [
    "routeCapability",
    "laneId",
    "publishCapability",
    "frame"
  ], [], "Rendezvous relay append request");
  return freezeWire({
    routeCapability: validateOpaqueValue(value.routeCapability, 32, "Rendezvous relay route capability"),
    laneId: validateOpaqueValue(value.laneId, 32, "Rendezvous relay lane ID"),
    publishCapability: validateOpaqueValue(
      value.publishCapability,
      32,
      "Rendezvous relay publish capability"
    ),
    frame: validateRendezvousRelayCiphertextFrameV2(value.frame)
  });
}

export function validateSyncRendezvousTransportV2Request(value) {
  requireExactRecord(value, [
    "routeCapability",
    "laneId",
    "readCapability",
    "afterSequence",
    "maxCount"
  ], [], "Rendezvous relay sync request");
  if (value.maxCount !== null) {
    requireInteger(
      value.maxCount,
      "Rendezvous relay sync count",
      1,
      rendezvousRelayTransportV2.maximumSyncFrames
    );
  }
  return freezeWire({
    routeCapability: validateOpaqueValue(value.routeCapability, 32, "Rendezvous relay route capability"),
    laneId: validateOpaqueValue(value.laneId, 32, "Rendezvous relay lane ID"),
    readCapability: validateOpaqueValue(value.readCapability, 32, "Rendezvous relay read capability"),
    afterSequence: requireInteger(
      value.afterSequence,
      "Rendezvous relay sync sequence",
      0,
      rendezvousRelayTransportV2.maximumFramesPerLane
    ),
    maxCount: value.maxCount
  });
}

export function validateDeleteRendezvousTransportV2Request(value) {
  requireExactRecord(value, [
    "routeCapability",
    "laneId",
    "deleteCapability"
  ], [], "Rendezvous relay delete request");
  return freezeWire({
    routeCapability: validateOpaqueValue(value.routeCapability, 32, "Rendezvous relay route capability"),
    laneId: validateOpaqueValue(value.laneId, 32, "Rendezvous relay lane ID"),
    deleteCapability: validateOpaqueValue(
      value.deleteCapability,
      32,
      "Rendezvous relay delete capability"
    )
  });
}

export function validateRendezvousRelaySyncBatchV2(value, { request } = {}) {
  requireExactRecord(value, [
    "frames",
    "highWatermark",
    "nextSequence",
    "hasMore"
  ], [], "Rendezvous relay sync batch");
  if (!Array.isArray(value.frames) ||
      value.frames.length > rendezvousRelayTransportV2.maximumSyncFrames ||
      typeof value.hasMore !== "boolean") {
    throw new TypeError("Rendezvous relay sync batch is invalid.");
  }
  const frames = value.frames.map(validateRendezvousRelayCiphertextFrameV2);
  if (new Set(frames.map(({ frameId }) => frameId.rawValue)).size !== frames.length ||
      frames.reduce((total, frame) =>
        total + requireBase64(frame.ciphertext, undefined, "Rendezvous relay ciphertext").byteLength,
      0) > rendezvousRelayTransportV2.maximumCiphertextBytesPerLane) {
    throw new TypeError("Rendezvous relay sync batch exceeds one bounded lane.");
  }
  const highWatermark = requireInteger(
    value.highWatermark,
    "Rendezvous relay high watermark",
    0,
    rendezvousRelayTransportV2.maximumFramesPerLane
  );
  const nextSequence = requireInteger(
    value.nextSequence,
    "Rendezvous relay next sequence",
    0,
    rendezvousRelayTransportV2.maximumFramesPerLane
  );
  const sync = request === undefined ? null : validateSyncRendezvousTransportV2Request(request);
  const startingSequence = sync?.afterSequence ?? (frames[0]?.sequence - 1);
  if (sync && frames.length > (sync.maxCount ?? rendezvousRelayTransportV2.maximumSyncFrames)) {
    throw new TypeError("Rendezvous relay sync batch exceeds the requested bound.");
  }
  if (frames.some((frame, index) => frame.sequence !== startingSequence + index + 1)) {
    throw new TypeError("Rendezvous relay sync batch contains a sequence gap.");
  }
  const expectedNext = frames.at(-1)?.sequence ?? (sync?.afterSequence ?? nextSequence);
  if (nextSequence !== expectedNext || nextSequence > highWatermark ||
      value.hasMore !== (nextSequence < highWatermark) ||
      (sync && sync.afterSequence > highWatermark)) {
    throw new TypeError("Rendezvous relay sync batch watermarks are inconsistent.");
  }
  return freezeWire({ frames, highWatermark, nextSequence, hasMore: value.hasMore });
}

export class RendezvousRelayAdapterV2 {
  #crypto;
  #transcriptDigest;
  #offererToResponderKey;
  #responderToOffererKey;

  constructor(token, state) {
    if (token !== constructionToken) {
      throw new TypeError("Use createRendezvousRelayAdapterV2().");
    }
    this.#crypto = state.crypto;
    this.#transcriptDigest = state.transcriptDigest;
    this.#offererToResponderKey = state.offererToResponderKey;
    this.#responderToOffererKey = state.responderToOffererKey;
    this.offer = state.offer;
    this.routeCapability = state.routeCapability;
    this.offererToResponder = state.offererToResponder;
    this.responderToOfferer = state.responderToOfferer;
    Object.freeze(this);
  }

  get registrationRequest() {
    return validateRegisterRendezvousTransportV2Request({
      version: 2,
      routeCapability: this.routeCapability,
      expiresAt: this.offer.expiresAt,
      lanes: [
        this.offererToResponder.registration,
        this.responderToOfferer.registration
      ]
    });
  }

  lane(direction) {
    requireDirection(direction);
    return direction === "offererToResponder"
      ? this.offererToResponder
      : this.responderToOfferer;
  }

  syncRequest({ receivingAs, afterSequence = 0, maxCount = null }) {
    const inbound = this.lane(rendezvousRelayInboundDirectionV2(receivingAs)).registration;
    return validateSyncRendezvousTransportV2Request({
      routeCapability: this.routeCapability,
      laneId: inbound.laneId,
      readCapability: inbound.readCapability,
      afterSequence,
      maxCount
    });
  }

  deletionRequests() {
    return freezeWire([this.offererToResponder, this.responderToOfferer].map(({ registration }) =>
      validateDeleteRendezvousTransportV2Request({
        routeCapability: this.routeCapability,
        laneId: registration.laneId,
        deleteCapability: registration.deleteCapability
      })));
  }

  async sealOpen({ open, frameID } = {}) {
    let payload;
    try {
      payload = validateRendezvousOpenV2(open, this.offer);
    } catch (error) {
      throw new RendezvousRelayAdapterV2Error("invalidPayload", "Rendezvous open is invalid.", { cause: error });
    }
    if (!equalBytes(
      requireBase64(payload.offerDigest, 32, "Rendezvous offer digest"),
      this.#transcriptDigest
    )) {
      throw new RendezvousRelayAdapterV2Error("invalidPayload", "Rendezvous open targets another offer.");
    }
    return this.#seal({
      encodedPayload: canonicalJsonBytes(payload),
      payloadKind: 1,
      direction: "responderToOfferer",
      sequence: 1,
      frameID
    });
  }

  async sealSessionFrame({ frame, transportSequence, frameID } = {}) {
    let payload;
    try {
      payload = validateRendezvousFrameV2(frame);
    } catch (error) {
      throw new RendezvousRelayAdapterV2Error("invalidPayload", "Rendezvous session frame is invalid.", { cause: error });
    }
    return this.#seal({
      encodedPayload: canonicalJsonBytes(payload),
      payloadKind: 2,
      direction: rendezvousRelayOutboundDirectionV2(payload.senderRole),
      sequence: transportSequence,
      frameID
    });
  }

  async open({ frame: frameValue, direction } = {}) {
    requireDirection(direction);
    let frame;
    try {
      frame = validateRendezvousRelayCiphertextFrameV2(frameValue);
    } catch (error) {
      throw new RendezvousRelayAdapterV2Error("invalidPayload", "Rendezvous relay frame is invalid.", { cause: error });
    }
    const combined = requireBase64(frame.ciphertext, undefined, "Rendezvous relay ciphertext");
    let plaintext;
    try {
      plaintext = bytes(await this.#crypto.aesGcmDecrypt({
        key: this.#transportKey(direction),
        nonce: combined.subarray(0, 12),
        ciphertext: combined.subarray(12),
        additionalData: this.#authenticatedData(direction, frame.frameId, frame.sequence)
      }), "Rendezvous relay plaintext");
    } catch (error) {
      throw new RendezvousRelayAdapterV2Error(
        "decryptionFailed",
        "Rendezvous relay frame authentication failed.",
        { cause: error }
      );
    }
    try {
      if (plaintext.byteLength < framingBytes ||
          !equalBytes(plaintext.subarray(0, magic.byteLength), magic)) {
        throw new RendezvousRelayAdapterV2Error("invalidPayload");
      }
      const kind = plaintext[magic.byteLength];
      const payloadLength = decodeUInt32(plaintext.subarray(5, 9));
      if (payloadLength <= 0 || framingBytes + payloadLength > plaintext.byteLength) {
        throw new RendezvousRelayAdapterV2Error("invalidPayload");
      }
      const encoded = new Uint8Array(plaintext.subarray(framingBytes, framingBytes + payloadLength));
      try {
        const parsed = parseExactJSON(decoder.decode(encoded));
        if (kind === 1) {
          if (direction !== "responderToOfferer" || frame.sequence !== 1) {
            throw new RendezvousRelayAdapterV2Error("invalidDirection");
          }
          const open = validateRendezvousOpenV2(parsed, this.offer);
          if (!equalBytes(encoded, canonicalJsonBytes(open)) ||
              !equalBytes(requireBase64(open.offerDigest, 32, "Rendezvous offer digest"), this.#transcriptDigest)) {
            throw new RendezvousRelayAdapterV2Error("invalidPayload");
          }
          return freezeWire({ kind: "open", open });
        }
        if (kind === 2) {
          const sessionFrame = validateRendezvousFrameV2(parsed);
          if (!equalBytes(encoded, canonicalJsonBytes(sessionFrame))) {
            throw new RendezvousRelayAdapterV2Error("invalidPayload");
          }
          if (rendezvousRelayOutboundDirectionV2(sessionFrame.senderRole) !== direction) {
            throw new RendezvousRelayAdapterV2Error("invalidDirection");
          }
          return freezeWire({ kind: "sessionFrame", frame: sessionFrame });
        }
        throw new RendezvousRelayAdapterV2Error("invalidPayload");
      } catch (error) {
        if (error instanceof RendezvousRelayAdapterV2Error) throw error;
        throw new RendezvousRelayAdapterV2Error("invalidPayload", "Rendezvous relay payload is invalid.", { cause: error });
      } finally {
        encoded.fill(0);
      }
    } finally {
      plaintext.fill(0);
      combined.fill(0);
    }
  }

  [inspectSymbol]() {
    return "RendezvousRelayAdapterV2(<redacted>)";
  }

  toJSON() {
    return { type: "RendezvousRelayAdapterV2", redacted: true };
  }

  async #seal({ encodedPayload, payloadKind, direction, sequence, frameID }) {
    requireDirection(direction);
    let frameId;
    try {
      requireInteger(
        sequence,
        "Rendezvous relay transport sequence",
        1,
        rendezvousRelayTransportV2.maximumFramesPerLane
      );
      frameId = frameID === undefined
        ? await generateFrameID(this.#crypto)
        : validateOpaqueValue(frameID, 16, "Rendezvous relay frame ID");
    } catch (error) {
      if (error instanceof RendezvousRelayAdapterV2Error) throw error;
      throw new RendezvousRelayAdapterV2Error(
        "invalidPayload",
        "Rendezvous relay frame coordinates are invalid.",
        { cause: error }
      );
    }
    const encoded = bytes(encodedPayload, "Rendezvous relay encoded payload");
    try {
      const minimumPlaintextBytes = framingBytes + encoded.byteLength;
      const bucket = rendezvousRelayTransportV2.allowedCiphertextByteCounts.find((candidate) =>
        candidate >= minimumPlaintextBytes + transportOverhead);
      if (bucket === undefined) {
        throw new RendezvousRelayAdapterV2Error("payloadTooLarge");
      }
      const plaintext = new Uint8Array(bucket - transportOverhead);
      plaintext.set(magic, 0);
      plaintext[4] = payloadKind;
      plaintext.set(uint32Bytes(encoded.byteLength), 5);
      plaintext.set(encoded, framingBytes);
      const paddingLength = plaintext.byteLength - minimumPlaintextBytes;
      if (paddingLength > 0) {
        plaintext.set(await cryptoRandomBytes(this.#crypto, paddingLength), minimumPlaintextBytes);
      }
      const nonce = await cryptoRandomBytes(this.#crypto, 12);
      let sealed;
      try {
        sealed = bytes(await this.#crypto.aesGcmEncrypt({
          key: this.#transportKey(direction),
          nonce,
          plaintext,
          additionalData: this.#authenticatedData(direction, frameId, sequence)
        }), "Rendezvous relay AES-GCM output");
        if (sealed.byteLength !== plaintext.byteLength + 16) {
          throw new RendezvousRelayAdapterV2Error("invalidPayload");
        }
        const frame = validateRendezvousRelayCiphertextFrameV2({
          frameId,
          sequence,
          ciphertext: base64(concatBytes(nonce, sealed))
        });
        const registration = this.lane(direction).registration;
        return validateAppendRendezvousTransportV2Request({
          routeCapability: this.routeCapability,
          laneId: registration.laneId,
          publishCapability: registration.publishCapability,
          frame
        });
      } finally {
        plaintext.fill(0);
        nonce.fill(0);
        sealed?.fill(0);
      }
    } finally {
      encoded.fill(0);
    }
  }

  #transportKey(direction) {
    return direction === "offererToResponder"
      ? this.#offererToResponderKey
      : this.#responderToOffererKey;
  }

  #authenticatedData(direction, frameId, sequence) {
    return concatBytes(
      encoder.encode("org.noctweave.rendezvous-relay-frame/v2"),
      Uint8Array.of(0),
      this.#transcriptDigest,
      Uint8Array.of(0),
      encoder.encode(direction),
      Uint8Array.of(0),
      requireBase64(frameId.rawValue, 16, "Rendezvous relay frame ID"),
      uint64Bytes(sequence)
    );
  }
}

export async function createRendezvousRelayAdapterV2({ crypto, offer: offerValue }) {
  let offer;
  try {
    offer = validateRendezvousOfferV2(offerValue);
  } catch (error) {
    throw new RendezvousRelayAdapterV2Error("invalidOffer", "Rendezvous offer is invalid.", { cause: error });
  }
  if (offer.purpose !== "contactPairing") {
    throw new RendezvousRelayAdapterV2Error("invalidOffer");
  }
  const seed = requireBase64(
    offer.transportCapability.opaqueValue,
    32,
    "Rendezvous transport capability"
  );
  const transcriptDigest = await rendezvousOfferDigestV2(crypto, offer);
  const material = async (label) => cryptoHmacSha256(crypto, {
    key: seed,
    data: concatBytes(
      encoder.encode("org.noctweave.rendezvous-relay-derivation/v2"),
      Uint8Array.of(0),
      encoder.encode(label),
      Uint8Array.of(0),
      transcriptDigest
    )
  });
  try {
    const [
      routeCapability,
      offererLane,
      offererPublish,
      offererRead,
      offererDelete,
      responderLane,
      responderPublish,
      responderRead,
      responderDelete,
      offererKey,
      responderKey
    ] = await Promise.all([
      "route-capability",
      "offerer-to-responder/lane",
      "offerer-to-responder/publish",
      "offerer-to-responder/read",
      "offerer-to-responder/delete",
      "responder-to-offerer/lane",
      "responder-to-offerer/publish",
      "responder-to-offerer/read",
      "responder-to-offerer/delete",
      "offerer-to-responder/transport-key",
      "responder-to-offerer/transport-key"
    ].map(material));
    try {
      const state = {
        crypto,
        offer,
        transcriptDigest: new Uint8Array(transcriptDigest),
        routeCapability: opaqueValue(routeCapability),
        offererToResponder: laneMaterial(
          "offererToResponder",
          offererLane,
          offererPublish,
          offererRead,
          offererDelete
        ),
        responderToOfferer: laneMaterial(
          "responderToOfferer",
          responderLane,
          responderPublish,
          responderRead,
          responderDelete
        ),
        offererToResponderKey: new Uint8Array(offererKey),
        responderToOffererKey: new Uint8Array(responderKey)
      };
      const adapter = new RendezvousRelayAdapterV2(constructionToken, state);
      validateRegisterRendezvousTransportV2Request(adapter.registrationRequest);
      return adapter;
    } finally {
      offererKey.fill(0);
      responderKey.fill(0);
    }
  } catch (error) {
    if (error instanceof RendezvousRelayAdapterV2Error) throw error;
    throw new RendezvousRelayAdapterV2Error("invalidOffer", "Rendezvous relay material is invalid.", { cause: error });
  } finally {
    seed.fill(0);
  }
}

function laneMaterial(direction, laneId, publishCapability, readCapability, deleteCapability) {
  return freezeWire({
    direction,
    registration: validateRendezvousRelayLaneRegistrationV2({
      laneId: opaqueValue(laneId),
      publishCapability: opaqueValue(publishCapability),
      readCapability: opaqueValue(readCapability),
      deleteCapability: opaqueValue(deleteCapability)
    })
  });
}

function opaqueValue(value) {
  return freezeWire({ rawValue: encodeBase64(value) });
}

function validateOpaqueValue(value, length, label) {
  requireExactRecord(value, ["rawValue"], [], label);
  requireNonzeroFixedBase64(value.rawValue, length, label);
  return freezeWire({ rawValue: value.rawValue });
}

async function generateFrameID(crypto) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const value = await cryptoRandomBytes(crypto, 16);
    if (value.some((octet) => octet !== 0)) return opaqueValue(value);
  }
  throw new RendezvousRelayAdapterV2Error("invalidPayload", "Unable to generate a frame ID.");
}

function requireDirection(direction) {
  if (!directions.has(direction)) {
    throw new RendezvousRelayAdapterV2Error("invalidDirection");
  }
  return direction;
}

function requireRole(role) {
  if (!roles.has(role)) {
    throw new RendezvousRelayAdapterV2Error("invalidDirection");
  }
  return role;
}

function instantMilliseconds(value, label) {
  if (value instanceof Date || typeof value === "number") {
    const result = value instanceof Date ? value.getTime() : value;
    if (!Number.isFinite(result) || result < 0) throw new TypeError(`${label} is invalid.`);
    return result;
  }
  return timestampMilliseconds(value, label);
}

function decodeUInt32(value) {
  if (value.byteLength !== 4) throw new TypeError("UInt32 requires four bytes.");
  return value.reduce((result, octet) => (result * 256) + octet, 0);
}
