import {
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteAuthorizationProofV2,
  opaqueRouteCredentialDigestV2,
  validateOpaqueReceiveRouteV2,
  validateOpaqueRouteAuthorizationProofV2,
  validateOpaqueRouteCreateRequestV2,
  validateOpaqueRouteLeaseV2,
  validateOpaqueRouteRenewRequestV2,
  validateOpaqueRouteTeardownRequestV2,
  verifyOpaqueRouteAuthorizationProofV2
} from "./opaque-route-v2.js";
import { validateOpaqueRoutePacketV2 } from "./opaque-route-packet-v2.js";
import {
  concatBytes,
  cryptoSha256,
  encodeBase64,
  freezeWire,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireNonzeroFixedBase64,
  uint16Bytes,
  uint64Bytes
} from "./private-v2.js";

const encoder = new TextEncoder();
const cursorBytes = 68;
const maximumSyncPage = 256;
const packetFrameBuckets = new Set([4_096, 16_384, 65_536]);

export const noctweaveOpaqueRouteRelayV2 = Object.freeze({
  version: 2,
  cursorBytes,
  maximumSyncPage
});

export function createOpaqueRouteCursorV2(rawValue) {
  return validateOpaqueRouteCursorV2(
    typeof rawValue === "string" ? { rawValue } : rawValue
  );
}

export function validateOpaqueRouteCursorV2(value) {
  requireExactRecord(value, ["rawValue"], [], "Opaque route cursor");
  requireBase64(value.rawValue, cursorBytes, "Opaque route cursor");
  return freezeWire({ rawValue: value.rawValue });
}

export async function makeOpaqueRouteSyncRequestV2({
  crypto,
  capabilities,
  after = null,
  limit = maximumSyncPage,
  requestID,
  authorizedAt = new Date(),
  nonce
}) {
  const routeID = fixedValue(capabilities?.routeID, "Opaque route ID");
  const readCredential = fixedValue(
    capabilities?.readCredential,
    "Opaque route read credential"
  );
  const idempotencyKey = requestID === undefined
    ? await createOpaqueRouteIdempotencyKeyV2(crypto)
    : fixedValue(requestID, "Opaque route request ID");
  const proofNonce = nonce === undefined
    ? await createOpaqueRouteProofNonceV2(crypto)
    : fixedValue(nonce, "Opaque route proof nonce");
  const unsigned = syncProjection({
    routeID,
    requestID: idempotencyKey,
    ...(after === null ? {} : { after: validateOpaqueRouteCursorV2(after) }),
    limit
  });
  const operationDigest = await opaqueRouteSyncOperationDigestV2(crypto, unsigned);
  const authorization = await makeOpaqueRouteAuthorizationProofV2({
    crypto,
    authority: "read",
    routeID,
    operationDigest,
    authorizedAt: requireCanonicalTimestamp(authorizedAt, "Opaque route authorization time"),
    nonce: proofNonce,
    secret: readCredential
  });
  return freezeWire({ ...unsigned, authorization });
}

export async function validateOpaqueRouteSyncRequestV2({ crypto, request: value }) {
  const request = syncProjection(value, true);
  const authorization = validateOpaqueRouteAuthorizationProofV2(value.authorization);
  const operationDigest = await opaqueRouteSyncOperationDigestV2(crypto, request);
  if (authorization.authority !== "read" || authorization.operationDigest !== operationDigest) {
    throw new TypeError("Opaque route sync authorization is not bound to its request.");
  }
  return freezeWire({ ...request, authorization });
}

export async function makeOpaqueRouteCommitRequestV2({
  crypto,
  capabilities,
  cursor,
  requestID,
  authorizedAt = new Date(),
  nonce
}) {
  const routeID = fixedValue(capabilities?.routeID, "Opaque route ID");
  const readCredential = fixedValue(
    capabilities?.readCredential,
    "Opaque route read credential"
  );
  const idempotencyKey = requestID === undefined
    ? await createOpaqueRouteIdempotencyKeyV2(crypto)
    : fixedValue(requestID, "Opaque route request ID");
  const proofNonce = nonce === undefined
    ? await createOpaqueRouteProofNonceV2(crypto)
    : fixedValue(nonce, "Opaque route proof nonce");
  const unsigned = commitProjection({
    routeID,
    requestID: idempotencyKey,
    cursor
  });
  const operationDigest = await opaqueRouteCommitOperationDigestV2(crypto, unsigned);
  const authorization = await makeOpaqueRouteAuthorizationProofV2({
    crypto,
    authority: "read",
    routeID,
    operationDigest,
    authorizedAt: requireCanonicalTimestamp(authorizedAt, "Opaque route authorization time"),
    nonce: proofNonce,
    secret: readCredential
  });
  return freezeWire({ ...unsigned, authorization });
}

export async function validateOpaqueRouteCommitRequestV2({ crypto, request: value }) {
  const request = commitProjection(value, true);
  const authorization = validateOpaqueRouteAuthorizationProofV2(value.authorization);
  const operationDigest = await opaqueRouteCommitOperationDigestV2(crypto, request);
  if (authorization.authority !== "read" || authorization.operationDigest !== operationDigest) {
    throw new TypeError("Opaque route commit authorization is not bound to its request.");
  }
  return freezeWire({ ...request, authorization });
}

export async function opaqueRouteSyncOperationDigestV2(crypto, value) {
  const request = syncProjection(value, Object.hasOwn(value, "authorization"));
  return encodeBase64(await storeDigest(crypto, "org.noctweave.opaque-route.sync/v2", [
    requireBase64(request.routeID.rawValue, 32, "Opaque route ID"),
    requireBase64(request.requestID.rawValue, 32, "Opaque route request ID"),
    request.after === undefined
      ? Uint8Array.of(0)
      : requireBase64(request.after.rawValue, cursorBytes, "Opaque route cursor"),
    uint16Bytes(request.limit)
  ]));
}

export async function opaqueRouteCommitOperationDigestV2(crypto, value) {
  const request = commitProjection(value, Object.hasOwn(value, "authorization"));
  return encodeBase64(await storeDigest(crypto, "org.noctweave.opaque-route.commit/v2", [
    requireBase64(request.routeID.rawValue, 32, "Opaque route ID"),
    requireBase64(request.requestID.rawValue, 32, "Opaque route request ID"),
    requireBase64(request.cursor.rawValue, cursorBytes, "Opaque route cursor")
  ]));
}

export function validateOpaqueRouteCreateSubmissionShapeV2(value) {
  requireExactRecord(value, ["transition", "renewCapability"], [], "Opaque route create submission");
  return freezeWire({
    transition: createTransitionProjection(value.transition),
    renewCapability: fixedValue(value.renewCapability, "Opaque route renew capability")
  });
}

export function validateOpaqueRouteRenewSubmissionShapeV2(value) {
  requireExactRecord(value, ["transition", "renewCapability"], [], "Opaque route renew submission");
  return freezeWire({
    transition: renewTransitionProjection(value.transition),
    renewCapability: fixedValue(value.renewCapability, "Opaque route renew capability")
  });
}

export function validateOpaqueRouteTeardownSubmissionShapeV2(value) {
  requireExactRecord(value, ["transition", "teardownCapability"], [], "Opaque route teardown submission");
  return freezeWire({
    transition: teardownTransitionProjection(value.transition),
    teardownCapability: fixedValue(
      value.teardownCapability,
      "Opaque route teardown capability"
    )
  });
}

export function validateOpaqueRouteEnqueueSubmissionShapeV2(value) {
  requireExactRecord(value, ["packet", "sendCapability"], [], "Opaque route enqueue submission");
  return freezeWire({
    packet: packetProjection(value.packet),
    sendCapability: fixedValue(value.sendCapability, "Opaque route send capability")
  });
}

export function validateOpaqueRouteSyncSubmissionShapeV2(value) {
  requireExactRecord(value, ["request", "readCredential"], [], "Opaque route sync submission");
  const request = syncProjection(value.request, true);
  return freezeWire({
    request: {
      ...request,
      authorization: validateOpaqueRouteAuthorizationProofV2(value.request.authorization)
    },
    readCredential: fixedValue(value.readCredential, "Opaque route read credential")
  });
}

export function validateOpaqueRouteCommitSubmissionShapeV2(value) {
  requireExactRecord(value, ["request", "readCredential"], [], "Opaque route commit submission");
  const request = commitProjection(value.request, true);
  return freezeWire({
    request: {
      ...request,
      authorization: validateOpaqueRouteAuthorizationProofV2(value.request.authorization)
    },
    readCredential: fixedValue(value.readCredential, "Opaque route read credential")
  });
}

export async function validateOpaqueRouteCreateSubmissionV2({ crypto, submission: value }) {
  const shape = validateOpaqueRouteCreateSubmissionShapeV2(value);
  const transition = await validateOpaqueRouteCreateRequestV2(crypto, shape.transition);
  await requireValidPresentedProof({
    crypto,
    transition,
    authority: "renew",
    secret: shape.renewCapability
  });
  if (encodeBase64(await opaqueRouteCredentialDigestV2(
    crypto,
    "renew",
    shape.renewCapability
  )) !== transition.renewCapabilityDigest) {
    throw new TypeError("Opaque route create submission presents a different renewal capability.");
  }
  return freezeWire({ transition, renewCapability: shape.renewCapability });
}

export async function validateOpaqueRouteRenewSubmissionV2({ crypto, submission: value }) {
  const shape = validateOpaqueRouteRenewSubmissionShapeV2(value);
  const transition = await validateOpaqueRouteRenewRequestV2(crypto, shape.transition);
  await requireValidPresentedProof({
    crypto,
    transition,
    authority: "renew",
    secret: shape.renewCapability
  });
  return freezeWire({ transition, renewCapability: shape.renewCapability });
}

export async function validateOpaqueRouteTeardownSubmissionV2({ crypto, submission: value }) {
  const shape = validateOpaqueRouteTeardownSubmissionShapeV2(value);
  const transition = await validateOpaqueRouteTeardownRequestV2(crypto, shape.transition);
  await requireValidPresentedProof({
    crypto,
    transition,
    authority: "teardown",
    secret: shape.teardownCapability
  });
  return freezeWire({ transition, teardownCapability: shape.teardownCapability });
}

export async function validateOpaqueRouteEnqueueSubmissionV2({ crypto, submission: value }) {
  const shape = validateOpaqueRouteEnqueueSubmissionShapeV2(value);
  const packet = await validateOpaqueRoutePacketV2({ crypto, packet: shape.packet });
  await requireValidPresentedProof({
    crypto,
    transition: packet,
    authority: "send",
    secret: shape.sendCapability
  });
  return freezeWire({ packet, sendCapability: shape.sendCapability });
}

export async function validateOpaqueRouteSyncSubmissionV2({ crypto, submission: value }) {
  const shape = validateOpaqueRouteSyncSubmissionShapeV2(value);
  const request = await validateOpaqueRouteSyncRequestV2({ crypto, request: shape.request });
  await requireValidPresentedProof({
    crypto,
    transition: request,
    authority: "read",
    secret: shape.readCredential
  });
  return freezeWire({ request, readCredential: shape.readCredential });
}

export async function validateOpaqueRouteCommitSubmissionV2({ crypto, submission: value }) {
  const shape = validateOpaqueRouteCommitSubmissionShapeV2(value);
  const request = await validateOpaqueRouteCommitRequestV2({ crypto, request: shape.request });
  await requireValidPresentedProof({
    crypto,
    transition: request,
    authority: "read",
    secret: shape.readCredential
  });
  return freezeWire({ request, readCredential: shape.readCredential });
}

export function validateOpaqueRouteStateResponseV2(value, transition) {
  requireExactRecord(value, ["type", "opaqueRouteV2"], [], "Opaque route state response");
  if (value.type !== "opaqueRouteV2") {
    throw new TypeError("Relay returned an incompatible opaque route state response.");
  }
  const route = validateOpaqueReceiveRouteV2(value.opaqueRouteV2);
  if (route.routeID.rawValue !== transition.routeID.rawValue ||
      route.lastIdempotencyKey.rawValue !== transition.idempotencyKey.rawValue ||
      route.lastTransitionDigest !== transition.authorization.operationDigest) {
    throw new TypeError("Relay returned opaque route state for a different transition.");
  }
  if (Object.hasOwn(transition, "sendCapabilityDigest") &&
      (route.sendCapabilityDigest !== transition.sendCapabilityDigest ||
       route.readCredentialDigest !== transition.readCredentialDigest ||
       route.renewCapabilityDigest !== transition.renewCapabilityDigest ||
       route.teardownCapabilityDigest !== transition.teardownCapabilityDigest ||
       route.creationIdempotencyKey.rawValue !== transition.idempotencyKey.rawValue ||
       route.creationDigest !== transition.authorization.operationDigest)) {
    throw new TypeError("Relay returned opaque route state with different creation authorities.");
  }
  return freezeWire({ type: value.type, opaqueRouteV2: route });
}

export function validateOpaqueRouteEnqueueResponseV2(value, packet) {
  requireExactRecord(value, ["type", "opaqueRouteAppendV2"], [], "Opaque route enqueue response");
  if (value.type !== "opaqueRouteAppendV2") {
    throw new TypeError("Relay returned an incompatible opaque route enqueue response.");
  }
  const receipt = enqueueReceiptProjection(value.opaqueRouteAppendV2);
  if (receipt.packetID.rawValue !== packet.packetID.rawValue) {
    throw new TypeError("Relay accepted a different opaque route packet.");
  }
  return freezeWire({ type: value.type, opaqueRouteAppendV2: receipt });
}

export async function validateOpaqueRouteSyncResponseV2({ crypto, response: value, request }) {
  requireExactRecord(value, ["type", "opaqueRouteSyncV2"], [], "Opaque route sync response");
  if (value.type !== "opaqueRouteSyncV2") {
    throw new TypeError("Relay returned an incompatible opaque route sync response.");
  }
  const batch = value.opaqueRouteSyncV2;
  requireExactRecord(batch, [
    "packets",
    "nextCursor",
    "highWatermark",
    "retentionFloor",
    "hasMore"
  ], [], "Opaque route sync batch");
  if (!Array.isArray(batch.packets) || batch.packets.length > request.limit ||
      typeof batch.hasMore !== "boolean") {
    throw new TypeError("Opaque route sync batch is outside its bounds.");
  }
  const packets = [];
  const packetIDs = new Set();
  for (const received of batch.packets) {
    requireExactRecord(received, ["routeRevision", "packet"], [], "Opaque route received packet");
    const routeRevision = requireInteger(
      received.routeRevision,
      "Opaque route revision",
      0,
      Number.MAX_SAFE_INTEGER
    );
    const packet = await validateOpaqueRoutePacketV2({ crypto, packet: received.packet });
    if (packet.routeID.rawValue !== request.routeID.rawValue ||
        packetIDs.has(packet.packetID.rawValue)) {
      throw new TypeError("Opaque route sync batch contains a mismatched or duplicate packet.");
    }
    packetIDs.add(packet.packetID.rawValue);
    packets.push(freezeWire({ routeRevision, packet }));
  }
  return freezeWire({
    type: value.type,
    opaqueRouteSyncV2: {
      packets,
      nextCursor: validateOpaqueRouteCursorV2(batch.nextCursor),
      highWatermark: validateOpaqueRouteCursorV2(batch.highWatermark),
      retentionFloor: validateOpaqueRouteCursorV2(batch.retentionFloor),
      hasMore: batch.hasMore
    }
  });
}

export function validateOpaqueRouteCommitResponseV2(value, request) {
  requireExactRecord(value, ["type", "opaqueRouteCommitV2"], [], "Opaque route commit response");
  if (value.type !== "opaqueRouteCommitV2") {
    throw new TypeError("Relay returned an incompatible opaque route commit response.");
  }
  const response = value.opaqueRouteCommitV2;
  requireExactRecord(response, [
    "committedCursor",
    "highWatermark",
    "retentionFloor"
  ], [], "Opaque route commit receipt");
  const committedCursor = validateOpaqueRouteCursorV2(response.committedCursor);
  if (committedCursor.rawValue !== request.cursor.rawValue) {
    throw new TypeError("Relay committed a different opaque route cursor.");
  }
  return freezeWire({
    type: value.type,
    opaqueRouteCommitV2: {
      committedCursor,
      highWatermark: validateOpaqueRouteCursorV2(response.highWatermark),
      retentionFloor: validateOpaqueRouteCursorV2(response.retentionFloor)
    }
  });
}

function syncProjection(value, withAuthorization = false) {
  requireExactRecord(value, ["routeID", "requestID", "limit"], [
    "after",
    ...(withAuthorization ? ["authorization"] : [])
  ], "Opaque route sync request");
  const result = {
    routeID: fixedValue(value.routeID, "Opaque route ID"),
    requestID: fixedValue(value.requestID, "Opaque route request ID"),
    limit: requireInteger(value.limit, "Opaque route sync limit", 1, maximumSyncPage)
  };
  if (Object.hasOwn(value, "after")) {
    result.after = validateOpaqueRouteCursorV2(value.after);
  }
  return freezeWire(result);
}

function commitProjection(value, withAuthorization = false) {
  requireExactRecord(value, ["routeID", "requestID", "cursor"], [
    ...(withAuthorization ? ["authorization"] : [])
  ], "Opaque route commit request");
  return freezeWire({
    routeID: fixedValue(value.routeID, "Opaque route ID"),
    requestID: fixedValue(value.requestID, "Opaque route request ID"),
    cursor: validateOpaqueRouteCursorV2(value.cursor)
  });
}

function createTransitionProjection(value) {
  requireExactRecord(value, [
    "version",
    "routeID",
    "sendCapabilityDigest",
    "readCredentialDigest",
    "renewCapabilityDigest",
    "teardownCapabilityDigest",
    "lease",
    "idempotencyKey",
    "authorization"
  ], [], "Opaque route create transition");
  if (value.version !== 2) throw new TypeError("Opaque route transition version must be 2.");
  return freezeWire({
    version: 2,
    routeID: fixedValue(value.routeID, "Opaque route ID"),
    sendCapabilityDigest: digest(value.sendCapabilityDigest, "Opaque route send digest"),
    readCredentialDigest: digest(value.readCredentialDigest, "Opaque route read digest"),
    renewCapabilityDigest: digest(value.renewCapabilityDigest, "Opaque route renew digest"),
    teardownCapabilityDigest: digest(value.teardownCapabilityDigest, "Opaque route teardown digest"),
    lease: validateOpaqueRouteLeaseV2(value.lease),
    idempotencyKey: fixedValue(value.idempotencyKey, "Opaque route idempotency key"),
    authorization: validateOpaqueRouteAuthorizationProofV2(value.authorization)
  });
}

function renewTransitionProjection(value) {
  requireExactRecord(value, [
    "version",
    "routeID",
    "renewalSequence",
    "previousTransitionDigest",
    "newExpiry",
    "authorizedAt",
    "idempotencyKey",
    "authorization"
  ], [], "Opaque route renew transition");
  if (value.version !== 2) throw new TypeError("Opaque route transition version must be 2.");
  return freezeWire({
    version: 2,
    routeID: fixedValue(value.routeID, "Opaque route ID"),
    renewalSequence: requireInteger(
      value.renewalSequence,
      "Opaque route renewal sequence",
      1,
      Number.MAX_SAFE_INTEGER
    ),
    previousTransitionDigest: digest(
      value.previousTransitionDigest,
      "Opaque route previous transition digest"
    ),
    newExpiry: requireCanonicalTimestamp(value.newExpiry, "Opaque route new expiry"),
    authorizedAt: requireCanonicalTimestamp(value.authorizedAt, "Opaque route authorization time"),
    idempotencyKey: fixedValue(value.idempotencyKey, "Opaque route idempotency key"),
    authorization: validateOpaqueRouteAuthorizationProofV2(value.authorization)
  });
}

function teardownTransitionProjection(value) {
  requireExactRecord(value, [
    "version",
    "routeID",
    "renewalSequence",
    "previousTransitionDigest",
    "authorizedAt",
    "idempotencyKey",
    "authorization"
  ], [], "Opaque route teardown transition");
  if (value.version !== 2) throw new TypeError("Opaque route transition version must be 2.");
  return freezeWire({
    version: 2,
    routeID: fixedValue(value.routeID, "Opaque route ID"),
    renewalSequence: requireInteger(
      value.renewalSequence,
      "Opaque route renewal sequence",
      0,
      Number.MAX_SAFE_INTEGER
    ),
    previousTransitionDigest: digest(
      value.previousTransitionDigest,
      "Opaque route previous transition digest"
    ),
    authorizedAt: requireCanonicalTimestamp(value.authorizedAt, "Opaque route authorization time"),
    idempotencyKey: fixedValue(value.idempotencyKey, "Opaque route idempotency key"),
    authorization: validateOpaqueRouteAuthorizationProofV2(value.authorization)
  });
}

function packetProjection(value) {
  requireExactRecord(value, [
    "routeID",
    "packetID",
    "sealedFrame",
    "authorization"
  ], [], "Opaque route packet");
  const sealed = requireBase64(value.sealedFrame, undefined, "Opaque route sealed frame");
  if (!packetFrameBuckets.has(sealed.byteLength)) {
    throw new TypeError("Opaque route sealed frame does not use a protocol padding bucket.");
  }
  return freezeWire({
    routeID: fixedValue(value.routeID, "Opaque route ID"),
    packetID: fixedValue(value.packetID, "Opaque route packet ID"),
    sealedFrame: value.sealedFrame,
    authorization: validateOpaqueRouteAuthorizationProofV2(value.authorization)
  });
}

function enqueueReceiptProjection(value) {
  requireExactRecord(value, [
    "packetID",
    "acceptedCursor",
    "highWatermark"
  ], [], "Opaque route enqueue receipt");
  return freezeWire({
    packetID: fixedValue(value.packetID, "Opaque route packet ID"),
    acceptedCursor: validateOpaqueRouteCursorV2(value.acceptedCursor),
    highWatermark: validateOpaqueRouteCursorV2(value.highWatermark)
  });
}

async function requireValidPresentedProof({ crypto, transition, authority, secret }) {
  const valid = await verifyOpaqueRouteAuthorizationProofV2({
    crypto,
    proof: transition.authorization,
    expectedAuthority: authority,
    routeID: transition.routeID,
    operationDigest: transition.authorization.operationDigest,
    secret
  });
  if (!valid) {
    throw new TypeError(`Opaque route ${authority} capability does not authorize this request.`);
  }
}

function fixedValue(value, label) {
  requireExactRecord(value, ["rawValue"], [], label);
  requireNonzeroFixedBase64(value.rawValue, 32, label);
  return freezeWire({ rawValue: value.rawValue });
}

function digest(value, label) {
  requireBase64(value, 32, label);
  return value;
}

async function storeDigest(crypto, domain, components) {
  return cryptoSha256(crypto, concatBytes(
    encoder.encode(domain),
    Uint8Array.of(0),
    ...components.flatMap((component) => [uint64Bytes(component.byteLength), component])
  ));
}
