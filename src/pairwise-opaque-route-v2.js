import {
  opaqueRouteCredentialDigestV2,
  validateOpaqueReceiveRouteV2,
  validateOpaqueRouteClientCapabilityMaterialV2,
  validateOpaqueRoutePolicyV2
} from "./opaque-route-v2.js";
import {
  createOpaqueRoutePacketReassemblerV2,
  restoreOpaqueRoutePacketReassemblerV2,
  validateOpaqueRoutePacketReassemblerStateV2,
  validateOpaqueRoutePayloadKeyV2
} from "./opaque-route-packet-v2.js";
import { validateOpaqueRouteCursorV2 } from "./opaque-route-relay-v2.js";
import {
  concatBytes,
  encodeBase64,
  equalBytes,
  freezeWire,
  cryptoSha256,
  requireBase64,
  requireCanonicalTimestamp,
  requireInteger,
  requireNonzeroFixedBase64,
  requireRecord,
  swiftCanonicalBytes,
  timestampMilliseconds
} from "./private-v2.js";
import { noctweaveRendezvousV2 } from "./rendezvous-v2.js";
import {
  validateRelationshipEndpointBindingV4,
  verifyRelationshipEndpointBindingV4
} from "./crypto/direct-v4.js";
import {
  noctweaveArchitectureV2,
  validateProtocolCapabilityManifest,
  validateRelationshipEndpointHandle
} from "./architecture-v2.js";

const encoder = new TextEncoder();
const inspectSymbol = Symbol.for("nodejs.util.inspect.custom");
const routeStates = new Set(["testing", "active", "draining", "revoked"]);
const relayTransports = new Set(["tcp", "http", "websocket"]);
const routeFields = Object.freeze([
  "routeID",
  "relay",
  "sendCapability",
  "payloadKey",
  "routeRevision",
  "policy",
  "validFrom",
  "expiresAt",
  "priority",
  "state",
  "testedAt",
  "drainAfter",
  "revokedAt"
]);
const routeSetFields = Object.freeze([
  "version",
  "relationshipID",
  "ownerEndpointHandle",
  "revision",
  "previousDigest",
  "routes",
  "issuedAt",
  "signature"
]);
const introductionFields = Object.freeze([
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
const localReceiveRouteFields = Object.freeze([
  "relay",
  "route",
  "clientCapabilities",
  "payloadKey",
  "committedCursor",
  "committedSequence",
  "committedRecordDigest",
  "gapState",
  "reassembler"
]);
const gapStateFields = Object.freeze([
  "reason",
  "expectedSequence",
  "observedSequence",
  "retentionFloorSequence",
  "detectedAt"
]);
const gapReasons = new Set([
  "retentionExpired",
  "sequenceDiscontinuity",
  "digestChainBreak",
  "cursorRegression"
]);

const ML_DSA_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_SECRET_KEY_BYTES = 4_032;
const ML_DSA_SIGNATURE_BYTES = 3_309;
const ML_KEM_PUBLIC_KEY_BYTES = 1_184;
const DIGEST_BYTES = 32;

export const noctweavePairwiseOpaqueRoutesV2 = Object.freeze({
  version: 2,
  maximumIntroductionLifetimeSeconds: noctweaveRendezvousV2.maximumLifetimeSeconds,
  maximumPersistedReassemblerBufferedBytes: 1 * 1_024 * 1_024,
  defaultRoutePriority: 100,
  routeStates: Object.freeze([...routeStates])
});

export const opaqueRouteGapReasonsV2 = Object.freeze([...gapReasons]);

export class PairwiseOpaqueRouteV2Error extends Error {
  constructor(code, message = code, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PairwiseOpaqueRouteV2Error";
    this.code = code;
  }
}

export class PairwiseRouteSetV2Error extends Error {
  constructor(code, message = code, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PairwiseRouteSetV2Error";
    this.code = code;
  }
}

export class OpaqueRouteGapV2Error extends PairwiseOpaqueRouteV2Error {
  constructor(gapState, localReceiveRoute) {
    super("routeGapDetected", "Opaque route synchronization continuity failed.");
    this.name = "OpaqueRouteGapV2Error";
    this.gapState = gapState;
    this.localReceiveRoute = localReceiveRoute;
  }
}

export async function createLocalOpaqueReceiveRouteV2({
  crypto,
  relay,
  route,
  clientCapabilities,
  payloadKey
}) {
  return validateLocalOpaqueReceiveRouteV2({
    crypto,
    route: {
      relay,
      route,
      clientCapabilities,
      payloadKey,
      committedCursor: null,
      committedSequence: 0,
      committedRecordDigest: encodeBase64(new Uint8Array(DIGEST_BYTES)),
      gapState: null,
      reassembler: createOpaqueRoutePacketReassemblerV2().snapshot()
    }
  });
}

export async function validateLocalOpaqueReceiveRouteV2({ crypto, route: value }) {
  try {
    requireExactKeys(value, localReceiveRouteFields, "Local opaque receive route");
    const relay = validatePairwiseRelayEndpointV2(value.relay);
    const route = validateOpaqueReceiveRouteV2(value.route);
    const clientCapabilities = validateOpaqueRouteClientCapabilityMaterialV2(
      value.clientCapabilities
    );
    const payloadKey = validateOpaqueRoutePayloadKeyV2(value.payloadKey);
    const committedCursor = value.committedCursor === null
      ? null
      : validateOpaqueRouteCursorV2(value.committedCursor);
    const committedSequence = requireInteger(
      value.committedSequence,
      "Opaque route committed sequence",
      0,
      Number.MAX_SAFE_INTEGER
    );
    const committedRecordDigest = wireDigest(
      value.committedRecordDigest,
      "Opaque route committed record digest"
    );
    const gapState = value.gapState === null
      ? null
      : validateOpaqueRouteGapStateV2(value.gapState);
    const reassembler = validateOpaqueRoutePacketReassemblerStateV2(
      value.reassembler,
      { routeID: route.routeID }
    );
    if (route.status !== "active" ||
        route.routeID.rawValue !== clientCapabilities.routeID.rawValue ||
        reassembler.maximumBufferedBytes >
          noctweavePairwiseOpaqueRoutesV2.maximumPersistedReassemblerBufferedBytes ||
        (committedCursor === null &&
          (committedSequence !== 0 || committedRecordDigest !== encodeBase64(new Uint8Array(DIGEST_BYTES))))) {
      throw new TypeError("Local opaque receive route state is inconsistent.");
    }
    for (const [authority, credential, expectedDigest] of [
      ["send", clientCapabilities.sendCapability, route.sendCapabilityDigest],
      ["read", clientCapabilities.readCredential, route.readCredentialDigest],
      ["renew", clientCapabilities.renewCapability, route.renewCapabilityDigest],
      ["teardown", clientCapabilities.teardownCapability, route.teardownCapabilityDigest]
    ]) {
      const actualDigest = await opaqueRouteCredentialDigestV2(crypto, authority, credential);
      if (!equalBytes(actualDigest, requireBase64(
        expectedDigest,
        DIGEST_BYTES,
        `Opaque route ${authority} capability digest`
      ))) {
        throw new TypeError(`Opaque route ${authority} authority does not match relay state.`);
      }
    }
    return redactedWire({
      relay,
      route,
      clientCapabilities,
      payloadKey,
      committedCursor,
      committedSequence,
      committedRecordDigest,
      gapState,
      reassembler
    }, "LocalOpaqueReceiveRouteV2");
  } catch (error) {
    if (error instanceof PairwiseOpaqueRouteV2Error) throw error;
    throw new PairwiseOpaqueRouteV2Error(
      "invalidRoute",
      "Local opaque receive route is invalid.",
      error
    );
  }
}

export function validateOpaqueRouteGapStateV2(value) {
  requireExactKeys(value, gapStateFields, "Opaque route gap state");
  if (!gapReasons.has(value.reason)) throw new TypeError("Opaque route gap reason is invalid.");
  const expectedSequence = requireInteger(
    value.expectedSequence,
    "Opaque route expected sequence",
    0,
    Number.MAX_SAFE_INTEGER
  );
  const observedSequence = requireInteger(
    value.observedSequence,
    "Opaque route observed sequence",
    0,
    Number.MAX_SAFE_INTEGER
  );
  const retentionFloorSequence = requireInteger(
    value.retentionFloorSequence,
    "Opaque route retention-floor sequence",
    0,
    Number.MAX_SAFE_INTEGER
  );
  if (retentionFloorSequence > observedSequence) {
    throw new TypeError("Opaque route gap bounds are invalid.");
  }
  return Object.freeze({
    reason: value.reason,
    expectedSequence,
    observedSequence,
    retentionFloorSequence,
    detectedAt: requireCanonicalTimestamp(value.detectedAt, "Opaque route gap detection time")
  });
}

export function detectOpaqueRouteGapV2({ batch, localReceiveRoute, detectedAt }) {
  const expectedSequence = requireInteger(
    localReceiveRoute?.committedSequence,
    "Opaque route committed sequence",
    0,
    Number.MAX_SAFE_INTEGER
  );
  const committedDigest = wireDigest(
    localReceiveRoute?.committedRecordDigest,
    "Opaque route committed record digest"
  );
  let reason = null;
  if (batch.retentionFloorSequence > expectedSequence) {
    reason = "retentionExpired";
  } else if (batch.startsAfterSequence < expectedSequence || batch.nextSequence < expectedSequence) {
    reason = "cursorRegression";
  } else if (batch.startsAfterSequence !== expectedSequence) {
    reason = "sequenceDiscontinuity";
  } else if (batch.startsAfterRecordDigest !== committedDigest) {
    reason = "digestChainBreak";
  }
  if (reason === null) return null;
  return validateOpaqueRouteGapStateV2({
    reason,
    expectedSequence,
    observedSequence: batch.startsAfterSequence,
    retentionFloorSequence: batch.retentionFloorSequence,
    detectedAt
  });
}

export function assertOpaqueRouteSyncContinuityV2({ batch, localReceiveRoute, detectedAt }) {
  const gapState = detectOpaqueRouteGapV2({ batch, localReceiveRoute, detectedAt });
  if (gapState === null) return batch;
  const quarantined = redactedWire(
    { ...localReceiveRoute, gapState },
    "LocalOpaqueReceiveRouteV2"
  );
  throw new OpaqueRouteGapV2Error(gapState, quarantined);
}

/**
 * Produces the terminal local state for a verified relay cursor gap. Pending
 * fragments are unreachable after a gap, while completed/evicted tombstones
 * remain bounded and durable for replay safety.
 */
export async function markLocalOpaqueReceiveRouteGapV2({
  crypto,
  localReceiveRoute: value,
  batch,
  detectedAt
}) {
  const localReceiveRoute = await validateLocalOpaqueReceiveRouteV2({ crypto, route: value });
  const gapState = detectOpaqueRouteGapV2({ batch, localReceiveRoute, detectedAt });
  if (gapState === null) return null;
  const reassembler = restoreOpaqueRoutePacketReassemblerV2(
    localReceiveRoute.reassembler,
    { routeID: localReceiveRoute.route.routeID }
  );
  reassembler.discardPendingBundles();
  return validateLocalOpaqueReceiveRouteV2({
    crypto,
    route: {
      ...localReceiveRoute,
      gapState,
      reassembler: reassembler.snapshot()
    }
  });
}

/**
 * Applies one reassembly mutation to an isolated candidate. A throwing update
 * leaves the caller's persisted route unchanged.
 */
export async function updateLocalOpaqueReceiveRouteReassemblerV2({
  crypto,
  localReceiveRoute: value,
  update
}) {
  if (typeof update !== "function") {
    throw new TypeError("Opaque route reassembly update must be a function.");
  }
  const localReceiveRoute = await validateLocalOpaqueReceiveRouteV2({ crypto, route: value });
  const reassembler = restoreOpaqueRoutePacketReassemblerV2(
    localReceiveRoute.reassembler,
    { routeID: localReceiveRoute.route.routeID }
  );
  const result = await update(reassembler);
  const next = await validateLocalOpaqueReceiveRouteV2({
    crypto,
    route: { ...localReceiveRoute, reassembler: reassembler.snapshot() }
  });
  return Object.freeze({ localReceiveRoute: next, result });
}

export async function advanceLocalOpaqueReceiveRouteV2({
  crypto,
  localReceiveRoute: value,
  batch,
  detectedAt
}) {
  const localReceiveRoute = await validateLocalOpaqueReceiveRouteV2({ crypto, route: value });
  if (localReceiveRoute.gapState !== null) {
    throw new OpaqueRouteGapV2Error(localReceiveRoute.gapState, localReceiveRoute);
  }
  assertOpaqueRouteSyncContinuityV2({ batch, localReceiveRoute, detectedAt });
  return validateLocalOpaqueReceiveRouteV2({
    crypto,
    route: {
      ...localReceiveRoute,
      committedCursor: batch.nextCursor,
      committedSequence: batch.nextSequence,
      committedRecordDigest: batch.nextRecordDigest,
      gapState: null
    }
  });
}

/**
 * Validates the only route authority that may be disclosed to a peer.
 * Read, renewal, and teardown secrets are intentionally not wire fields.
 */
export function validateOpaqueSendRouteV2(value) {
  try {
    requireRecord(value, "Opaque send route");
    requireExactKeys(value, routeFields, "Opaque send route");
    const routeID = validateFixedWireValue(value.routeID, "Opaque route ID");
    const sendCapability = validateFixedWireValue(
      value.sendCapability,
      "Opaque route send capability"
    );
    const payloadKey = validateFixedWireValue(value.payloadKey, "Opaque route payload key");
    const relay = validatePairwiseRelayEndpointV2(value.relay);
    requireExactKeys(value.policy, [
      "paddingBucket",
      "retentionBucket",
      "quotaBucket",
      "transportRequirement"
    ], "Opaque route policy");
    const policy = validateOpaqueRoutePolicyV2(value.policy);
    const validFrom = requireCanonicalTimestamp(value.validFrom, "Pairwise route valid-from time");
    const expiresAt = requireCanonicalTimestamp(value.expiresAt, "Pairwise route expiry");
    if (timestampMilliseconds(expiresAt) <= timestampMilliseconds(validFrom)) {
      throw new TypeError("Pairwise route expiry must follow its valid-from time.");
    }
    const routeRevision = requireInteger(
      value.routeRevision,
      "Pairwise route revision",
      0,
      Number.MAX_SAFE_INTEGER
    );
    const priority = requireInteger(value.priority, "Pairwise route priority", 0, 0xffff);
    if (!routeStates.has(value.state)) {
      throw new TypeError("Pairwise route state is invalid.");
    }
    const testedAt = optionalCanonicalTimestamp(value.testedAt, "Pairwise route test time");
    const drainAfter = optionalCanonicalTimestamp(value.drainAfter, "Pairwise route drain time");
    const revokedAt = optionalCanonicalTimestamp(value.revokedAt, "Pairwise route revocation time");
    validateRouteLifecycle({
      state: value.state,
      validFrom,
      expiresAt,
      testedAt,
      drainAfter,
      revokedAt
    });
    return redactedWire({
      routeID,
      relay,
      sendCapability,
      payloadKey,
      routeRevision,
      policy,
      validFrom,
      expiresAt,
      priority,
      state: value.state,
      testedAt,
      drainAfter,
      revokedAt
    }, "OpaqueSendRouteV2");
  } catch (error) {
    if (error instanceof PairwiseOpaqueRouteV2Error) throw error;
    throw new PairwiseOpaqueRouteV2Error("invalidRoute", "Opaque send route is invalid.", error);
  }
}

/**
 * Projects endpoint-local receive authority into peer-visible send authority.
 * All four local capability digests are checked before the projection is made.
 */
export async function createOpaqueSendRouteV2({
  crypto,
  relay,
  route: routeValue,
  clientCapabilities: clientCapabilitiesValue,
  payloadKey: payloadKeyValue,
  priority = noctweavePairwiseOpaqueRoutesV2.defaultRoutePriority,
  state = "active"
}) {
  try {
    const route = validateOpaqueReceiveRouteV2(routeValue);
    requireExactKeys(clientCapabilitiesValue, [
      "routeID",
      "sendCapability",
      "readCredential",
      "renewCapability",
      "teardownCapability"
    ], "Opaque route client capability material");
    for (const [field, label] of [
      ["routeID", "Opaque route ID"],
      ["sendCapability", "Opaque route send capability"],
      ["readCredential", "Opaque route read credential"],
      ["renewCapability", "Opaque route renew capability"],
      ["teardownCapability", "Opaque route teardown capability"]
    ]) {
      validateFixedWireValue(clientCapabilitiesValue[field], label);
    }
    const clientCapabilities = validateOpaqueRouteClientCapabilityMaterialV2(
      clientCapabilitiesValue
    );
    const payloadKey = validateOpaqueRoutePayloadKeyV2(payloadKeyValue);
    if (route.status !== "active" ||
        route.routeID.rawValue !== clientCapabilities.routeID.rawValue) {
      throw new TypeError("Opaque receive route does not match its local capability material.");
    }
    const authorityChecks = [
      ["send", clientCapabilities.sendCapability, route.sendCapabilityDigest],
      ["read", clientCapabilities.readCredential, route.readCredentialDigest],
      ["renew", clientCapabilities.renewCapability, route.renewCapabilityDigest],
      ["teardown", clientCapabilities.teardownCapability, route.teardownCapabilityDigest]
    ];
    for (const [authority, credential, expectedDigest] of authorityChecks) {
      const actualDigest = await opaqueRouteCredentialDigestV2(crypto, authority, credential);
      if (!equalBytes(actualDigest, requireBase64(
        expectedDigest,
        DIGEST_BYTES,
        `Opaque route ${authority} capability digest`
      ))) {
        throw new TypeError(`Opaque route ${authority} authority does not match relay state.`);
      }
    }
    return validateOpaqueSendRouteV2({
      routeID: clientCapabilities.routeID,
      relay,
      sendCapability: clientCapabilities.sendCapability,
      payloadKey,
      routeRevision: route.lease.renewalSequence,
      policy: route.lease.policy,
      validFrom: route.lease.issuedAt,
      expiresAt: route.lease.expiresAt,
      priority,
      state,
      testedAt: state === "active" ? route.lease.issuedAt : null,
      drainAfter: null,
      revokedAt: null
    });
  } catch (error) {
    if (error instanceof PairwiseOpaqueRouteV2Error) throw error;
    throw new PairwiseOpaqueRouteV2Error("invalidRoute", "Local receive route cannot be disclosed.", error);
  }
}

export function opaqueSendRouteIsUsableV2(value, at = Date.now()) {
  const route = validateOpaqueSendRouteV2(value);
  const date = flexibleTimestampMilliseconds(at, "Pairwise route use time");
  if (date < timestampMilliseconds(route.validFrom) || date >= timestampMilliseconds(route.expiresAt)) {
    return false;
  }
  if (route.state === "active") return true;
  return route.state === "draining" && date < timestampMilliseconds(route.drainAfter);
}

export function validatePairwiseRouteSetV2(value) {
  try {
    requireRecord(value, "Pairwise route set");
    requireExactKeys(value, routeSetFields, "Pairwise route set");
    if (value.version !== noctweavePairwiseOpaqueRoutesV2.version ||
        !canonicalUUID(value.relationshipID)) {
      throw new TypeError("Pairwise route-set identity is invalid.");
    }
    requireExactKeys(value.ownerEndpointHandle, ["rawValue"], "Route-set owner endpoint handle");
    const ownerEndpointHandle = validateRelationshipEndpointHandle(value.ownerEndpointHandle);
    const revision = requireInteger(
      value.revision,
      "Pairwise route-set revision",
      0,
      Number.MAX_SAFE_INTEGER
    );
    let previousDigest = null;
    if (value.previousDigest !== null) {
      requireBase64(value.previousDigest, DIGEST_BYTES, "Previous pairwise route-set digest");
      previousDigest = value.previousDigest;
    }
    if ((revision === 0) !== (previousDigest === null)) {
      throw new TypeError("Pairwise route-set history link is invalid.");
    }
    if (!Array.isArray(value.routes) || value.routes.length === 0 ||
        value.routes.length > noctweaveArchitectureV2.maximumRoutes) {
      throw new TypeError("Pairwise route-set route count is invalid.");
    }
    const routes = value.routes.map(validateOpaqueSendRouteV2);
    const routeIDs = routes.map((route) => route.routeID.rawValue);
    const sortedRouteIDs = [...routeIDs].sort(compareBase64Values);
    if (new Set(routeIDs).size !== routeIDs.length ||
        routeIDs.some((routeID, index) => routeID !== sortedRouteIDs[index]) ||
        !routes.some((route) => route.state === "active" || route.state === "draining")) {
      throw new TypeError("Pairwise route-set routes are not a current ordered snapshot.");
    }
    const issuedAt = requireCanonicalTimestamp(value.issuedAt, "Pairwise route-set issue time");
    if (routes.some((route) => timestampMilliseconds(route.validFrom) > timestampMilliseconds(issuedAt))) {
      throw new TypeError("Pairwise route set predates one of its routes.");
    }
    const signature = requireBase64(value.signature, undefined, "Pairwise route-set signature");
    if (signature.byteLength === 0 || signature.byteLength > 8 * 1_024) {
      throw new TypeError("Pairwise route-set signature length is invalid.");
    }
    return Object.freeze({
      version: noctweavePairwiseOpaqueRoutesV2.version,
      relationshipID: value.relationshipID,
      ownerEndpointHandle: freezeWire(ownerEndpointHandle),
      revision,
      previousDigest,
      routes: Object.freeze(routes),
      issuedAt,
      signature: value.signature
    });
  } catch (error) {
    if (error instanceof PairwiseRouteSetV2Error) throw error;
    throw new PairwiseRouteSetV2Error("invalidState", "Pairwise route set is invalid.", error);
  }
}

export function pairwiseRouteSetV2SignablePayload(value) {
  return Object.freeze(routeSetSignatureProjection(validatePairwiseRouteSetV2(value)));
}

export function pairwiseRouteSetV2SignableBytes(value) {
  return swiftCanonicalBytes(pairwiseRouteSetV2SignablePayload(value));
}

export function verifyPairwiseRouteSetV2({ pqc, routeSet: routeSetValue, ownerSigningPublicKey }) {
  let routeSet;
  try {
    routeSet = validatePairwiseRouteSetV2(routeSetValue);
  } catch {
    return false;
  }
  if (typeof pqc?.verify !== "function") {
    throw new TypeError("Pairwise route-set verification requires ML-DSA verification.");
  }
  try {
    return pqc.verify(
      swiftCanonicalBytes(routeSetSignatureProjection(routeSet)),
      requireBase64(routeSet.signature, ML_DSA_SIGNATURE_BYTES, "Pairwise route-set signature"),
      requireBase64(ownerSigningPublicKey, ML_DSA_PUBLIC_KEY_BYTES, "Route owner signing key")
    );
  } catch {
    return false;
  }
}

export function createPairwiseRouteSetV2({
  pqc,
  relationshipID,
  ownerEndpointHandle,
  activeRoutes,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  if (!Array.isArray(activeRoutes) || activeRoutes.length === 0) {
    throw new PairwiseRouteSetV2Error("invalidState", "An initial active route is required.");
  }
  const normalizedIssuedAt = requireCanonicalTimestamp(issuedAt, "Pairwise route-set issue time");
  const routes = activeRoutes.map(validateOpaqueSendRouteV2);
  if (routes.some((route) => route.state !== "active" ||
      !opaqueSendRouteIsUsableV2(route, normalizedIssuedAt))) {
    throw new PairwiseRouteSetV2Error("invalidState", "Initial pairwise routes must be active and usable.");
  }
  return signPairwiseRouteSetV2({
    pqc,
    relationshipID,
    ownerEndpointHandle,
    revision: 0,
    previousDigest: null,
    routes,
    issuedAt: normalizedIssuedAt,
    ownerSigningPublicKey,
    ownerSigningSecretKey
  });
}

export async function pairwiseRouteSetV2Digest(crypto, value) {
  const routeSet = validatePairwiseRouteSetV2(value);
  return encodeBase64(await cryptoSha256(crypto, swiftCanonicalBytes(routeSet)));
}

export async function derivePairwiseRelationshipIDV2({ crypto, rendezvousTranscriptDigest }) {
  const digest = requireBase64(
    wireDigest(rendezvousTranscriptDigest, "Rendezvous transcript digest"),
    DIGEST_BYTES,
    "Rendezvous transcript digest"
  );
  const relationshipDigest = await cryptoSha256(crypto, concatBytes(
    encoder.encode("Noctweave/pairwise-relationship-id/v2"),
    Uint8Array.of(0),
    digest
  ));
  const uuidBytes = new Uint8Array(relationshipDigest.subarray(0, 16));
  uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40;
  uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80;
  return uuidFromBytes(uuidBytes);
}

export function usablePairwiseRoutesV2(value, at = Date.now()) {
  const routeSet = validatePairwiseRouteSetV2(value);
  return Object.freeze(routeSet.routes
    .filter((route) => opaqueSendRouteIsUsableV2(route, at))
    .sort((left, right) => left.priority - right.priority || compareRoutes(left, right)));
}

export async function addTestingPairwiseRouteV2({
  crypto,
  pqc,
  current,
  route: routeValue,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  const routeSet = validatePairwiseRouteSetV2(current);
  const route = validateOpaqueSendRouteV2(routeValue);
  const existing = routeSet.routes.find((candidate) =>
    candidate.routeID.rawValue === route.routeID.rawValue
  );
  if (existing) {
    if (equalBytes(swiftCanonicalBytes(existing), swiftCanonicalBytes(route))) return routeSet;
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const transitionTime = requireCanonicalTimestamp(issuedAt, "Pairwise route-set transition time");
  if (route.state !== "testing" || route.testedAt !== null ||
      timestampMilliseconds(route.validFrom) < timestampMilliseconds(routeSet.issuedAt) ||
      timestampMilliseconds(route.validFrom) > timestampMilliseconds(transitionTime)) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const retained = routeSet.routes.filter((candidate) => candidate.state !== "revoked");
  if (retained.length >= noctweaveArchitectureV2.maximumRoutes) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  return transitionPairwiseRouteSetV2({
    crypto,
    pqc,
    current: routeSet,
    routes: [...retained, route],
    issuedAt: transitionTime,
    ownerSigningPublicKey,
    ownerSigningSecretKey
  });
}

export async function markPairwiseRouteTestedV2({
  crypto,
  pqc,
  current,
  routeID,
  testedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  const routeSet = validatePairwiseRouteSetV2(current);
  const routeValue = validateFixedWireValue(routeID, "Opaque route ID").rawValue;
  const index = routeSet.routes.findIndex((route) => route.routeID.rawValue === routeValue);
  if (index < 0 || routeSet.routes[index].state !== "testing") {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const time = requireCanonicalTimestamp(testedAt, "Pairwise route test time");
  const route = routeSet.routes[index];
  if (route.testedAt === time) return routeSet;
  if (route.testedAt !== null || timestampMilliseconds(time) < timestampMilliseconds(route.validFrom)) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const routes = [...routeSet.routes];
  routes[index] = replaceRouteLifecycle(route, {
    state: "testing",
    testedAt: time,
    drainAfter: null,
    revokedAt: null
  });
  return transitionPairwiseRouteSetV2({
    crypto,
    pqc,
    current: routeSet,
    routes,
    issuedAt: time,
    ownerSigningPublicKey,
    ownerSigningSecretKey
  });
}

export async function promotePairwiseRouteV2({
  crypto,
  pqc,
  current,
  routeID,
  replacingRouteIDs,
  overlapUntil,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  const routeSet = validatePairwiseRouteSetV2(current);
  const targetID = validateFixedWireValue(routeID, "Opaque route ID").rawValue;
  if (!Array.isArray(replacingRouteIDs) || replacingRouteIDs.length === 0) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const replacements = replacingRouteIDs.map((value) =>
    validateFixedWireValue(value, "Replaced opaque route ID").rawValue
  );
  const replacementSet = new Set(replacements);
  const transitionTime = requireCanonicalTimestamp(issuedAt, "Pairwise route promotion time");
  const overlap = requireCanonicalTimestamp(overlapUntil, "Pairwise route overlap deadline");
  const targetIndex = routeSet.routes.findIndex((route) => route.routeID.rawValue === targetID);
  const target = routeSet.routes[targetIndex];
  if (replacementSet.size !== replacements.length || replacementSet.has(targetID) ||
      timestampMilliseconds(overlap) <= timestampMilliseconds(transitionTime) ||
      !target || target.state !== "testing" || target.testedAt === null ||
      timestampMilliseconds(target.testedAt) > timestampMilliseconds(transitionTime) ||
      replacements.some((id) => !routeSet.routes.some((route) =>
        route.routeID.rawValue === id && route.state === "active"
      ))) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const routes = routeSet.routes.map((route, index) => {
    if (index === targetIndex) {
      return replaceRouteLifecycle(route, {
        state: "active",
        testedAt: route.testedAt,
        drainAfter: null,
        revokedAt: null
      });
    }
    if (!replacementSet.has(route.routeID.rawValue)) return route;
    return replaceRouteLifecycle(route, {
      state: "draining",
      testedAt: route.testedAt,
      drainAfter: overlap,
      revokedAt: null
    });
  });
  return transitionPairwiseRouteSetV2({
    crypto,
    pqc,
    current: routeSet,
    routes,
    issuedAt: transitionTime,
    ownerSigningPublicKey,
    ownerSigningSecretKey
  });
}

// Records a successful targeted probe and promotes the route in one signed
// successor. No unpublished intermediate route-set revision is created.
export async function promoteProbedPairwiseRouteV2({
  crypto,
  pqc,
  current,
  routeID,
  replacingRouteIDs,
  testedAt,
  overlapUntil,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  const routeSet = validatePairwiseRouteSetV2(current);
  const targetID = validateFixedWireValue(routeID, "Opaque route ID").rawValue;
  if (!Array.isArray(replacingRouteIDs) || replacingRouteIDs.length === 0) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const replacements = replacingRouteIDs.map((value) =>
    validateFixedWireValue(value, "Replaced opaque route ID").rawValue
  );
  const replacementSet = new Set(replacements);
  const tested = requireCanonicalTimestamp(testedAt, "Pairwise route probe time");
  const transitionTime = requireCanonicalTimestamp(issuedAt, "Pairwise route promotion time");
  const overlap = requireCanonicalTimestamp(overlapUntil, "Pairwise route overlap deadline");
  const targetIndex = routeSet.routes.findIndex((route) => route.routeID.rawValue === targetID);
  const target = routeSet.routes[targetIndex];
  if (replacementSet.size !== replacements.length || replacementSet.has(targetID) ||
      timestampMilliseconds(tested) > timestampMilliseconds(transitionTime) ||
      timestampMilliseconds(overlap) <= timestampMilliseconds(transitionTime) ||
      !target || target.state !== "testing" || target.testedAt !== null ||
      timestampMilliseconds(tested) < timestampMilliseconds(target.validFrom) ||
      replacements.some((id) => !routeSet.routes.some((route) =>
        route.routeID.rawValue === id && route.state === "active"
      ))) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const routes = routeSet.routes.map((route, index) => {
    if (index === targetIndex) {
      return replaceRouteLifecycle(route, {
        state: "active",
        testedAt: tested,
        drainAfter: null,
        revokedAt: null
      });
    }
    if (!replacementSet.has(route.routeID.rawValue)) return route;
    return replaceRouteLifecycle(route, {
      state: "draining",
      testedAt: route.testedAt,
      drainAfter: overlap,
      revokedAt: null
    });
  });
  return transitionPairwiseRouteSetV2({
    crypto,
    pqc,
    current: routeSet,
    routes,
    issuedAt: transitionTime,
    ownerSigningPublicKey,
    ownerSigningSecretKey
  });
}

export async function revokeDrainedPairwiseRouteV2({
  crypto,
  pqc,
  current,
  routeID,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  return revokePairwiseRoute({
    crypto,
    pqc,
    current,
    routeID,
    issuedAt,
    ownerSigningPublicKey,
    ownerSigningSecretKey,
    expectedState: "draining"
  });
}

export async function abandonTestingPairwiseRouteV2({
  crypto,
  pqc,
  current,
  routeID,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  return revokePairwiseRoute({
    crypto,
    pqc,
    current,
    routeID,
    issuedAt,
    ownerSigningPublicKey,
    ownerSigningSecretKey,
    expectedState: "testing"
  });
}

export function validateContactIntroductionV2(value, { pqc } = {}) {
  const introduction = normalizeContactIntroductionV2(value);
  if (!verifyPairwiseRouteSetV2({
    pqc,
    routeSet: introduction.receiveRoutes,
    ownerSigningPublicKey: introduction.endpointBinding.signingPublicKey
  })) {
    throw new PairwiseOpaqueRouteV2Error(
      "invalidIntroduction",
      "Contact introduction route set is not signed by its endpoint."
    );
  }
  return introduction;
}

function normalizeContactIntroductionV2(value) {
  try {
    requireRecord(value, "Contact introduction");
    requireExactKeys(value, introductionFields, "Contact introduction");
    if (value.version !== noctweavePairwiseOpaqueRoutesV2.version ||
        !boundedString(value.relationshipPseudonym, 512)) {
      throw new TypeError("Contact introduction relationship fields are invalid.");
    }
    requireBase64(
      value.relationshipSigningPublicKey,
      ML_DSA_PUBLIC_KEY_BYTES,
      "Contact introduction relationship signing key"
    );
    requireBase64(
      value.relationshipAgreementPublicKey,
      ML_KEM_PUBLIC_KEY_BYTES,
      "Contact introduction relationship agreement key"
    );
    validateExactRelationshipEndpointBinding(value.endpointBinding);
    const endpointBinding = validateRelationshipEndpointBindingV4(
      value.endpointBinding,
      value.endpointBinding?.prekeyBundle?.createdAt
    );
    const receiveRoutes = validatePairwiseRouteSetV2(value.receiveRoutes);
    requireBase64(
      value.rendezvousTranscriptDigest,
      DIGEST_BYTES,
      "Rendezvous transcript digest"
    );
    const issuedAt = requireCanonicalTimestamp(value.issuedAt, "Contact introduction issue time");
    const expiresAt = requireCanonicalTimestamp(value.expiresAt, "Contact introduction expiry");
    const lifetime = timestampMilliseconds(expiresAt) - timestampMilliseconds(issuedAt);
    if (lifetime <= 0 ||
        lifetime > noctweavePairwiseOpaqueRoutesV2.maximumIntroductionLifetimeSeconds * 1_000 ||
        usablePairwiseRoutesV2(receiveRoutes, issuedAt).length === 0 ||
        usablePairwiseRoutesV2(receiveRoutes, issuedAt).some((route) =>
          timestampMilliseconds(route.expiresAt) <= timestampMilliseconds(expiresAt)
        )) {
      throw new TypeError("Contact introduction is not bound to current active state.");
    }
    requireBase64(value.signature, ML_DSA_SIGNATURE_BYTES, "Contact introduction signature");
    return Object.freeze({
      version: noctweavePairwiseOpaqueRoutesV2.version,
      relationshipPseudonym: value.relationshipPseudonym,
      relationshipSigningPublicKey: value.relationshipSigningPublicKey,
      relationshipAgreementPublicKey: value.relationshipAgreementPublicKey,
      endpointBinding: freezeWire(endpointBinding),
      receiveRoutes,
      rendezvousTranscriptDigest: value.rendezvousTranscriptDigest,
      issuedAt,
      expiresAt,
      signature: value.signature
    });
  } catch (error) {
    if (error instanceof PairwiseOpaqueRouteV2Error && error.code === "invalidIntroduction") {
      throw error;
    }
    throw new PairwiseOpaqueRouteV2Error(
      "invalidIntroduction",
      "Contact introduction is invalid.",
      error
    );
  }
}

export function contactIntroductionV2SignablePayload(value) {
  return Object.freeze(introductionSignatureProjection(normalizeContactIntroductionV2(value)));
}

export function contactIntroductionV2SignableBytes(value) {
  return swiftCanonicalBytes(contactIntroductionV2SignablePayload(value));
}

/**
 * Creates a one-use introduction from explicitly supplied relationship keys.
 * There is deliberately no aggregate-authority parameter: callers must mint a
 * fresh disposable relationship authority and endpoint binding for this peer.
 */
export async function createContactIntroductionV2({
  crypto,
  pqc,
  relationshipPseudonym,
  relationshipSigningPublicKey,
  relationshipSigningSecretKey,
  relationshipAgreementPublicKey,
  endpointBinding,
  receiveRoutes,
  rendezvousTranscriptDigest,
  issuedAt,
  expiresAt
}) {
  try {
    if (typeof pqc?.sign !== "function") {
      throw new TypeError("Contact introduction creation requires ML-DSA signing.");
    }
    const digest = wireDigest(rendezvousTranscriptDigest, "Rendezvous transcript digest");
    await verifyRelationshipEndpointBindingV4({
      crypto,
      pqc,
      authoritySigningPublicKey: relationshipSigningPublicKey,
      endpointBinding,
      now: requireCanonicalTimestamp(issuedAt, "Contact introduction issue time")
    });
    if (receiveRoutes?.relationshipID !== await derivePairwiseRelationshipIDV2({
      crypto,
      rendezvousTranscriptDigest: digest
    })) {
      throw new TypeError("Contact introduction route set belongs to a different relationship.");
    }
    if (!verifyPairwiseRouteSetV2({
      pqc,
      routeSet: receiveRoutes,
      ownerSigningPublicKey: endpointBinding?.signingPublicKey
    })) {
      throw new TypeError("Contact introduction route set is not signed by its endpoint.");
    }
    const unsigned = {
      version: noctweavePairwiseOpaqueRoutesV2.version,
      relationshipPseudonym,
      relationshipSigningPublicKey,
      relationshipAgreementPublicKey,
      endpointBinding,
      receiveRoutes,
      rendezvousTranscriptDigest: digest,
      issuedAt: requireCanonicalTimestamp(issuedAt, "Contact introduction issue time"),
      expiresAt: requireCanonicalTimestamp(expiresAt, "Contact introduction expiry")
    };
    const placeholder = normalizeContactIntroductionV2({
      ...unsigned,
      signature: encodeBase64(new Uint8Array(ML_DSA_SIGNATURE_BYTES))
    });
    const secretKey = requireBase64(
      relationshipSigningSecretKey,
      ML_DSA_SECRET_KEY_BYTES,
      "Contact introduction relationship signing secret key"
    );
    let signature;
    try {
      signature = pqc.sign(
        swiftCanonicalBytes(introductionSignatureProjection(placeholder)),
        secretKey
      );
    } finally {
      secretKey.fill(0);
    }
    if (!(signature instanceof Uint8Array) || signature.byteLength !== ML_DSA_SIGNATURE_BYTES) {
      throw new TypeError("Contact introduction signing returned an invalid signature.");
    }
    return validateContactIntroductionV2(
      { ...unsigned, signature: encodeBase64(signature) },
      { pqc }
    );
  } catch (error) {
    if (error instanceof PairwiseOpaqueRouteV2Error) throw error;
    throw new PairwiseOpaqueRouteV2Error(
      "invalidIntroduction",
      "Contact introduction could not be created.",
      error
    );
  }
}

export async function verifyContactIntroductionV2({
  crypto,
  pqc,
  introduction: introductionValue,
  rendezvousTranscriptDigest,
  at = Date.now()
}) {
  const introduction = validateContactIntroductionV2(introductionValue, { pqc });
  const expectedDigest = wireDigest(rendezvousTranscriptDigest, "Expected rendezvous transcript digest");
  if (!equalBytes(
    requireBase64(introduction.rendezvousTranscriptDigest, DIGEST_BYTES, "Rendezvous transcript digest"),
    requireBase64(expectedDigest, DIGEST_BYTES, "Expected rendezvous transcript digest")
  )) {
    throw new PairwiseOpaqueRouteV2Error(
      "wrongRendezvous",
      "Contact introduction belongs to a different rendezvous."
    );
  }
  if (introduction.receiveRoutes.relationshipID !== await derivePairwiseRelationshipIDV2({
    crypto,
    rendezvousTranscriptDigest: introduction.rendezvousTranscriptDigest
  })) {
    throw new PairwiseOpaqueRouteV2Error(
      "wrongRendezvous",
      "Contact introduction route set belongs to a different relationship."
    );
  }
  const verificationTime = flexibleTimestampMilliseconds(at, "Contact introduction verification time");
  if (verificationTime < timestampMilliseconds(introduction.issuedAt) ||
      verificationTime >= timestampMilliseconds(introduction.expiresAt)) {
    throw new PairwiseOpaqueRouteV2Error(
      "expiredIntroduction",
      "Contact introduction is not valid at the requested time."
    );
  }
  if (typeof pqc?.verify !== "function") {
    throw new TypeError("Contact introduction verification requires ML-DSA verification.");
  }
  let verified = false;
  try {
    verified = pqc.verify(
      swiftCanonicalBytes(introductionSignatureProjection(introduction)),
      requireBase64(introduction.signature, ML_DSA_SIGNATURE_BYTES, "Contact introduction signature"),
      requireBase64(
        introduction.relationshipSigningPublicKey,
        ML_DSA_PUBLIC_KEY_BYTES,
        "Contact introduction relationship signing key"
      )
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    throw new PairwiseOpaqueRouteV2Error(
      "invalidSignature",
      "Contact introduction signature failed verification."
    );
  }
  try {
    await verifyRelationshipEndpointBindingV4({
      crypto,
      pqc,
      authoritySigningPublicKey: introduction.relationshipSigningPublicKey,
      endpointBinding: introduction.endpointBinding,
      now: introduction.endpointBinding.prekeyBundle.createdAt
    });
    if (!verifyPairwiseRouteSetV2({
      pqc,
      routeSet: introduction.receiveRoutes,
      ownerSigningPublicKey: introduction.endpointBinding.signingPublicKey
    })) {
      throw new TypeError("Contact introduction route set signature is invalid.");
    }
  } catch (error) {
    throw new PairwiseOpaqueRouteV2Error(
      "invalidIntroduction",
      "Contact introduction endpoint is not currently certified.",
      error
    );
  }
  return introduction;
}

function signPairwiseRouteSetV2({
  pqc,
  relationshipID,
  ownerEndpointHandle,
  revision,
  previousDigest,
  routes,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  if (typeof pqc?.sign !== "function" || typeof pqc?.verify !== "function") {
    throw new TypeError("Pairwise route-set signing requires ML-DSA signing and verification.");
  }
  const orderedRoutes = routes.map(validateOpaqueSendRouteV2).sort(compareRoutes);
  const unsigned = {
    version: noctweavePairwiseOpaqueRoutesV2.version,
    relationshipID,
    ownerEndpointHandle,
    revision,
    previousDigest,
    routes: orderedRoutes,
    issuedAt
  };
  const placeholder = validatePairwiseRouteSetV2({
    ...unsigned,
    signature: encodeBase64(new Uint8Array(ML_DSA_SIGNATURE_BYTES))
  });
  const secretKey = requireBase64(
    ownerSigningSecretKey,
    ML_DSA_SECRET_KEY_BYTES,
    "Route owner signing secret key"
  );
  let signature;
  try {
    signature = pqc.sign(swiftCanonicalBytes(routeSetSignatureProjection(placeholder)), secretKey);
  } finally {
    secretKey.fill(0);
  }
  if (!(signature instanceof Uint8Array) || signature.byteLength !== ML_DSA_SIGNATURE_BYTES) {
    throw new PairwiseRouteSetV2Error("invalidState", "Route-set signing returned an invalid signature.");
  }
  const result = validatePairwiseRouteSetV2({ ...unsigned, signature: encodeBase64(signature) });
  if (!verifyPairwiseRouteSetV2({ pqc, routeSet: result, ownerSigningPublicKey })) {
    throw new PairwiseRouteSetV2Error("invalidState", "Route-set signing key does not match its endpoint.");
  }
  return result;
}

async function transitionPairwiseRouteSetV2({
  crypto,
  pqc,
  current,
  routes,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey
}) {
  const routeSet = validatePairwiseRouteSetV2(current);
  const transitionTime = requireCanonicalTimestamp(issuedAt, "Pairwise route-set transition time");
  if (!verifyPairwiseRouteSetV2({ pqc, routeSet, ownerSigningPublicKey }) ||
      routeSet.revision >= Number.MAX_SAFE_INTEGER ||
      timestampMilliseconds(transitionTime) < timestampMilliseconds(routeSet.issuedAt)) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  try {
    return signPairwiseRouteSetV2({
      pqc,
      relationshipID: routeSet.relationshipID,
      ownerEndpointHandle: routeSet.ownerEndpointHandle,
      revision: routeSet.revision + 1,
      previousDigest: await pairwiseRouteSetV2Digest(crypto, routeSet),
      routes,
      issuedAt: transitionTime,
      ownerSigningPublicKey,
      ownerSigningSecretKey
    });
  } catch (error) {
    if (error instanceof PairwiseRouteSetV2Error && error.code === "invalidTransition") throw error;
    throw new PairwiseRouteSetV2Error("invalidTransition", "Pairwise route transition is invalid.", error);
  }
}

async function revokePairwiseRoute({
  crypto,
  pqc,
  current,
  routeID,
  issuedAt,
  ownerSigningPublicKey,
  ownerSigningSecretKey,
  expectedState
}) {
  const routeSet = validatePairwiseRouteSetV2(current);
  const routeValue = validateFixedWireValue(routeID, "Opaque route ID").rawValue;
  const index = routeSet.routes.findIndex((route) => route.routeID.rawValue === routeValue);
  if (index < 0) throw new PairwiseRouteSetV2Error("invalidTransition");
  const route = routeSet.routes[index];
  if (route.state === "revoked") return routeSet;
  const transitionTime = requireCanonicalTimestamp(issuedAt, "Pairwise route revocation time");
  const threshold = expectedState === "draining" ? route.drainAfter : route.validFrom;
  if (route.state !== expectedState || threshold === null ||
      timestampMilliseconds(transitionTime) < timestampMilliseconds(threshold)) {
    throw new PairwiseRouteSetV2Error("invalidTransition");
  }
  const routes = [...routeSet.routes];
  routes[index] = replaceRouteLifecycle(route, {
    state: "revoked",
    testedAt: route.testedAt,
    drainAfter: expectedState === "draining" ? route.drainAfter : null,
    revokedAt: transitionTime
  });
  return transitionPairwiseRouteSetV2({
    crypto,
    pqc,
    current: routeSet,
    routes,
    issuedAt: transitionTime,
    ownerSigningPublicKey,
    ownerSigningSecretKey
  });
}

function replaceRouteLifecycle(route, { state, testedAt, drainAfter, revokedAt }) {
  try {
    return validateOpaqueSendRouteV2({
      routeID: route.routeID,
      relay: route.relay,
      sendCapability: route.sendCapability,
      payloadKey: route.payloadKey,
      routeRevision: route.routeRevision,
      policy: route.policy,
      validFrom: route.validFrom,
      expiresAt: route.expiresAt,
      priority: route.priority,
      state,
      testedAt,
      drainAfter,
      revokedAt
    });
  } catch (error) {
    throw new PairwiseRouteSetV2Error("invalidTransition", "Pairwise route lifecycle is invalid.", error);
  }
}

function routeSetSignatureProjection(value) {
  const payload = {
    version: value.version,
    relationshipID: value.relationshipID,
    ownerEndpointHandle: value.ownerEndpointHandle,
    revision: value.revision,
    routes: value.routes,
    issuedAt: value.issuedAt
  };
  if (value.previousDigest !== null) payload.previousDigest = value.previousDigest;
  return payload;
}

function introductionSignatureProjection(value) {
  return {
    version: value.version,
    relationshipPseudonym: value.relationshipPseudonym,
    relationshipSigningPublicKey: value.relationshipSigningPublicKey,
    relationshipAgreementPublicKey: value.relationshipAgreementPublicKey,
    endpointBinding: value.endpointBinding,
    receiveRoutes: value.receiveRoutes,
    rendezvousTranscriptDigest: value.rendezvousTranscriptDigest,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt
  };
}

function validatePairwiseRelayEndpointV2(value) {
  requireRecord(value, "Pairwise relay endpoint");
  const allowed = [
    "host",
    "port",
    "useTLS",
    "transport",
    "tlsCertificateFingerprintSHA256",
    "directorySigningPublicKey"
  ];
  requireAllowedKeys(value, allowed, "Pairwise relay endpoint");
  for (const required of ["host", "port", "useTLS", "transport"]) {
    if (!Object.hasOwn(value, required)) {
      throw new TypeError(`Pairwise relay endpoint is missing ${required}.`);
    }
  }
  if (!boundedString(value.host, 255) || controlCharacterPattern().test(value.host) ||
      typeof value.useTLS !== "boolean" || !relayTransports.has(value.transport)) {
    throw new TypeError("Pairwise relay endpoint is malformed.");
  }
  const relay = {
    host: value.host,
    port: requireInteger(value.port, "Pairwise relay port", 1, 0xffff),
    useTLS: value.useTLS,
    transport: value.transport
  };
  if (value.tlsCertificateFingerprintSHA256 !== undefined) {
    requireBase64(
      value.tlsCertificateFingerprintSHA256,
      DIGEST_BYTES,
      "Relay TLS certificate fingerprint"
    );
    relay.tlsCertificateFingerprintSHA256 = value.tlsCertificateFingerprintSHA256;
  }
  if (value.directorySigningPublicKey !== undefined) {
    requireBase64(
      value.directorySigningPublicKey,
      ML_DSA_PUBLIC_KEY_BYTES,
      "Relay directory signing key"
    );
    relay.directorySigningPublicKey = value.directorySigningPublicKey;
  }
  if (!value.useTLS && !isLiteralLoopback(value.host)) {
    throw new TypeError("Pairwise route capabilities require authenticated confidential transport.");
  }
  return freezeWire(relay);
}

function validateExactRelationshipEndpointBinding(endpoint) {
  requireRecord(endpoint, "Relationship endpoint binding");
  requireExactKeys(endpoint, [
    "version",
    "signingPublicKey",
    "agreementPublicKey",
    "capabilities",
    "prekeyBundle",
    "prekeyPackageSignature",
    "issuedAt",
    "authoritySignature"
  ], "Relationship endpoint binding");
  requireCanonicalTimestamp(endpoint.issuedAt, "Relationship endpoint issue time");
  requireRecord(endpoint.capabilities, "Relationship endpoint capabilities");
  requireExactKeys(
    endpoint.capabilities,
    ["architectureVersion", "modules", "contentTypes"],
    "Relationship endpoint capabilities"
  );
  validateProtocolCapabilityManifest(endpoint.capabilities);
  const bundle = requireRecord(endpoint.prekeyBundle, "Relationship endpoint prekey bundle");
  requireExactKeys(bundle, [
    "version",
    "relationshipSigningKeyDigest",
    "signedPrekey",
    "oneTimePrekeys",
    "createdAt"
  ], "Relationship endpoint prekey bundle");
  requireCanonicalTimestamp(bundle.createdAt, "Relationship endpoint prekey creation time");
  const signedPrekey = requireRecord(bundle.signedPrekey, "Relationship endpoint signed prekey");
  requireExactKeys(signedPrekey, [
    "id",
    "publicKey",
    "issuedAt",
    "expiresAt",
    "signature"
  ], "Relationship endpoint signed prekey");
  requireCanonicalTimestamp(signedPrekey.issuedAt, "Relationship endpoint signed prekey issue time");
  requireCanonicalTimestamp(signedPrekey.expiresAt, "Relationship endpoint signed prekey expiry");
}

function validateFixedWireValue(value, label) {
  requireRecord(value, label);
  requireExactKeys(value, ["rawValue"], label);
  requireNonzeroFixedBase64(value.rawValue, DIGEST_BYTES, label);
  return redactedWire({ rawValue: value.rawValue }, label);
}

function validateRouteLifecycle({ state, validFrom, expiresAt, testedAt, drainAfter, revokedAt }) {
  const validFromMilliseconds = timestampMilliseconds(validFrom);
  const expiresAtMilliseconds = timestampMilliseconds(expiresAt);
  if (testedAt !== null && (
    timestampMilliseconds(testedAt) < validFromMilliseconds ||
    timestampMilliseconds(testedAt) >= expiresAtMilliseconds
  )) {
    throw new TypeError("Pairwise route test time is outside its lifetime.");
  }
  if (drainAfter !== null && (
    timestampMilliseconds(drainAfter) <= validFromMilliseconds ||
    timestampMilliseconds(drainAfter) > expiresAtMilliseconds
  )) {
    throw new TypeError("Pairwise route drain time is outside its lifetime.");
  }
  if (revokedAt !== null && timestampMilliseconds(revokedAt) < validFromMilliseconds) {
    throw new TypeError("Pairwise route revocation predates the route.");
  }
  switch (state) {
  case "testing":
    if (drainAfter !== null || revokedAt !== null) throw new TypeError("Testing route lifecycle is invalid.");
    break;
  case "active":
    if (testedAt === null || drainAfter !== null || revokedAt !== null) {
      throw new TypeError("Active route lifecycle is invalid.");
    }
    break;
  case "draining":
    if (testedAt === null || drainAfter === null || revokedAt !== null) {
      throw new TypeError("Draining route lifecycle is invalid.");
    }
    break;
  case "revoked":
    if (revokedAt === null || (drainAfter !== null &&
        timestampMilliseconds(revokedAt) < timestampMilliseconds(drainAfter))) {
      throw new TypeError("Revoked route lifecycle is invalid.");
    }
    break;
  default:
    throw new TypeError("Pairwise route lifecycle state is invalid.");
  }
}

function optionalCanonicalTimestamp(value, label) {
  return value === null ? null : requireCanonicalTimestamp(value, label);
}

function compareRoutes(left, right) {
  return compareBase64Values(left.routeID.rawValue, right.routeID.rawValue);
}

function compareBase64Values(leftValue, rightValue) {
  const left = requireBase64(leftValue, DIGEST_BYTES, "Opaque route ID");
  const right = requireBase64(rightValue, DIGEST_BYTES, "Opaque route ID");
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function wireDigest(value, label) {
  if (value instanceof Uint8Array) {
    if (value.byteLength !== DIGEST_BYTES) throw new TypeError(`${label} must be 32 bytes.`);
    return encodeBase64(value);
  }
  requireBase64(value, DIGEST_BYTES, label);
  return value;
}

function flexibleTimestampMilliseconds(value, label) {
  const milliseconds = value instanceof Date
    ? value.getTime()
    : typeof value === "number"
      ? value
      : new Date(value).getTime();
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    throw new TypeError(`${label} is invalid.`);
  }
  return milliseconds;
}

function requireExactKeys(value, expected, label) {
  requireRecord(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${label} fields must match the current protocol exactly.`);
  }
}

function requireAllowedKeys(value, allowed, label) {
  requireRecord(value, label);
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) {
    throw new TypeError(`${label} contains an unknown field.`);
  }
}

function redactedWire(value, label) {
  const wire = { ...value };
  Object.defineProperty(wire, "toString", {
    value: () => `${label}(<redacted>)`,
    enumerable: false
  });
  Object.defineProperty(wire, inspectSymbol, {
    value: () => `${label}(<redacted>)`,
    enumerable: false
  });
  return Object.freeze(wire);
}

function boundedString(value, maximumBytes) {
  return typeof value === "string" && value.length > 0 && value.trim() === value &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function canonicalUUID(value) {
  return typeof value === "string" &&
    /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u.test(value);
}

function uuidFromBytes(value) {
  if (!(value instanceof Uint8Array) || value.byteLength !== 16) {
    throw new TypeError("Pairwise relationship digest is invalid.");
  }
  const hex = [...value].map((octet) => octet.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isLiteralLoopback(host) {
  const normalized = host.toLowerCase();
  if (normalized === "localhost" || normalized === "::1" || normalized === "[::1]") return true;
  const octets = normalized.split(".");
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255) &&
    Number(octets[0]) === 127;
}

function controlCharacterPattern() {
  return /[\u0000-\u001F\u007F-\u009F]/u;
}
