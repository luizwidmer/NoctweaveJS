import {
  concatBytes,
  cryptoHmacSha256,
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
  swiftCanonicalBytes,
  timestampMilliseconds,
  uint64Bytes
} from "./private-v2.js";

const encoder = new TextEncoder();
const authorities = new Set(["send", "read", "renew", "teardown"]);
const statuses = new Set(["active", "tornDown"]);
const paddingBuckets = new Set([4_096, 16_384, 65_536]);
const retentionBuckets = new Set([3_600, 21_600, 86_400, 604_800]);
const quotaBuckets = new Set([64, 256, 1_024]);

export const noctweaveOpaqueRoutesV2 = Object.freeze({
  version: 2,
  advertisedByDefault: false,
  credentialBytes: 32,
  digestBytes: 32,
  minimumLeaseDurationSeconds: 5 * 60,
  maximumLeaseDurationSeconds: 30 * 24 * 60 * 60,
  maximumAuthorizationClockSkewSeconds: 5 * 60,
  maximumAuthorizationReplayEntries: 4_096,
  paddingBuckets: Object.freeze([...paddingBuckets]),
  retentionBuckets: Object.freeze([...retentionBuckets]),
  quotaBuckets: Object.freeze([...quotaBuckets])
});

export class OpaqueRouteV2Error extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "OpaqueRouteV2Error";
    this.code = code;
  }
}

export async function createOpaqueRouteClientCapabilityMaterialV2(crypto) {
  const values = [];
  while (values.length < 5) {
    const candidate = await cryptoRandomBytes(crypto, noctweaveOpaqueRoutesV2.credentialBytes);
    const encoded = encodeBase64(candidate);
    if (candidate.some((octet) => octet !== 0) && !values.includes(encoded)) {
      values.push(encoded);
    }
  }
  return freezeWire({
    routeID: { rawValue: values[0] },
    sendCapability: { rawValue: values[1] },
    readCredential: { rawValue: values[2] },
    renewCapability: { rawValue: values[3] },
    teardownCapability: { rawValue: values[4] }
  });
}

export async function createOpaqueRouteIdempotencyKeyV2(crypto) {
  return freezeWire({ rawValue: encodeBase64(await nonzeroRandom(crypto)) });
}

export async function createOpaqueRouteProofNonceV2(crypto) {
  return freezeWire({ rawValue: encodeBase64(await nonzeroRandom(crypto)) });
}

export function validateOpaqueRouteClientCapabilityMaterialV2(value) {
  requireRecord(value, "Opaque route client capability material");
  const result = {
    routeID: validateFixedValue(value.routeID, "Opaque route ID"),
    sendCapability: validateFixedValue(value.sendCapability, "Opaque route send capability"),
    readCredential: validateFixedValue(value.readCredential, "Opaque route read credential"),
    renewCapability: validateFixedValue(value.renewCapability, "Opaque route renew capability"),
    teardownCapability: validateFixedValue(value.teardownCapability, "Opaque route teardown capability")
  };
  const authorities = [
    result.sendCapability.rawValue,
    result.readCredential.rawValue,
    result.renewCapability.rawValue,
    result.teardownCapability.rawValue
  ];
  if (new Set(authorities).size !== authorities.length) {
    throw new OpaqueRouteV2Error("invalidCredential", "Opaque route authorities must be independent.");
  }
  return freezeWire(result);
}

export function createOpaqueRoutePolicyV2({ paddingBucket, retentionBucket, quotaBucket }) {
  return validateOpaqueRoutePolicyV2({
    paddingBucket,
    retentionBucket,
    quotaBucket,
    transportRequirement: "confidentialAuthenticated"
  });
}

export function validateOpaqueRoutePolicyV2(value) {
  requireRecord(value, "Opaque route policy");
  if (!paddingBuckets.has(value.paddingBucket) || !retentionBuckets.has(value.retentionBucket) ||
      !quotaBuckets.has(value.quotaBucket) || value.transportRequirement !== "confidentialAuthenticated") {
    throw new OpaqueRouteV2Error("invalidPolicy");
  }
  if (value.paddingBucket * value.quotaBucket > 64 * 1_024 * 1_024) {
    throw new OpaqueRouteV2Error("invalidPolicy");
  }
  return freezeWire({
    paddingBucket: value.paddingBucket,
    retentionBucket: value.retentionBucket,
    quotaBucket: value.quotaBucket,
    transportRequirement: "confidentialAuthenticated"
  });
}

export function createOpaqueRouteLeaseV2({ issuedAt, expiresAt, policy }) {
  return validateOpaqueRouteLeaseV2({
    issuedAt: requireCanonicalTimestamp(issuedAt, "Opaque route issue time"),
    lastRenewedAt: requireCanonicalTimestamp(issuedAt, "Opaque route issue time"),
    expiresAt: requireCanonicalTimestamp(expiresAt, "Opaque route expiry"),
    renewalSequence: 0,
    policy
  });
}

export function validateOpaqueRouteLeaseV2(value) {
  requireRecord(value, "Opaque route lease");
  const issuedAt = requireCanonicalTimestamp(value.issuedAt, "Opaque route issue time");
  const lastRenewedAt = requireCanonicalTimestamp(value.lastRenewedAt, "Opaque route renewal time");
  const expiresAt = requireCanonicalTimestamp(value.expiresAt, "Opaque route expiry");
  const issued = timestampMilliseconds(issuedAt);
  const renewed = timestampMilliseconds(lastRenewedAt);
  const expiry = timestampMilliseconds(expiresAt);
  const remainingSeconds = (expiry - renewed) / 1_000;
  if (issued > renewed || renewed >= expiry ||
      remainingSeconds < noctweaveOpaqueRoutesV2.minimumLeaseDurationSeconds ||
      remainingSeconds > noctweaveOpaqueRoutesV2.maximumLeaseDurationSeconds) {
    throw new OpaqueRouteV2Error("invalidLease");
  }
  return freezeWire({
    issuedAt,
    lastRenewedAt,
    expiresAt,
    renewalSequence: requireInteger(value.renewalSequence, "Opaque route renewal sequence", 0, Number.MAX_SAFE_INTEGER - 1),
    policy: validateOpaqueRoutePolicyV2(value.policy)
  });
}

export async function opaqueRouteCredentialDigestV2(crypto, authority, credentialValue) {
  if (!authorities.has(authority)) {
    throw new OpaqueRouteV2Error("invalidCredential");
  }
  const credential = validateFixedValue(credentialValue, `Opaque route ${authority} credential`);
  return opaqueRouteDigest(crypto, `org.noctweave.opaque-route.credential.${authority}/v2`, [
    requireBase64(credential.rawValue, 32, "Opaque route credential")
  ]);
}

export async function makeOpaqueRouteAuthorizationProofV2({
  crypto,
  authority,
  routeID,
  operationDigest,
  authorizedAt,
  nonce,
  secret
}) {
  if (!authorities.has(authority)) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  const normalizedRouteID = validateFixedValue(routeID, "Opaque route ID");
  const normalizedNonce = validateFixedValue(nonce, "Opaque route proof nonce");
  const normalizedSecret = validateFixedValue(secret, "Opaque route authorization secret");
  requireBase64(operationDigest, 32, "Opaque route operation digest");
  const normalizedAuthorizedAt = requireCanonicalTimestamp(authorizedAt, "Opaque route authorization time");
  const unsigned = {
    authority,
    nonce: normalizedNonce,
    operationDigest,
    authorizedAt: normalizedAuthorizedAt
  };
  const mac = await cryptoHmacSha256(crypto, {
    key: requireBase64(normalizedSecret.rawValue, 32, "Opaque route authorization secret"),
    data: opaqueRouteAuthorizationMaterial({
      authority,
      routeID: normalizedRouteID,
      operationDigest,
      authorizedAt: normalizedAuthorizedAt,
      nonce: normalizedNonce
    })
  });
  return freezeWire({ ...unsigned, mac: encodeBase64(mac) });
}

export async function verifyOpaqueRouteAuthorizationProofV2({
  crypto,
  proof: proofValue,
  expectedAuthority,
  routeID,
  operationDigest,
  secret
}) {
  const proof = validateOpaqueRouteAuthorizationProofV2(proofValue);
  if (proof.authority !== expectedAuthority || proof.operationDigest !== operationDigest) {
    return false;
  }
  const normalizedRouteID = validateFixedValue(routeID, "Opaque route ID");
  const normalizedSecret = validateFixedValue(secret, "Opaque route authorization secret");
  const expected = await cryptoHmacSha256(crypto, {
    key: requireBase64(normalizedSecret.rawValue, 32, "Opaque route authorization secret"),
    data: opaqueRouteAuthorizationMaterial({
      authority: expectedAuthority,
      routeID: normalizedRouteID,
      operationDigest,
      authorizedAt: proof.authorizedAt,
      nonce: proof.nonce
    })
  });
  return equalBytes(expected, requireBase64(proof.mac, 32, "Opaque route MAC"));
}

export function validateOpaqueRouteAuthorizationProofV2(value) {
  requireRecord(value, "Opaque route authorization proof");
  if (!authorities.has(value.authority)) {
    throw new OpaqueRouteV2Error("invalidAuthorization");
  }
  requireBase64(value.operationDigest, 32, "Opaque route operation digest");
  requireBase64(value.mac, 32, "Opaque route MAC");
  return freezeWire({
    authority: value.authority,
    nonce: validateFixedValue(value.nonce, "Opaque route proof nonce"),
    operationDigest: value.operationDigest,
    authorizedAt: requireCanonicalTimestamp(value.authorizedAt, "Opaque route authorization time"),
    mac: value.mac
  });
}

export async function makeOpaqueRouteCreateRequestV2({ crypto, capabilities: capabilityValue, lease: leaseValue, idempotencyKey, nonce }) {
  const capabilities = validateOpaqueRouteClientCapabilityMaterialV2(capabilityValue);
  const lease = validateOpaqueRouteLeaseV2(leaseValue);
  if (lease.renewalSequence !== 0) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  const unsigned = freezeWire({
    version: 2,
    routeID: capabilities.routeID,
    sendCapabilityDigest: encodeBase64(await opaqueRouteCredentialDigestV2(crypto, "send", capabilities.sendCapability)),
    readCredentialDigest: encodeBase64(await opaqueRouteCredentialDigestV2(crypto, "read", capabilities.readCredential)),
    renewCapabilityDigest: encodeBase64(await opaqueRouteCredentialDigestV2(crypto, "renew", capabilities.renewCapability)),
    teardownCapabilityDigest: encodeBase64(await opaqueRouteCredentialDigestV2(crypto, "teardown", capabilities.teardownCapability)),
    lease,
    idempotencyKey: validateFixedValue(idempotencyKey, "Opaque route idempotency key")
  });
  const transitionDigest = encodeBase64(await opaqueRouteDigest(
    crypto,
    "org.noctweave.opaque-route.create/v2",
    [swiftCanonicalBytes(unsigned)]
  ));
  const authorization = await makeOpaqueRouteAuthorizationProofV2({
    crypto,
    authority: "renew",
    routeID: capabilities.routeID,
    operationDigest: transitionDigest,
    authorizedAt: lease.issuedAt,
    nonce,
    secret: capabilities.renewCapability
  });
  return freezeWire({ ...unsigned, authorization });
}

export async function makeOpaqueRouteRenewRequestV2({
  crypto,
  capabilities: capabilityValue,
  current: currentValue,
  newExpiry,
  authorizedAt,
  idempotencyKey,
  nonce
}) {
  const capabilities = validateOpaqueRouteClientCapabilityMaterialV2(capabilityValue);
  const current = validateOpaqueReceiveRouteV2(currentValue);
  if (current.routeID.rawValue !== capabilities.routeID.rawValue || current.status !== "active") {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  const unsigned = freezeWire({
    version: 2,
    routeID: capabilities.routeID,
    renewalSequence: current.lease.renewalSequence + 1,
    previousTransitionDigest: current.lastTransitionDigest,
    newExpiry: requireCanonicalTimestamp(newExpiry, "Opaque route new expiry"),
    authorizedAt: requireCanonicalTimestamp(authorizedAt, "Opaque route authorization time"),
    idempotencyKey: validateFixedValue(idempotencyKey, "Opaque route idempotency key")
  });
  const transitionDigest = encodeBase64(await opaqueRouteDigest(
    crypto,
    "org.noctweave.opaque-route.renew/v2",
    [swiftCanonicalBytes(unsigned)]
  ));
  const authorization = await makeOpaqueRouteAuthorizationProofV2({
    crypto,
    authority: "renew",
    routeID: capabilities.routeID,
    operationDigest: transitionDigest,
    authorizedAt: unsigned.authorizedAt,
    nonce,
    secret: capabilities.renewCapability
  });
  return freezeWire({ ...unsigned, authorization });
}

export async function makeOpaqueRouteTeardownRequestV2({
  crypto,
  capabilities: capabilityValue,
  current: currentValue,
  authorizedAt,
  idempotencyKey,
  nonce
}) {
  const capabilities = validateOpaqueRouteClientCapabilityMaterialV2(capabilityValue);
  const current = validateOpaqueReceiveRouteV2(currentValue);
  if (current.routeID.rawValue !== capabilities.routeID.rawValue) {
    throw new OpaqueRouteV2Error("routeMismatch");
  }
  const unsigned = freezeWire({
    version: 2,
    routeID: capabilities.routeID,
    renewalSequence: current.lease.renewalSequence,
    previousTransitionDigest: current.lastTransitionDigest,
    authorizedAt: requireCanonicalTimestamp(authorizedAt, "Opaque route authorization time"),
    idempotencyKey: validateFixedValue(idempotencyKey, "Opaque route idempotency key")
  });
  const transitionDigest = encodeBase64(await opaqueRouteDigest(
    crypto,
    "org.noctweave.opaque-route.teardown/v2",
    [swiftCanonicalBytes(unsigned)]
  ));
  const authorization = await makeOpaqueRouteAuthorizationProofV2({
    crypto,
    authority: "teardown",
    routeID: capabilities.routeID,
    operationDigest: transitionDigest,
    authorizedAt: unsigned.authorizedAt,
    nonce,
    secret: capabilities.teardownCapability
  });
  return freezeWire({ ...unsigned, authorization });
}

export async function opaqueRouteTransitionDigestV2(crypto, value) {
  requireRecord(value, "Opaque route transition request");
  let domain;
  let unsigned;
  if ("sendCapabilityDigest" in value) {
    domain = "org.noctweave.opaque-route.create/v2";
    unsigned = createUnsignedProjection(value);
  } else if ("newExpiry" in value) {
    domain = "org.noctweave.opaque-route.renew/v2";
    unsigned = renewUnsignedProjection(value);
  } else {
    domain = "org.noctweave.opaque-route.teardown/v2";
    unsigned = teardownUnsignedProjection(value);
  }
  return opaqueRouteDigest(crypto, domain, [swiftCanonicalBytes(unsigned)]);
}

export async function validateOpaqueRouteCreateRequestV2(crypto, value) {
  requireRecord(value, "Opaque route create request");
  const unsigned = createUnsignedProjection(value);
  const digests = [
    unsigned.sendCapabilityDigest,
    unsigned.readCredentialDigest,
    unsigned.renewCapabilityDigest,
    unsigned.teardownCapabilityDigest
  ];
  if (unsigned.version !== 2 || unsigned.lease.renewalSequence !== 0 || new Set(digests).size !== 4) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  const transitionDigest = encodeBase64(await opaqueRouteTransitionDigestV2(crypto, unsigned));
  const authorization = validateOpaqueRouteAuthorizationProofV2(value.authorization);
  if (authorization.authority !== "renew" || authorization.authorizedAt !== unsigned.lease.issuedAt ||
      authorization.operationDigest !== transitionDigest) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  return freezeWire({ ...unsigned, authorization });
}

export async function validateOpaqueRouteRenewRequestV2(crypto, value) {
  const unsigned = renewUnsignedProjection(value);
  if (unsigned.version !== 2 || unsigned.renewalSequence < 1) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  const transitionDigest = encodeBase64(await opaqueRouteTransitionDigestV2(crypto, unsigned));
  const authorization = validateOpaqueRouteAuthorizationProofV2(value.authorization);
  if (authorization.authority !== "renew" || authorization.authorizedAt !== unsigned.authorizedAt ||
      authorization.operationDigest !== transitionDigest) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  return freezeWire({ ...unsigned, authorization });
}

export async function validateOpaqueRouteTeardownRequestV2(crypto, value) {
  const unsigned = teardownUnsignedProjection(value);
  const transitionDigest = encodeBase64(await opaqueRouteTransitionDigestV2(crypto, unsigned));
  const authorization = validateOpaqueRouteAuthorizationProofV2(value.authorization);
  if (authorization.authority !== "teardown" || authorization.authorizedAt !== unsigned.authorizedAt ||
      authorization.operationDigest !== transitionDigest) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  return freezeWire({ ...unsigned, authorization });
}

export async function createOpaqueReceiveRouteV2({
  crypto,
  request: requestValue,
  presentedRenewCapability,
  existing = null,
  confidentialTransport,
  receivedAt
}) {
  requireConfidentialTransport(confidentialTransport);
  const request = await validateOpaqueRouteCreateRequestV2(crypto, requestValue);
  const capability = validateFixedValue(presentedRenewCapability, "Opaque route renew capability");
  const now = requireCanonicalTimestamp(receivedAt, "Opaque route receive time");
  validateAuthorizationTime(request.authorization.authorizedAt, now);
  const transitionDigest = encodeBase64(await opaqueRouteTransitionDigestV2(crypto, request));
  const credentialDigest = encodeBase64(await opaqueRouteCredentialDigestV2(crypto, "renew", capability));
  if (credentialDigest !== request.renewCapabilityDigest || !await verifyOpaqueRouteAuthorizationProofV2({
    crypto,
    proof: request.authorization,
    expectedAuthority: "renew",
    routeID: request.routeID,
    operationDigest: transitionDigest,
    secret: capability
  })) {
    throw new OpaqueRouteV2Error("invalidAuthorization");
  }
  if (existing !== null) {
    const state = validateOpaqueReceiveRouteV2(existing);
    if (state.routeID.rawValue !== request.routeID.rawValue) {
      throw new OpaqueRouteV2Error("routeMismatch");
    }
    if (state.status === "tornDown") {
      throw new OpaqueRouteV2Error("routeTornDown");
    }
    if (state.creationIdempotencyKey.rawValue === request.idempotencyKey.rawValue) {
      if (state.creationDigest !== transitionDigest) {
        throw new OpaqueRouteV2Error("idempotencyConflict");
      }
      return state;
    }
    throw new OpaqueRouteV2Error("routeAlreadyExists");
  }
  requireLeaseActive(request.lease, now);
  return validateOpaqueReceiveRouteV2({
    version: 2,
    routeID: request.routeID,
    sendCapabilityDigest: request.sendCapabilityDigest,
    readCredentialDigest: request.readCredentialDigest,
    renewCapabilityDigest: request.renewCapabilityDigest,
    teardownCapabilityDigest: request.teardownCapabilityDigest,
    lease: request.lease,
    status: "active",
    createdAt: request.lease.issuedAt,
    creationIdempotencyKey: request.idempotencyKey,
    creationDigest: transitionDigest,
    lastIdempotencyKey: request.idempotencyKey,
    lastTransitionDigest: transitionDigest
  });
}

export async function renewOpaqueReceiveRouteV2({ crypto, current: currentValue, request: requestValue, presentedCapability, confidentialTransport, receivedAt }) {
  requireConfidentialTransport(confidentialTransport);
  const current = validateOpaqueReceiveRouteV2(currentValue);
  const request = await validateOpaqueRouteRenewRequestV2(crypto, requestValue);
  const capability = validateFixedValue(presentedCapability, "Opaque route renew capability");
  const now = requireCanonicalTimestamp(receivedAt, "Opaque route receive time");
  if (request.routeID.rawValue !== current.routeID.rawValue) {
    throw new OpaqueRouteV2Error("routeMismatch");
  }
  const transitionDigest = encodeBase64(await opaqueRouteTransitionDigestV2(crypto, request));
  if (request.idempotencyKey.rawValue === current.lastIdempotencyKey.rawValue) {
    if (transitionDigest !== current.lastTransitionDigest) {
      throw new OpaqueRouteV2Error("idempotencyConflict");
    }
    await requireValidCapabilityProof({ crypto, current, request, capability, authority: "renew", transitionDigest });
    return current;
  }
  if (current.status !== "active") throw new OpaqueRouteV2Error("routeTornDown");
  requireLeaseActive(current.lease, now);
  const expectedSequence = current.lease.renewalSequence + 1;
  if (request.renewalSequence < expectedSequence) {
    throw new OpaqueRouteV2Error(request.renewalSequence === current.lease.renewalSequence ? "transitionFork" : "staleTransition");
  }
  if (request.renewalSequence !== expectedSequence) throw new OpaqueRouteV2Error("transitionOutOfOrder");
  if (request.previousTransitionDigest !== current.lastTransitionDigest) throw new OpaqueRouteV2Error("transitionFork");
  validateAuthorizationTime(request.authorization.authorizedAt, now);
  if (timestampMilliseconds(request.authorizedAt) < timestampMilliseconds(current.lease.lastRenewedAt)) {
    throw new OpaqueRouteV2Error("invalidAuthorization");
  }
  await requireValidCapabilityProof({ crypto, current, request, capability, authority: "renew", transitionDigest });
  const lease = renewLease(current.lease, request.authorizedAt, request.newExpiry);
  return validateOpaqueReceiveRouteV2({
    ...current,
    lease,
    lastIdempotencyKey: request.idempotencyKey,
    lastTransitionDigest: transitionDigest
  });
}

export async function teardownOpaqueReceiveRouteV2({ crypto, current: currentValue, request: requestValue, presentedCapability, confidentialTransport, receivedAt }) {
  requireConfidentialTransport(confidentialTransport);
  const current = validateOpaqueReceiveRouteV2(currentValue);
  const request = await validateOpaqueRouteTeardownRequestV2(crypto, requestValue);
  const capability = validateFixedValue(presentedCapability, "Opaque route teardown capability");
  const now = requireCanonicalTimestamp(receivedAt, "Opaque route receive time");
  if (request.routeID.rawValue !== current.routeID.rawValue) throw new OpaqueRouteV2Error("routeMismatch");
  const transitionDigest = encodeBase64(await opaqueRouteTransitionDigestV2(crypto, request));
  if (request.idempotencyKey.rawValue === current.lastIdempotencyKey.rawValue) {
    if (transitionDigest !== current.lastTransitionDigest) throw new OpaqueRouteV2Error("idempotencyConflict");
    await requireValidCapabilityProof({ crypto, current, request, capability, authority: "teardown", transitionDigest });
    return current;
  }
  if (current.status !== "active") throw new OpaqueRouteV2Error("routeTornDown");
  if (request.renewalSequence < current.lease.renewalSequence) throw new OpaqueRouteV2Error("staleTransition");
  if (request.renewalSequence !== current.lease.renewalSequence) throw new OpaqueRouteV2Error("transitionOutOfOrder");
  if (request.previousTransitionDigest !== current.lastTransitionDigest) throw new OpaqueRouteV2Error("transitionFork");
  validateAuthorizationTime(request.authorization.authorizedAt, now);
  await requireValidCapabilityProof({ crypto, current, request, capability, authority: "teardown", transitionDigest });
  return validateOpaqueReceiveRouteV2({
    ...current,
    status: "tornDown",
    tornDownAt: now,
    lastIdempotencyKey: request.idempotencyKey,
    lastTransitionDigest: transitionDigest
  });
}

export function validateOpaqueReceiveRouteV2(value) {
  requireRecord(value, "Opaque receive route");
  if (value.version !== 2 || !statuses.has(value.status)) throw new OpaqueRouteV2Error("invalidRequest");
  const digests = [value.sendCapabilityDigest, value.readCredentialDigest, value.renewCapabilityDigest, value.teardownCapabilityDigest];
  digests.forEach((digest) => requireBase64(digest, 32, "Opaque route credential digest"));
  if (new Set(digests).size !== 4) throw new OpaqueRouteV2Error("invalidRequest");
  const lease = validateOpaqueRouteLeaseV2(value.lease);
  const createdAt = requireCanonicalTimestamp(value.createdAt, "Opaque route creation time");
  if (createdAt !== lease.issuedAt) throw new OpaqueRouteV2Error("invalidRequest");
  const result = {
    version: 2,
    routeID: validateFixedValue(value.routeID, "Opaque route ID"),
    sendCapabilityDigest: value.sendCapabilityDigest,
    readCredentialDigest: value.readCredentialDigest,
    renewCapabilityDigest: value.renewCapabilityDigest,
    teardownCapabilityDigest: value.teardownCapabilityDigest,
    lease,
    status: value.status,
    createdAt,
    creationIdempotencyKey: validateFixedValue(value.creationIdempotencyKey, "Opaque route creation idempotency key"),
    creationDigest: validateDigestString(value.creationDigest, "Opaque route creation digest"),
    lastIdempotencyKey: validateFixedValue(value.lastIdempotencyKey, "Opaque route last idempotency key"),
    lastTransitionDigest: validateDigestString(value.lastTransitionDigest, "Opaque route last transition digest")
  };
  if (value.status === "tornDown") {
    result.tornDownAt = requireCanonicalTimestamp(value.tornDownAt, "Opaque route teardown time");
    if (timestampMilliseconds(result.tornDownAt) < timestampMilliseconds(createdAt)) throw new OpaqueRouteV2Error("invalidRequest");
  } else if (value.tornDownAt !== undefined && value.tornDownAt !== null) {
    throw new OpaqueRouteV2Error("invalidRequest");
  }
  return freezeWire(result);
}

export async function makeOpaqueRouteUseAuthorizationV2({ crypto, capabilities: capabilityValue, authority, operationDigest, authorizedAt, nonce }) {
  if (authority !== "send" && authority !== "read") throw new OpaqueRouteV2Error("invalidRequest");
  const capabilities = validateOpaqueRouteClientCapabilityMaterialV2(capabilityValue);
  return makeOpaqueRouteAuthorizationProofV2({
    crypto,
    authority,
    routeID: capabilities.routeID,
    operationDigest: validateDigestString(operationDigest, "Opaque route operation digest"),
    authorizedAt,
    nonce,
    secret: authority === "send" ? capabilities.sendCapability : capabilities.readCredential
  });
}

export function createOpaqueRouteAuthorizationReplayLedgerV2() {
  return freezeWire({ consumedDigests: [] });
}

export function validateOpaqueRouteAuthorizationReplayLedgerV2(value) {
  requireRecord(value, "Opaque route replay ledger");
  if (!Array.isArray(value.consumedDigests) ||
      value.consumedDigests.length > noctweaveOpaqueRoutesV2.maximumAuthorizationReplayEntries) {
    throw new OpaqueRouteV2Error("invalidAuthorization");
  }
  value.consumedDigests.forEach((digest) => requireBase64(digest, 32, "Opaque route replay digest"));
  if (new Set(value.consumedDigests).size !== value.consumedDigests.length) {
    throw new OpaqueRouteV2Error("invalidAuthorization");
  }
  return freezeWire({ consumedDigests: [...value.consumedDigests].sort(compareBase64Bytes) });
}

export async function authorizeOpaqueRouteUseV2({
  crypto,
  current: currentValue,
  proof: proofValue,
  operationDigest,
  presentedCredential,
  authority,
  confidentialTransport,
  receivedAt,
  replayLedger: replayLedgerValue
}) {
  requireConfidentialTransport(confidentialTransport);
  if (authority !== "send" && authority !== "read") throw new OpaqueRouteV2Error("invalidRequest");
  const current = validateOpaqueReceiveRouteV2(currentValue);
  if (current.status !== "active") throw new OpaqueRouteV2Error("routeTornDown");
  const now = requireCanonicalTimestamp(receivedAt, "Opaque route receive time");
  requireLeaseActive(current.lease, now);
  const proof = validateOpaqueRouteAuthorizationProofV2(proofValue);
  validateAuthorizationTime(proof.authorizedAt, now);
  const credential = validateFixedValue(presentedCredential, "Opaque route presented credential");
  const digest = validateDigestString(operationDigest, "Opaque route operation digest");
  const expectedCredentialDigest = authority === "send" ? current.sendCapabilityDigest : current.readCredentialDigest;
  if (encodeBase64(await opaqueRouteCredentialDigestV2(crypto, authority, credential)) !== expectedCredentialDigest ||
      !await verifyOpaqueRouteAuthorizationProofV2({
        crypto,
        proof,
        expectedAuthority: authority,
        routeID: current.routeID,
        operationDigest: digest,
        secret: credential
      })) {
    throw new OpaqueRouteV2Error("invalidAuthorization");
  }
  const ledger = validateOpaqueRouteAuthorizationReplayLedgerV2(replayLedgerValue);
  const replayDigest = encodeBase64(await opaqueRouteDigest(
    crypto,
    "org.noctweave.opaque-route.authorization-replay/v2",
    [swiftCanonicalBytes(proof)]
  ));
  if (ledger.consumedDigests.includes(replayDigest)) throw new OpaqueRouteV2Error("authorizationReplay");
  if (ledger.consumedDigests.length >= noctweaveOpaqueRoutesV2.maximumAuthorizationReplayEntries) {
    throw new OpaqueRouteV2Error("authorizationLedgerExhausted");
  }
  return freezeWire({ consumedDigests: [...ledger.consumedDigests, replayDigest].sort(compareBase64Bytes) });
}

function createUnsignedProjection(value) {
  requireRecord(value, "Opaque route create request");
  const result = {
    version: value.version,
    routeID: validateFixedValue(value.routeID, "Opaque route ID"),
    sendCapabilityDigest: validateDigestString(value.sendCapabilityDigest, "Opaque route send digest"),
    readCredentialDigest: validateDigestString(value.readCredentialDigest, "Opaque route read digest"),
    renewCapabilityDigest: validateDigestString(value.renewCapabilityDigest, "Opaque route renew digest"),
    teardownCapabilityDigest: validateDigestString(value.teardownCapabilityDigest, "Opaque route teardown digest"),
    lease: validateOpaqueRouteLeaseV2(value.lease),
    idempotencyKey: validateFixedValue(value.idempotencyKey, "Opaque route idempotency key")
  };
  return freezeWire(result);
}

function renewUnsignedProjection(value) {
  requireRecord(value, "Opaque route renew request");
  return freezeWire({
    version: value.version,
    routeID: validateFixedValue(value.routeID, "Opaque route ID"),
    renewalSequence: requireInteger(value.renewalSequence, "Opaque route renewal sequence", 1, Number.MAX_SAFE_INTEGER),
    previousTransitionDigest: validateDigestString(value.previousTransitionDigest, "Opaque route previous transition digest"),
    newExpiry: requireCanonicalTimestamp(value.newExpiry, "Opaque route new expiry"),
    authorizedAt: requireCanonicalTimestamp(value.authorizedAt, "Opaque route authorization time"),
    idempotencyKey: validateFixedValue(value.idempotencyKey, "Opaque route idempotency key")
  });
}

function teardownUnsignedProjection(value) {
  requireRecord(value, "Opaque route teardown request");
  return freezeWire({
    version: value.version,
    routeID: validateFixedValue(value.routeID, "Opaque route ID"),
    renewalSequence: requireInteger(value.renewalSequence, "Opaque route renewal sequence", 0, Number.MAX_SAFE_INTEGER),
    previousTransitionDigest: validateDigestString(value.previousTransitionDigest, "Opaque route previous transition digest"),
    authorizedAt: requireCanonicalTimestamp(value.authorizedAt, "Opaque route authorization time"),
    idempotencyKey: validateFixedValue(value.idempotencyKey, "Opaque route idempotency key")
  });
}

function opaqueRouteAuthorizationMaterial({ authority, routeID, operationDigest, authorizedAt, nonce }) {
  return swiftCanonicalBytes({
    version: 2,
    authority,
    routeID,
    operationDigest,
    authorizedAt,
    nonce
  });
}

async function opaqueRouteDigest(crypto, domain, components) {
  return cryptoSha256(crypto, concatBytes(
    encoder.encode(domain),
    ...components.flatMap((component) => [uint64Bytes(component.byteLength), component])
  ));
}

async function requireValidCapabilityProof({ crypto, current, request, capability, authority, transitionDigest }) {
  const expectedDigest = authority === "renew" ? current.renewCapabilityDigest : current.teardownCapabilityDigest;
  if (encodeBase64(await opaqueRouteCredentialDigestV2(crypto, authority, capability)) !== expectedDigest ||
      !await verifyOpaqueRouteAuthorizationProofV2({
        crypto,
        proof: request.authorization,
        expectedAuthority: authority,
        routeID: current.routeID,
        operationDigest: transitionDigest,
        secret: capability
      })) {
    throw new OpaqueRouteV2Error("invalidAuthorization");
  }
}

function renewLease(current, renewedAtValue, newExpiryValue) {
  const renewedAt = requireCanonicalTimestamp(renewedAtValue, "Opaque route renewal time");
  const newExpiry = requireCanonicalTimestamp(newExpiryValue, "Opaque route new expiry");
  if (timestampMilliseconds(renewedAt) < timestampMilliseconds(current.lastRenewedAt) ||
      timestampMilliseconds(renewedAt) >= timestampMilliseconds(current.expiresAt) ||
      timestampMilliseconds(newExpiry) <= timestampMilliseconds(current.expiresAt)) {
    throw new OpaqueRouteV2Error("invalidLease");
  }
  return validateOpaqueRouteLeaseV2({
    issuedAt: current.issuedAt,
    lastRenewedAt: renewedAt,
    expiresAt: newExpiry,
    renewalSequence: current.renewalSequence + 1,
    policy: current.policy
  });
}

function requireLeaseActive(lease, at) {
  const instant = timestampMilliseconds(at);
  if (instant < timestampMilliseconds(lease.issuedAt) || instant >= timestampMilliseconds(lease.expiresAt)) {
    throw new OpaqueRouteV2Error("routeExpired");
  }
}

function validateAuthorizationTime(authorizedAt, receivedAt) {
  if (Math.abs(timestampMilliseconds(receivedAt) - timestampMilliseconds(authorizedAt)) >
      noctweaveOpaqueRoutesV2.maximumAuthorizationClockSkewSeconds * 1_000) {
    throw new OpaqueRouteV2Error("authorizationExpired");
  }
}

function requireConfidentialTransport(value) {
  if (value !== true) throw new OpaqueRouteV2Error("confidentialTransportRequired");
}

function validateFixedValue(value, label) {
  requireRecord(value, label);
  requireNonzeroFixedBase64(value.rawValue, 32, label);
  return freezeWire({ rawValue: value.rawValue });
}

function validateDigestString(value, label) {
  requireBase64(value, 32, label);
  return value;
}

async function nonzeroRandom(crypto) {
  while (true) {
    const value = await cryptoRandomBytes(crypto, 32);
    if (value.some((octet) => octet !== 0)) return value;
  }
}

function compareBase64Bytes(left, right) {
  const leftBytes = requireBase64(left, 32, "Replay digest");
  const rightBytes = requireBase64(right, 32, "Replay digest");
  for (let index = 0; index < 32; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return leftBytes[index] - rightBytes[index];
  }
  return 0;
}
