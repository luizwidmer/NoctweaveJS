import { swiftISODate } from "./crypto/swift-canonical.js";

const fields = Object.freeze([
  "version",
  "consent",
  "mutedUntil",
  "deliveryReceiptsEnabled",
  "readReceiptsEnabled"
]);
const consentStates = new Set(["pendingRequest", "accepted", "blocked"]);

export const relationshipConsentStatesV2 = Object.freeze([...consentStates]);

/**
 * Local-only policy for one unlinkable relationship. It is never advertised,
 * synchronized through a global account, or interpreted as a reusable block
 * identity.
 */
export function createRelationshipLocalPolicyV2({
  consent = "accepted",
  mutedUntil = null,
  deliveryReceiptsEnabled = true,
  readReceiptsEnabled = true
} = {}) {
  return validateRelationshipLocalPolicyV2({
    version: 2,
    consent,
    mutedUntil: mutedUntil == null ? null : swiftISODate(new Date(mutedUntil)),
    deliveryReceiptsEnabled,
    readReceiptsEnabled
  });
}

export function validateRelationshipLocalPolicyV2(value) {
  requireExactRecord(value);
  if (value.version !== 2 || !consentStates.has(value.consent) ||
      (value.mutedUntil !== null && !Number.isFinite(Date.parse(value.mutedUntil))) ||
      typeof value.deliveryReceiptsEnabled !== "boolean" ||
      typeof value.readReceiptsEnabled !== "boolean") {
    throw new TypeError("Relationship local policy is invalid.");
  }
  if (value.mutedUntil !== null && swiftISODate(new Date(value.mutedUntil)) !== value.mutedUntil) {
    throw new TypeError("Relationship mute time must use the canonical timestamp format.");
  }
  return Object.freeze({ ...value });
}

export function relationshipAllowsUserSendingV2(value) {
  return validateRelationshipLocalPolicyV2(value).consent === "accepted";
}

export function relationshipAcceptsInboundEventsV2(value) {
  return validateRelationshipLocalPolicyV2(value).consent !== "blocked";
}

export function relationshipIsMutedV2(value, at = Date.now()) {
  const policy = validateRelationshipLocalPolicyV2(value);
  if (!Number.isFinite(at)) throw new TypeError("Mute comparison time is invalid.");
  return policy.mutedUntil !== null && at < Date.parse(policy.mutedUntil);
}

function requireExactRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Relationship local policy must be an object.");
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new TypeError("Relationship local-policy fields do not match the current schema.");
  }
}
