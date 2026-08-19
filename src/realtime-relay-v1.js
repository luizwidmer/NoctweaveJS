import {
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireNonzeroFixedBase64
} from "./private-v2.js";

const MAX_RECORD_BYTES = 512 * 1_024;
const MAX_RECORDS_PER_PAGE = 256;

export const pairingLobbyRelayV1Limits = Object.freeze({
  leaseIDBytes: 16,
  leaseCapabilityBytes: 32,
  maximumAnnouncementBytes: 12 * 1_024,
  minimumLeaseSeconds: 30,
  maximumLeaseSeconds: 120,
  maximumListings: 32
});

export function validateRealtimeRouteCreateRequestV1(value) {
  requireExactRecord(value, [
    "routeCapability", "appendCapability", "readCapability", "expiresAt"
  ], [], "Realtime route create request");
  const capabilities = [
    requireCapability(value.routeCapability, "Realtime route capability"),
    requireCapability(value.appendCapability, "Realtime append capability"),
    requireCapability(value.readCapability, "Realtime read capability")
  ];
  if (new Set(capabilities.map(base64Key)).size !== capabilities.length) {
    throw new TypeError("Realtime route capabilities must be distinct.");
  }
  requireCanonicalTimestamp(value.expiresAt, "Realtime route expiry");
  return value;
}

export function validateRealtimeRouteAppendRequestV1(value) {
  requireExactRecord(value, [
    "routeCapability", "appendCapability", "recordID", "payload"
  ], [], "Realtime route append request");
  requireCapability(value.routeCapability, "Realtime route capability");
  requireCapability(value.appendCapability, "Realtime append capability");
  requireUUID(value.recordID, "Realtime record ID");
  const payload = requireBase64(value.payload, undefined, "Realtime route payload");
  if (payload.byteLength === 0 || payload.byteLength > MAX_RECORD_BYTES) {
    throw new TypeError("Realtime route payload exceeds its protocol bounds.");
  }
  return value;
}

export function validateRealtimeRouteSubscribeRequestV1(value) {
  requireExactRecord(value, [
    "routeCapability", "readCapability", "afterSequence"
  ], [], "Realtime route subscribe request");
  requireCapability(value.routeCapability, "Realtime route capability");
  requireCapability(value.readCapability, "Realtime read capability");
  requireInteger(value.afterSequence, "Realtime route cursor", 0, Number.MAX_SAFE_INTEGER);
  return value;
}

export function validateRealtimeRouteSyncRequestV1(value) {
  requireExactRecord(value, [
    "routeCapability", "subscriptionCapability", "afterSequence", "maxRecords"
  ], [], "Realtime route sync request");
  requireCapability(value.routeCapability, "Realtime route capability");
  requireCapability(value.subscriptionCapability, "Realtime subscription capability");
  requireInteger(value.afterSequence, "Realtime route cursor", 0, Number.MAX_SAFE_INTEGER);
  requireInteger(value.maxRecords, "Realtime route page size", 1, MAX_RECORDS_PER_PAGE);
  return value;
}

export function validateRealtimeRouteUnsubscribeRequestV1(value) {
  requireExactRecord(value, [
    "routeCapability", "subscriptionCapability"
  ], [], "Realtime route unsubscribe request");
  requireCapability(value.routeCapability, "Realtime route capability");
  requireCapability(value.subscriptionCapability, "Realtime subscription capability");
  return value;
}

export function validateRealtimeRouteCreatedV1(value, request = undefined) {
  validateRealtimeRouteCreateRequestV1(value);
  if (request !== undefined) {
    validateRealtimeRouteCreateRequestV1(request);
    if (value.routeCapability !== request.routeCapability ||
        value.appendCapability !== request.appendCapability ||
        value.readCapability !== request.readCapability ||
        value.expiresAt !== request.expiresAt) {
      throw new TypeError("Realtime route response does not match its create request.");
    }
  }
  return value;
}

export function validateRealtimeRouteAppendReceiptV1(value, request = undefined) {
  requireExactRecord(value, ["sequence", "recordID"], [], "Realtime append receipt");
  requireInteger(value.sequence, "Realtime append sequence", 1, Number.MAX_SAFE_INTEGER);
  requireUUID(value.recordID, "Realtime append record ID");
  if (request !== undefined && value.recordID.toUpperCase() !== request.recordID.toUpperCase()) {
    throw new TypeError("Realtime append receipt does not match its request.");
  }
  return value;
}

export function validateRealtimeRouteSubscriptionV1(value, request = undefined) {
  requireExactRecord(value, [
    "subscriptionCapability", "routeCapability", "nextSequence", "expiresAt"
  ], [], "Realtime route subscription");
  requireCapability(value.subscriptionCapability, "Realtime subscription capability");
  requireCapability(value.routeCapability, "Realtime route capability");
  requireInteger(value.nextSequence, "Realtime subscription cursor", 0, Number.MAX_SAFE_INTEGER);
  requireCanonicalTimestamp(value.expiresAt, "Realtime subscription expiry");
  if (request !== undefined && (value.routeCapability !== request.routeCapability ||
      value.nextSequence !== request.afterSequence)) {
    throw new TypeError("Realtime subscription does not match its request.");
  }
  return value;
}

export function validateOpaqueRelaySyncBatchV1(value, request = undefined) {
  requireExactRecord(value, [
    "records", "nextSequence", "highWatermark", "retentionFloor", "hasMore"
  ], [], "Realtime route sync batch");
  if (!Array.isArray(value.records) || value.records.length > MAX_RECORDS_PER_PAGE ||
      (request !== undefined && value.records.length > request.maxRecords)) {
    throw new TypeError("Realtime route batch exceeds its protocol bounds.");
  }
  const seenSequences = new Set();
  const seenIDs = new Set();
  let previous = request?.afterSequence ?? 0;
  for (const record of value.records) {
    requireExactRecord(record, ["sequence", "recordID", "payload"], [], "Realtime route record");
    requireInteger(record.sequence, "Realtime record sequence", 1, Number.MAX_SAFE_INTEGER);
    requireUUID(record.recordID, "Realtime record ID");
    const payload = requireBase64(record.payload, undefined, "Realtime record payload");
    if (payload.byteLength === 0 || payload.byteLength > MAX_RECORD_BYTES ||
        record.sequence <= previous || seenSequences.has(record.sequence) ||
        seenIDs.has(record.recordID.toUpperCase())) {
      throw new TypeError("Realtime route record is invalid or duplicated.");
    }
    previous = record.sequence;
    seenSequences.add(record.sequence);
    seenIDs.add(record.recordID.toUpperCase());
  }
  requireInteger(value.nextSequence, "Realtime next sequence", 0, Number.MAX_SAFE_INTEGER);
  requireInteger(value.highWatermark, "Realtime high watermark", 0, Number.MAX_SAFE_INTEGER);
  requireInteger(value.retentionFloor, "Realtime retention floor", 0, Number.MAX_SAFE_INTEGER);
  if (typeof value.hasMore !== "boolean" || value.nextSequence > value.highWatermark ||
      value.retentionFloor > value.highWatermark + 1 ||
      value.nextSequence !== (value.records.at(-1)?.sequence ?? request?.afterSequence ?? 0) ||
      value.hasMore !== (value.nextSequence < value.highWatermark)) {
    throw new TypeError("Realtime route batch cursor state is invalid.");
  }
  return value;
}

export function validatePairingLobbyAcquireRequestV1(value) {
  requireExactRecord(value, [
    "leaseID", "leaseCapability", "announcement", "ttlSeconds"
  ], [], "Pairing lobby acquire request");
  requireNonzeroFixedBase64(value.leaseID, pairingLobbyRelayV1Limits.leaseIDBytes,
    "Pairing lobby lease ID");
  requireNonzeroFixedBase64(value.leaseCapability, pairingLobbyRelayV1Limits.leaseCapabilityBytes,
    "Pairing lobby lease capability");
  const announcement = requireBase64(value.announcement, undefined, "Pairing lobby announcement");
  if (announcement.byteLength === 0 ||
      announcement.byteLength > pairingLobbyRelayV1Limits.maximumAnnouncementBytes) {
    throw new TypeError("Pairing lobby announcement exceeds its protocol bounds.");
  }
  requireInteger(value.ttlSeconds, "Pairing lobby lease lifetime",
    pairingLobbyRelayV1Limits.minimumLeaseSeconds,
    pairingLobbyRelayV1Limits.maximumLeaseSeconds);
  return value;
}

export function validatePairingLobbyReleaseRequestV1(value) {
  requireExactRecord(value, ["leaseID", "leaseCapability"], [], "Pairing lobby release request");
  requireNonzeroFixedBase64(value.leaseID, pairingLobbyRelayV1Limits.leaseIDBytes,
    "Pairing lobby lease ID");
  requireNonzeroFixedBase64(value.leaseCapability, pairingLobbyRelayV1Limits.leaseCapabilityBytes,
    "Pairing lobby lease capability");
  return value;
}

export function validatePairingLobbyListRequestV1(value) {
  requireExactRecord(value, [], [], "Pairing lobby list request");
  return value;
}

export function validatePairingLobbyLeaseV1(value, request = undefined) {
  requireExactRecord(value, ["leaseID", "announcement", "expiresAt"], [], "Pairing lobby lease");
  requireNonzeroFixedBase64(value.leaseID, pairingLobbyRelayV1Limits.leaseIDBytes,
    "Pairing lobby lease ID");
  const announcement = requireBase64(value.announcement, undefined, "Pairing lobby announcement");
  requireCanonicalTimestamp(value.expiresAt, "Pairing lobby lease expiry");
  if (announcement.byteLength === 0 ||
      announcement.byteLength > pairingLobbyRelayV1Limits.maximumAnnouncementBytes ||
      (request !== undefined && (value.leaseID !== request.leaseID ||
        value.announcement !== request.announcement))) {
    throw new TypeError("Pairing lobby lease does not match its request.");
  }
  return value;
}

export function validatePairingLobbyListingsV1(value) {
  if (!Array.isArray(value) || value.length > pairingLobbyRelayV1Limits.maximumListings) {
    throw new TypeError("Pairing lobby listing response exceeds its protocol bounds.");
  }
  return value.map((lease) => validatePairingLobbyLeaseV1(lease));
}

function requireCapability(value, label) {
  return requireNonzeroFixedBase64(value, 32, label);
}

function requireUUID(value, label) {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function base64Key(value) {
  return Array.from(value).join(",");
}
