import {
  validateOpaqueRouteCommitSubmissionShapeV2,
  validateOpaqueRouteCreateSubmissionShapeV2,
  validateOpaqueRouteEnqueueSubmissionShapeV2,
  validateOpaqueRouteRenewSubmissionShapeV2,
  validateOpaqueRouteSyncSubmissionShapeV2,
  validateOpaqueRouteTeardownSubmissionShapeV2
} from "./opaque-route-relay-v2.js";
import { requireExactRecord, requireRecord } from "./private-v2.js";

const requestTypes = new Set([
  "health",
  "info",
  "createOpaqueRouteV2",
  "renewOpaqueRouteV2",
  "teardownOpaqueRouteV2",
  "appendOpaqueRouteV2",
  "syncOpaqueRouteV2",
  "commitOpaqueRouteV2",
  "uploadAttachment",
  "fetchAttachment"
]);

export const relayRequests = Object.freeze({
  health(authToken) {
    return withAuth({ type: "health" }, authToken);
  },

  info(authToken) {
    return withAuth({ type: "info" }, authToken);
  },

  createOpaqueRoute(request, authToken) {
    return withAuth({
      type: "createOpaqueRouteV2",
      createOpaqueRouteV2: validateOpaqueRouteCreateSubmissionShapeV2(request)
    }, authToken);
  },

  renewOpaqueRoute(request, authToken) {
    return withAuth({
      type: "renewOpaqueRouteV2",
      renewOpaqueRouteV2: validateOpaqueRouteRenewSubmissionShapeV2(request)
    }, authToken);
  },

  teardownOpaqueRoute(request, authToken) {
    return withAuth({
      type: "teardownOpaqueRouteV2",
      teardownOpaqueRouteV2: validateOpaqueRouteTeardownSubmissionShapeV2(request)
    }, authToken);
  },

  enqueueOpaqueRoute(request, authToken) {
    return withAuth({
      type: "appendOpaqueRouteV2",
      appendOpaqueRouteV2: validateOpaqueRouteEnqueueSubmissionShapeV2(request)
    }, authToken);
  },

  syncOpaqueRoute(request, authToken) {
    return withAuth({
      type: "syncOpaqueRouteV2",
      syncOpaqueRouteV2: validateOpaqueRouteSyncSubmissionShapeV2(request)
    }, authToken);
  },

  commitOpaqueRoute(request, authToken) {
    return withAuth({
      type: "commitOpaqueRouteV2",
      commitOpaqueRouteV2: validateOpaqueRouteCommitSubmissionShapeV2(request)
    }, authToken);
  },

  uploadAttachment(request, authToken) {
    requireRecord(request, "Attachment upload request");
    return withAuth({ type: "uploadAttachment", uploadAttachment: request }, authToken);
  },

  fetchAttachment(request, authToken) {
    requireRecord(request, "Attachment retrieval request");
    return withAuth({ type: "fetchAttachment", fetchAttachment: request }, authToken);
  }
});

export function validateRelayRequestEnvelopeV2(value) {
  requireRecord(value, "Relay request");
  if (!requestTypes.has(value.type)) {
    throw new TypeError("Relay request type is not part of the current JavaScript protocol surface.");
  }
  const payloadKey = requestPayloadKey(value.type);
  requireExactRecord(
    value,
    payloadKey === null ? ["type"] : ["type", payloadKey],
    ["authToken"],
    "Relay request"
  );
  validateAuthToken(value.authToken);
  switch (value.type) {
  case "createOpaqueRouteV2":
    validateOpaqueRouteCreateSubmissionShapeV2(value.createOpaqueRouteV2);
    break;
  case "renewOpaqueRouteV2":
    validateOpaqueRouteRenewSubmissionShapeV2(value.renewOpaqueRouteV2);
    break;
  case "teardownOpaqueRouteV2":
    validateOpaqueRouteTeardownSubmissionShapeV2(value.teardownOpaqueRouteV2);
    break;
  case "appendOpaqueRouteV2":
    validateOpaqueRouteEnqueueSubmissionShapeV2(value.appendOpaqueRouteV2);
    break;
  case "syncOpaqueRouteV2":
    validateOpaqueRouteSyncSubmissionShapeV2(value.syncOpaqueRouteV2);
    break;
  case "commitOpaqueRouteV2":
    validateOpaqueRouteCommitSubmissionShapeV2(value.commitOpaqueRouteV2);
    break;
  case "uploadAttachment":
    requireRecord(value.uploadAttachment, "Attachment upload request");
    break;
  case "fetchAttachment":
    requireRecord(value.fetchAttachment, "Attachment retrieval request");
    break;
  default:
    break;
  }
  return value;
}

function requestPayloadKey(type) {
  switch (type) {
  case "createOpaqueRouteV2": return "createOpaqueRouteV2";
  case "renewOpaqueRouteV2": return "renewOpaqueRouteV2";
  case "teardownOpaqueRouteV2": return "teardownOpaqueRouteV2";
  case "appendOpaqueRouteV2": return "appendOpaqueRouteV2";
  case "syncOpaqueRouteV2": return "syncOpaqueRouteV2";
  case "commitOpaqueRouteV2": return "commitOpaqueRouteV2";
  case "uploadAttachment": return "uploadAttachment";
  case "fetchAttachment": return "fetchAttachment";
  default: return null;
  }
}

function withAuth(request, authToken) {
  validateAuthToken(authToken);
  return authToken == null || authToken === ""
    ? request
    : { ...request, authToken };
}

function validateAuthToken(value) {
  if (value != null && (typeof value !== "string" ||
      new TextEncoder().encode(value).byteLength > 4_096)) {
    throw new TypeError("Relay authentication token must be no larger than 4096 UTF-8 bytes.");
  }
}
