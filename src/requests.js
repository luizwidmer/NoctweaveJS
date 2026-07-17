import {
  validateCommitMailboxCursorRequest,
  validateRegisterMailboxConsumerRequest,
  validateRetireInboxRequest,
  validateRevokeMailboxConsumerRequest,
  validateSyncMailboxRequest
} from "./architecture-v2.js";
import { validateProtocolEnvelopeV1 } from "./crypto/noctweave-wire.js";

export const relayRequests = {
  health(authToken) {
    return withAuth({ type: "health" }, authToken);
  },

  info(authToken) {
    return withAuth({ type: "info" }, authToken);
  },

  registerInbox(request, authToken) {
    return withAuth({ type: "registerInbox", registerInbox: request }, authToken);
  },

  retireInbox(request, authToken) {
    return withAuth({
      type: "retireInbox",
      retireInbox: validateRetireInboxRequest(request)
    }, authToken);
  },

  deliver(request, authToken) {
    return withAuth({
      type: "deliver",
      deliver: {
        ...request,
        envelope: validateProtocolEnvelopeV1(request?.envelope)
      }
    }, authToken);
  },

  fetch(request, authToken) {
    return withAuth({ type: "fetch", fetch: request }, authToken);
  },

  registerMailboxConsumer(request, authToken) {
    return withAuth({
      type: "registerMailboxConsumer",
      registerMailboxConsumer: validateRegisterMailboxConsumerRequest(request)
    }, authToken);
  },

  syncMailbox(request, authToken) {
    return withAuth({
      type: "syncMailbox",
      syncMailbox: validateSyncMailboxRequest(request)
    }, authToken);
  },

  commitMailboxCursor(request, authToken) {
    return withAuth({
      type: "commitMailboxCursor",
      commitMailboxCursor: validateCommitMailboxCursorRequest(request)
    }, authToken);
  },

  revokeMailboxConsumer(request, authToken) {
    return withAuth({
      type: "revokeMailboxConsumer",
      revokeMailboxConsumer: validateRevokeMailboxConsumerRequest(request)
    }, authToken);
  },

  uploadAttachment(request, authToken) {
    return withAuth({ type: "uploadAttachment", uploadAttachment: request }, authToken);
  },

  fetchAttachment(request, authToken) {
    return withAuth({ type: "fetchAttachment", fetchAttachment: request }, authToken);
  }
};

function withAuth(request, authToken) {
  if (authToken == null || authToken === "") {
    return request;
  }
  return { ...request, authToken };
}
