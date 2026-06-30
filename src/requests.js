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

  deliver(request, authToken) {
    return withAuth({ type: "deliver", deliver: request }, authToken);
  },

  fetch(request, authToken) {
    return withAuth({ type: "fetch", fetch: request }, authToken);
  },

  acknowledgeMessages(request, authToken) {
    return withAuth({ type: "acknowledgeMessages", acknowledgeMessages: request }, authToken);
  },

  uploadPrekeys(request, authToken) {
    return withAuth({ type: "uploadPrekeys", uploadPrekeys: request }, authToken);
  },

  fetchPrekeyBundle(request, authToken) {
    return withAuth({ type: "fetchPrekeyBundle", fetchPrekeyBundle: request }, authToken);
  },

  createGroup(request, authToken) {
    return withAuth({ type: "createGroup", createGroup: request }, authToken);
  },

  getGroup(request, authToken) {
    return withAuth({ type: "getGroup", getGroup: request }, authToken);
  },

  listGroups(request, authToken) {
    return withAuth({ type: "listGroups", listGroups: request }, authToken);
  },

  listGroupInvitations(request, authToken) {
    return withAuth({ type: "listGroupInvitations", listGroupInvitations: request }, authToken);
  },

  inviteGroupMembers(request, authToken) {
    return withAuth({ type: "inviteGroupMembers", inviteGroupMembers: request }, authToken);
  },

  deliverGroupMessage(request, authToken) {
    return withAuth({ type: "deliverGroupMessage", deliverGroupMessage: request }, authToken);
  },

  fetchGroupMessages(request, authToken) {
    return withAuth({ type: "fetchGroupMessages", fetchGroupMessages: request }, authToken);
  },

  acknowledgeGroupMessages(request, authToken) {
    return withAuth({ type: "acknowledgeGroupMessages", acknowledgeGroupMessages: request }, authToken);
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
