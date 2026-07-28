import { initializeAppearanceControl } from "./theme.js";

initializeAppearanceControl();

const $ = (selector) => document.querySelector(selector);
const elements = {
  companionStatus: $("#companionStatus"),
  setupPanel: $("#setupPanel"),
  createPanel: $("#createPanel"),
  groupListPanel: $("#groupListPanel"),
  setupCompanion: $("#setupCompanion"),
  storageProfile: $("#storageProfile"),
  groupPersonaName: $("#groupPersonaName"),
  groupRelay: $("#groupRelay"),
  groupName: $("#groupName"),
  createRelay: $("#createRelay"),
  createGroup: $("#createGroup"),
  refreshGroups: $("#refreshGroups"),
  groupList: $("#groupList"),
  selectedGroupName: $("#selectedGroupName"),
  selectedGroupID: $("#selectedGroupID"),
  syncGroup: $("#syncGroup"),
  groupMessages: $("#groupMessages"),
  groupMessage: $("#groupMessage"),
  sendGroupMessage: $("#sendGroupMessage"),
  groupMessageStatus: $("#groupMessageStatus"),
  admissionPanel: $("#admissionPanel"),
  admissionRequest: $("#admissionRequest"),
  admissionResponse: $("#admissionResponse"),
  acceptAdmission: $("#acceptAdmission"),
  copyAdmissionResponse: $("#copyAdmissionResponse"),
  admissionStatus: $("#admissionStatus")
};

const state = {
  selectedGroupID: null,
  groups: [],
  busy: false,
  localNames: loadLocalNames()
};

elements.setupCompanion.addEventListener("click", () =>
  perform(setupCompanion, elements.companionStatus));
elements.createGroup.addEventListener("click", () =>
  perform(createGroup, elements.groupMessageStatus));
elements.refreshGroups.addEventListener("click", () =>
  perform(refreshGroups, elements.groupMessageStatus));
elements.syncGroup.addEventListener("click", () =>
  perform(syncMessages, elements.groupMessageStatus));
elements.sendGroupMessage.addEventListener("click", () =>
  perform(sendMessage, elements.groupMessageStatus));
elements.acceptAdmission.addEventListener("click", () =>
  perform(acceptAdmission, elements.admissionStatus));
elements.copyAdmissionResponse.addEventListener("click", () =>
  perform(copyWelcome, elements.admissionStatus));
elements.groupMessage.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    void perform(sendMessage, elements.groupMessageStatus);
  }
});

void perform(boot, elements.companionStatus);

async function boot() {
  const status = await api("/status");
  elements.storageProfile.textContent = status.encryptedState
    ? "Group state is encrypted by NoctweaveCore using the host secure-storage boundary."
    : "Development-only plaintext Core state is active. Do not use this mode for real conversations.";
  if (!status.available) {
    elements.companionStatus.textContent = "Core companion unavailable";
    elements.storageProfile.textContent = status.reason;
    elements.setupCompanion.disabled = true;
    return;
  }
  if (!status.initialized) {
    elements.companionStatus.textContent = "Setup required";
    return;
  }
  activate(status.groups ?? []);
}

async function setupCompanion() {
  const status = await api("/setup", {
    method: "POST",
    body: {
      displayName: elements.groupPersonaName.value,
      relay: elements.groupRelay.value
    }
  });
  activate(status.groups ?? []);
}

function activate(groups) {
  elements.companionStatus.textContent = "Local Core companion ready";
  elements.setupPanel.hidden = true;
  elements.createPanel.hidden = false;
  elements.groupListPanel.hidden = false;
  renderGroups(groups);
}

async function createGroup() {
  const localName = elements.groupName.value.trim() || "Unnamed group";
  const result = await api("/groups", {
    method: "POST",
    body: { relay: elements.createRelay.value }
  });
  state.localNames[result.groupID] = localName;
  saveLocalNames();
  renderGroups(result.groups ?? await api("/groups"));
  selectGroup(result.groupID);
  await syncMessages();
}

async function refreshGroups() {
  renderGroups(await api("/groups"));
  if (state.selectedGroupID) {
    await syncMessages();
  }
}

function renderGroups(groups) {
  state.groups = Array.isArray(groups) ? groups : [];
  elements.groupList.replaceChildren();
  if (state.groups.length === 0) {
    elements.groupList.textContent = "No groups yet.";
    return;
  }
  for (const group of state.groups) {
    const article = document.createElement("article");
    const details = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = state.localNames[group.groupID] ?? `Group ${group.groupID.slice(0, 8)}`;
    const metadata = document.createElement("span");
    metadata.textContent = `${group.memberCount} member${group.memberCount === 1 ? "" : "s"} · epoch ${group.epoch}`;
    details.append(title, metadata);
    const button = document.createElement("button");
    button.className = "subtle";
    button.textContent = state.selectedGroupID === group.groupID ? "Open" : "Select";
    button.addEventListener("click", () => {
      selectGroup(group.groupID);
      void perform(syncMessages, elements.groupMessageStatus);
    });
    article.append(details, button);
    elements.groupList.append(article);
  }
}

function selectGroup(groupID) {
  state.selectedGroupID = groupID;
  const group = state.groups.find((candidate) => candidate.groupID === groupID);
  elements.selectedGroupName.textContent = state.localNames[groupID] ?? `Group ${groupID.slice(0, 8)}`;
  elements.selectedGroupID.textContent = groupID;
  elements.syncGroup.disabled = false;
  elements.groupMessage.disabled = false;
  elements.sendGroupMessage.disabled = false;
  elements.admissionPanel.hidden = false;
  elements.groupMessageStatus.textContent = group
    ? `${group.memberCount} member${group.memberCount === 1 ? "" : "s"} · epoch ${group.epoch}`
    : "Group selected.";
  renderGroups(state.groups);
}

async function syncMessages() {
  requireSelectedGroup();
  const events = await api(`/groups/${state.selectedGroupID}/events`);
  renderMessages(events);
  state.groups = await api("/groups");
  renderGroups(state.groups);
  elements.groupMessageStatus.textContent = `Synchronized ${events.length} durable event${events.length === 1 ? "" : "s"}.`;
}

async function sendMessage() {
  requireSelectedGroup();
  const text = elements.groupMessage.value.trim();
  if (!text) throw new Error("Write a message first.");
  const result = await api(`/groups/${state.selectedGroupID}/messages`, {
    method: "POST",
    body: { text }
  });
  elements.groupMessage.value = "";
  renderMessages(result.events ?? []);
  elements.groupMessageStatus.textContent = result.complete
    ? "Encrypted group message published."
    : `Message retained for retry: ${result.disposition}.`;
}

function renderMessages(events) {
  elements.groupMessages.replaceChildren();
  if (!Array.isArray(events) || events.length === 0) {
    const empty = document.createElement("div");
    empty.className = "groupEmpty";
    empty.textContent = "No group messages yet.";
    elements.groupMessages.append(empty);
    return;
  }
  for (const event of events) {
    const bubble = document.createElement("article");
    bubble.className = `messageBubble ${event.outgoing ? "outbound" : "inbound"}`;
    const text = document.createElement("div");
    text.textContent = event.text ?? event.fallbackText ?? `[${event.contentType?.canonicalName ?? "group event"}]`;
    const metadata = document.createElement("span");
    const author = event.outgoing ? "You" : shortHandle(event.authorCredentialHandle);
    metadata.textContent = `${author} · ${new Date(event.createdAt).toLocaleString()}`;
    bubble.append(text, metadata);
    elements.groupMessages.append(bubble);
  }
  elements.groupMessages.scrollTop = elements.groupMessages.scrollHeight;
}

async function acceptAdmission() {
  requireSelectedGroup();
  const result = await api(`/groups/${state.selectedGroupID}/admissions`, {
    method: "POST",
    body: { requestLink: elements.admissionRequest.value }
  });
  elements.admissionResponse.value = result.responseLink;
  elements.admissionStatus.textContent = result.maintenanceComplete
    ? "Member added. Return this one-use Welcome to the requesting device."
    : "Welcome created; group maintenance still has durable retry work.";
  await refreshGroups();
}

async function copyWelcome() {
  const value = elements.admissionResponse.value.trim();
  if (!value) throw new Error("Generate a Welcome response first.");
  await navigator.clipboard.writeText(value);
  elements.admissionStatus.textContent = "Welcome copied.";
}

async function api(path, options = {}) {
  const init = { method: options.method ?? "GET", headers: {} };
  if (options.body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(`/api/group-companion${path}`, init);
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error ?? `Group companion failed (${response.status}).`);
  }
  return result;
}

async function perform(operation, errorTarget = elements.companionStatus) {
  if (state.busy) return;
  state.busy = true;
  setButtonsDisabled(true);
  try {
    await operation();
  } catch (error) {
    const message = String(error?.message ?? error);
    if (errorTarget === elements.companionStatus) {
      elements.companionStatus.textContent = `Action needs attention: ${message}`;
    } else {
      errorTarget.textContent = message;
    }
  } finally {
    state.busy = false;
    setButtonsDisabled(false);
  }
}

function setButtonsDisabled(disabled) {
  for (const button of document.querySelectorAll("button")) {
    button.disabled = disabled || (
      (button === elements.syncGroup || button === elements.sendGroupMessage) &&
      state.selectedGroupID === null
    );
  }
}

function requireSelectedGroup() {
  if (!state.selectedGroupID) {
    throw new Error("Select a group first.");
  }
}

function shortHandle(value) {
  const text = typeof value === "string"
    ? value
    : value?.rawValue ?? value?.value ?? JSON.stringify(value);
  return `Member ${String(text).slice(0, 8)}`;
}

function loadLocalNames() {
  try {
    const value = JSON.parse(localStorage.getItem("noctweave.groupNames.v1") ?? "{}");
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    return {};
  }
}

function saveLocalNames() {
  localStorage.setItem("noctweave.groupNames.v1", JSON.stringify(state.localNames));
}
