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
  admissionRequestFile: $("#admissionRequestFile"),
  admissionRequestSummary: $("#admissionRequestSummary"),
  admissionResponse: $("#admissionResponse"),
  admissionResponseActions: $("#admissionResponseActions"),
  acceptAdmission: $("#acceptAdmission"),
  copyAdmissionResponse: $("#copyAdmissionResponse"),
  admissionStatus: $("#admissionStatus")
};

const GROUP_ARTIFACT_MAX_BYTES = 24 * 1_024 * 1_024;
const GROUP_REQUEST_PREFIX = "noctweave-group-admission-v1:";
const GROUP_WELCOME_PREFIX = "noctweave-group-welcome-v1:";
const GROUP_ARTIFACT_MEDIA_TYPE = "application/vnd.noctweave.group-exchange";

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
$("#openAdmissionRequest").addEventListener("click", () => elements.admissionRequestFile.click());
elements.admissionRequestFile.addEventListener("change", () =>
  perform(importAdmissionRequest, elements.admissionStatus));
elements.admissionRequest.addEventListener("input", () => {
  clearAdmissionResponse();
  elements.admissionRequestSummary.textContent = elements.admissionRequest.value.trim()
    ? "Manual request entered · verify its source before approval"
    : "No request loaded.";
  updateAdmissionReadiness();
});
$("#shareAdmissionResponse").addEventListener("click", () =>
  perform(shareWelcome, elements.admissionStatus));
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
  const changedGroup = state.selectedGroupID !== groupID;
  state.selectedGroupID = groupID;
  if (changedGroup) resetAdmissionExchange();
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
  const requestLink = normalizedGroupArtifact(
    elements.admissionRequest.value,
    GROUP_REQUEST_PREFIX,
    "group admission request"
  );
  clearAdmissionResponse();
  const result = await api(`/groups/${state.selectedGroupID}/admissions`, {
    method: "POST",
    body: { requestLink }
  });
  elements.admissionResponse.value = normalizedGroupArtifact(
    result.responseLink,
    GROUP_WELCOME_PREFIX,
    "group Welcome"
  );
  elements.admissionResponseActions.hidden = false;
  elements.admissionRequest.value = "";
  elements.admissionRequestSummary.textContent = "Request consumed · signed Welcome ready";
  updateAdmissionReadiness();
  elements.admissionStatus.textContent = result.maintenanceComplete
    ? "Member added. Return this one-use Welcome to the requesting device."
    : "Welcome created; group maintenance still has durable retry work.";
  await refreshGroups();
}

async function importAdmissionRequest() {
  const file = elements.admissionRequestFile.files?.[0];
  elements.admissionRequestFile.value = "";
  if (!file) return;
  elements.admissionRequest.value = "";
  elements.admissionRequestSummary.textContent = "No request loaded.";
  clearAdmissionResponse();
  updateAdmissionReadiness();
  if (file.size < 1 || file.size > GROUP_ARTIFACT_MAX_BYTES) {
    throw new Error("The group request file is empty or exceeds 24 MiB.");
  }
  let value;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
  } catch {
    throw new Error("The group request file is not valid UTF-8.");
  }
  elements.admissionRequest.value = normalizedGroupArtifact(
    value,
    GROUP_REQUEST_PREFIX,
    "group admission request"
  );
  elements.admissionRequestSummary.textContent = `${file.name} · ${formatBytes(file.size)} · ready to verify`;
  elements.admissionStatus.textContent = "Request loaded exactly from file. Verify and add the member when ready.";
  updateAdmissionReadiness();
}

async function shareWelcome() {
  const value = normalizedGroupArtifact(
    elements.admissionResponse.value,
    GROUP_WELCOME_PREFIX,
    "group Welcome"
  );
  const filename = `Noctweave Group Welcome ${state.selectedGroupID.slice(0, 8)}.noctgroup`;
  const file = new File([value], filename, { type: GROUP_ARTIFACT_MEDIA_TYPE });
  if (typeof navigator.share === "function" &&
      typeof navigator.canShare === "function" && navigator.canShare({ files: [file] })) {
    await navigator.share({
      title: "Noctweave group Welcome",
      text: "One-use Noctweave group Welcome. Return it only to the device that created the request.",
      files: [file]
    });
    elements.admissionStatus.textContent = "Welcome shared. Keep no extra copies after the requesting device joins.";
    return;
  }
  downloadArtifact(value, filename);
  elements.admissionStatus.textContent = "Welcome file saved. Send it privately, then delete the transferred copy after use.";
}

async function copyWelcome() {
  const value = normalizedGroupArtifact(
    elements.admissionResponse.value,
    GROUP_WELCOME_PREFIX,
    "group Welcome"
  );
  await navigator.clipboard.writeText(value);
  elements.admissionStatus.textContent = "Welcome copied as a fallback. Prefer the file path for large groups and clear the system clipboard after use.";
}

function normalizedGroupArtifact(value, prefix, label) {
  if (typeof value !== "string") throw new Error(`The ${label} is missing.`);
  const normalized = value.trim();
  const byteLength = new TextEncoder().encode(normalized).byteLength;
  if (!normalized.startsWith(prefix) || byteLength < prefix.length ||
      byteLength > GROUP_ARTIFACT_MAX_BYTES) {
    throw new Error(`This is not a supported ${label}.`);
  }
  return normalized;
}

function downloadArtifact(value, filename) {
  const blob = new Blob([value], { type: GROUP_ARTIFACT_MEDIA_TYPE });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function formatBytes(value) {
  if (value < 1_024) return `${value} B`;
  if (value < 1_024 * 1_024) return `${(value / 1_024).toFixed(1)} KiB`;
  return `${(value / (1_024 * 1_024)).toFixed(1)} MiB`;
}

function admissionRequestIsReady() {
  try {
    normalizedGroupArtifact(
      elements.admissionRequest.value,
      GROUP_REQUEST_PREFIX,
      "group admission request"
    );
    return state.selectedGroupID !== null;
  } catch {
    return false;
  }
}

function updateAdmissionReadiness() {
  elements.acceptAdmission.disabled = state.busy || !admissionRequestIsReady();
}

function clearAdmissionResponse() {
  elements.admissionResponse.value = "";
  elements.admissionResponseActions.hidden = true;
}

function resetAdmissionExchange() {
  elements.admissionRequest.value = "";
  elements.admissionRequestFile.value = "";
  elements.admissionRequestSummary.textContent = "No request loaded.";
  clearAdmissionResponse();
  elements.admissionStatus.textContent = "No pending admission.";
  updateAdmissionReadiness();
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
    ) || (
      button === elements.acceptAdmission && !admissionRequestIsReady()
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
