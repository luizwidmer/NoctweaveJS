import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

test("a group refresh cannot switch conversations while its messages are in flight", async () => {
  const source = await readFile(new URL("../client/groups.js", import.meta.url), "utf8");
  class Element {
    constructor(tag = "div") {
      this.tag = tag; this.value = ""; this.textContent = ""; this.disabled = false;
      this.hidden = false; this.children = []; this.listeners = new Map();
      this.dataset = {}; this.attributes = new Map(); this.scrollTop = 0;
      this.scrollHeight = 0; this.clientHeight = 100;
    }
    addEventListener(name, callback) { this.listeners.set(name, callback); }
    replaceChildren(...children) { this.children = children; }
    append(...children) { this.children.push(...children); }
    click() { if (!this.disabled) return this.listeners.get("click")?.(); }
    setAttribute(name, value) { this.attributes.set(name, value); }
  }
  const elements = new Map();
  const created = [];
  const groups = [
    { groupID: "group-a", memberCount: 2, epoch: 1 },
    { groupID: "group-b", memberCount: 2, epoch: 1 }
  ];
  const refreshedGroups = groups.map((group) => ({ ...group, epoch: 2 }));
  const otherMessages = [{ id: "b-event", text: "Only for group B", outgoing: false, createdAt: "2026-10-17T12:00:00Z" }];
  let finishMessages;
  const pendingMessages = new Promise((resolve) => { finishMessages = resolve; });
  const context = vm.createContext({
    console, TextEncoder,
    initializeAppearanceControl() {}, rejectLegacyPlaintextPreference() {},
    document: {
      hidden: false, visibilityState: "visible", addEventListener() {},
      querySelector(selector) {
        if (!elements.has(selector)) elements.set(selector, new Element("button"));
        return elements.get(selector);
      },
      querySelectorAll: () => [...elements.values(), ...created].filter(({ tag }) => tag === "button"),
      createElement(tag) { const value = new Element(tag); created.push(value); return value; }
    },
    setInterval() {}, addEventListener() {},
    async fetch(path) {
      let result = refreshedGroups;
      if (path.endsWith("/group-a/events")) result = await pendingMessages;
      if (path.endsWith("/group-b/events")) result = otherMessages;
      return { ok: true, json: async () => result };
    }
  });
  vm.runInContext(source.replace(/^import\b[\s\S]*?;\n/gmu, "") +
    "\nglobalThis.harness = { state, selectGroup, perform, refreshGroups };", context);
  for (let i = 0; i < 10; i++) await Promise.resolve(); // Finish the initial locked boot.
  const { state, selectGroup, perform, refreshGroups } = context.harness;
  state.accessToken = "a".repeat(64);
  state.groups = groups;
  selectGroup("group-a");
  const refreshing = perform(refreshGroups, elements.get("#groupMessageStatus"));
  for (let i = 0; i < 20; i++) await Promise.resolve();
  assert.equal(state.busy, true);
  // The /groups response rebuilt the list while /events is still pending.
  const groupB = elements.get("#groupList").children[1].children[1];
  groupB.click();
  const selectedWhilePending = state.selectedGroupID;
  finishMessages([{ id: "a-event", text: "Only for group A", outgoing: false, createdAt: "2026-10-17T12:00:00Z" }]);
  await refreshing;
  assert.equal(selectedWhilePending, "group-a", "an in-flight refresh must retain its conversation");
  assert.equal(state.selectedGroupID, "group-a");
  const timeline = elements.get("#groupMessages");
  const messageA = timeline.children[0];
  assert.equal(messageA.children[0].textContent, "Only for group A");
  await perform(refreshGroups, elements.get("#groupMessageStatus"));
  assert.equal(timeline.children[0], messageA, "an unchanged resync should retain the message node");
  // Selection is available again once the same refresh finishes.
  const composer = elements.get("#groupMessage");
  composer.value = "Draft for group A";
  await elements.get("#groupList").children[1].children[1].click();
  assert.equal(state.selectedGroupID, "group-b");
  assert.equal(composer.value, "");
  assert.equal(timeline.children[0].children[0].textContent, "Only for group B");
  assert.equal(elements.get("#groupList").children[1].children[1].attributes.get("aria-pressed"), "true");
  composer.value = "Draft for group B";
  await elements.get("#groupList").children[0].children[1].click();
  assert.equal(composer.value, "Draft for group A");
});
