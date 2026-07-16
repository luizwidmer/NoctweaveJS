import { NoctweaveRelayClient } from "./relay-client.js";
import { NoctweaveStateRepository } from "./storage.js";

export class NoctweaveWebClient {
  constructor({ relay, store, stateKey, authToken, fetch, WebSocket, timeoutMs }) {
    if (!relay) {
      throw new TypeError("NoctweaveWebClient requires a relay endpoint.");
    }
    if (!store) {
      throw new TypeError("NoctweaveWebClient requires a storage adapter.");
    }
    this.relay = relay instanceof NoctweaveRelayClient
      ? relay
      : new NoctweaveRelayClient(relay, { authToken, fetch, WebSocket, timeoutMs });
    this.state = new NoctweaveStateRepository(store, { key: stateKey });
    this.v2Mailboxes = new Set();
  }

  async loadState() {
    const state = await this.state.load();
    this.rememberV2Mailboxes(state);
    return state;
  }

  async saveState(nextState) {
    this.rememberV2Mailboxes(nextState);
    return this.state.save(nextState);
  }

  async clearState() {
    return this.state.clear();
  }

  async health() {
    return this.relay.health();
  }

  async info() {
    return this.relay.info();
  }

  async raw(request) {
    return this.relay.send(request);
  }

  async fetchInbox({ inboxId, routingToken, maxCount, longPollTimeoutSeconds, accessProof }) {
    await this.assertLegacyMailboxAllowed(inboxId, "fetch");
    return this.relay.send({
      type: "fetch",
      fetch: { inboxId, routingToken, maxCount, longPollTimeoutSeconds, accessProof }
    });
  }

  async acknowledgeInbox({ inboxId, messageIds, accessProof }) {
    await this.assertLegacyMailboxAllowed(inboxId, "acknowledgement");
    return this.relay.send({
      type: "acknowledgeMessages",
      acknowledgeMessages: { inboxId, messageIds, accessProof }
    });
  }

  async registerMailboxConsumer(request, options) {
    this.v2Mailboxes.add(request.inboxId);
    return this.relay.registerMailboxConsumer(request, options);
  }

  async syncMailbox(request, options) {
    this.v2Mailboxes.add(request.inboxId);
    return this.relay.syncMailbox(request, options);
  }

  async commitMailboxCursor(request, options) {
    this.v2Mailboxes.add(request.inboxId);
    return this.relay.commitMailboxCursor(request, options);
  }

  async revokeMailboxConsumer(request, options) {
    this.v2Mailboxes.add(request.inboxId);
    return this.relay.revokeMailboxConsumer(request, options);
  }

  async assertLegacyMailboxAllowed(inboxId, operation) {
    if (!this.v2Mailboxes.has(inboxId)) {
      this.rememberV2Mailboxes(await this.state.load());
    }
    if (this.v2Mailboxes.has(inboxId)) {
      throw new Error(`Legacy ${operation} is disabled after mailbox v2 consumer registration.`);
    }
  }

  rememberV2Mailboxes(state) {
    const candidates = [
      state?.identity,
      state?.profile?.identity,
      state?.activeProfile?.identity
    ];
    for (const identity of candidates) {
      const routes = identity?.localInstallation?.mailboxRoutes;
      if (typeof identity?.inboxId !== "string" || !routes || typeof routes !== "object") continue;
      if (Object.values(routes).some((route) =>
        route?.mode === "v2" || route?.mode === "pending-v2-registration")) {
        this.v2Mailboxes.add(identity.inboxId);
      }
    }
  }
}
