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
  }

  async loadState() {
    return this.state.load();
  }

  async saveState(nextState) {
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

  async registerMailboxConsumer(request, options) {
    return this.relay.registerMailboxConsumer(request, options);
  }

  async syncMailbox(request, options) {
    return this.relay.syncMailbox(request, options);
  }

  async commitMailboxCursor(request, options) {
    return this.relay.commitMailboxCursor(request, options);
  }

  async revokeMailboxConsumer(request, options) {
    return this.relay.revokeMailboxConsumer(request, options);
  }
}
