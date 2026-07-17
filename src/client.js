import { NoctweaveRelayClient } from "./relay-client.js";
import { NoctweaveStateRepository } from "./storage.js";

export class NoctweaveWebClient {
  constructor({ relay, store, stateKey, authToken, fetch, WebSocket, timeoutMs, crypto }) {
    if (!relay) {
      throw new TypeError("NoctweaveWebClient requires a relay endpoint.");
    }
    if (!store) {
      throw new TypeError("NoctweaveWebClient requires a storage adapter.");
    }
    this.relay = relay instanceof NoctweaveRelayClient
      ? relay
      : new NoctweaveRelayClient(relay, { authToken, fetch, WebSocket, timeoutMs, crypto });
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

  async createOpaqueRoute(request, options) {
    return this.relay.createOpaqueRoute(request, options);
  }

  async renewOpaqueRoute(request, options) {
    return this.relay.renewOpaqueRoute(request, options);
  }

  async teardownOpaqueRoute(request, options) {
    return this.relay.teardownOpaqueRoute(request, options);
  }

  async enqueueOpaqueRoute(request, options) {
    return this.relay.enqueueOpaqueRoute(request, options);
  }

  async syncOpaqueRoute(request, options) {
    return this.relay.syncOpaqueRoute(request, options);
  }

  async commitOpaqueRoute(request, options) {
    return this.relay.commitOpaqueRoute(request, options);
  }
}
