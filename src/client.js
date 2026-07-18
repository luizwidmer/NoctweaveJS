import { NoctweaveRelayClient } from "./relay-client.js";
import { NoctweaveStateRepository } from "./storage.js";
import {
  makeOpaqueRouteCommitRequestV2,
  makeOpaqueRouteSyncRequestV2
} from "./opaque-route-relay-v2.js";
import {
  OpaqueRouteGapV2Error,
  advanceLocalOpaqueReceiveRouteV2,
  assertOpaqueRouteSyncContinuityV2,
  validateLocalOpaqueReceiveRouteV2
} from "./pairwise-opaque-route-v2.js";
import { swiftISODate } from "./crypto/swift-canonical.js";

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
    this.crypto = crypto ?? this.relay.protocolCrypto;
    if (!this.crypto) {
      throw new TypeError("NoctweaveWebClient requires protocol cryptography.");
    }
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

  async registerRendezvousTransportV2(request, options) {
    return this.relay.registerRendezvousTransportV2(request, options);
  }

  async appendRendezvousTransportV2(request, options) {
    return this.relay.appendRendezvousTransportV2(request, options);
  }

  async syncRendezvousTransportV2(request, options) {
    return this.relay.syncRendezvousTransportV2(request, options);
  }

  async deleteRendezvousTransportV2(request, options) {
    return this.relay.deleteRendezvousTransportV2(request, options);
  }

  async registerFederationNode(request, options) {
    return this.relay.registerFederationNode(request, options);
  }

  async listFederationNodes(request, options) {
    return this.relay.listFederationNodes(request, options);
  }

  async syncOpaqueRoute(localReceiveRouteValue, {
    limit = 256,
    requestID,
    authorizedAt = swiftISODate(),
    nonce,
    relayOptions
  } = {}) {
    const localReceiveRoute = await validateLocalOpaqueReceiveRouteV2({
      crypto: this.crypto,
      route: localReceiveRouteValue
    });
    if (localReceiveRoute.gapState !== null) {
      throw new OpaqueRouteGapV2Error(localReceiveRoute.gapState, localReceiveRoute);
    }
    const request = await makeOpaqueRouteSyncRequestV2({
      crypto: this.crypto,
      capabilities: localReceiveRoute.clientCapabilities,
      after: localReceiveRoute.committedCursor,
      limit,
      requestID,
      authorizedAt,
      nonce
    });
    const batch = await this.relay.syncOpaqueRoute({
      request,
      readCredential: localReceiveRoute.clientCapabilities.readCredential
    }, relayOptions);
    assertOpaqueRouteSyncContinuityV2({
      batch,
      localReceiveRoute,
      detectedAt: authorizedAt
    });
    return Object.freeze({ batch, localReceiveRoute });
  }

  async commitOpaqueRoute({ localReceiveRoute: routeValue, batch, durablyProcessed }, {
    requestID,
    authorizedAt = swiftISODate(),
    nonce,
    relayOptions
  } = {}) {
    if (durablyProcessed !== true) {
      throw new TypeError("Opaque route packets must be durably processed before cursor commit.");
    }
    const localReceiveRoute = await validateLocalOpaqueReceiveRouteV2({
      crypto: this.crypto,
      route: routeValue
    });
    assertOpaqueRouteSyncContinuityV2({
      batch,
      localReceiveRoute,
      detectedAt: authorizedAt
    });
    const request = await makeOpaqueRouteCommitRequestV2({
      crypto: this.crypto,
      capabilities: localReceiveRoute.clientCapabilities,
      cursor: batch.nextCursor,
      requestID,
      authorizedAt,
      nonce
    });
    const commit = await this.relay.commitOpaqueRoute({
      request,
      readCredential: localReceiveRoute.clientCapabilities.readCredential
    }, relayOptions);
    return Object.freeze({
      commit,
      localReceiveRoute: await advanceLocalOpaqueReceiveRouteV2({
        crypto: this.crypto,
        localReceiveRoute,
        batch,
        commitResponse: commit,
        detectedAt: authorizedAt
      })
    });
  }
}
