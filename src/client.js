import { NoctweaveRelayClient } from "./relay-client.js";
import { NoctweaveStateRepository } from "./storage.js";
import {
  makeOpaqueRouteCommitRequestV2,
  makeOpaqueRouteSyncRequestV2,
  validateOpaqueRouteCommitResponseV2
} from "./opaque-route-relay-v2.js";
import {
  OpaqueRouteGapV2Error,
  advanceLocalOpaqueReceiveRouteV2,
  markLocalOpaqueReceiveRouteGapV2,
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
    persistLocalState,
    requestID,
    authorizedAt = swiftISODate(),
    nonce,
    relayOptions
  } = {}) {
    requireLocalPersistenceTransaction(persistLocalState);
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
    const gapRoute = await markLocalOpaqueReceiveRouteGapV2({
      crypto: this.crypto,
      batch,
      localReceiveRoute,
      detectedAt: authorizedAt
    });
    if (gapRoute !== null) {
      await persistLocalState(Object.freeze({
        kind: "routeGap",
        previousLocalReceiveRoute: localReceiveRoute,
        localReceiveRoute: gapRoute,
        batch
      }));
      throw new OpaqueRouteGapV2Error(gapRoute.gapState, gapRoute);
    }
    return Object.freeze({ batch, localReceiveRoute });
  }

  async commitOpaqueRoute({ localReceiveRoute: routeValue, batch, persistLocalState }, {
    requestID,
    authorizedAt = swiftISODate(),
    nonce,
    relayOptions
  } = {}) {
    requireLocalPersistenceTransaction(persistLocalState);
    const localReceiveRoute = await validateLocalOpaqueReceiveRouteV2({
      crypto: this.crypto,
      route: routeValue
    });
    const candidate = await advanceLocalOpaqueReceiveRouteV2({
      crypto: this.crypto,
      localReceiveRoute,
      batch,
      detectedAt: authorizedAt
    });

    // The callback is the application's transaction boundary. It must make
    // the candidate cursor, reassembly snapshot, and any effects derived from
    // this batch durable together. Returning successfully is the only local
    // commit authorization; an assertion boolean cannot represent durability.
    await persistLocalState(Object.freeze({
      kind: "cursorAdvance",
      previousLocalReceiveRoute: localReceiveRoute,
      localReceiveRoute: candidate,
      batch
    }));

    let commit = null;
    try {
      const request = await makeOpaqueRouteCommitRequestV2({
        crypto: this.crypto,
        capabilities: localReceiveRoute.clientCapabilities,
        cursor: batch.nextCursor,
        requestID,
        authorizedAt,
        nonce
      });
      commit = await this.relay.commitOpaqueRoute({
        request,
        readCredential: localReceiveRoute.clientCapabilities.readCredential
      }, relayOptions);
      validateOpaqueRouteCommitResponseV2(commit, { cursor: batch.nextCursor });
    } catch {
      // Relay garbage collection is best-effort after the local transaction.
      // A repeated sync can safely retry it from the persisted local cursor.
      commit = null;
    }
    return Object.freeze({
      localReceiveRoute: candidate,
      relayCommit: Object.freeze({
        status: commit === null ? "deferred" : "accepted",
        response: commit
      })
    });
  }
}

function requireLocalPersistenceTransaction(value) {
  if (typeof value !== "function") {
    throw new TypeError(
      "Opaque route synchronization requires a local persistence transaction callback."
    );
  }
  return value;
}
