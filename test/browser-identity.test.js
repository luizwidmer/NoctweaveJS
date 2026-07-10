import assert from "node:assert/strict";
import test from "node:test";
import {
  NoctweaveBrowserIdentityService,
  parseBrowserRelayEndpoint,
  validateBrowserDisplayName
} from "../src/index.js";

test("browser identity setup verifies relay and registers a post-quantum inbox", async () => {
  const requests = [];
  const clients = [];
  const service = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory(endpoint, options) {
      clients.push({ endpoint, options });
      return {
        health: async () => ({ type: "ok" }),
        info: async () => ({ type: "info", relayInfo: { relayName: "Test Relay", kind: "standard" } }),
        send: async (request) => {
          requests.push(request);
          return { type: "ok" };
        }
      };
    }
  });

  const result = await service.createAndRegister({
    displayName: "  Alice   Example ",
    relay: "https://relay.example",
    authToken: "relay-password"
  });

  assert.equal(result.identity.displayName, "Alice Example");
  assert.match(result.identity.inboxId, /^noctweave1/);
  assert.equal(result.identity.contactOffer.inboxId, result.identity.inboxId);
  assert.equal(result.relay.endpoint.useTLS, true);
  assert.equal(result.relay.relayInfo.relayName, "Test Relay");
  assert.equal(clients.length, 2);
  assert.equal(clients[0].options.authToken, "relay-password");
  assert.equal(requests[0].type, "registerInbox");
  assert.equal(requests[0].registerInbox.inboxId, result.identity.inboxId);
  assert.equal(requests[0].registerInbox.accessProof.signature.length > 100, true);
});

test("browser setup rejects raw TCP, invalid names, coordinators, and failed registration", async () => {
  assert.throws(() => parseBrowserRelayEndpoint("relay.example:9339"), /requires an HTTP/);
  assert.throws(() => validateBrowserDisplayName("   "), /Display name/);

  const coordinator = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: { kind: "coordinator" } })
    })
  });
  await assert.rejects(() => coordinator.verifyRelay("https://relay.example"), /client-facing/);

  const rejected = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: { kind: "standard" } }),
      send: async () => ({ type: "error" })
    })
  });
  await assert.rejects(
    () => rejected.createAndRegister({ displayName: "Alice", relay: "https://relay.example" }),
    /rejected inbox registration/
  );
});

function mockPQC() {
  let sequence = 1;
  return {
    generateSigningKeypair() {
      return keypair(1_952, 4_032, sequence++);
    },
    generateKemKeypair() {
      return keypair(1_184, 2_400, sequence++);
    },
    sign() {
      return new Uint8Array(3_309).fill(0x5a);
    }
  };
}

function keypair(publicLength, secretLength, seed) {
  return {
    publicKey: new Uint8Array(publicLength).fill(seed),
    secretKey: new Uint8Array(secretLength).fill(seed + 10)
  };
}

function mockCrypto() {
  return {
    async sha256(value) {
      const digest = new Uint8Array(32);
      digest.fill(value[0] ?? 0);
      return digest;
    }
  };
}
