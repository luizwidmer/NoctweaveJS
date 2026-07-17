import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  NoctweaveBrowserIdentityService,
  browserIdentityStateSchema,
  parseBrowserRelayEndpoint,
  validateBrowserDisplayName,
  validateBrowserIdentityState
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
        info: async () => ({ type: "info", relayInfo: testRelayInfo({ relayName: "Test Relay" }) }),
        send: async (request) => {
          requests.push(request);
          if (request.type === "registerMailboxConsumer") {
            return mailboxConsumerResponse(request.registerMailboxConsumer);
          }
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
  assert.equal(result.identity.contactOffer.version, 4);
  assert.equal(
    result.identity.contactOffer.preferredInstallationEndpoint.installationId,
    result.identity.localInstallation.id
  );
  assert.equal(result.relay.endpoint.useTLS, true);
  assert.equal(result.relay.relayInfo.relayName, "Test Relay");
  assert.equal(clients.length, 3);
  assert.equal(clients[0].options.authToken, "relay-password");
  assert.equal(requests[0].type, "registerInbox");
  assert.equal(requests[0].registerInbox.inboxId, result.identity.inboxId);
  assert.equal(requests[0].registerInbox.registrationVersion, 2);
  assert.equal(requests[0].registerInbox.contactOffer, undefined);
  assert.equal(requests[0].registerInbox.accessProof.signature.length > 100, true);
  const registrationJSON = JSON.stringify(requests[0]);
  for (const forbiddenName of [
    "contactOffer",
    "displayName",
    "signingPublicKey",
    "agreementPublicKey",
    "installationManifest",
    "endpointCertificate",
    "prekey"
  ]) {
    assert.equal(registrationJSON.includes(forbiddenName), false, forbiddenName);
  }
  assert.equal(registrationJSON.includes(result.identity.signing.publicKey), false);
  assert.equal(registrationJSON.includes(result.identity.agreement.publicKey), false);
  assert.equal(registrationJSON.includes(result.identity.localInstallation.signing.publicKey), false);
  assert.equal(registrationJSON.includes(result.identity.localInstallation.agreement.publicKey), false);
  assert.equal(registrationJSON.includes(result.identity.identityGenerationId), false);
  assert.equal(registrationJSON.includes(result.identity.localInstallation.id), false);
  assert.equal(
    registrationJSON.includes(result.identity.localInstallation.prekeys.signedPrekeyPublicKey),
    false
  );
  assert.equal(requests[1].type, "registerMailboxConsumer");
  assert.equal(requests[1].registerMailboxConsumer.sponsorConsumerId, undefined);
  const mailboxRoute = Object.values(result.identity.localInstallation.mailboxRoutes)[0];
  assert.equal(
    requests[1].registerMailboxConsumer.consumerSigningPublicKey,
    mailboxRoute.signing.publicKey
  );
  assert.notEqual(
    mailboxRoute.signing.publicKey,
    result.identity.localInstallation.signing.publicKey
  );
  assert.notEqual(result.identity.localInstallation.signing.publicKey, result.identity.signing.publicKey);
  assert.notEqual(result.identity.localInstallation.agreement.publicKey, result.identity.agreement.publicKey);
  assert.equal(mailboxRoute.mode, "v2");
  assert.equal(result.identity.stateSchema, browserIdentityStateSchema);
  assert.equal(Object.hasOwn(result.identity.localInstallation, "mailboxConsumerIdsByRoute"), false);
  assert.equal(Object.hasOwn(mailboxRoute, "legacySponsorConsumerId"), false);
  assert.equal(mailboxRoute.cursor, null);
  assert.equal(mailboxRoute.pendingCommit, null);
  assert.equal(mailboxRoute.committedSequence, 0);
  assert.doesNotThrow(() => validateBrowserIdentityState(result.identity));
});

test("browser identity decoding rejects every pre-1.0 or incomplete state", () => {
  const oldState = {
    displayName: "Old Alice",
    architectureVersion: 2
  };
  assert.throws(() => validateBrowserIdentityState(oldState), /unsupported state schema/);

  const currentButIncomplete = {
    ...oldState,
    stateSchema: browserIdentityStateSchema
  };
  assert.throws(() => validateBrowserIdentityState(currentButIncomplete), /malformed/);
});

test("fresh browser identity creation fails closed when PQ key generation fails", async () => {
  const pqc = mockPQC();
  pqc.generateKemKeypair = () => ({ publicKey: new Uint8Array(), secretKey: new Uint8Array() });
  const service = new NoctweaveBrowserIdentityService({ pqc, crypto: mockCrypto() });
  await assert.rejects(
    () => service.createFreshIdentityState({ displayName: "Alice", relay: "https://relay.example" }),
    /key generation failed/
  );
});

test("browser setup rejects raw TCP, invalid names, coordinators, and failed registration", async () => {
  assert.throws(() => parseBrowserRelayEndpoint("relay.example:9339"), /requires an HTTP/);
  assert.throws(() => validateBrowserDisplayName("   "), /Display name/);

  const coordinator = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: testRelayInfo({ kind: "coordinator" }) })
    })
  });
  await assert.rejects(() => coordinator.verifyRelay("https://relay.example"), /client-facing/);

  const incompatibleRelay = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: { kind: "standard" } })
    })
  });
  await assert.rejects(
    () => incompatibleRelay.verifyRelay("https://relay.example"),
    /architecture-v2 capability manifest/
  );

  const rejected = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: testRelayInfo() }),
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
    },
    verify() {
      return true;
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
      if (value.byteLength === 1_952 || value.byteLength === 1_184) {
        const digest = new Uint8Array(32);
        digest.fill(value[0] ?? 0);
        return digest;
      }
      return new Uint8Array(createHash("sha256").update(value).digest());
    }
  };
}

function mailboxConsumerResponse(request) {
  return {
    type: "mailboxConsumer",
    mailboxConsumer: {
      consumerId: request.consumerId,
      consumerSigningPublicKey: request.consumerSigningPublicKey,
      state: "active",
      committedSequence: request.startingSequence ?? 0,
      registeredAt: "2026-07-16T12:34:56Z"
    }
  };
}

function serialized(value) {
  return {
    publicKey: Buffer.from(value.publicKey).toString("base64"),
    secretKey: Buffer.from(value.secretKey).toString("base64")
  };
}

function testRelayInfo(overrides = {}) {
  return {
    kind: "standard",
    protocolCapabilities: {
      architectureVersion: 2,
      modules: [
        { module: "nw.core", versions: [2], status: "provisional", limits: {} },
        { module: "nw.mailbox", versions: [2], status: "provisional", limits: { maxPage: 256 } }
      ]
    },
    ...overrides
  };
}
