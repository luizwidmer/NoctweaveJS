import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
});

test("legacy stored identities persist fresh endpoint state before binding it", async () => {
  const events = [];
  const pqc = mockPQC();
  const crypto = mockCrypto();
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  const access = pqc.generateSigningKeypair();
  const accessDigest = await crypto.sha256(access.publicKey);
  const legacy = {
    displayName: "Legacy Alice",
    signing: serialized(signing),
    agreement: serialized(agreement),
    access: serialized(access),
    inboxId: "noctweave1qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpskx0f2v",
    accessFingerprint: Buffer.from(accessDigest).toString("base64"),
    signingFingerprint: Buffer.from(await crypto.sha256(signing.publicKey)).toString("base64")
  };
  const service = new NoctweaveBrowserIdentityService({
    pqc,
    crypto,
    relayClientFactory: () => ({
      send: async (request) => {
        events.push({ type: "request", request });
        return mailboxConsumerResponse(request.registerMailboxConsumer);
      }
    })
  });

  const migrated = await service.migrateAndRegisterIdentity({
    identity: legacy,
    relay: "https://relay.example",
    persist: async (identity) => events.push({
      type: "persist",
      mode: Object.values(identity.localInstallation.mailboxRoutes)[0].mode
    })
  });

  assert.deepEqual(events.map((event) => `${event.type}:${event.mode ?? event.request.type}`), [
    "persist:pending-v2-registration",
    "request:registerMailboxConsumer",
    "persist:v2"
  ]);
  assert.equal(migrated.architectureVersion, 2);
  assert.notEqual(migrated.localInstallation.signing.publicKey, legacy.signing.publicKey);
  assert.notEqual(migrated.localInstallation.agreement.publicKey, legacy.agreement.publicKey);
});

test("interrupted identity migration retries the same persisted endpoint and consumer", async () => {
  const pqc = mockPQC();
  const crypto = mockCrypto();
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  const access = pqc.generateSigningKeypair();
  const accessDigest = await crypto.sha256(access.publicKey);
  const legacy = {
    displayName: "Retry Alice",
    signing: serialized(signing),
    agreement: serialized(agreement),
    access: serialized(access),
    inboxId: "noctweave1qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpskx0f2v",
    accessFingerprint: Buffer.from(accessDigest).toString("base64"),
    signingFingerprint: Buffer.from(await crypto.sha256(signing.publicKey)).toString("base64")
  };
  let persisted;
  const interrupted = new NoctweaveBrowserIdentityService({
    pqc,
    crypto,
    relayClientFactory: () => ({ send: async () => { throw new Error("network interrupted"); } })
  });
  await assert.rejects(
    () => interrupted.migrateAndRegisterIdentity({
      identity: legacy,
      relay: "https://relay.example",
      persist: async (identity) => { persisted = structuredClone(identity); }
    }),
    /network interrupted/
  );
  const pendingRoute = Object.values(persisted.localInstallation.mailboxRoutes)[0];
  assert.equal(pendingRoute.committedSequence, 0);
  const persistedSigningKey = pendingRoute.signing.publicKey;
  const persistedConsumerId = pendingRoute.consumerId;
  let retriedRequest;
  const retry = new NoctweaveBrowserIdentityService({
    pqc,
    crypto,
    relayClientFactory: () => ({
      send: async (request) => {
        retriedRequest = request.registerMailboxConsumer;
        return mailboxConsumerResponse(retriedRequest);
      }
    })
  });
  const recovered = await retry.migrateAndRegisterIdentity({
    identity: persisted,
    relay: "https://relay.example",
    persist: async (identity) => { persisted = structuredClone(identity); }
  });

  assert.equal(retriedRequest.consumerSigningPublicKey, persistedSigningKey);
  assert.notEqual(retriedRequest.consumerSigningPublicKey, persisted.localInstallation.signing.publicKey);
  assert.equal(retriedRequest.consumerId, persistedConsumerId);
  assert.equal(Object.values(recovered.localInstallation.mailboxRoutes)[0].mode, "v2");
  assert.equal(Object.values(recovered.localInstallation.mailboxRoutes)[0].committedSequence, 0);
});

test("endpoint-key mailbox bindings rotate to a fresh route credential", async () => {
  const pqc = mockPQC();
  const crypto = mockCrypto();
  const signing = pqc.generateSigningKeypair();
  const agreement = pqc.generateKemKeypair();
  const access = pqc.generateSigningKeypair();
  const identity = {
    displayName: "Route migration",
    signing: serialized(signing),
    agreement: serialized(agreement),
    access: serialized(access),
    inboxId: "noctweave1qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpskx0f2v",
    accessFingerprint: Buffer.from(await crypto.sha256(access.publicKey)).toString("base64"),
    signingFingerprint: Buffer.from(await crypto.sha256(signing.publicKey)).toString("base64")
  };
  const requests = [];
  const service = new NoctweaveBrowserIdentityService({
    pqc,
    crypto,
    relayClientFactory: () => ({
      send: async (request) => {
        requests.push(request);
        if (request.type === "registerMailboxConsumer") {
          return mailboxConsumerResponse(request.registerMailboxConsumer);
        }
        const revoked = request.revokeMailboxConsumer;
        return {
          type: "mailboxConsumer",
          mailboxConsumer: {
            consumerId: revoked.consumerId,
            state: "revoked",
            committedSequence: 0,
            registeredAt: "2026-07-16T12:34:56Z",
            revokedAt: "2026-07-16T12:35:00Z"
          }
        };
      }
    })
  });
  const prepared = await service.prepareArchitectureV2Identity(identity, {
    relay: "https://relay.example"
  });
  const local = prepared.identity.localInstallation;
  const [routeKey, route] = Object.entries(local.mailboxRoutes)[0];
  const legacyConsumerId = route.consumerId;
  local.mailboxRoutes[routeKey] = {
    mode: "v2",
    consumerId: legacyConsumerId,
    registration: {
      ...route.registration,
      consumerId: legacyConsumerId,
      consumerSigningPublicKey: local.signing.publicKey,
      state: "active",
      committedSequence: 0,
      registeredAt: "2026-07-16T12:34:56Z"
    },
    cursor: null,
    committedSequence: 0,
    pendingCommit: null
  };

  const migrated = await service.bindMailboxConsumer({
    identity: prepared.identity,
    relay: "https://relay.example"
  });
  const migratedRoute = migrated.localInstallation.mailboxRoutes[routeKey];
  const registration = requests.find((request) => request.type === "registerMailboxConsumer")
    .registerMailboxConsumer;
  const revocation = requests.find((request) => request.type === "revokeMailboxConsumer")
    .revokeMailboxConsumer;

  assert.equal(registration.sponsorConsumerId, legacyConsumerId);
  assert.notEqual(registration.consumerId, legacyConsumerId);
  assert.notEqual(registration.consumerSigningPublicKey, local.signing.publicKey);
  assert.equal(revocation.consumerId, legacyConsumerId);
  assert.equal(migratedRoute.mode, "v2");
  assert.equal(migratedRoute.legacySponsorConsumerId, undefined);
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

  const legacyRelay = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: { kind: "standard" } })
    })
  });
  await assert.rejects(
    () => legacyRelay.verifyRelay("https://relay.example"),
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

  const recoveryRequired = new NoctweaveBrowserIdentityService({
    pqc: mockPQC(),
    crypto: mockCrypto(),
    relayClientFactory: () => ({
      health: async () => ({ type: "ok" }),
      info: async () => ({ type: "info", relayInfo: testRelayInfo() }),
      send: async (request) => request.type === "registerInbox"
        ? { type: "ok" }
        : { type: "error", error: "The old inbox has no active route credential; create a fresh identity generation and inbox" }
    })
  });
  await assert.rejects(
    () => recoveryRequired.createAndRegister({ displayName: "Alice", relay: "https://relay.example" }),
    /old inbox is closed/
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
