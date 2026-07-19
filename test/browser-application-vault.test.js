import assert from "node:assert/strict";
import test from "node:test";

import {
  HostAnchoredBrowserApplicationVaultV2,
  browserApplicationVaultSlotV2,
  executeAnchoredBrowserLocalBurnV2
} from "../client/messaging-service.js";
import { base64 } from "../src/index.js";

const passphrase = "correct horse battery staple";

test("fixed application vault slot authenticates scope, burn, and fresh reinitialization", async () => {
  const host = new AtomicApplicationSlotHost();
  const requests = [];
  const vault = applicationVault(host, requests);
  const firstPersona = { displayName: "First", relationships: [] };
  const opened = await vault.initialize({ passphrase, persona: firstPersona });
  assert.deepEqual(opened.persona, firstPersona);
  const active = await vault.inspect();
  assert.equal(active.status, "active");
  assert.equal(requests.length, 1);
  assert.deepEqual(Object.keys(requests[0]).sort(), ["anchorKey", "relationshipID", "stateKey"]);
  assert.equal(requests[0].relationshipID, browserApplicationVaultSlotV2.scope);
  assert.equal(JSON.stringify(firstPersona).includes(browserApplicationVaultSlotV2.scope), false);

  await vault.beginBurn();
  assert.equal((await vault.inspect()).status, "burning");
  await assert.rejects(
    () => vault.unlock({ passphrase }),
    (error) => error.code === "vaultUnavailable"
  );
  await assert.rejects(
    () => vault.initialize({ passphrase, persona: { displayName: "Bypass" } }),
    (error) => error.code === "vaultBurnInProgress"
  );
  const recovered = await vault.unlockBurnRecovery({ passphrase });
  assert.deepEqual(recovered.persona, firstPersona);

  await vault.finishBurn();
  const burned = host.currentRecord();
  assert.equal(burned.status, "burned");
  assert.equal(burned.salt, null);
  assert.equal(burned.encryptedRecord, null);
  const generationAfterBurn = host.anchor.generation;

  const secondPersona = { displayName: "Second", relationships: [] };
  await vault.initialize({ passphrase: "a different secure passphrase", persona: secondPersona });
  const second = await vault.inspect();
  assert.equal(second.status, "active");
  assert.notEqual(second.vaultScopeID, active.vaultScopeID);
  assert.equal(host.anchor.generation, generationAfterBurn + 1);
});

test("application vault rejects ciphertext rollback and scope substitution", async () => {
  const host = new AtomicApplicationSlotHost();
  const vault = applicationVault(host);
  await vault.initialize({ passphrase, persona: { revision: 1 } });
  const firstRecord = structuredClone(host.currentRecord());
  const firstAnchor = structuredClone(host.anchor);
  await vault.save({ revision: 2 });
  const currentRecord = structuredClone(host.currentRecord());
  const currentAnchor = structuredClone(host.anchor);

  host.replaceRecord(firstRecord);
  const rolledBackCiphertext = applicationVault(host);
  await assert.rejects(
    () => rolledBackCiphertext.inspect(),
    (error) => error.code === "vaultRollbackDetected"
  );

  host.replaceRecord({
    ...currentRecord,
    vaultScopeID: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
  });
  const substitutedScope = applicationVault(host);
  await assert.rejects(
    () => substitutedScope.inspect(),
    (error) => error.code === "vaultRollbackDetected"
  );

  host.replaceRecord(firstRecord);
  host.replaceAnchor(firstAnchor);
  const rolledBackHostGeneration = applicationVault(host);
  await assert.rejects(
    () => rolledBackHostGeneration.inspect(),
    /host monotonic generation rolled back/
  );

  host.replaceRecord(currentRecord);
  host.replaceAnchor(currentAnchor);
  assert.equal((await applicationVault(host).inspect()).status, "active");
});

test("multi-relationship burn remains terminal across every injected crash phase", async () => {
  for (const crash of [
    { phase: "relationshipBlocked", index: 0 },
    { phase: "relationshipBlocked", index: 1 },
    { phase: "relationshipDestroyed", index: 0 },
    { phase: "relationshipDestroyed", index: 1 },
    { phase: "aggregateBurned", index: undefined }
  ]) {
    const host = new AtomicApplicationSlotHost();
    const vault = applicationVault(host);
    const relationships = [
      { relationshipID: "11111111-1111-4111-8111-111111111111" },
      { relationshipID: "22222222-2222-4222-8222-222222222222" }
    ];
    await vault.initialize({ passphrase, persona: { relationships } });
    const fake = new FakeBurnMessaging();
    await assert.rejects(
      () => executeAnchoredBrowserLocalBurnV2({
        vault,
        messaging: fake,
        relationships,
        checkpoint: ({ phase, index }) => {
          if (phase === crash.phase && index === crash.index) throw new Error("injected crash");
        }
      }),
      /injected crash/
    );
    assert.equal(fake.relayCalls, 0, `${crash.phase}:${crash.index ?? "final"}`);

    const status = await applicationVault(host).inspect();
    assert.equal(new Set(["burning", "burned"]).has(status.status), true);
    await assert.rejects(
      () => applicationVault(host).unlock({ passphrase }),
      (error) => error.code === "vaultUnavailable"
    );

    if (status.status === "burning") {
      const recoveryVault = applicationVault(host);
      const recovered = await recoveryVault.unlockBurnRecovery({ passphrase });
      assert.deepEqual(recovered.persona.relationships, relationships);
      const completed = await executeAnchoredBrowserLocalBurnV2({
        vault: recoveryVault,
        messaging: fake,
        relationships: recovered.persona.relationships
      });
      assert.equal(completed.burned, true);
      assert.equal(fake.blocked.size, 2);
      assert.equal(fake.destroyed.size, 2);
      assert.equal(fake.relayCalls, 2);
      assert.equal((await recoveryVault.inspect()).status, "burned");
    } else {
      assert.equal(fake.blocked.size, 2);
      assert.equal(fake.destroyed.size, 2);
    }
    const terminal = host.currentRecord();
    assert.equal(terminal.status, "burned");
    assert.equal(terminal.encryptedRecord, null);
  }
});

function applicationVault(host, requests = []) {
  return new HostAnchoredBrowserApplicationVaultV2({
    crypto: {
      sha256: async (data) => new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", data))
    },
    storageCrypto: globalThis.crypto,
    stateAnchorStoreFactory: async (request) => {
      requests.push(structuredClone(request));
      return host;
    }
  });
}

class FakeBurnMessaging {
  constructor() {
    this.blocked = new Set();
    this.destroyed = new Set();
    this.relayCalls = 0;
  }

  async anchorRelationshipsForBurn(relationships) {
    for (const { relationshipID } of relationships) this.blocked.add(relationshipID);
    return { complete: true, terminal: relationships.length };
  }

  async destroyRollbackAnchors(relationships) {
    for (const { relationshipID } of relationships) {
      assert.equal(this.blocked.has(relationshipID), true);
      this.destroyed.add(relationshipID);
    }
    return { complete: true, destroyed: relationships.length };
  }

  async teardownRelationshipRoutes({ relationshipID }) {
    assert.equal(this.destroyed.has(relationshipID), true);
    this.relayCalls += 1;
    return { complete: true, failures: [] };
  }
}

class AtomicApplicationSlotHost {
  constructor() {
    this.anchor = null;
    this.highWatermark = 0;
    this.records = new Map();
    this.key = new Uint8Array(32).fill(0x91);
    this.encryptedStateStoreBackend = Object.freeze({
      get: async (key) => this.records.has(key) ? structuredClone(this.records.get(key)) : null,
      set: async (key, value) => this.records.set(key, structuredClone(value)),
      delete: async (key) => this.records.delete(key)
    });
  }

  async load({ relationshipID, loadEncryptedState }) {
    if (this.anchor !== null) {
      if (this.anchor.generation < this.highWatermark) {
        throw new Error("host monotonic generation rolled back");
      }
      assert.equal(this.anchor.relationshipID, relationshipID);
      assert.equal(this.anchor.authenticationTag, await this.authenticationTag(this.anchor));
    }
    return {
      anchor: this.anchor === null ? null : structuredClone(this.anchor),
      state: await loadEncryptedState()
    };
  }

  async commit({
    relationshipID,
    expectedAnchor,
    nextGeneration,
    nextStateDigest,
    persistEncryptedState
  }) {
    assert.equal(JSON.stringify(expectedAnchor), JSON.stringify(this.anchor));
    assert.equal(nextGeneration, (this.anchor?.generation ?? 0) + 1);
    const unsigned = {
      version: 2,
      relationshipID,
      generation: nextGeneration,
      stateDigest: nextStateDigest
    };
    await persistEncryptedState();
    this.anchor = {
      ...unsigned,
      authenticationTag: await this.authenticationTag(unsigned)
    };
    this.highWatermark = nextGeneration;
    return structuredClone(this.anchor);
  }

  currentRecord() {
    return structuredClone([...this.records.values()][0]);
  }

  replaceRecord(record) {
    const key = [...this.records.keys()][0];
    this.records.set(key, structuredClone(record));
  }

  replaceAnchor(anchor) {
    this.anchor = structuredClone(anchor);
  }

  async authenticationTag(anchor) {
    const bytes = new TextEncoder().encode(JSON.stringify({
      version: anchor.version,
      relationshipID: anchor.relationshipID,
      generation: anchor.generation,
      stateDigest: anchor.stateDigest
    }));
    const input = new Uint8Array(this.key.byteLength + bytes.byteLength);
    input.set(this.key);
    input.set(bytes, this.key.byteLength);
    return base64(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input)));
  }
}
