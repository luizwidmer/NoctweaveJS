import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";
import { createIndexedDBBrowserAnchorStoreFactoryV2 } from "../client/browser-security-profile.js";

const scope = { relationshipID: "PRIVATE_RELATIONSHIP_CANARY", anchorKey: "PRIVATE_ANCHOR_CANARY", stateKey: "PRIVATE_STATE_KEY_CANARY" };
const digest = Buffer.alloc(32).toString("base64");

test("browser anchors and state round-trip with no scope or metadata canaries in IndexedDB", async () => {
  const indexedDB = new TestIndexedDB();
  const factory = createIndexedDBBrowserAnchorStoreFactoryV2({ indexedDB, storageCrypto: webcrypto });
  const store = await factory(scope);
  const first = await store.commit({
    anchorKey: scope.anchorKey,
    relationshipID: scope.relationshipID,
    expectedAnchor: null,
    nextGeneration: 1,
    nextStateDigest: digest,
    persistEncryptedState: () => store.encryptedStateStoreBackend.set(scope.stateKey, {
      ciphertext: "PRIVATE_STATE_CANARY"
    })
  });
  const loaded = await store.load({
    anchorKey: scope.anchorKey,
    relationshipID: scope.relationshipID,
    loadEncryptedState: () => store.encryptedStateStoreBackend.get(scope.stateKey)
  });
  assert.deepEqual(loaded.anchor, first);
  assert.deepEqual(loaded.state, { ciphertext: "PRIVATE_STATE_CANARY" });

  const database = indexedDB.databases.get("NoctweaveJS-Browser-v2");
  const entries = [...database.stores.get("sealedAnchors").values(), ...database.stores.get("sealedStates").values()];
  assert.equal(entries.length, 2);
  for (const entry of entries) {
    assert.match(entry.id, /^[A-Za-z0-9+/]{43}=$/u);
    const stored = `${entry.id} ${Buffer.from(entry.value).toString("utf8")}`;
    for (const canary of [scope.relationshipID, scope.anchorKey, scope.stateKey, digest, "PRIVATE_STATE_CANARY"]) {
      assert.equal(stored.includes(canary), false, canary);
    }
  }
  assert.equal(database.stores.get("anchors").size, 0);
  assert.equal(database.stores.get("encryptedStates").size, 0);

  const stale = await factory(scope);
  await stale.load({
    anchorKey: scope.anchorKey,
    relationshipID: scope.relationshipID,
    loadEncryptedState: () => stale.encryptedStateStoreBackend.get(scope.stateKey)
  });
  await store.commit({
    anchorKey: scope.anchorKey,
    relationshipID: scope.relationshipID,
    expectedAnchor: first,
    nextGeneration: 2,
    nextStateDigest: digest,
    persistEncryptedState: () => store.encryptedStateStoreBackend.set(scope.stateKey, { ciphertext: "NEW_SECRET" })
  });
  await assert.rejects(stale.commit({
    anchorKey: scope.anchorKey,
    relationshipID: scope.relationshipID,
    expectedAnchor: first,
    nextGeneration: 2,
    nextStateDigest: digest,
    persistEncryptedState: () => stale.encryptedStateStoreBackend.set(scope.stateKey, { ciphertext: "STALE_SECRET" })
  }), /compare-and-swap failed/u);
});

test("wrong or missing IndexedDB encryption key fails closed and does not rewrite records", async () => {
  for (const replacement of ["wrong", "missing"]) {
    const indexedDB = new TestIndexedDB();
    const factory = createIndexedDBBrowserAnchorStoreFactoryV2({ indexedDB, storageCrypto: webcrypto });
    const store = await factory(scope);
    await store.commit({
      anchorKey: scope.anchorKey,
      relationshipID: scope.relationshipID,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest,
      persistEncryptedState: () => store.encryptedStateStoreBackend.set(scope.stateKey, { ciphertext: "SECRET" })
    });
    const database = indexedDB.databases.get("NoctweaveJS-Browser-v2");
    const before = structuredClone([...database.stores.get("sealedAnchors").values()]);
    if (replacement === "wrong") {
      database.stores.get("integrityKeys").get("browser-anchor-encryption-v3").value =
        await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    } else {
      database.stores.get("integrityKeys").delete("browser-anchor-encryption-v3");
    }
    const reopenedFactory = createIndexedDBBrowserAnchorStoreFactoryV2({ indexedDB, storageCrypto: webcrypto });
    if (replacement === "missing") {
      await assert.rejects(reopenedFactory(scope), /encryption key is missing/u);
    } else {
      const reopened = await reopenedFactory(scope);
      await assert.rejects(reopened.load({
        anchorKey: scope.anchorKey,
        relationshipID: scope.relationshipID,
        loadEncryptedState: () => reopened.encryptedStateStoreBackend.get(scope.stateKey)
      }), /authentication failed/u);
    }
    assert.deepEqual([...database.stores.get("sealedAnchors").values()], before);
  }
});

test("wrong IndexedDB integrity key fails closed before a new opaque record ID is used", async () => {
  const indexedDB = new TestIndexedDB();
  const store = await createIndexedDBBrowserAnchorStoreFactoryV2({ indexedDB, storageCrypto: webcrypto })(scope);
  await store.commit({
    anchorKey: scope.anchorKey,
    relationshipID: scope.relationshipID,
    expectedAnchor: null,
    nextGeneration: 1,
    nextStateDigest: digest,
    persistEncryptedState: () => store.encryptedStateStoreBackend.set(scope.stateKey, { ciphertext: "SECRET" })
  });
  const database = indexedDB.databases.get("NoctweaveJS-Browser-v2");
  database.stores.get("integrityKeys").get("browser-anchor-integrity-v2").value =
    await webcrypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const reopenedFactory = createIndexedDBBrowserAnchorStoreFactoryV2({ indexedDB, storageCrypto: webcrypto });
  await assert.rejects(reopenedFactory(scope), /integrity key authentication failed/u);
  assert.equal(database.stores.get("sealedAnchors").size, 1);
});

test("legacy plaintext anchor records block startup without deleting developer data", async () => {
  const indexedDB = new TestIndexedDB();
  await createIndexedDBBrowserAnchorStoreFactoryV2({ indexedDB, storageCrypto: webcrypto })(scope);
  const database = indexedDB.databases.get("NoctweaveJS-Browser-v2");
  database.stores.get("anchors").set("plaintext", { id: "plaintext", value: { relationshipID: "PRIVATE_LEGACY_CANARY" } });
  const nextFactory = createIndexedDBBrowserAnchorStoreFactoryV2({ indexedDB, storageCrypto: webcrypto });
  await assert.rejects(nextFactory(scope), /Legacy plaintext IndexedDB anchors/u);
  assert.equal(database.stores.get("anchors").get("plaintext").value.relationshipID, "PRIVATE_LEGACY_CANARY");
});

class TestIndexedDB {
  constructor() { this.databases = new Map(); }
  open(name) {
    const result = {};
    queueMicrotask(() => {
      const fresh = !this.databases.has(name);
      result.result = this.databases.get(name) ?? new TestDatabase();
      this.databases.set(name, result.result);
      if (fresh) result.onupgradeneeded?.();
      result.onsuccess?.();
    });
    return result;
  }
}

class TestDatabase {
  constructor() { this.stores = new Map(); this.objectStoreNames = { contains: (name) => this.stores.has(name) }; }
  createObjectStore(name) { const store = new Map(); this.stores.set(name, store); return new TestObjectStore(store); }
  transaction(names) { return new TestTransaction(this, Array.isArray(names) ? names : [names]); }
}

class TestTransaction {
  constructor(database, names) {
    this.database = database;
    this.names = names;
    setTimeout(() => this.oncomplete?.(), 5);
  }
  objectStore(name) {
    if (!this.names.includes(name)) throw new Error(`Store ${name} is outside this transaction.`);
    const store = this.database.stores.get(name);
    if (!store) throw new Error(`Missing object store ${name}.`);
    return new TestObjectStore(store);
  }
}

class TestObjectStore {
  constructor(store) { this.store = store; }
  get(key) { return this.request(this.store.get(key)); }
  count() { return this.request(this.store.size); }
  add(value) { if (this.store.has(value.id)) throw new Error("ConstraintError"); this.store.set(value.id, structuredClone(value)); return this.request(value); }
  put(value) { this.store.set(value.id, structuredClone(value)); return this.request(value); }
  delete(key) { this.store.delete(key); return this.request(undefined); }
  request(value) {
    const request = {};
    queueMicrotask(() => { request.result = structuredClone(value); request.onsuccess?.(); });
    return request;
  }
}
