import assert from "node:assert/strict";
import test from "node:test";
import {
  BrowserLocalStorageStore,
  DatabaseNoctweaveStore,
  EncryptedNoctweaveStore,
  MemoryNoctweaveStore,
  NoctweaveStateRepository
} from "../src/index.js";

test("memory store clones records", async () => {
  const store = new MemoryNoctweaveStore();
  const value = { contacts: [{ name: "Alice" }] };
  await store.set("state", value);
  value.contacts[0].name = "Mutated";

  const loaded = await store.get("state");
  assert.equal(loaded.contacts[0].name, "Alice");
});

test("raw stores reject unbounded keys, oversized records, and non-JSON values", async () => {
  const memory = new MemoryNoctweaveStore();
  await assert.rejects(() => memory.set("x".repeat(257), { value: 1 }), /Storage key/);
  await assert.rejects(
    () => memory.set("state", { payload: "x".repeat(12 * 1024 * 1024 + 1) }),
    /size limit/
  );
  await assert.rejects(() => memory.set("state", { value: 1n }), /JSON serializable/);

  const database = new DatabaseNoctweaveStore({
    get: async () => null,
    set: async () => {},
    delete: async () => {}
  });
  await assert.rejects(() => database.get("x".repeat(257)), /Storage key/);
  assert.throws(
    () => new NoctweaveStateRepository({}, { key: "state" }),
    /must implement get/
  );
});

test("localStorage store namespaces records", async () => {
  const storage = makeLocalStorage();
  const store = new BrowserLocalStorageStore({ namespace: "test", storage });

  await store.set("state", { relay: "https://relay.example" });
  assert.equal(storage.getItem("test:state"), "{\"relay\":\"https://relay.example\"}");
  assert.deepEqual(await store.get("state"), { relay: "https://relay.example" });

  await store.clear();
  assert.equal(storage.length, 0);
});

test("database adapter store delegates persistence", async () => {
  const records = new Map();
  const store = new DatabaseNoctweaveStore({
    get: async (key) => records.get(key) ?? null,
    set: async (key, value) => records.set(key, value),
    delete: async (key) => records.delete(key),
    clear: async () => records.clear()
  });

  const repo = new NoctweaveStateRepository(store);
  await repo.save({ inboxId: "nw1..." });
  assert.deepEqual(await repo.load(), { inboxId: "nw1..." });
  await repo.clear();
  assert.equal(await repo.load(), null);
});

test("encrypted store refuses plaintext records and hides persisted state", async () => {
  const backend = new MemoryNoctweaveStore();
  const store = new EncryptedNoctweaveStore(backend, {
    keyBytes: new Uint8Array(32).fill(7)
  });

  await store.set("state", { inboxId: "nw1secret", contacts: [{ name: "Alice" }] });
  const raw = await backend.get("state");

  assert.equal(raw.__noctweaveEncrypted, 1);
  assert.equal(JSON.stringify(raw).includes("nw1secret"), false);
  assert.deepEqual(await store.get("state"), { inboxId: "nw1secret", contacts: [{ name: "Alice" }] });

  await backend.set("plaintext", { inboxId: "leak" });
  await assert.rejects(() => store.get("plaintext"), /refused to load plaintext/);
});

test("encrypted store passphrase mode requires a strong explicit KDF configuration", async () => {
  assert.throws(
    () => new EncryptedNoctweaveStore(new MemoryNoctweaveStore(), {
      passphrase: "too short",
      salt: new Uint8Array(16)
    }),
    /at least 12 characters/
  );
  assert.throws(
    () => new EncryptedNoctweaveStore(new MemoryNoctweaveStore(), {
      passphrase: "correct horse battery staple"
    }),
    /requires a unique persisted salt/
  );
  assert.throws(
    () => new EncryptedNoctweaveStore(new MemoryNoctweaveStore(), {
      passphrase: "correct horse battery staple",
      salt: new Uint8Array(8)
    }),
    /at least 16 bytes/
  );
  assert.throws(
    () => new EncryptedNoctweaveStore(new MemoryNoctweaveStore(), {
      passphrase: "correct horse battery staple",
      salt: new Uint8Array(16),
      iterations: 1_000
    }),
    /between 100000 and 10000000/
  );
});

test("encrypted store rejects malformed envelopes and unbounded keys", async () => {
  const backend = new MemoryNoctweaveStore();
  const store = new EncryptedNoctweaveStore(backend, {
    keyBytes: new Uint8Array(32).fill(3)
  });
  await backend.set("bad", {
    __noctweaveEncrypted: 1,
    version: 1,
    algorithm: "AES-256-GCM",
    nonce: "not-base64",
    ciphertext: "AAAA"
  });
  await assert.rejects(() => store.get("bad"), /Invalid storage nonce/);
  await assert.rejects(() => store.set("x".repeat(257), { value: 1 }), /Storage key/);
});

test("encrypted store passphrase mode round trips with a persisted salt", async () => {
  const backend = new MemoryNoctweaveStore();
  const options = {
    passphrase: "correct horse battery staple",
    salt: new Uint8Array(16).fill(9),
    iterations: 100_000
  };
  const writer = new EncryptedNoctweaveStore(backend, options);
  await writer.set("state", { value: "encrypted" });

  const reader = new EncryptedNoctweaveStore(backend, options);
  assert.deepEqual(await reader.get("state"), { value: "encrypted" });
});

test("state repository serializes concurrent updates", async () => {
  const repository = new NoctweaveStateRepository(new MemoryNoctweaveStore());
  await repository.save({ count: 0 });

  await Promise.all(Array.from({ length: 20 }, () => repository.update((state) => ({
    count: state.count + 1
  }))));

  assert.deepEqual(await repository.load(), { count: 20 });
});

function makeLocalStorage() {
  const records = new Map();
  return {
    get length() {
      return records.size;
    },
    key(index) {
      return Array.from(records.keys())[index] ?? null;
    },
    getItem(key) {
      return records.has(key) ? records.get(key) : null;
    },
    setItem(key, value) {
      records.set(key, String(value));
    },
    removeItem(key) {
      records.delete(key);
    }
  };
}
