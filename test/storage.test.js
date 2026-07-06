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
