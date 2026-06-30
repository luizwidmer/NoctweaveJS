export class MemoryNoctweaveStore {
  constructor(initialEntries = []) {
    this.records = new Map(initialEntries);
  }

  async get(key) {
    return this.records.has(key) ? cloneValue(this.records.get(key)) : null;
  }

  async set(key, value) {
    this.records.set(key, cloneValue(value));
  }

  async delete(key) {
    this.records.delete(key);
  }

  async clear() {
    this.records.clear();
  }
}

export class BrowserLocalStorageStore {
  constructor({ namespace = "noctweave", storage } = {}) {
    this.namespace = namespace;
    this.storage = storage ?? globalThis.localStorage;
    if (!this.storage) {
      throw new Error("localStorage is not available in this runtime.");
    }
  }

  async get(key) {
    const raw = this.storage.getItem(this.storageKey(key));
    return raw == null ? null : JSON.parse(raw);
  }

  async set(key, value) {
    this.storage.setItem(this.storageKey(key), JSON.stringify(value));
  }

  async delete(key) {
    this.storage.removeItem(this.storageKey(key));
  }

  async clear() {
    const prefix = `${this.namespace}:`;
    for (let index = this.storage.length - 1; index >= 0; index -= 1) {
      const key = this.storage.key(index);
      if (key?.startsWith(prefix)) {
        this.storage.removeItem(key);
      }
    }
  }

  storageKey(key) {
    return `${this.namespace}:${key}`;
  }
}

export class IndexedDBNoctweaveStore {
  constructor({ databaseName = "noctweave", storeName = "records", version = 1, indexedDB } = {}) {
    this.databaseName = databaseName;
    this.storeName = storeName;
    this.version = version;
    this.indexedDB = indexedDB ?? globalThis.indexedDB;
    if (!this.indexedDB) {
      throw new Error("IndexedDB is not available in this runtime.");
    }
    this.databasePromise = null;
  }

  async get(key) {
    return this.transaction("readonly", (store) => requestToPromise(store.get(key)));
  }

  async set(key, value) {
    await this.transaction("readwrite", (store) => requestToPromise(store.put(value, key)));
  }

  async delete(key) {
    await this.transaction("readwrite", (store) => requestToPromise(store.delete(key)));
  }

  async clear() {
    await this.transaction("readwrite", (store) => requestToPromise(store.clear()));
  }

  async transaction(mode, operation) {
    const database = await this.open();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(this.storeName, mode);
      const store = tx.objectStore(this.storeName);
      let operationPromise;
      tx.oncomplete = () => {};
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
      try {
        operationPromise = Promise.resolve(operation(store));
      } catch (error) {
        reject(error);
        return;
      }
      operationPromise.then(resolve, reject);
    });
  }

  open() {
    if (this.databasePromise) {
      return this.databasePromise;
    }
    this.databasePromise = new Promise((resolve, reject) => {
      const request = this.indexedDB.open(this.databaseName, this.version);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(this.storeName)) {
          database.createObjectStore(this.storeName);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return this.databasePromise;
  }
}

export class DatabaseNoctweaveStore {
  constructor(adapter) {
    for (const method of ["get", "set", "delete"]) {
      if (typeof adapter?.[method] !== "function") {
        throw new TypeError(`Database adapter must implement ${method}(...)`);
      }
    }
    this.adapter = adapter;
  }

  async get(key) {
    return this.adapter.get(key);
  }

  async set(key, value) {
    await this.adapter.set(key, value);
  }

  async delete(key) {
    await this.adapter.delete(key);
  }

  async clear() {
    if (typeof this.adapter.clear === "function") {
      await this.adapter.clear();
      return;
    }
    throw new Error("Database adapter does not implement clear().");
  }
}

export class NoctweaveStateRepository {
  constructor(store, { key = "client-state" } = {}) {
    this.store = store;
    this.key = key;
  }

  async load() {
    return this.store.get(this.key);
  }

  async save(state) {
    await this.store.set(this.key, state);
    return state;
  }

  async update(mutator) {
    const current = await this.load();
    const next = await mutator(current);
    await this.save(next);
    return next;
  }

  async clear() {
    await this.store.delete(this.key);
  }
}

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}

function cloneValue(value) {
  if (value == null) {
    return value;
  }
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
}
