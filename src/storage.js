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
      let operationResult;
      let settled = false;
      const fail = (error) => {
        if (!settled) {
          settled = true;
          reject(error);
        }
      };
      tx.oncomplete = () => {
        if (!settled) {
          settled = true;
          resolve(operationResult);
        }
      };
      tx.onerror = () => fail(tx.error);
      tx.onabort = () => fail(tx.error);
      try {
        Promise.resolve(operation(store))
          .then((result) => {
            operationResult = result;
          })
          .catch((error) => {
            try {
              tx.abort();
            } catch {
              // Ignore abort failures; the original error is more useful.
            }
            fail(error);
          });
      } catch (error) {
        try {
          tx.abort();
        } catch {
          // Ignore abort failures; the original error is more useful.
        }
        fail(error);
      }
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

export class EncryptedNoctweaveStore {
  constructor(store, options = {}) {
    for (const method of ["get", "set", "delete"]) {
      if (typeof store?.[method] !== "function") {
        throw new TypeError(`Encrypted store backend must implement ${method}(...)`);
      }
    }
    this.store = store;
    this.crypto = options.crypto ?? globalThis.crypto;
    if (!this.crypto?.subtle || typeof this.crypto.getRandomValues !== "function") {
      throw new Error("WebCrypto is required for encrypted Noctweave storage.");
    }
    this.keyPromise = this.resolveKey(options);
  }

  async get(key) {
    const envelope = await this.store.get(key);
    if (envelope == null) {
      return null;
    }
    if (envelope.__noctweaveEncrypted !== 1) {
      throw new Error("Encrypted store refused to load plaintext state.");
    }
    const cryptoKey = await this.keyPromise;
    const plaintext = await this.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(envelope.nonce),
        additionalData: storageAAD(key)
      },
      cryptoKey,
      base64ToBytes(envelope.ciphertext)
    );
    const plaintextBytes = new Uint8Array(plaintext);
    try {
      return JSON.parse(new TextDecoder().decode(plaintextBytes));
    } finally {
      plaintextBytes.fill(0);
    }
  }

  async set(key, value) {
    const cryptoKey = await this.keyPromise;
    const nonce = randomBytes(this.crypto, 12);
    const plaintext = new TextEncoder().encode(JSON.stringify(value));
    try {
      const ciphertext = await this.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: storageAAD(key)
        },
        cryptoKey,
        plaintext
      );
      await this.store.set(key, {
        __noctweaveEncrypted: 1,
        version: 1,
        algorithm: "AES-256-GCM",
        nonce: bytesToBase64(nonce),
        ciphertext: bytesToBase64(new Uint8Array(ciphertext))
      });
    } finally {
      plaintext.fill(0);
    }
  }

  async delete(key) {
    await this.store.delete(key);
  }

  async clear() {
    if (typeof this.store.clear === "function") {
      await this.store.clear();
      return;
    }
    throw new Error("Encrypted store backend does not implement clear().");
  }

  async resolveKey(options) {
    if (typeof globalThis.CryptoKey !== "undefined" && options.key instanceof globalThis.CryptoKey) {
      return options.key;
    }
    if (options.keyBytes || options.rawKey) {
      const raw = copyBytesFromInput(options.keyBytes ?? options.rawKey);
      if (raw.byteLength !== 32) {
        raw.fill(0);
        throw new Error("Encrypted store raw key must be 32 bytes.");
      }
      try {
        return await this.crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
      } finally {
        raw.fill(0);
      }
    }
    if (options.passphrase) {
      const salt = bytesFromInput(options.salt ?? "noctweave-js-storage-v1");
      const passphraseBytes = new TextEncoder().encode(String(options.passphrase));
      let baseKey;
      try {
        baseKey = await this.crypto.subtle.importKey(
          "raw",
          passphraseBytes,
          "PBKDF2",
          false,
          ["deriveKey"]
        );
      } finally {
        passphraseBytes.fill(0);
      }
      return this.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: Number(options.iterations ?? 210_000),
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    }
    throw new Error("Encrypted store requires keyBytes, rawKey, key, or passphrase.");
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
    this.queue = Promise.resolve();
  }

  async load() {
    return this.store.get(this.key);
  }

  async save(state) {
    return this.serialized(async () => {
      await this.store.set(this.key, state);
      return state;
    });
  }

  async update(mutator) {
    return this.serialized(async () => {
      const current = await this.store.get(this.key);
      const next = await mutator(current);
      await this.store.set(this.key, next);
      return next;
    });
  }

  async clear() {
    await this.serialized(() => this.store.delete(this.key));
  }

  serialized(operation) {
    const next = this.queue.then(operation, operation);
    this.queue = next.catch(() => {});
    return next;
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

function storageAAD(key) {
  return new TextEncoder().encode(`noctweave-storage:v1:${key}`);
}

function randomBytes(crypto, length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesFromInput(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (typeof value === "string") {
    return new TextEncoder().encode(value);
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  throw new TypeError("Expected bytes, ArrayBuffer, array, or string.");
}

function copyBytesFromInput(value) {
  return new Uint8Array(bytesFromInput(value));
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "base64"));
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
