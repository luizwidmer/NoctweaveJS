import { parseExactJSON } from "./strict-json.js";

const MAX_STORAGE_KEY_BYTES = 256;
const MAX_PLAINTEXT_RECORD_BYTES = 8 * 1024 * 1024;
const MAX_ENCRYPTED_RECORD_BYTES = 12 * 1024 * 1024;
const MIN_PASSPHRASE_CHARACTERS = 12;
const MAX_PASSPHRASE_BYTES = 1024;

export class MemoryNoctweaveStore {
  constructor(initialEntries = []) {
    this.records = new Map();
    for (const [key, value] of initialEntries) {
      validateStorageKey(key);
      validateRecordSize(value);
      this.records.set(key, cloneValue(value));
    }
  }

  async get(key) {
    validateStorageKey(key);
    const value = this.records.has(key) ? cloneValue(this.records.get(key)) : null;
    validateRecordSize(value);
    return value;
  }

  async set(key, value) {
    validateStorageKey(key);
    validateRecordSize(value);
    this.records.set(key, cloneValue(value));
  }

  async delete(key) {
    validateStorageKey(key);
    this.records.delete(key);
  }

  async clear() {
    this.records.clear();
  }
}

export class BrowserLocalStorageStore {
  constructor({ namespace = "noctweave", storage } = {}) {
    validateStorageKey(namespace);
    this.namespace = namespace;
    this.storage = storage ?? globalThis.localStorage;
    if (!this.storage) {
      throw new Error("localStorage is not available in this runtime.");
    }
  }

  async get(key) {
    validateStorageKey(key);
    const raw = this.storage.getItem(this.storageKey(key));
    if (raw == null) {
      return null;
    }
    if (raw.length > MAX_ENCRYPTED_RECORD_BYTES) {
      throw new Error("Stored record exceeds its size limit.");
    }
    return parseExactJSON(raw);
  }

  async set(key, value) {
    validateStorageKey(key);
    const encoded = JSON.stringify(value);
    if (typeof encoded !== "string" || encoded.length > MAX_ENCRYPTED_RECORD_BYTES) {
      throw new Error("Stored record exceeds its size limit.");
    }
    this.storage.setItem(this.storageKey(key), encoded);
  }

  async delete(key) {
    validateStorageKey(key);
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
    validateStorageKey(databaseName);
    validateStorageKey(storeName);
    if (!Number.isSafeInteger(version) || version < 1 || version > 1_000_000) {
      throw new TypeError("IndexedDB version must be an integer between 1 and 1000000.");
    }
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
    validateStorageKey(key);
    const value = await this.transaction("readonly", (store) => requestToPromise(store.get(key)));
    validateRecordSize(value);
    return value;
  }

  async set(key, value) {
    validateStorageKey(key);
    validateRecordSize(value);
    await this.transaction("readwrite", (store) => requestToPromise(store.put(value, key)));
  }

  async delete(key) {
    validateStorageKey(key);
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
    validateEncryptedStoreKeyOptions(options);
    this.keyOptions = options;
    this.keyPromise = null;
  }

  async get(key) {
    validateStorageKey(key);
    const envelope = await this.store.get(key);
    if (envelope == null) {
      return null;
    }
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) ||
        envelope.__noctweaveEncrypted !== 1 || envelope.version !== 1 ||
        envelope.algorithm !== "AES-256-GCM") {
      throw new Error("Encrypted store refused to load plaintext state.");
    }
    const nonce = base64ToBytesStrict(envelope.nonce, "storage nonce", 12, 12);
    const ciphertext = base64ToBytesStrict(
      envelope.ciphertext,
      "storage ciphertext",
      MAX_ENCRYPTED_RECORD_BYTES
    );
    if (ciphertext.byteLength < 16) {
      throw new Error("Encrypted store record is malformed.");
    }
    const cryptoKey = await this.encryptionKey();
    try {
      const plaintext = await this.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: storageAAD(key)
        },
        cryptoKey,
        ciphertext
      );
      const plaintextBytes = new Uint8Array(plaintext);
      try {
        if (plaintextBytes.byteLength > MAX_PLAINTEXT_RECORD_BYTES) {
          throw new Error("Decrypted store record exceeds its size limit.");
        }
        return parseExactJSON(new TextDecoder("utf-8", { fatal: true }).decode(plaintextBytes));
      } finally {
        plaintextBytes.fill(0);
      }
    } finally {
      nonce.fill(0);
      ciphertext.fill(0);
    }
  }

  async set(key, value) {
    validateStorageKey(key);
    const cryptoKey = await this.encryptionKey();
    const nonce = randomBytes(this.crypto, 12);
    const serialized = JSON.stringify(value);
    if (typeof serialized !== "string") {
      throw new Error("Encrypted store value is not JSON serializable.");
    }
    const plaintext = new TextEncoder().encode(serialized);
    try {
      if (plaintext.byteLength > MAX_PLAINTEXT_RECORD_BYTES) {
        throw new Error("Encrypted store record exceeds its size limit.");
      }
      const ciphertext = await this.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: storageAAD(key)
        },
        cryptoKey,
        plaintext
      );
      if (ciphertext.byteLength > MAX_ENCRYPTED_RECORD_BYTES) {
        throw new Error("Encrypted store record exceeds its size limit.");
      }
      await this.store.set(key, {
        __noctweaveEncrypted: 1,
        version: 1,
        algorithm: "AES-256-GCM",
        nonce: bytesToBase64(nonce),
        ciphertext: bytesToBase64(new Uint8Array(ciphertext))
      });
    } finally {
      plaintext.fill(0);
      nonce.fill(0);
    }
  }

  async delete(key) {
    validateStorageKey(key);
    await this.store.delete(key);
  }

  async clear() {
    if (typeof this.store.clear === "function") {
      await this.store.clear();
      return;
    }
    throw new Error("Encrypted store backend does not implement clear().");
  }

  encryptionKey() {
    this.keyPromise ??= this.resolveKey(this.keyOptions);
    return this.keyPromise;
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
    if (options.passphrase !== undefined) {
      const passphrase = String(options.passphrase);
      validateStorePassphrase(passphrase);
      if (options.salt === undefined) {
        throw new Error("Encrypted store passphrase mode requires a unique persisted salt.");
      }
      const salt = copyBytesFromInput(options.salt);
      if (salt.byteLength < 16) {
        salt.fill(0);
        throw new Error("Encrypted store passphrase salt must be at least 16 bytes.");
      }
      const iterations = Number(options.iterations ?? 210_000);
      if (!Number.isSafeInteger(iterations) || iterations < 100_000 || iterations > 10_000_000) {
        salt.fill(0);
        throw new Error("Encrypted store PBKDF2 iterations must be between 100000 and 10000000.");
      }
      const passphraseBytes = new TextEncoder().encode(passphrase);
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
      try {
        return await this.crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt,
            iterations,
            hash: "SHA-256"
          },
          baseKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
      } finally {
        salt.fill(0);
      }
    }
    throw new Error("Encrypted store requires keyBytes, rawKey, key, or passphrase.");
  }
}

function validateEncryptedStoreKeyOptions(options) {
  if (typeof globalThis.CryptoKey !== "undefined" && options.key instanceof globalThis.CryptoKey) {
    return;
  }
  if (options.keyBytes || options.rawKey) {
    const raw = copyBytesFromInput(options.keyBytes ?? options.rawKey);
    const valid = raw.byteLength === 32;
    raw.fill(0);
    if (!valid) {
      throw new Error("Encrypted store raw key must be 32 bytes.");
    }
    return;
  }
  if (options.passphrase !== undefined) {
    validateStorePassphrase(String(options.passphrase));
    if (options.salt === undefined) {
      throw new Error("Encrypted store passphrase mode requires a unique persisted salt.");
    }
    const salt = copyBytesFromInput(options.salt);
    const validSalt = salt.byteLength >= 16;
    salt.fill(0);
    if (!validSalt) {
      throw new Error("Encrypted store passphrase salt must be at least 16 bytes.");
    }
    const iterations = Number(options.iterations ?? 210_000);
    if (!Number.isSafeInteger(iterations) || iterations < 100_000 || iterations > 10_000_000) {
      throw new Error("Encrypted store PBKDF2 iterations must be between 100000 and 10000000.");
    }
    return;
  }
  throw new Error("Encrypted store requires keyBytes, rawKey, key, or passphrase.");
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
    validateStorageKey(key);
    const value = await this.adapter.get(key);
    validateRecordSize(value);
    return value;
  }

  async set(key, value) {
    validateStorageKey(key);
    validateRecordSize(value);
    await this.adapter.set(key, value);
  }

  async delete(key) {
    validateStorageKey(key);
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
    for (const method of ["get", "set", "delete"]) {
      if (typeof store?.[method] !== "function") {
        throw new TypeError(`State repository store must implement ${method}(...).`);
      }
    }
    validateStorageKey(key);
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
  validateStorageKey(key);
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

function base64ToBytesStrict(value, label, maximumBytes, exactBytes = null) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > Math.ceil(maximumBytes / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  let bytes;
  if (typeof Buffer !== "undefined") {
    bytes = new Uint8Array(Buffer.from(value, "base64"));
  } else {
    const binary = atob(value);
    bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
  }
  if (bytes.byteLength > maximumBytes ||
      (exactBytes !== null && bytes.byteLength !== exactBytes) ||
      bytesToBase64(bytes) !== value) {
    bytes.fill(0);
    throw new Error(`Invalid ${label}.`);
  }
  return bytes;
}

function validateStorageKey(key) {
  if (typeof key !== "string" || key.length === 0 ||
      new TextEncoder().encode(key).byteLength > MAX_STORAGE_KEY_BYTES) {
    throw new TypeError("Storage key must be a non-empty string no larger than 256 bytes.");
  }
}

function validateRecordSize(value) {
  if (value == null) {
    return;
  }
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new TypeError("Stored record must be JSON serializable.");
  }
  if (typeof encoded !== "string" || new TextEncoder().encode(encoded).byteLength > MAX_ENCRYPTED_RECORD_BYTES) {
    throw new Error("Stored record exceeds its size limit.");
  }
}

function validateStorePassphrase(passphrase) {
  const byteLength = new TextEncoder().encode(passphrase).byteLength;
  if (passphrase.length < MIN_PASSPHRASE_CHARACTERS || byteLength > MAX_PASSPHRASE_BYTES) {
    throw new Error(
      `Encrypted store passphrase must contain at least ${MIN_PASSPHRASE_CHARACTERS} characters and no more than ${MAX_PASSPHRASE_BYTES} UTF-8 bytes.`
    );
  }
}
