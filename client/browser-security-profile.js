import { base64, canonicalJsonBytes } from "../src/crypto/swift-canonical.js";

export const browserRollbackResistanceWarning =
  "Browser IndexedDB is a best-effort, rollbackable profile. It is encrypted and integrity-authenticated, but ordinary browser storage has no hardware rollback resistance and is not equivalent to the hardened Electrobun host anchor. A restored browser profile or older disk image may be undetectable.";

export const browserSecurityStorageProfileV2 = Object.freeze({
  id: "browser-indexeddb-authenticated-v2",
  label: "Browser: encrypted IndexedDB with authenticated atomic anchors",
  hardwareRollbackResistance: false,
  warning: browserRollbackResistanceWarning
});

const databaseVersion = 1;
const anchorStoreName = "anchors";
const stateStoreName = "encryptedStates";
const keyStoreName = "integrityKeys";
const integrityKeyID = "browser-anchor-integrity-v2";
const erasedDigest = base64(new Uint8Array(32));
const encoder = new TextEncoder();

export function browserSecurityStorageCapabilityV2({
  indexedDB = globalThis.indexedDB,
  storageCrypto = globalThis.crypto
} = {}) {
  const available = Boolean(indexedDB?.open && storageCrypto?.subtle?.sign &&
    storageCrypto?.subtle?.generateKey);
  return Object.freeze({
    ...browserSecurityStorageProfileV2,
    available,
    reason: available ? null : "This browser does not expose IndexedDB and WebCrypto HMAC; the client refuses to use ordinary browser storage as an anchor."
  });
}

export function createIndexedDBBrowserAnchorStoreFactoryV2({
  indexedDB = globalThis.indexedDB,
  storageCrypto = globalThis.crypto,
  databaseName = "NoctweaveJS-Browser-v2"
} = {}) {
  const capability = browserSecurityStorageCapabilityV2({ indexedDB, storageCrypto });
  if (!capability.available) return null;
  const databasePromise = openDatabase(indexedDB, databaseName);
  const integrityKeyPromise = loadOrCreateIntegrityKey({
    databasePromise,
    storageCrypto
  });
  return async (scope) => new IndexedDBBrowserAnchorStore({
    ...scope,
    databasePromise,
    integrityKeyPromise,
    storageCrypto
  });
}

export class IndexedDBBrowserAnchorStore {
  constructor({
    relationshipID,
    anchorKey,
    stateKey,
    databasePromise,
    integrityKeyPromise,
    storageCrypto
  }) {
    if ([relationshipID, anchorKey, stateKey].some((value) =>
      typeof value !== "string" || value.length === 0)) {
      throw new TypeError("IndexedDB anchor scope is invalid.");
    }
    this.relationshipID = relationshipID;
    this.anchorKey = anchorKey;
    this.stateKey = stateKey;
    this.databasePromise = databasePromise;
    this.integrityKeyPromise = integrityKeyPromise;
    this.storageCrypto = storageCrypto;
    this.readRecord = unset;
    this.stagedRecord = unset;
    this.stage = null;
    this.encryptedStateStoreBackend = Object.freeze({
      get: (key) => this.getEncryptedRecord(key),
      set: (key, value) => this.stageEncryptedRecord(key, value),
      delete: (key) => this.stageEncryptedDeletion(key)
    });
  }

  async load({ anchorKey, relationshipID, loadEncryptedState }) {
    this.requireScope(anchorKey, relationshipID);
    if (this.stage !== null || typeof loadEncryptedState !== "function") {
      throw new Error("IndexedDB browser anchor load is not serializable.");
    }
    const database = await this.databasePromise;
    const current = await transaction(database, [anchorStoreName, stateStoreName], "readonly", async (tx) => ({
      anchor: await request(tx.objectStore(anchorStoreName).get(this.anchorID())),
      state: await request(tx.objectStore(stateStoreName).get(this.stateID()))
    }));
    const anchor = current.anchor?.value ?? null;
    const state = current.state?.value ?? null;
    if (anchor !== null) await this.verifyAnchor(anchor);
    this.readRecord = state === null ? null : structuredClone(state);
    try {
      const loadedState = await loadEncryptedState();
      return Object.freeze({ anchor: anchor === null ? null : structuredClone(anchor), state: loadedState });
    } finally {
      this.readRecord = unset;
    }
  }

  async erasureStatus({ anchorKey, relationshipID }) {
    this.requireScope(anchorKey, relationshipID);
    const database = await this.databasePromise;
    const entry = await transaction(database, anchorStoreName, "readonly", (tx) =>
      request(tx.objectStore(anchorStoreName).get(this.anchorID())));
    const anchor = entry?.value ?? null;
    if (anchor !== null) await this.verifyAnchor(anchor);
    return Object.freeze({ erased: anchor?.erased === true });
  }

  async commit({
    anchorKey,
    relationshipID,
    expectedAnchor,
    nextGeneration,
    nextStateDigest,
    persistEncryptedState
  }) {
    this.requireScope(anchorKey, relationshipID);
    if (this.stage !== null || typeof persistEncryptedState !== "function") {
      throw new Error("IndexedDB browser anchor commit is not serializable.");
    }
    this.stage = "commit";
    this.stagedRecord = unset;
    try {
      await persistEncryptedState();
      if (this.stagedRecord === unset || this.stagedRecord === null) {
        throw new Error("Encrypted browser state was not staged for atomic commit.");
      }
      const encryptedRecord = structuredClone(this.stagedRecord);
      requireCanonicalDigest(nextStateDigest, "IndexedDB browser state digest");
      const database = await this.databasePromise;
      const integrityKey = await this.integrityKeyPromise;
      const committed = await transaction(database, [anchorStoreName, stateStoreName], "readwrite", async (tx) => {
        const anchorObjectStore = tx.objectStore(anchorStoreName);
        const stateObjectStore = tx.objectStore(stateStoreName);
        const current = (await request(anchorObjectStore.get(this.anchorID())))?.value ?? null;
        if (current !== null) await this.verifyAnchor(current, integrityKey);
        if (!anchorsEqual(current, expectedAnchor) || nextGeneration !== (current?.generation ?? 0) + 1) {
          throw new Error("IndexedDB browser anchor compare-and-swap failed.");
        }
        const unsigned = {
          version: 2,
          relationshipID: this.relationshipID,
          generation: nextGeneration,
          stateDigest: nextStateDigest,
          authenticationTag: null
        };
        const anchor = await authenticatedAnchor(unsigned, integrityKey, this.storageCrypto);
        anchorObjectStore.put({ id: this.anchorID(), value: anchor });
        stateObjectStore.put({ id: this.stateID(), value: encryptedRecord });
        return anchor;
      });
      return structuredClone(committed);
    } finally {
      this.stagedRecord = unset;
      this.stage = null;
    }
  }

  async destroy({ anchorKey, relationshipID, expectedAnchor, destroyEncryptedState }) {
    this.requireScope(anchorKey, relationshipID);
    if (this.stage !== null || typeof destroyEncryptedState !== "function") {
      throw new Error("IndexedDB browser anchor destruction is not serializable.");
    }
    this.stage = "destroy";
    this.stagedRecord = unset;
    try {
      await destroyEncryptedState();
      if (this.stagedRecord !== null) throw new Error("Encrypted browser state was not staged for atomic destruction.");
      const database = await this.databasePromise;
      const integrityKey = await this.integrityKeyPromise;
      await transaction(database, [anchorStoreName, stateStoreName], "readwrite", async (tx) => {
        const anchorObjectStore = tx.objectStore(anchorStoreName);
        const current = (await request(anchorObjectStore.get(this.anchorID())))?.value ?? null;
        if (current !== null) await this.verifyAnchor(current, integrityKey);
        if (!anchorsEqual(current, expectedAnchor)) throw new Error("IndexedDB browser anchor destruction compare-and-swap failed.");
        const unsigned = {
          version: 2,
          relationshipID: this.relationshipID,
          generation: (current?.generation ?? 0) + 1,
          stateDigest: erasedDigest,
          authenticationTag: null,
          erased: true
        };
        const tombstone = await authenticatedAnchor(unsigned, integrityKey, this.storageCrypto);
        anchorObjectStore.put({ id: this.anchorID(), value: tombstone });
        tx.objectStore(stateStoreName).delete(this.stateID());
      });
      return Object.freeze({ destroyed: true });
    } finally {
      this.stagedRecord = unset;
      this.stage = null;
    }
  }

  async getEncryptedRecord(key) {
    this.requireStateKey(key);
    if (this.readRecord === unset || this.stage !== null) throw new Error("IndexedDB encrypted state may only load inside anchor.load(...).");
    return this.readRecord === null ? null : structuredClone(this.readRecord);
  }

  async stageEncryptedRecord(key, value) {
    this.requireStateKey(key);
    if (this.stage !== "commit" || this.stagedRecord !== unset) throw new Error("IndexedDB encrypted state write escaped atomic anchor commit.");
    this.stagedRecord = structuredClone(value);
  }

  async stageEncryptedDeletion(key) {
    this.requireStateKey(key);
    if (this.stage !== "destroy" || this.stagedRecord !== unset) throw new Error("IndexedDB encrypted state deletion escaped atomic anchor destruction.");
    this.stagedRecord = null;
  }

  async verifyAnchor(anchor, providedKey = null) {
    if (!anchor || anchor.version !== 2 || anchor.relationshipID !== this.relationshipID ||
        !Number.isSafeInteger(anchor.generation) || anchor.generation < 1 ||
        typeof anchor.stateDigest !== "string" || typeof anchor.authenticationTag !== "string") {
      throw new Error("IndexedDB browser anchor is malformed.");
    }
    const key = providedKey ?? await this.integrityKeyPromise;
    const unsigned = { ...anchor, authenticationTag: null };
    if (anchor.erased === true && anchor.stateDigest !== erasedDigest) throw new Error("IndexedDB browser erasure tombstone is malformed.");
    const expected = await authenticatedAnchor(unsigned, key, this.storageCrypto);
    if (expected.authenticationTag !== anchor.authenticationTag) throw new Error("IndexedDB browser anchor authentication failed.");
  }

  anchorID() { return `${this.relationshipID}\u0000${this.anchorKey}`; }
  stateID() { return `${this.relationshipID}\u0000${this.stateKey}`; }
  requireScope(anchorKey, relationshipID) {
    if (anchorKey !== this.anchorKey || relationshipID !== this.relationshipID) throw new Error("IndexedDB browser anchor scope changed after construction.");
  }
  requireStateKey(key) {
    if (key !== this.stateKey) throw new Error("IndexedDB browser encrypted state key is outside its anchor scope.");
  }
}

const unset = Symbol("unset IndexedDB encrypted record");

function openDatabase(indexedDB, databaseName) {
  return new Promise((resolve, reject) => {
    const opening = indexedDB.open(databaseName, databaseVersion);
    opening.onupgradeneeded = () => {
      const database = opening.result;
      if (!database.objectStoreNames.contains(anchorStoreName)) database.createObjectStore(anchorStoreName, { keyPath: "id" });
      if (!database.objectStoreNames.contains(stateStoreName)) database.createObjectStore(stateStoreName, { keyPath: "id" });
      if (!database.objectStoreNames.contains(keyStoreName)) database.createObjectStore(keyStoreName, { keyPath: "id" });
    };
    opening.onsuccess = () => resolve(opening.result);
    opening.onerror = () => reject(opening.error ?? new Error("IndexedDB browser anchor database could not open."));
    opening.onblocked = () => reject(new Error("IndexedDB browser anchor database is blocked by another profile.") );
  });
}

async function loadOrCreateIntegrityKey({ databasePromise, storageCrypto }) {
  const database = await databasePromise;
  const existing = await transaction(database, keyStoreName, "readonly", (tx) =>
    request(tx.objectStore(keyStoreName).get(integrityKeyID)));
  if (existing?.value) return existing.value;
  const generated = await storageCrypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  try {
    await transaction(database, keyStoreName, "readwrite", (tx) => {
      tx.objectStore(keyStoreName).add({ id: integrityKeyID, value: generated });
    });
    return generated;
  } catch (error) {
    const winner = await transaction(database, keyStoreName, "readonly", (tx) =>
      request(tx.objectStore(keyStoreName).get(integrityKeyID)));
    if (winner?.value) return winner.value;
    throw error;
  }
}

async function authenticatedAnchor(unsigned, key, storageCrypto) {
  const payload = { ...unsigned, authenticationTag: null };
  const tag = await storageCrypto.subtle.sign(
    { name: "HMAC" }, key, canonicalJsonBytes(payload)
  );
  return Object.freeze({ ...unsigned, authenticationTag: base64(new Uint8Array(tag)) });
}

function anchorsEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function requireCanonicalDigest(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/u.test(value)) {
    throw new Error(`${label} is malformed.`);
  }
  let bytes;
  try {
    bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  } catch {
    throw new Error(`${label} is malformed.`);
  }
  if (bytes.byteLength !== 32 || base64(bytes) !== value) {
    throw new Error(`${label} is malformed.`);
  }
}

function request(operation) {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result);
    operation.onerror = () => reject(operation.error ?? new Error("IndexedDB request failed."));
  });
}

function transaction(database, stores, mode, operation) {
  return new Promise((resolve, reject) => {
    const tx = database.transaction(stores, mode);
    let result;
    Promise.resolve().then(() => operation(tx)).then((value) => {
      result = value;
    }, reject);
    tx.oncomplete = () => resolve(result);
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed."));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted."));
  });
}
