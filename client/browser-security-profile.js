import { base64, canonicalJsonBytes } from "../src/crypto/swift-canonical.js";

export const browserRollbackResistanceWarning =
  "Browser IndexedDB is a best-effort, rollbackable profile. It is encrypted and integrity-authenticated, but ordinary browser storage has no hardware rollback resistance and is not equivalent to the hardened Electrobun host anchor. A restored browser profile or older disk image may be undetectable.";

export const browserSecurityStorageProfileV2 = Object.freeze({
  id: "browser-indexeddb-authenticated-v2",
  label: "Browser: encrypted IndexedDB with authenticated atomic anchors",
  hardwareRollbackResistance: false,
  warning: browserRollbackResistanceWarning
});

const databaseVersion = 2;
const anchorStoreName = "anchors";
const stateStoreName = "encryptedStates";
const sealedAnchorStoreName = "sealedAnchors";
const sealedStateStoreName = "sealedStates";
const keyStoreName = "integrityKeys";
const integrityKeyID = "browser-anchor-integrity-v2";
const encryptionKeyID = "browser-anchor-encryption-v3";
const keyCheckID = "browser-anchor-key-check-v3";
const erasedDigest = base64(new Uint8Array(32));
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const maximumSealedAnchorBytes = 4_096;
const maximumSealedStateBytes = 32 * 1024 * 1024;

export function browserSecurityStorageCapabilityV2({
  indexedDB = globalThis.indexedDB,
  storageCrypto = globalThis.crypto
} = {}) {
  const available = Boolean(indexedDB?.open && storageCrypto?.getRandomValues && storageCrypto?.subtle?.sign &&
    storageCrypto?.subtle?.encrypt && storageCrypto?.subtle?.decrypt &&
    storageCrypto?.subtle?.generateKey);
  return Object.freeze({
    ...browserSecurityStorageProfileV2,
    available,
    reason: available ? null : "This browser does not expose IndexedDB and WebCrypto authenticated encryption; the client refuses to use ordinary browser storage as an anchor."
  });
}

export function createIndexedDBBrowserAnchorStoreFactoryV2({
  indexedDB = globalThis.indexedDB,
  storageCrypto = globalThis.crypto,
  databaseName = "NoctweaveJS-Browser-v2"
} = {}) {
  const capability = browserSecurityStorageCapabilityV2({ indexedDB, storageCrypto });
  if (!capability.available) return null;
  let readyPromise;
  return async (scope) => {
    readyPromise ??= (async () => {
      const database = await openDatabase(indexedDB, databaseName);
      await rejectLegacyPlaintextRecords(database);
      const databasePromise = Promise.resolve(database);
      const [integrityKey, encryptionKey] = await Promise.all([
        loadOrCreateIntegrityKey({ databasePromise, storageCrypto }),
        loadOrCreateEncryptionKey({ databasePromise, storageCrypto })
      ]);
      await verifyOrCreateKeyCheck(database, integrityKey, storageCrypto);
      return { database, integrityKey, encryptionKey };
    })();
    const { database, integrityKey, encryptionKey } = await readyPromise;
    return new IndexedDBBrowserAnchorStore({
      ...scope,
      databasePromise: Promise.resolve(database),
      integrityKeyPromise: Promise.resolve(integrityKey),
      encryptionKeyPromise: Promise.resolve(encryptionKey),
      storageCrypto
    });
  };
}

export class IndexedDBBrowserAnchorStore {
  constructor({
    relationshipID,
    anchorKey,
    stateKey,
    databasePromise,
    integrityKeyPromise,
    encryptionKeyPromise,
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
    this.encryptionKeyPromise = encryptionKeyPromise;
    this.storageCrypto = storageCrypto;
    this.anchorIDPromise = opaqueRecordID("anchor", `${relationshipID}\u0000${anchorKey}`, integrityKeyPromise, storageCrypto);
    this.stateIDPromise = opaqueRecordID("state", `${relationshipID}\u0000${stateKey}`, integrityKeyPromise, storageCrypto);
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
    const [anchorID, stateID, encryptionKey] = await Promise.all([
      this.anchorIDPromise, this.stateIDPromise, this.encryptionKeyPromise
    ]);
    const current = await transaction(database, [sealedAnchorStoreName, sealedStateStoreName], "readonly", async (tx) => ({
      anchor: await request(tx.objectStore(sealedAnchorStoreName).get(anchorID)),
      state: await request(tx.objectStore(sealedStateStoreName).get(stateID))
    }));
    const anchor = current.anchor === undefined ? null : await openRecord(
      current.anchor.value, "anchor", anchorID, encryptionKey, this.storageCrypto, maximumSealedAnchorBytes
    );
    const state = current.state === undefined ? null : await openRecord(
      current.state.value, "state", stateID, encryptionKey, this.storageCrypto, maximumSealedStateBytes
    );
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
    const [anchorID, encryptionKey] = await Promise.all([this.anchorIDPromise, this.encryptionKeyPromise]);
    const entry = await transaction(database, sealedAnchorStoreName, "readonly", (tx) =>
      request(tx.objectStore(sealedAnchorStoreName).get(anchorID)));
    const anchor = entry === undefined ? null : await openRecord(
      entry.value, "anchor", anchorID, encryptionKey, this.storageCrypto, maximumSealedAnchorBytes
    );
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
      const [anchorID, stateID, integrityKey, encryptionKey] = await Promise.all([
        this.anchorIDPromise, this.stateIDPromise, this.integrityKeyPromise, this.encryptionKeyPromise
      ]);
      const snapshot = await transaction(database, sealedAnchorStoreName, "readonly", (tx) =>
        request(tx.objectStore(sealedAnchorStoreName).get(anchorID)));
      const current = snapshot === undefined ? null : await openRecord(
        snapshot.value, "anchor", anchorID, encryptionKey, this.storageCrypto, maximumSealedAnchorBytes
      );
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
      const [sealedAnchor, sealedState] = await Promise.all([
        sealRecord(anchor, "anchor", anchorID, encryptionKey, this.storageCrypto, maximumSealedAnchorBytes),
        sealRecord(encryptedRecord, "state", stateID, encryptionKey, this.storageCrypto, maximumSealedStateBytes)
      ]);
      await transaction(database, [sealedAnchorStoreName, sealedStateStoreName], "readwrite", async (tx) => {
        const anchorObjectStore = tx.objectStore(sealedAnchorStoreName);
        const live = await request(anchorObjectStore.get(anchorID));
        if (!sealedEntriesEqual(live, snapshot)) throw new Error("IndexedDB browser anchor compare-and-swap failed.");
        anchorObjectStore.put({ id: anchorID, value: sealedAnchor });
        tx.objectStore(sealedStateStoreName).put({ id: stateID, value: sealedState });
      });
      return structuredClone(anchor);
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
      const [anchorID, stateID, integrityKey, encryptionKey] = await Promise.all([
        this.anchorIDPromise, this.stateIDPromise, this.integrityKeyPromise, this.encryptionKeyPromise
      ]);
      const snapshot = await transaction(database, sealedAnchorStoreName, "readonly", (tx) =>
        request(tx.objectStore(sealedAnchorStoreName).get(anchorID)));
      const current = snapshot === undefined ? null : await openRecord(
        snapshot.value, "anchor", anchorID, encryptionKey, this.storageCrypto, maximumSealedAnchorBytes
      );
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
      const sealedTombstone = await sealRecord(
        tombstone, "anchor", anchorID, encryptionKey, this.storageCrypto, maximumSealedAnchorBytes
      );
      await transaction(database, [sealedAnchorStoreName, sealedStateStoreName], "readwrite", async (tx) => {
        const anchorObjectStore = tx.objectStore(sealedAnchorStoreName);
        const live = await request(anchorObjectStore.get(anchorID));
        if (!sealedEntriesEqual(live, snapshot)) throw new Error("IndexedDB browser anchor destruction compare-and-swap failed.");
        anchorObjectStore.put({ id: anchorID, value: sealedTombstone });
        tx.objectStore(sealedStateStoreName).delete(stateID);
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
      if (!database.objectStoreNames.contains(sealedAnchorStoreName)) database.createObjectStore(sealedAnchorStoreName, { keyPath: "id" });
      if (!database.objectStoreNames.contains(sealedStateStoreName)) database.createObjectStore(sealedStateStoreName, { keyPath: "id" });
      if (!database.objectStoreNames.contains(keyStoreName)) database.createObjectStore(keyStoreName, { keyPath: "id" });
    };
    opening.onsuccess = () => resolve(opening.result);
    opening.onerror = () => reject(opening.error ?? new Error("IndexedDB browser anchor database could not open."));
    opening.onblocked = () => reject(new Error("IndexedDB browser anchor database is blocked by another profile.") );
  });
}

async function rejectLegacyPlaintextRecords(database) {
  const counts = await transaction(database, [anchorStoreName, stateStoreName], "readonly", async (tx) => [
    await request(tx.objectStore(anchorStoreName).count()),
    await request(tx.objectStore(stateStoreName).count())
  ]);
  if (counts.some((count) => count !== 0)) {
    throw new Error("Legacy plaintext IndexedDB anchors were found. Preserve this prerelease profile and clear this site's IndexedDB manually before continuing.");
  }
}

async function hasSealedRecords(database) {
  const counts = await transaction(database, [sealedAnchorStoreName, sealedStateStoreName], "readonly", async (tx) => [
    await request(tx.objectStore(sealedAnchorStoreName).count()),
    await request(tx.objectStore(sealedStateStoreName).count())
  ]);
  return counts.some((count) => count !== 0);
}

async function loadOrCreateIntegrityKey({ databasePromise, storageCrypto }) {
  const database = await databasePromise;
  const existing = await transaction(database, keyStoreName, "readonly", (tx) =>
    request(tx.objectStore(keyStoreName).get(integrityKeyID)));
  if (existing?.value) return existing.value;
  if (await hasSealedRecords(database)) throw new Error("IndexedDB integrity key is missing; encrypted browser records were preserved.");
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

async function loadOrCreateEncryptionKey({ databasePromise, storageCrypto }) {
  const database = await databasePromise;
  const existing = await transaction(database, keyStoreName, "readonly", (tx) =>
    request(tx.objectStore(keyStoreName).get(encryptionKeyID)));
  if (existing?.value) return existing.value;
  if (await hasSealedRecords(database)) throw new Error("IndexedDB encryption key is missing; encrypted browser records were preserved.");
  const generated = await storageCrypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  try {
    await transaction(database, keyStoreName, "readwrite", (tx) => {
      tx.objectStore(keyStoreName).add({ id: encryptionKeyID, value: generated });
    });
    return generated;
  } catch (error) {
    const winner = await transaction(database, keyStoreName, "readonly", (tx) =>
      request(tx.objectStore(keyStoreName).get(encryptionKeyID)));
    if (winner?.value) return winner.value;
    throw error;
  }
}

async function verifyOrCreateKeyCheck(database, integrityKey, storageCrypto) {
  const digest = base64(new Uint8Array(await storageCrypto.subtle.sign(
    { name: "HMAC" }, integrityKey, encoder.encode("Noctweave/IndexedDB/key-check/v3")
  )));
  const existing = await transaction(database, keyStoreName, "readonly", (tx) =>
    request(tx.objectStore(keyStoreName).get(keyCheckID)));
  if (existing) {
    if (existing.value !== digest) throw new Error("IndexedDB browser integrity key authentication failed.");
    return;
  }
  if (await hasSealedRecords(database)) throw new Error("IndexedDB browser key check is missing; encrypted records were preserved.");
  try {
    await transaction(database, keyStoreName, "readwrite", (tx) => {
      tx.objectStore(keyStoreName).add({ id: keyCheckID, value: digest });
    });
  } catch (error) {
    const winner = await transaction(database, keyStoreName, "readonly", (tx) =>
      request(tx.objectStore(keyStoreName).get(keyCheckID)));
    if (winner?.value !== digest) throw error;
  }
}

async function opaqueRecordID(kind, scope, integrityKeyPromise, storageCrypto) {
  const key = await integrityKeyPromise;
  const digest = await storageCrypto.subtle.sign(
    { name: "HMAC" }, key, encoder.encode(`Noctweave/IndexedDB/${kind}/v3\u0000${scope}`)
  );
  return base64(new Uint8Array(digest));
}

async function sealRecord(value, kind, id, key, storageCrypto, maximumBytes) {
  const plaintext = encoder.encode(JSON.stringify(value));
  try {
    if (plaintext.byteLength > maximumBytes - 28) throw new Error("IndexedDB browser record exceeds its storage bound.");
    const iv = storageCrypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await storageCrypto.subtle.encrypt({
      name: "AES-GCM", iv, additionalData: encoder.encode(`${kind}\u0000${id}`)
    }, key, plaintext));
    const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    combined.set(iv);
    combined.set(ciphertext, iv.byteLength);
    return combined;
  } finally {
    plaintext.fill(0);
  }
}

async function openRecord(stored, kind, id, key, storageCrypto, maximumBytes) {
  if (!(stored instanceof Uint8Array) || stored.byteLength < 29 || stored.byteLength > maximumBytes) {
    throw new Error("IndexedDB browser encrypted record is malformed.");
  }
  let plaintext;
  try {
    plaintext = new Uint8Array(await storageCrypto.subtle.decrypt({
      name: "AES-GCM", iv: stored.subarray(0, 12), additionalData: encoder.encode(`${kind}\u0000${id}`)
    }, key, stored.subarray(12)));
    return JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new Error("IndexedDB browser encrypted record authentication failed.");
  } finally {
    plaintext?.fill(0);
  }
}

function sealedEntriesEqual(left, right) {
  if (left === undefined || right === undefined) return left === right;
  if (left.id !== right.id || !(left.value instanceof Uint8Array) ||
      !(right.value instanceof Uint8Array) || left.value.byteLength !== right.value.byteLength) return false;
  return left.value.every((value, index) => value === right.value[index]);
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
