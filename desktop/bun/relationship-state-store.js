import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  mkdir,
  open,
  rename,
  rm
} from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const runtimeAnchorVersion = 2;
const secureAnchorVersion = 3;
const transactionVersion = 3;
const stateRecordVersion = 3;
const maximumEncryptedRecordBytes = 12 * 1024 * 1024;
const maximumHostRecordBytes = 20 * 1024 * 1024;
const keychainServicePrefix = "org.noctweave.js-client.relationship-state.v3";
const erasedDigest = Buffer.alloc(32).toString("base64");

export const desktopRelationshipStateCapability = Object.freeze({
  available: process.platform === "darwin",
  kind: process.platform === "darwin" ? "macos-keychain-journal-v3" : "unavailable",
  reason: process.platform === "darwin"
    ? null
    : "The desktop rollback anchor currently requires macOS Keychain; this platform has no audited secure monotonic backend."
});

export class MacOSKeychainVault {
  constructor({ securityPath = "/usr/bin/security" } = {}) {
    this.securityPath = securityPath;
  }

  async get({ service, account }) {
    this.requireAvailable();
    try {
      const { stdout } = await execFileAsync(this.securityPath, [
        "find-generic-password",
        "-s", service,
        "-a", account,
        "-w"
      ], { encoding: "utf8", maxBuffer: 64 * 1024 });
      return stdout.replace(/[\r\n]+$/u, "");
    } catch (error) {
      const diagnostic = `${error?.stderr ?? ""} ${error?.message ?? ""}`;
      if (error?.code === 44 || /could not be found|item not found/iu.test(diagnostic)) {
        return null;
      }
      throw new Error("macOS Keychain lookup failed.", { cause: error });
    }
  }

  async set({ service, account, value }) {
    this.requireAvailable();
    // `security(1)` has no safe stdin form for generic-password data. This
    // backend therefore stores only non-secret, opaque rollback metadata in
    // the Keychain item. Message keys, plaintext, and encryption keys never
    // enter this command line.
    await execFileAsync(this.securityPath, [
      "add-generic-password",
      "-U",
      "-s", service,
      "-a", account,
      "-w", value
    ], { encoding: "utf8", maxBuffer: 64 * 1024 });
  }

  async delete({ service, account }) {
    this.requireAvailable();
    try {
      await execFileAsync(this.securityPath, [
        "delete-generic-password",
        "-s", service,
        "-a", account
      ], { encoding: "utf8", maxBuffer: 64 * 1024 });
    } catch (error) {
      const diagnostic = `${error?.stderr ?? ""} ${error?.message ?? ""}`;
      if (error?.code === 44 || /could not be found|item not found/iu.test(diagnostic)) return;
      throw new Error("macOS Keychain deletion failed.", { cause: error });
    }
  }

  requireAvailable() {
    if (process.platform !== "darwin") {
      throw new Error(desktopRelationshipStateCapability.reason);
    }
  }
}

export class DesktopRelationshipStateStore {
  constructor({
    rootDirectory = defaultStateRoot(),
    secureVault = new MacOSKeychainVault(),
    capability = desktopRelationshipStateCapability,
    faultInjector = null
  } = {}) {
    this.rootDirectory = rootDirectory;
    this.secureVault = secureVault;
    this.capability = capability;
    this.faultInjector = faultInjector;
    this.queue = Promise.resolve();
  }

  capabilityReport() {
    return Object.freeze({ ...this.capability });
  }

  async erasureStatus(scopeValue) {
    return this.serialized(async () => {
      this.requireAvailable();
      const scope = relationshipStateScope(scopeValue, { rootDirectory: this.rootDirectory });
      return withScopeLock(scope, async () => {
        await this.recoverUnlocked(scope);
        const anchor = await this.loadSecureAnchor(scope);
        const state = await readJSON(scope.paths.state, { missing: null });
        if (anchor?.erased === true) {
          if (state !== null) await durableRemove(scope.paths.state);
          return Object.freeze({ erased: true });
        }
        validateStateAndAnchor(state, anchor, scope);
        return Object.freeze({ erased: false });
      });
    });
  }

  async load(scopeValue) {
    return this.serialized(async () => {
      this.requireAvailable();
      const scope = relationshipStateScope(scopeValue, { rootDirectory: this.rootDirectory });
      return withScopeLock(scope, async () => {
        await this.recoverUnlocked(scope);
        const anchor = await this.loadSecureAnchor(scope);
        if (anchor?.erased === true) throw erasedRelationshipError();
        const state = await readJSON(scope.paths.state, { missing: null });
        validateStateAndAnchor(state, anchor, scope);
        return Object.freeze({
          anchor: anchor === null ? null : runtimeAnchor(anchor, scope),
          encryptedRecord: state === null ? null : structuredClone(state.encryptedRecord)
        });
      });
    });
  }

  async commit({
    relationshipID,
    expectedAnchor,
    nextGeneration,
    nextStateDigest,
    encryptedRecord
  }) {
    return this.serialized(async () => {
      this.requireAvailable();
      const scope = relationshipStateScope(
        { relationshipID },
        { rootDirectory: this.rootDirectory }
      );
      validateEncryptedRecord(encryptedRecord);
      validateGeneration(nextGeneration);
      validateDigest(nextStateDigest, "next state digest");
      return withScopeLock(scope, async () => {
        await this.recoverUnlocked(scope);
        const current = await this.loadSecureAnchor(scope);
        if (current?.erased === true) throw erasedRelationshipError();
        const existingState = await readJSON(scope.paths.state, { missing: null });
        validateStateAndAnchor(existingState, current, scope);
        const expected = validateRuntimeAnchor(expectedAnchor, scope.relationshipID);
        if (!equalJSON(current === null ? null : runtimeAnchor(current, scope), expected) ||
            nextGeneration !== (current?.generation ?? 0) + 1) {
          throw new Error("Desktop relationship anchor compare-and-swap failed.");
        }

        const encryptedRecordDigest = digestEncryptedRecord(encryptedRecord);
        const nextAnchor = createSecureAnchor({
          scopeDigest: scope.scopeDigest,
          generation: nextGeneration,
          stateDigest: nextStateDigest,
          encryptedRecordDigest,
          erased: false
        });
        const nextState = {
          version: stateRecordVersion,
          scopeDigest: scope.scopeDigest,
          generation: nextGeneration,
          stateDigest: nextStateDigest,
          encryptedRecordDigest,
          encryptedRecord: structuredClone(encryptedRecord)
        };
        const transaction = {
          version: transactionVersion,
          kind: "commit",
          scopeDigest: scope.scopeDigest,
          expectedAnchor: current,
          nextAnchor,
          nextState
        };
        await durableWriteJSON(scope.paths.transaction, transaction);
        await this.fault("afterJournal", scope);
        await this.storeSecureAnchor(scope, nextAnchor);
        await this.fault("afterSecureCommit", scope);
        await durableWriteJSON(scope.paths.state, nextState);
        await this.fault("afterStateCommit", scope);
        await durableRemove(scope.paths.transaction);
        return Object.freeze(runtimeAnchor(nextAnchor, scope));
      });
    });
  }

  async destroy({
    relationshipID,
    expectedAnchor
  }) {
    return this.serialized(async () => {
      this.requireAvailable();
      const scope = relationshipStateScope(
        { relationshipID },
        { rootDirectory: this.rootDirectory }
      );
      return withScopeLock(scope, async () => {
        // Local erasure is the terminal authority. It must remain possible
        // when ciphertext or a prior filesystem journal is missing/corrupt.
        // The Keychain item is the only generation authority consulted here.
        const current = await this.loadSecureAnchor(scope);
        if (current?.erased === true) {
          await durableRemove(scope.paths.state);
          return Object.freeze({ destroyed: true, alreadyDestroyed: true });
        }
        const expected = expectedAnchor === null
          ? null
          : validateRuntimeAnchor(expectedAnchor, scope.relationshipID);
        if (expected !== null &&
            (current === null || !equalJSON(runtimeAnchor(current, scope), expected))) {
          throw new Error("Desktop relationship anchor destruction compare-and-swap failed.");
        }
        const tombstone = createSecureAnchor({
          scopeDigest: scope.scopeDigest,
          generation: (current?.generation ?? 0) + 1,
          stateDigest: erasedDigest,
          encryptedRecordDigest: erasedDigest,
          erased: true
        });
        const transaction = {
          version: transactionVersion,
          kind: "destroy",
          scopeDigest: scope.scopeDigest,
          expectedAnchor: current,
          nextAnchor: tombstone,
          nextState: null
        };
        await durableWriteJSON(scope.paths.transaction, transaction);
        await this.fault("afterDestroyJournal", scope);
        await this.storeSecureAnchor(scope, tombstone);
        await this.fault("afterSecureDestroy", scope);
        await durableRemove(scope.paths.state);
        await durableRemove(scope.paths.transaction);
        return Object.freeze({ destroyed: true });
      });
    });
  }

  async recoverUnlocked(scope) {
    const transaction = await readJSON(scope.paths.transaction, { missing: null });
    if (transaction === null) return;
    validateTransaction(transaction, scope);
    const current = await this.loadSecureAnchor(scope);
    const expected = transaction.expectedAnchor;
    const next = transaction.nextAnchor;
    if (transaction.kind === "commit") {
      if (equalJSON(current, next)) {
        validateStateAndAnchor(transaction.nextState, next, scope);
        await durableWriteJSON(scope.paths.state, transaction.nextState);
        await durableRemove(scope.paths.transaction);
        return;
      }
      if (equalJSON(current, expected)) {
        await durableRemove(scope.paths.transaction);
        return;
      }
    } else if (transaction.kind === "destroy") {
      if (equalJSON(current, next)) {
        await durableRemove(scope.paths.state);
        await durableRemove(scope.paths.transaction);
        return;
      }
      if (equalJSON(current, expected)) {
        await durableRemove(scope.paths.transaction);
        return;
      }
    }
    throw new Error("Relationship-state crash journal conflicts with Keychain authority.");
  }

  async loadSecureAnchor(scope) {
    const encoded = await this.secureVault.get(scope.keychain.anchor);
    if (encoded === null) return null;
    let parsed;
    try {
      parsed = JSON.parse(encoded);
    } catch (error) {
      throw new Error("Keychain relationship anchor is malformed.", { cause: error });
    }
    return validateSecureAnchor(parsed, scope);
  }

  async storeSecureAnchor(scope, anchor) {
    await this.secureVault.set({
      ...scope.keychain.anchor,
      value: JSON.stringify(anchor)
    });
  }

  requireAvailable() {
    if (this.capability?.available !== true) {
      throw new Error(this.capability?.reason ?? "Secure desktop relationship state is unavailable.");
    }
  }

  async fault(stage, scope) {
    if (typeof this.faultInjector === "function") await this.faultInjector(stage, scope);
  }

  serialized(operation) {
    const next = this.queue.then(operation, operation);
    this.queue = next.catch(() => {});
    return next;
  }
}

export function relationshipStateScope(
  { relationshipID },
  { rootDirectory = defaultStateRoot() } = {}
) {
  const relationship = canonicalUUID(relationshipID);
  // One application has exactly one burn scope for a relationship. URL
  // profiles and WebView storage keys are routing details, never authority.
  const scopeDigest = digestHex(`scope\0${relationship}`);
  const directory = join(rootDirectory, scopeDigest);
  return {
    scopeDigest,
    relationshipID: relationship,
    paths: {
      directory,
      state: join(directory, "state.json"),
      transaction: join(directory, "transaction.json"),
      lock: join(directory, "host.lock")
    },
    keychain: {
      anchor: {
        service: `${keychainServicePrefix}.anchor`,
        account: scopeDigest
      }
    }
  };
}

function defaultStateRoot() {
  return join(
    homedir(),
    "Library",
    "Application Support",
    "org.noctweave.js-client",
    "durable-pairwise-v3"
  );
}

function createSecureAnchor({
  scopeDigest,
  generation,
  stateDigest,
  encryptedRecordDigest,
  erased
}) {
  const unsigned = {
    version: secureAnchorVersion,
    scopeDigest,
    generation,
    stateDigest,
    encryptedRecordDigest,
    erased
  };
  return { ...unsigned, authenticationTag: anchorChecksum(unsigned) };
}

function validateSecureAnchor(anchor, scope) {
  exact(anchor, [
    "version",
    "scopeDigest",
    "generation",
    "stateDigest",
    "encryptedRecordDigest",
    "erased",
    "authenticationTag"
  ], "secure relationship anchor");
  if (anchor.version !== secureAnchorVersion || anchor.scopeDigest !== scope.scopeDigest ||
      typeof anchor.erased !== "boolean") {
    throw new Error("Relationship anchor scope is invalid.");
  }
  validateGeneration(anchor.generation);
  validateDigest(anchor.stateDigest, "state digest");
  validateDigest(anchor.encryptedRecordDigest, "encrypted record digest");
  validateDigest(anchor.authenticationTag, "anchor authentication tag");
  if (anchor.erased &&
      (anchor.stateDigest !== erasedDigest || anchor.encryptedRecordDigest !== erasedDigest)) {
    throw new Error("Relationship erasure tombstone is malformed.");
  }
  const unsigned = {
    version: anchor.version,
    scopeDigest: anchor.scopeDigest,
    generation: anchor.generation,
    stateDigest: anchor.stateDigest,
    encryptedRecordDigest: anchor.encryptedRecordDigest,
    erased: anchor.erased
  };
  if (anchor.authenticationTag !== anchorChecksum(unsigned)) {
    throw new Error("Keychain relationship anchor checksum failed.");
  }
  return { ...anchor };
}

function runtimeAnchor(anchor, scope) {
  if (anchor.erased) throw erasedRelationshipError();
  return {
    version: runtimeAnchorVersion,
    relationshipID: scope.relationshipID,
    generation: anchor.generation,
    stateDigest: anchor.stateDigest,
    authenticationTag: anchor.authenticationTag
  };
}

function validateRuntimeAnchor(anchor, relationshipID) {
  if (anchor === null) return null;
  exact(anchor, [
    "version",
    "relationshipID",
    "generation",
    "stateDigest",
    "authenticationTag"
  ], "relationship anchor");
  if (anchor.version !== runtimeAnchorVersion || anchor.relationshipID !== relationshipID) {
    throw new Error("Relationship anchor scope is invalid.");
  }
  validateGeneration(anchor.generation);
  validateDigest(anchor.stateDigest, "state digest");
  validateDigest(anchor.authenticationTag, "anchor authentication tag");
  return { ...anchor };
}

function anchorChecksum(unsigned) {
  // Keychain presence and update ordering are the authority. This checksum is
  // corruption detection over the exact opaque metadata, not a secret MAC.
  return createHash("sha256")
    .update("noctweave/desktop-relationship-anchor/v3\0", "utf8")
    .update(JSON.stringify(unsigned), "utf8")
    .digest("base64");
}

function validateTransaction(transaction, scope) {
  exact(transaction, [
    "version",
    "kind",
    "scopeDigest",
    "expectedAnchor",
    "nextAnchor",
    "nextState"
  ], "relationship transaction");
  if (transaction.version !== transactionVersion ||
      (transaction.kind !== "commit" && transaction.kind !== "destroy") ||
      transaction.scopeDigest !== scope.scopeDigest) {
    throw new Error("Relationship-state crash journal scope is invalid.");
  }
  if (transaction.expectedAnchor !== null) {
    validateSecureAnchor(transaction.expectedAnchor, scope);
  }
  const next = validateSecureAnchor(transaction.nextAnchor, scope);
  if (transaction.kind === "commit") {
    if (next.erased || transaction.nextState === null) {
      throw new Error("Relationship commit journal is incomplete.");
    }
    validateStateAndAnchor(transaction.nextState, next, scope);
  } else if (!next.erased || transaction.nextState !== null) {
    throw new Error("Relationship destroy journal is malformed.");
  }
}

function validateStateAndAnchor(record, anchor, scope) {
  if ((anchor === null) !== (record === null)) {
    throw new Error("Desktop relationship state and Keychain anchor generations diverged.");
  }
  if (record === null) return;
  if (anchor.erased) throw erasedRelationshipError();
  validateStateRecord(record, scope);
  if (record.generation !== anchor.generation ||
      record.stateDigest !== anchor.stateDigest ||
      record.encryptedRecordDigest !== anchor.encryptedRecordDigest) {
    throw new Error("Desktop relationship ciphertext was rolled back or replaced.");
  }
}

function validateStateRecord(record, scope) {
  exact(record, [
    "version",
    "scopeDigest",
    "generation",
    "stateDigest",
    "encryptedRecordDigest",
    "encryptedRecord"
  ], "encrypted relationship state record");
  if (record.version !== stateRecordVersion || record.scopeDigest !== scope.scopeDigest) {
    throw new Error("Encrypted relationship state record scope is invalid.");
  }
  validateGeneration(record.generation);
  validateDigest(record.stateDigest, "encrypted state digest");
  validateDigest(record.encryptedRecordDigest, "encrypted record digest");
  validateEncryptedRecord(record.encryptedRecord);
  if (record.encryptedRecordDigest !== digestEncryptedRecord(record.encryptedRecord)) {
    throw new Error("Desktop relationship encrypted-record digest verification failed.");
  }
  return record;
}

function digestEncryptedRecord(record) {
  validateEncryptedRecord(record);
  const canonical = {
    __noctweaveEncrypted: record.__noctweaveEncrypted,
    version: record.version,
    algorithm: record.algorithm,
    nonce: record.nonce,
    ciphertext: record.ciphertext
  };
  return createHash("sha256")
    .update("noctweave/desktop-encrypted-record/v1\0", "utf8")
    .update(JSON.stringify(canonical), "utf8")
    .digest("base64");
}

function validateEncryptedRecord(record) {
  exact(record, [
    "__noctweaveEncrypted",
    "version",
    "algorithm",
    "nonce",
    "ciphertext"
  ], "encrypted browser record");
  if (record.__noctweaveEncrypted !== 1 || record.version !== 1 ||
      record.algorithm !== "AES-256-GCM") {
    throw new Error("Desktop host accepts only encrypted Noctweave records.");
  }
  decodeBase64(record.nonce, 12, "encrypted record nonce");
  const ciphertext = decodeBase64(record.ciphertext, null, "encrypted record ciphertext");
  if (ciphertext.byteLength < 16 || ciphertext.byteLength > maximumEncryptedRecordBytes) {
    throw new Error("Encrypted desktop relationship record exceeds its bound.");
  }
}

async function withScopeLock(scope, operation) {
  const release = await acquireScopeLock(scope);
  let operationError = null;
  try {
    return await operation();
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await release();
    } catch (releaseError) {
      if (operationError === null) throw releaseError;
      operationError.lockReleaseError = releaseError;
    }
  }
}

async function acquireScopeLock(scope) {
  await ensurePrivateDirectory(scope.paths.directory);
  try {
    await writeExclusiveFile(scope.paths.lock, JSON.stringify({
      pid: process.pid,
      nonce: randomUUID(),
      createdAt: new Date().toISOString()
    }));
  } catch (error) {
    if (error?.code === "EEXIST") {
      // Never rename a supposedly dead owner's lock: PID observation and
      // rename form a reclamation race. A crashed host requires explicit
      // operator cleanup, while concurrent hosts fail closed.
      throw new Error("Relationship-state scope lock is already held; refusing unsafe recovery.");
    }
    throw error;
  }
  await syncDirectory(scope.paths.directory);
  return async () => durableRemove(scope.paths.lock);
}

async function writeExclusiveFile(path, value) {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(value, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function durableWriteJSON(path, value) {
  const directory = dirname(path);
  await ensurePrivateDirectory(directory);
  const temporary = `${path}.${randomUUID()}.tmp`;
  await writeExclusiveFile(temporary, JSON.stringify(value));
  await rename(temporary, path);
  await syncDirectory(directory);
}

async function durableRemove(path) {
  await rm(path, { force: true });
  await syncDirectory(dirname(path));
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, "r");
    await handle.sync();
  } catch (error) {
    if (error?.code !== "ENOENT" && error?.code !== "EINVAL" && error?.code !== "ENOTSUP") {
      throw error;
    }
  } finally {
    await handle?.close();
  }
}

async function readJSON(path, { missing }) {
  let handle;
  try {
    handle = await open(
      path,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC
    );
  } catch (error) {
    if (error?.code === "ENOENT") return missing;
    throw error;
  }
  try {
    const stat = await handle.stat();
    const owner = typeof process.getuid === "function" ? process.getuid() : stat.uid;
    if (!stat.isFile() || stat.uid !== owner || (stat.mode & 0o077) !== 0 ||
        stat.size > maximumHostRecordBytes) {
      throw new Error(`Desktop relationship record ${path} is not a private bounded regular file.`);
    }
    const encoded = await handle.readFile("utf8");
    if (Buffer.byteLength(encoded, "utf8") > maximumHostRecordBytes) {
      throw new Error(`Desktop relationship record ${path} exceeds its bound.`);
    }
    return JSON.parse(encoded);
  } catch (error) {
    if (error?.message?.includes("private bounded regular file") ||
        error?.message?.includes("exceeds its bound")) throw error;
    throw new Error(`Desktop relationship record ${path} is malformed.`, { cause: error });
  } finally {
    await handle.close();
  }
}

async function ensurePrivateDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const handle = await open(
    directory,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC
  );
  try {
    const stat = await handle.stat();
    const owner = typeof process.getuid === "function" ? process.getuid() : stat.uid;
    if (!stat.isDirectory() || stat.uid !== owner || (stat.mode & 0o077) !== 0) {
      throw new Error("Desktop relationship-state directory is not private to this user.");
    }
  } finally {
    await handle.close();
  }
}

function decodeBase64(value, exactBytes, label) {
  if (typeof value !== "string" || value.length === 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value ||
      (exactBytes !== null && decoded.byteLength !== exactBytes)) {
    throw new Error(`Invalid ${label}.`);
  }
  return decoded;
}

function validateDigest(value, label) {
  decodeBase64(value, 32, label);
}

function validateGeneration(value) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error("Relationship anchor generation is invalid.");
  }
}

function canonicalUUID(value) {
  if (typeof value !== "string" ||
      !/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u.test(value)) {
    throw new Error("Desktop relationship ID is invalid.");
  }
  return value;
}

function digestHex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} fields are invalid.`);
  }
}

function equalJSON(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function erasedRelationshipError() {
  return new Error("This relationship scope was erased and cannot be initialized again.");
}
