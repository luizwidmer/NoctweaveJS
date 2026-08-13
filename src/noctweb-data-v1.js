import { base64, canonicalJsonBytes } from "./crypto/swift-canonical.js";
import { bytes, WebCryptoPrimitives } from "./crypto/webcrypto.js";
import {
  concatBytes,
  cryptoRandomBytes,
  cryptoSha256,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  uint64Bytes
} from "./private-v2.js";
import { parseExactJSON } from "./strict-json.js";

const textEncoder = new TextEncoder();
const hex64 = "[0-9a-f]{64}";
const publisherIDPattern = new RegExp(`^nwpub1_${hex64}$`, "u");
const databaseIDPattern = new RegExp(`^nwdb1_${hex64}$`, "u");
const accountIDPattern = new RegExp(`^nwa1_${hex64}$`, "u");
const suffixPattern = /^\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])$/u;
const siteLabelPattern = /^(?!-)[a-z0-9-]+(?<!-)$/u;
const collectionPattern = /^(?!-)[a-z0-9-]+(?<!-)$/u;
const recordIDPattern = /^[A-Za-z0-9._:-]+$/u;
const readPolicies = new Set(["public", "owner", "owner-or-publisher"]);
const writePolicies = new Set(["publisher", "owner", "owner-or-publisher"]);
const actorKinds = new Set(["publisher", "account"]);

export const noctwebDataV1 = Object.freeze({
  module: "nw.noctweb-data",
  version: 1,
  publisherSignatureAlgorithm: "Ed25519",
  accountSignatureAlgorithm: "ML-DSA-65"
});

export const noctwebDataV1Limits = Object.freeze({
  maximumCollections: 32,
  maximumCollectionNameBytes: 48,
  maximumRecordIDBytes: 96,
  maximumRecordBytes: 64 * 1_024,
  maximumRecordsPerDatabase: 10_000,
  maximumAccountsPerDatabase: 10_000,
  maximumPage: 100,
  maximumDatabaseBytes: 64 * 1_024 * 1_024,
  idempotencyKeyBytes: 32,
  nonceBytes: 32,
  publisherPublicKeyBytes: 32,
  publisherSignatureBytes: 64,
  accountPublicKeyBytes: 1_952,
  accountSecretKeyBytes: 4_032,
  accountSignatureBytes: 3_309
});

export async function noctwebDataPublisherID(crypto, publicKey) {
  const key = exactBytes(publicKey, noctwebDataV1Limits.publisherPublicKeyBytes, "publisher public key");
  return `nwpub1_${hexadecimal(await cryptoSha256(
    crypto,
    concatBytes(domain("org.noctweave.noctweb/publisher-id/v1"), key)
  ))}`;
}

export async function noctwebDataDatabaseID(crypto, origin) {
  validateNoctwebDataOriginV1(origin);
  return `nwdb1_${hexadecimal(await cryptoSha256(crypto, noctwebDataTranscriptsV1.origin(origin)))}`;
}

export async function noctwebDataAccountID(crypto, databaseID, publicKey) {
  validateDatabaseID(databaseID);
  const key = exactBytes(publicKey, noctwebDataV1Limits.accountPublicKeyBytes, "account public key");
  return `nwa1_${hexadecimal(await cryptoSha256(
    crypto,
    noctwebDataTranscriptsV1.accountIdentity(databaseID, key)
  ))}`;
}

export async function createNoctwebDataOriginV1({
  crypto = new WebCryptoPrimitives(),
  relaySuffix,
  siteLabel,
  publisherSigningPublicKey
}) {
  const publicKey = exactBytes(
    publisherSigningPublicKey,
    noctwebDataV1Limits.publisherPublicKeyBytes,
    "publisher public key"
  );
  const origin = {
    version: 1,
    relaySuffix: validateRelaySuffix(relaySuffix),
    siteLabel: validateSiteLabel(siteLabel),
    publisherID: await noctwebDataPublisherID(crypto, publicKey),
    publisherSigningPublicKey: base64(publicKey)
  };
  return Object.freeze(validateNoctwebDataOriginV1(origin));
}

export class NoctwebDataPublisherAuthorityV1 {
  static async generate({
    crypto = new WebCryptoPrimitives(),
    subtle = globalThis.crypto?.subtle,
    relaySuffix,
    siteLabel
  } = {}) {
    requireSubtle(subtle);
    const keyPair = await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    const publicKey = new Uint8Array(await subtle.exportKey("raw", keyPair.publicKey));
    return this.create({ crypto, subtle, privateKey: keyPair.privateKey, publicKey, relaySuffix, siteLabel });
  }

  static async create({
    crypto = new WebCryptoPrimitives(),
    subtle = globalThis.crypto?.subtle,
    privateKey,
    publicKey,
    relaySuffix,
    siteLabel
  }) {
    requireDataCrypto(crypto, true);
    requireSubtle(subtle);
    if (!privateKey) throw new TypeError("A non-exported Ed25519 publisher private key is required.");
    const origin = await createNoctwebDataOriginV1({
      crypto,
      relaySuffix,
      siteLabel,
      publisherSigningPublicKey: publicKey
    });
    return new NoctwebDataPublisherAuthorityV1({ crypto, subtle, privateKey, origin });
  }

  constructor({ crypto, subtle, privateKey, origin }) {
    this.crypto = crypto;
    this.subtle = subtle;
    this.privateKey = privateKey;
    this.origin = origin;
  }

  async databaseID() {
    return noctwebDataDatabaseID(this.crypto, this.origin);
  }

  async createDatabaseRequest(collections, { idempotencyKey } = {}) {
    const normalizedCollections = normalizeCollections(collections);
    const idempotency = await randomOrExact(
      this.crypto,
      idempotencyKey,
      noctwebDataV1Limits.idempotencyKeyBytes,
      "database idempotency key"
    );
    const draft = {
      origin: this.origin,
      collections: normalizedCollections,
      idempotencyKey: base64(idempotency),
      signature: base64(new Uint8Array(noctwebDataV1Limits.publisherSignatureBytes))
    };
    const signature = new Uint8Array(await this.subtle.sign(
      { name: "Ed25519" },
      this.privateKey,
      noctwebDataTranscriptsV1.createDatabase(draft)
    ));
    return Object.freeze(validateNoctwebDataDatabaseCreateRequestV1({
      ...draft,
      signature: base64(signature)
    }));
  }

  async putRequest(input) {
    return signMutationRequest({
      authority: this,
      operation: "put",
      input,
      databaseID: input.databaseID ?? await this.databaseID()
    });
  }

  async getRequest(input) {
    return signReadRequest({
      authority: this,
      operation: "get",
      input,
      databaseID: input.databaseID ?? await this.databaseID()
    });
  }

  async listRequest(input) {
    return signReadRequest({
      authority: this,
      operation: "list",
      input,
      databaseID: input.databaseID ?? await this.databaseID()
    });
  }

  async deleteRequest(input) {
    return signMutationRequest({
      authority: this,
      operation: "delete",
      input,
      databaseID: input.databaseID ?? await this.databaseID()
    });
  }

  async sign(message) {
    return new Uint8Array(await this.subtle.sign({ name: "Ed25519" }, this.privateKey, message));
  }

  actor() {
    return Object.freeze({ kind: "publisher", id: this.origin.publisherID });
  }
}

export class NoctwebDataAccountAuthorityV1 {
  static async generate({ crypto, databaseID }) {
    requireDataCrypto(crypto, true, true);
    validateDatabaseID(databaseID);
    const keyPair = await crypto.generateSigningKeypair();
    return this.create({ crypto, databaseID, keyPair });
  }

  static async create({ crypto, databaseID, keyPair }) {
    requireDataCrypto(crypto, true, true);
    validateDatabaseID(databaseID);
    requireExactRecord(keyPair, ["publicKey", "secretKey"], [], "Noctweb account keypair");
    const publicKey = exactBytes(
      keyPair.publicKey,
      noctwebDataV1Limits.accountPublicKeyBytes,
      "account public key"
    );
    const secretKey = exactBytes(
      keyPair.secretKey,
      noctwebDataV1Limits.accountSecretKeyBytes,
      "account secret key"
    );
    const accountID = await noctwebDataAccountID(crypto, databaseID, publicKey);
    return new NoctwebDataAccountAuthorityV1({
      crypto,
      databaseID,
      accountID,
      publicKey: new Uint8Array(publicKey),
      secretKey: new Uint8Array(secretKey)
    });
  }

  constructor({ crypto, databaseID, accountID, publicKey, secretKey }) {
    this.crypto = crypto;
    this.databaseID = databaseID;
    this.accountID = accountID;
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  async registrationRequest({ idempotencyKey } = {}) {
    const idempotency = await randomOrExact(
      this.crypto,
      idempotencyKey,
      noctwebDataV1Limits.idempotencyKeyBytes,
      "account registration idempotency key"
    );
    const draft = {
      databaseID: this.databaseID,
      accountID: this.accountID,
      accountSigningPublicKey: base64(this.publicKey),
      idempotencyKey: base64(idempotency),
      signature: base64(new Uint8Array(noctwebDataV1Limits.accountSignatureBytes))
    };
    return Object.freeze(validateNoctwebDataAccountRegisterRequestV1({
      ...draft,
      signature: base64(await this.sign(noctwebDataTranscriptsV1.registerAccount(draft)))
    }));
  }

  async putRequest(input) {
    return signMutationRequest({ authority: this, operation: "put", input, databaseID: this.databaseID });
  }

  async getRequest(input) {
    return signReadRequest({ authority: this, operation: "get", input, databaseID: this.databaseID });
  }

  async listRequest(input) {
    return signReadRequest({ authority: this, operation: "list", input, databaseID: this.databaseID });
  }

  async deleteRequest(input) {
    return signMutationRequest({ authority: this, operation: "delete", input, databaseID: this.databaseID });
  }

  async sign(message) {
    const signature = bytes(await this.crypto.sign(message, this.secretKey), "ML-DSA-65 signature");
    return exactBytes(signature, noctwebDataV1Limits.accountSignatureBytes, "ML-DSA-65 signature");
  }

  actor() {
    return Object.freeze({ kind: "account", id: this.accountID });
  }

  exportKeypair() {
    return Object.freeze({
      publicKey: new Uint8Array(this.publicKey),
      secretKey: new Uint8Array(this.secretKey)
    });
  }

  destroy() {
    this.secretKey.fill(0);
  }
}

/// A narrow object suitable for injection as `window.noctweb.data`. It fixes
/// the database and collection schema at construction time, never exposes key
/// material, and does not permit publisher-authorized writes from page code.
export class NoctwebDataPageCapabilityV1 {
  static async create({ relay, account, collections, maxOperationsPerMinute = 60 }) {
    if (!(account instanceof NoctwebDataAccountAuthorityV1)) {
      throw new TypeError("Noctweb page data requires a per-origin account authority.");
    }
    requirePageRelay(relay);
    const normalizedCollections = normalizeCollections(collections);
    requireInteger(maxOperationsPerMinute, "Noctweb page operation limit", 1, 600);
    await relay.registerNoctwebAccount(await account.registrationRequest());
    return new NoctwebDataPageCapabilityV1({
      relay,
      account,
      collections: normalizedCollections,
      maxOperationsPerMinute
    });
  }

  #relay;
  #account;
  #collections;
  #maxOperationsPerMinute;
  #operationTimes = [];

  constructor({ relay, account, collections, maxOperationsPerMinute }) {
    this.#relay = relay;
    this.#account = account;
    this.#collections = new Map(collections.map((collection) => [collection.name, collection]));
    this.#maxOperationsPerMinute = maxOperationsPerMinute;
    Object.freeze(this);
  }

  get accountID() {
    return this.#account.accountID;
  }

  async get(collection, recordID) {
    this.#consumeOperation();
    const policy = this.#collection(collection);
    const request = policy.readPolicy === "public"
      ? { databaseID: this.#account.databaseID, collection, recordID }
      : await this.#account.getRequest({ collection, recordID });
    return pageRecord(await this.#relay.getNoctwebRecord(request));
  }

  async list(collection, { afterRecordID, limit = 50 } = {}) {
    this.#consumeOperation();
    const policy = this.#collection(collection);
    const input = {
      collection,
      ...(afterRecordID === undefined ? {} : { afterRecordID }),
      limit
    };
    const request = policy.readPolicy === "public"
      ? { databaseID: this.#account.databaseID, ...input }
      : await this.#account.listRequest(input);
    const response = await this.#relay.listNoctwebRecords(request);
    return Object.freeze({
      records: Object.freeze(response.records.map(pageRecord)),
      nextCursor: response.nextCursor ?? null
    });
  }

  async put(collection, recordID, value, { expectedRevision = 0, idempotencyKey } = {}) {
    this.#consumeOperation();
    const policy = this.#collection(collection);
    if (policy.writePolicy === "publisher") {
      throw new Error("This collection is read-only for site visitors.");
    }
    const request = await this.#account.putRequest({
      collection,
      recordID,
      ownerAccountID: this.#account.accountID,
      payload: encodeNoctwebDataJSON(value),
      expectedRevision,
      ...(idempotencyKey === undefined ? {} : { idempotencyKey })
    });
    return pageRecord(await this.#relay.putNoctwebRecord(request));
  }

  async delete(collection, recordID, { expectedRevision, idempotencyKey } = {}) {
    this.#consumeOperation();
    const policy = this.#collection(collection);
    if (policy.writePolicy === "publisher") {
      throw new Error("This collection is read-only for site visitors.");
    }
    return Object.freeze(await this.#relay.deleteNoctwebRecord(await this.#account.deleteRequest({
      collection,
      recordID,
      expectedRevision,
      ...(idempotencyKey === undefined ? {} : { idempotencyKey })
    })));
  }

  #collection(name) {
    validateCollectionName(name);
    const policy = this.#collections.get(name);
    if (!policy) throw new Error("The requested collection is not available to this origin.");
    return policy;
  }

  #consumeOperation() {
    const cutoff = Date.now() - 60_000;
    this.#operationTimes = this.#operationTimes.filter((timestamp) => timestamp > cutoff);
    if (this.#operationTimes.length >= this.#maxOperationsPerMinute) {
      throw new Error("Noctweb page data rate limit reached.");
    }
    this.#operationTimes.push(Date.now());
  }
}

export function encodeNoctwebDataJSON(value) {
  const encoded = canonicalJsonBytes(value);
  if (encoded.byteLength === 0 || encoded.byteLength > noctwebDataV1Limits.maximumRecordBytes) {
    throw new TypeError("Noctweb data JSON exceeds the record size limit.");
  }
  return encoded;
}

export function decodeNoctwebDataJSON(value) {
  const payload = bytes(value, "Noctweb data JSON");
  if (payload.byteLength === 0 || payload.byteLength > noctwebDataV1Limits.maximumRecordBytes) {
    throw new TypeError("Noctweb data JSON exceeds the record size limit.");
  }
  return parseExactJSON(new TextDecoder("utf-8", { fatal: true }).decode(payload));
}

export function validateNoctwebDataOriginV1(value) {
  requireExactRecord(
    value,
    ["version", "relaySuffix", "siteLabel", "publisherID", "publisherSigningPublicKey"],
    [],
    "Noctweb data origin"
  );
  if (value.version !== 1) throw new TypeError("Noctweb data origin version is invalid.");
  validateRelaySuffix(value.relaySuffix);
  validateSiteLabel(value.siteLabel);
  validatePublisherID(value.publisherID);
  requireBase64(
    value.publisherSigningPublicKey,
    noctwebDataV1Limits.publisherPublicKeyBytes,
    "Noctweb publisher public key"
  );
  return value;
}

export function validateNoctwebDataCollectionV1(value) {
  requireExactRecord(value, ["name", "readPolicy", "writePolicy"], [], "Noctweb data collection");
  validateCollectionName(value.name);
  if (!readPolicies.has(value.readPolicy) || !writePolicies.has(value.writePolicy)) {
    throw new TypeError("Noctweb data collection policy is invalid.");
  }
  return value;
}

export function validateNoctwebDataAuthorizationV1(value) {
  requireExactRecord(value, ["actorKind", "actorID", "nonce", "signature"], [], "Noctweb data authorization");
  if (!actorKinds.has(value.actorKind)) throw new TypeError("Noctweb data actor kind is invalid.");
  validateActorID(value.actorID, value.actorKind);
  requireBase64(value.nonce, noctwebDataV1Limits.nonceBytes, "Noctweb data nonce");
  requireBase64(
    value.signature,
    value.actorKind === "publisher"
      ? noctwebDataV1Limits.publisherSignatureBytes
      : noctwebDataV1Limits.accountSignatureBytes,
    "Noctweb data signature"
  );
  return value;
}

export function validateNoctwebDataDatabaseCreateRequestV1(value) {
  requireExactRecord(value, ["origin", "collections", "idempotencyKey", "signature"], [], "Noctweb database request");
  validateNoctwebDataOriginV1(value.origin);
  const normalized = normalizeCollections(value.collections);
  if (normalized.some((entry, index) => entry.name !== value.collections[index]?.name)) {
    throw new TypeError("Noctweb database collections must be sorted.");
  }
  requireBase64(value.idempotencyKey, noctwebDataV1Limits.idempotencyKeyBytes, "Noctweb database idempotency key");
  requireBase64(value.signature, noctwebDataV1Limits.publisherSignatureBytes, "Noctweb database signature");
  return value;
}

export function validateNoctwebDataAccountRegisterRequestV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "accountID", "accountSigningPublicKey", "idempotencyKey", "signature"],
    [],
    "Noctweb account registration"
  );
  validateDatabaseID(value.databaseID);
  validateAccountID(value.accountID);
  requireBase64(value.accountSigningPublicKey, noctwebDataV1Limits.accountPublicKeyBytes, "Noctweb account public key");
  requireBase64(value.idempotencyKey, noctwebDataV1Limits.idempotencyKeyBytes, "Noctweb account idempotency key");
  requireBase64(value.signature, noctwebDataV1Limits.accountSignatureBytes, "Noctweb account signature");
  return value;
}

export function validateNoctwebDataRecordPutRequestV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "recordID", "payload", "expectedRevision", "idempotencyKey", "authorization"],
    ["ownerAccountID"],
    "Noctweb record put"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  if (value.ownerAccountID !== undefined) validateAccountID(value.ownerAccountID);
  const payload = requireBase64(value.payload, undefined, "Noctweb record payload");
  if (payload.byteLength === 0 || payload.byteLength > noctwebDataV1Limits.maximumRecordBytes) {
    throw new TypeError("Noctweb record payload exceeds its size bound.");
  }
  requireInteger(value.expectedRevision, "Noctweb expected revision", 0, Number.MAX_SAFE_INTEGER);
  requireBase64(value.idempotencyKey, noctwebDataV1Limits.idempotencyKeyBytes, "Noctweb record idempotency key");
  validateNoctwebDataAuthorizationV1(value.authorization);
  return value;
}

export function validateNoctwebDataRecordGetRequestV1(value) {
  requireExactRecord(value, ["databaseID", "collection", "recordID"], ["authorization"], "Noctweb record get");
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  if (value.authorization !== undefined) validateNoctwebDataAuthorizationV1(value.authorization);
  return value;
}

export function validateNoctwebDataRecordListRequestV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "limit"],
    ["afterRecordID", "authorization"],
    "Noctweb record list"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  if (value.afterRecordID !== undefined) validateRecordID(value.afterRecordID);
  requireInteger(value.limit, "Noctweb record list limit", 1, noctwebDataV1Limits.maximumPage);
  if (value.authorization !== undefined) validateNoctwebDataAuthorizationV1(value.authorization);
  return value;
}

export function validateNoctwebDataRecordDeleteRequestV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "recordID", "expectedRevision", "idempotencyKey", "authorization"],
    [],
    "Noctweb record deletion"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  requireInteger(value.expectedRevision, "Noctweb deleted revision", 1, Number.MAX_SAFE_INTEGER);
  requireBase64(value.idempotencyKey, noctwebDataV1Limits.idempotencyKeyBytes, "Noctweb deletion idempotency key");
  validateNoctwebDataAuthorizationV1(value.authorization);
  return value;
}

export function validateNoctwebDataDatabaseReceiptV1(value) {
  requireExactRecord(value, ["databaseID", "created"], [], "Noctweb database receipt");
  validateDatabaseID(value.databaseID);
  if (typeof value.created !== "boolean") throw new TypeError("Noctweb database receipt created flag is invalid.");
  return value;
}

export function validateNoctwebDataAccountReceiptV1(value) {
  requireExactRecord(value, ["databaseID", "accountID", "created"], [], "Noctweb account receipt");
  validateDatabaseID(value.databaseID);
  validateAccountID(value.accountID);
  if (typeof value.created !== "boolean") throw new TypeError("Noctweb account receipt created flag is invalid.");
  return value;
}

export function validateNoctwebDataRecordV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "recordID", "payload", "revision", "createdAt", "updatedAt"],
    ["ownerAccountID"],
    "Noctweb record"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  if (value.ownerAccountID !== undefined) validateAccountID(value.ownerAccountID);
  const payload = requireBase64(value.payload, undefined, "Noctweb record payload");
  if (payload.byteLength === 0 || payload.byteLength > noctwebDataV1Limits.maximumRecordBytes) {
    throw new TypeError("Noctweb record payload exceeds its size bound.");
  }
  requireInteger(value.revision, "Noctweb record revision", 1, Number.MAX_SAFE_INTEGER);
  const created = new Date(requireCanonicalTimestamp(value.createdAt, "Noctweb record creation time")).getTime();
  const updated = new Date(requireCanonicalTimestamp(value.updatedAt, "Noctweb record update time")).getTime();
  if (updated < created) throw new TypeError("Noctweb record update predates creation.");
  return value;
}

export function validateNoctwebDataRecordListV1(value) {
  requireExactRecord(value, ["records"], ["nextCursor"], "Noctweb record list");
  if (!Array.isArray(value.records) || value.records.length > noctwebDataV1Limits.maximumPage) {
    throw new TypeError("Noctweb record list exceeds its page bound.");
  }
  value.records.forEach(validateNoctwebDataRecordV1);
  if (value.nextCursor !== undefined) validateRecordID(value.nextCursor);
  return value;
}

export function validateNoctwebDataDeleteReceiptV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "recordID", "deletedRevision"],
    [],
    "Noctweb deletion receipt"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  requireInteger(value.deletedRevision, "Noctweb deleted revision", 1, Number.MAX_SAFE_INTEGER);
  return value;
}

export const noctwebDataTranscriptsV1 = Object.freeze({
  origin(origin) {
    validateNoctwebDataOriginV1(origin);
    return concatBytes(
      domain("org.noctweave.noctweb/data-origin/v1"),
      appendString(origin.relaySuffix),
      appendString(origin.siteLabel),
      appendString(origin.publisherID),
      appendData(requireBase64(origin.publisherSigningPublicKey, 32, "publisher public key"))
    );
  },
  createDatabase(request) {
    validateNoctwebDataDatabaseCreateRequestV1(request);
    const collections = request.collections.flatMap((item) => [
      appendString(item.name), appendString(item.readPolicy), appendString(item.writePolicy)
    ]);
    return concatBytes(
      domain("org.noctweave.noctweb/data-create/v1"),
      appendData(this.origin(request.origin)),
      uint64Bytes(request.collections.length),
      ...collections,
      appendData(requireBase64(request.idempotencyKey, 32, "idempotency key"))
    );
  },
  accountIdentity(databaseID, publicKey) {
    validateDatabaseID(databaseID);
    return concatBytes(
      domain("org.noctweave.noctweb/account-id/v1"),
      appendString(databaseID),
      appendData(exactBytes(publicKey, 1_952, "account public key"))
    );
  },
  registerAccount(request) {
    validateNoctwebDataAccountRegisterRequestV1(request);
    return concatBytes(
      domain("org.noctweave.noctweb/account-register/v1"),
      appendString(request.databaseID),
      appendString(request.accountID),
      appendData(requireBase64(request.accountSigningPublicKey, 1_952, "account public key")),
      appendData(requireBase64(request.idempotencyKey, 32, "idempotency key"))
    );
  },
  putRecord(request) {
    validateNoctwebDataRecordPutRequestV1(request);
    return concatBytes(
      authorizedDomain("org.noctweave.noctweb/data-put/v1", request.authorization),
      appendString(request.databaseID), appendString(request.collection), appendString(request.recordID),
      appendOptionalString(request.ownerAccountID),
      appendData(requireBase64(request.payload, undefined, "record payload")),
      uint64Bytes(request.expectedRevision),
      appendData(requireBase64(request.idempotencyKey, 32, "idempotency key"))
    );
  },
  getRecord(request) {
    validateNoctwebDataRecordGetRequestV1(request);
    return concatBytes(
      optionalAuthorizedDomain("org.noctweave.noctweb/data-get/v1", request.authorization),
      appendString(request.databaseID), appendString(request.collection), appendString(request.recordID)
    );
  },
  listRecords(request) {
    validateNoctwebDataRecordListRequestV1(request);
    return concatBytes(
      optionalAuthorizedDomain("org.noctweave.noctweb/data-list/v1", request.authorization),
      appendString(request.databaseID), appendString(request.collection),
      appendOptionalString(request.afterRecordID), uint64Bytes(request.limit)
    );
  },
  deleteRecord(request) {
    validateNoctwebDataRecordDeleteRequestV1(request);
    return concatBytes(
      authorizedDomain("org.noctweave.noctweb/data-delete/v1", request.authorization),
      appendString(request.databaseID), appendString(request.collection), appendString(request.recordID),
      uint64Bytes(request.expectedRevision),
      appendData(requireBase64(request.idempotencyKey, 32, "idempotency key"))
    );
  }
});

async function signMutationRequest({ authority, operation, input, databaseID }) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Noctweb mutation input must be an object.");
  }
  const actor = authority.actor();
  const nonce = await cryptoRandomBytes(authority.crypto, noctwebDataV1Limits.nonceBytes);
  const idempotency = await randomOrExact(
    authority.crypto,
    input.idempotencyKey,
    noctwebDataV1Limits.idempotencyKeyBytes,
    `${operation} idempotency key`
  );
  const emptyAuthorization = {
    actorKind: actor.kind,
    actorID: actor.id,
    nonce: base64(nonce),
    signature: base64(new Uint8Array(actor.kind === "publisher"
      ? noctwebDataV1Limits.publisherSignatureBytes
      : noctwebDataV1Limits.accountSignatureBytes))
  };
  let draft;
  let transcript;
  if (operation === "put") {
    const payload = input.payload instanceof Uint8Array || input.payload instanceof ArrayBuffer || ArrayBuffer.isView(input.payload)
      ? bytes(input.payload, "Noctweb record payload")
      : encodeNoctwebDataJSON(input.payload);
    draft = {
      databaseID: validateDatabaseID(databaseID),
      collection: validateCollectionName(input.collection),
      recordID: validateRecordID(input.recordID),
      ...(input.ownerAccountID === undefined ? {} : { ownerAccountID: validateAccountID(input.ownerAccountID) }),
      payload: base64(payload),
      expectedRevision: requireInteger(input.expectedRevision ?? 0, "Noctweb expected revision", 0, Number.MAX_SAFE_INTEGER),
      idempotencyKey: base64(idempotency),
      authorization: emptyAuthorization
    };
    validateNoctwebDataRecordPutRequestV1(draft);
    transcript = noctwebDataTranscriptsV1.putRecord(draft);
  } else {
    draft = {
      databaseID: validateDatabaseID(databaseID),
      collection: validateCollectionName(input.collection),
      recordID: validateRecordID(input.recordID),
      expectedRevision: requireInteger(input.expectedRevision, "Noctweb expected revision", 1, Number.MAX_SAFE_INTEGER),
      idempotencyKey: base64(idempotency),
      authorization: emptyAuthorization
    };
    validateNoctwebDataRecordDeleteRequestV1(draft);
    transcript = noctwebDataTranscriptsV1.deleteRecord(draft);
  }
  const signed = {
    ...draft,
    authorization: { ...emptyAuthorization, signature: base64(await authority.sign(transcript)) }
  };
  return Object.freeze(operation === "put"
    ? validateNoctwebDataRecordPutRequestV1(signed)
    : validateNoctwebDataRecordDeleteRequestV1(signed));
}

async function signReadRequest({ authority, operation, input, databaseID }) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Noctweb read input must be an object.");
  }
  const actor = authority.actor();
  const nonce = await cryptoRandomBytes(authority.crypto, noctwebDataV1Limits.nonceBytes);
  const emptyAuthorization = {
    actorKind: actor.kind,
    actorID: actor.id,
    nonce: base64(nonce),
    signature: base64(new Uint8Array(actor.kind === "publisher"
      ? noctwebDataV1Limits.publisherSignatureBytes
      : noctwebDataV1Limits.accountSignatureBytes))
  };
  const draft = operation === "get" ? {
    databaseID: validateDatabaseID(databaseID),
    collection: validateCollectionName(input.collection),
    recordID: validateRecordID(input.recordID),
    authorization: emptyAuthorization
  } : {
    databaseID: validateDatabaseID(databaseID),
    collection: validateCollectionName(input.collection),
    ...(input.afterRecordID === undefined ? {} : { afterRecordID: validateRecordID(input.afterRecordID) }),
    limit: requireInteger(input.limit ?? noctwebDataV1Limits.maximumPage, "Noctweb record list limit", 1, noctwebDataV1Limits.maximumPage),
    authorization: emptyAuthorization
  };
  const transcript = operation === "get"
    ? noctwebDataTranscriptsV1.getRecord(draft)
    : noctwebDataTranscriptsV1.listRecords(draft);
  const signed = {
    ...draft,
    authorization: { ...emptyAuthorization, signature: base64(await authority.sign(transcript)) }
  };
  return Object.freeze(operation === "get"
    ? validateNoctwebDataRecordGetRequestV1(signed)
    : validateNoctwebDataRecordListRequestV1(signed));
}

function normalizeCollections(collections) {
  if (!Array.isArray(collections) || collections.length === 0 ||
      collections.length > noctwebDataV1Limits.maximumCollections) {
    throw new TypeError("Noctweb database must define 1 to 32 collections.");
  }
  const result = collections.map((item) => ({
    name: item.name,
    readPolicy: item.readPolicy,
    writePolicy: item.writePolicy
  })).sort((left, right) => left.name.localeCompare(right.name, "en", { sensitivity: "variant" }));
  result.forEach(validateNoctwebDataCollectionV1);
  if (new Set(result.map(({ name }) => name)).size !== result.length) {
    throw new TypeError("Noctweb collection names must be unique.");
  }
  return Object.freeze(result.map(Object.freeze));
}

function authorizedDomain(name, authorization) {
  validateNoctwebDataAuthorizationV1(authorization);
  return concatBytes(
    domain(name),
    appendString(authorization.actorKind),
    appendString(authorization.actorID),
    appendData(requireBase64(authorization.nonce, 32, "authorization nonce"))
  );
}

function optionalAuthorizedDomain(name, authorization) {
  return authorization === undefined
    ? concatBytes(domain(name), Uint8Array.of(0))
    : concatBytes(domain(name), Uint8Array.of(1), appendString(authorization.actorKind),
      appendString(authorization.actorID), appendData(requireBase64(authorization.nonce, 32, "authorization nonce")));
}

function domain(value) {
  return concatBytes(textEncoder.encode(value), Uint8Array.of(0));
}

function appendString(value) {
  return appendData(textEncoder.encode(value));
}

function appendOptionalString(value) {
  return value === undefined
    ? Uint8Array.of(0)
    : concatBytes(Uint8Array.of(1), appendString(value));
}

function appendData(value) {
  const data = bytes(value, "transcript field");
  return concatBytes(uint64Bytes(data.byteLength), data);
}

function validateRelaySuffix(value) {
  if (typeof value !== "string" || value.length < 3 || utf8Length(value) > 64 ||
      !suffixPattern.test(value) || value !== value.toLowerCase()) {
    throw new TypeError("Noctweb relay suffix is invalid.");
  }
  return value;
}

function validateSiteLabel(value) {
  if (typeof value !== "string" || utf8Length(value) > 63 || !siteLabelPattern.test(value) ||
      value !== value.toLowerCase()) {
    throw new TypeError("Noctweb site label is invalid.");
  }
  return value;
}

function validateCollectionName(value) {
  if (typeof value !== "string" || utf8Length(value) > noctwebDataV1Limits.maximumCollectionNameBytes ||
      !collectionPattern.test(value)) {
    throw new TypeError("Noctweb collection name is invalid.");
  }
  return value;
}

function validateRecordID(value) {
  if (typeof value !== "string" || utf8Length(value) > noctwebDataV1Limits.maximumRecordIDBytes ||
      !recordIDPattern.test(value)) {
    throw new TypeError("Noctweb record ID is invalid.");
  }
  return value;
}

function validatePublisherID(value) {
  if (typeof value !== "string" || !publisherIDPattern.test(value)) {
    throw new TypeError("Noctweb publisher ID is invalid.");
  }
  return value;
}

function validateDatabaseID(value) {
  if (typeof value !== "string" || !databaseIDPattern.test(value)) {
    throw new TypeError("Noctweb database ID is invalid.");
  }
  return value;
}

function validateAccountID(value) {
  if (typeof value !== "string" || !accountIDPattern.test(value)) {
    throw new TypeError("Noctweb account ID is invalid.");
  }
  return value;
}

function validateActorID(value, kind) {
  return kind === "publisher" ? validatePublisherID(value) : validateAccountID(value);
}

function exactBytes(value, length, label) {
  const result = bytes(value, label);
  if (result.byteLength !== length) throw new TypeError(`${label} must contain exactly ${length} bytes.`);
  return result;
}

async function randomOrExact(crypto, value, length, label) {
  return value === undefined
    ? cryptoRandomBytes(crypto, length)
    : new Uint8Array(exactBytes(value, length, label));
}

function requireDataCrypto(crypto, randomnessRequired, signaturesRequired = false) {
  if (typeof crypto?.sha256 !== "function" ||
      (randomnessRequired && typeof crypto?.randomBytes !== "function") ||
      (signaturesRequired && (typeof crypto?.generateSigningKeypair !== "function" || typeof crypto?.sign !== "function"))) {
    throw new TypeError("Noctweb data requires SHA-256, secure randomness, and the requested signing implementation.");
  }
  return crypto;
}

function requirePageRelay(relay) {
  for (const method of [
    "registerNoctwebAccount",
    "putNoctwebRecord",
    "getNoctwebRecord",
    "listNoctwebRecords",
    "deleteNoctwebRecord"
  ]) {
    if (typeof relay?.[method] !== "function") {
      throw new TypeError("Noctweb page data requires a compatible relay client.");
    }
  }
  return relay;
}

function pageRecord(record) {
  validateNoctwebDataRecordV1(record);
  return Object.freeze({
    id: record.recordID,
    ownerAccountID: record.ownerAccountID ?? null,
    revision: record.revision,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    value: decodeNoctwebDataJSON(requireBase64(record.payload, undefined, "Noctweb record payload"))
  });
}

function requireSubtle(subtle) {
  if (!subtle || typeof subtle.sign !== "function") {
    throw new TypeError("WebCrypto Ed25519 support is required for publisher authority.");
  }
  return subtle;
}

function hexadecimal(value) {
  return [...bytes(value, "digest")].map((octet) => octet.toString(16).padStart(2, "0")).join("");
}

function utf8Length(value) {
  return textEncoder.encode(value).byteLength;
}
