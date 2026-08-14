import { base64, canonicalJsonBytes, swiftISODate } from "./crypto/swift-canonical.js";
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
  maximumAccountsPerDatabase: 1_024,
  maximumDatabases: 256,
  maximumDatabasesPerPublisher: 8,
  maximumRecordsPerOwner: 256,
  maximumBytesPerOwner: 2 * 1_024 * 1_024,
  maximumMutationReplayEntries: 1_024,
  maximumMutationReplayBytes: 8 * 1_024 * 1_024,
  mutationReplayLifetimeSeconds: 5 * 60 + 31,
  authorizationLifetimeSeconds: 2 * 60,
  maximumAuthorizationLifetimeSeconds: 5 * 60,
  authorizationClockSkewSeconds: 30,
  maximumPage: 8,
  maximumDatabaseBytes: 64 * 1_024 * 1_024,
  maximumTotalDataBytes: 512 * 1_024 * 1_024,
  idempotencyKeyBytes: 32,
  nonceBytes: 32,
  publisherPublicKeyBytes: 32,
  publisherSignatureBytes: 64,
  accountPublicKeyBytes: 1_952,
  accountSecretKeyBytes: 4_032,
  accountSignatureBytes: 3_309,
  payloadKeyBytes: 32,
  payloadKeyIDBytes: 32,
  payloadNonceBytes: 12
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
      databaseID: await this.databaseID(),
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
  static async create({ relay, account, origin, collections, encryptionKey, maxOperationsPerMinute = 60 }) {
    if (!(account instanceof NoctwebDataAccountAuthorityV1)) {
      throw new TypeError("Noctweb page data requires a per-origin account authority.");
    }
    requirePageRelay(relay);
    validateNoctwebDataOriginV1(origin);
    requirePayloadCrypto(account.crypto);
    const publisherKey = requireBase64(
      origin.publisherSigningPublicKey,
      noctwebDataV1Limits.publisherPublicKeyBytes,
      "publisher public key"
    );
    if (origin.publisherID !== await noctwebDataPublisherID(account.crypto, publisherKey)) {
      throw new TypeError("Noctweb page origin publisher ID does not match its signing key.");
    }
    const normalizedOrigin = Object.freeze({ ...origin });
    const expectedDatabaseID = await noctwebDataDatabaseID(account.crypto, normalizedOrigin);
    if (expectedDatabaseID !== account.databaseID) {
      throw new TypeError("Noctweb page origin does not match its account database.");
    }
    const normalizedCollections = normalizeCollections(collections);
    requireInteger(maxOperationsPerMinute, "Noctweb page operation limit", 1, 600);
    const payloadKey = new Uint8Array(exactBytes(
      encryptionKey,
      noctwebDataV1Limits.payloadKeyBytes,
      "Noctweb page data encryption key"
    ));
    return new NoctwebDataPageCapabilityV1({
      relay,
      account,
      origin: normalizedOrigin,
      encryptionKey: payloadKey,
      collections: normalizedCollections,
      maxOperationsPerMinute
    });
  }

  #relay;
  #account;
  #origin;
  #encryptionKey;
  #collections;
  #maxOperationsPerMinute;
  #operationTimes = [];
  #destroyed = false;

  constructor({ relay, account, origin, encryptionKey, collections, maxOperationsPerMinute }) {
    this.#relay = relay;
    this.#account = account;
    this.#origin = origin;
    this.#encryptionKey = encryptionKey;
    this.#collections = new Map(collections.map((collection) => [collection.name, collection]));
    this.#maxOperationsPerMinute = maxOperationsPerMinute;
    Object.freeze(this);
  }

  get accountID() {
    this.#assertLive();
    return this.#account.accountID;
  }

  destroy() {
    if (this.#destroyed) return;
    this.#encryptionKey.fill(0);
    this.#operationTimes = [];
    this.#destroyed = true;
  }

  async get(collection, recordID, { ownerScope } = {}) {
    this.#consumeOperation();
    const policy = this.#collection(collection);
    const ownerAccountID = this.#readOwner(policy, ownerScope);
    const request = policy.readPolicy === "public"
      ? {
          databaseID: this.#account.databaseID,
          collection,
          recordID,
          ...(ownerAccountID === undefined ? {} : { ownerAccountID })
        }
      : await this.#account.getRequest({ collection, recordID, ownerAccountID: this.#account.accountID });
    return this.#pageRecord(await this.#relay.getNoctwebRecord(request), policy);
  }

  async list(collection, {
    afterRecordID,
    limit = noctwebDataV1Limits.maximumPage,
    ownerScope
  } = {}) {
    this.#consumeOperation();
    const policy = this.#collection(collection);
    const input = {
      collection,
      ...(afterRecordID === undefined ? {} : { afterRecordID }),
      limit
    };
    const ownerAccountID = this.#readOwner(policy, ownerScope);
    const request = policy.readPolicy === "public"
      ? {
          databaseID: this.#account.databaseID,
          ...input,
          ...(ownerAccountID === undefined ? {} : { ownerAccountID })
        }
      : await this.#account.listRequest({ ...input, ownerAccountID: this.#account.accountID });
    const response = await this.#relay.listNoctwebRecords(request);
    return Object.freeze({
      records: Object.freeze(await Promise.all(
        response.records.map((record) => this.#pageRecord(record, policy))
      )),
      nextCursor: response.nextCursor ?? null
    });
  }

  async put(collection, recordID, value, { expectedRevision = 0, idempotencyKey } = {}) {
    this.#consumeOperation();
    const policy = this.#collection(collection);
    if (policy.writePolicy === "publisher") {
      throw new Error("This collection is read-only for site visitors.");
    }
    const payload = await encryptNoctwebDataJSONV1({
      crypto: this.#account.crypto,
      key: this.#encryptionKey,
      databaseID: this.#account.databaseID,
      collection,
      recordID,
      ownerAccountID: this.#account.accountID,
      revision: expectedRevision + 1,
      value
    });
    const request = await this.#account.putRequest({
      collection, recordID, ownerAccountID: this.#account.accountID,
      payload, expectedRevision,
      ...(idempotencyKey === undefined ? {} : { idempotencyKey })
    });
    return this.#pageRecord(await this.#relay.putNoctwebRecord(request), policy);
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
      ownerAccountID: this.#account.accountID,
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

  #readOwner(policy, ownerScope) {
    if (ownerScope !== undefined && ownerScope !== "account" && ownerScope !== "global") {
      throw new TypeError("Noctweb page data owner scope must be account or global.");
    }
    if (policy.readPolicy !== "public") {
      if (ownerScope === "global") {
        throw new Error("Private collections require the page account namespace.");
      }
      return this.#account.accountID;
    }
    if (ownerScope === "account") return this.#account.accountID;
    if (ownerScope === "global") return undefined;
    return policy.writePolicy === "publisher" ? undefined : this.#account.accountID;
  }

  #consumeOperation() {
    this.#assertLive();
    const cutoff = Date.now() - 60_000;
    this.#operationTimes = this.#operationTimes.filter((timestamp) => timestamp > cutoff);
    if (this.#operationTimes.length >= this.#maxOperationsPerMinute) {
      throw new Error("Noctweb page data rate limit reached.");
    }
    this.#operationTimes.push(Date.now());
  }

  #assertLive() {
    if (this.#destroyed) {
      throw new Error("Noctweb page data capability was destroyed.");
    }
  }

  async #pageRecord(record, policy) {
    validateNoctwebDataRecordV1(record);
    const validProof = await verifyNoctwebDataRecordProvenanceV1({
      crypto: this.#account.crypto,
      subtle: globalThis.crypto?.subtle,
      origin: this.#origin,
      record
    });
    if (!validProof || !recordAuthorMatchesPolicy(record, policy)) {
      throw new Error("Noctweb record provenance was rejected.");
    }
    return Object.freeze({
      id: record.recordID,
      ownerAccountID: record.ownerAccountID ?? null,
      revision: record.revision,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      value: await decryptNoctwebDataJSONV1({
        crypto: this.#account.crypto,
        key: this.#encryptionKey,
        record
      })
    });
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

export async function encryptNoctwebDataJSONV1({
  crypto,
  key,
  databaseID,
  collection,
  recordID,
  ownerAccountID,
  revision,
  value
}) {
  requirePayloadCrypto(crypto);
  const keyBytes = exactBytes(key, noctwebDataV1Limits.payloadKeyBytes, "Noctweb data encryption key");
  const keyID = await cryptoSha256(
    crypto,
    concatBytes(domain("org.noctweave.noctweb/payload-key-id/v1"), keyBytes)
  );
  const nonce = await cryptoRandomBytes(crypto, noctwebDataV1Limits.payloadNonceBytes);
  const aad = noctwebDataEncryptedPayloadAADV1({
    databaseID,
    collection,
    recordID,
    ownerAccountID,
    revision,
    keyID
  });
  const ciphertext = bytes(await crypto.aesGcmEncrypt({
    key: keyBytes,
    nonce,
    plaintext: encodeNoctwebDataJSON(value),
    additionalData: aad
  }), "Noctweb encrypted payload");
  const encoded = canonicalJsonBytes({
    algorithm: "AES-256-GCM",
    ciphertext: base64(ciphertext),
    keyID: base64(keyID),
    nonce: base64(nonce),
    version: 1
  });
  validateNoctwebDataEncryptedPayloadBytesV1(encoded);
  return encoded;
}

export async function decryptNoctwebDataJSONV1({
  crypto,
  key,
  record
}) {
  requirePayloadCrypto(crypto);
  validateNoctwebDataRecordV1(record);
  const keyBytes = exactBytes(key, noctwebDataV1Limits.payloadKeyBytes, "Noctweb data encryption key");
  const envelope = validateNoctwebDataEncryptedPayloadBytesV1(
    requireBase64(record.payload, undefined, "Noctweb record payload")
  );
  const expectedKeyID = await cryptoSha256(
    crypto,
    concatBytes(domain("org.noctweave.noctweb/payload-key-id/v1"), keyBytes)
  );
  if (!equalBytes(expectedKeyID, requireBase64(envelope.keyID, 32, "Noctweb payload key ID"))) {
    throw new Error("Noctweb payload was not encrypted for this origin key.");
  }
  const plaintext = await crypto.aesGcmDecrypt({
    key: keyBytes,
    nonce: requireBase64(envelope.nonce, 12, "Noctweb payload nonce"),
    ciphertext: requireBase64(envelope.ciphertext, undefined, "Noctweb payload ciphertext"),
    additionalData: noctwebDataEncryptedPayloadAADV1({
      databaseID: record.databaseID,
      collection: record.collection,
      recordID: record.recordID,
      ownerAccountID: record.ownerAccountID,
      revision: record.revision,
      keyID: expectedKeyID
    })
  });
  return decodeNoctwebDataJSON(plaintext);
}

export function validateNoctwebDataEncryptedPayloadBytesV1(value) {
  const payload = bytes(value, "Noctweb encrypted payload");
  if (payload.byteLength === 0 || payload.byteLength > noctwebDataV1Limits.maximumRecordBytes) {
    throw new TypeError("Noctweb encrypted payload exceeds its size bound.");
  }
  const envelope = parseExactJSON(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  requireExactRecord(envelope, ["version", "algorithm", "keyID", "nonce", "ciphertext"], [], "Noctweb encrypted payload");
  if (envelope.version !== 1 || envelope.algorithm !== "AES-256-GCM") {
    throw new TypeError("Noctweb encrypted payload algorithm is invalid.");
  }
  requireBase64(envelope.keyID, noctwebDataV1Limits.payloadKeyIDBytes, "Noctweb payload key ID");
  requireBase64(envelope.nonce, noctwebDataV1Limits.payloadNonceBytes, "Noctweb payload nonce");
  const ciphertext = requireBase64(envelope.ciphertext, undefined, "Noctweb payload ciphertext");
  if (ciphertext.byteLength <= 16 || ciphertext.byteLength > noctwebDataV1Limits.maximumRecordBytes) {
    throw new TypeError("Noctweb payload ciphertext is invalid.");
  }
  if (!equalBytes(payload, canonicalJsonBytes(envelope))) {
    throw new TypeError("Noctweb encrypted payload must use canonical JSON.");
  }
  return envelope;
}

export function validateNoctwebDataRecordProvenanceV1(value) {
  requireExactRecord(value, [
    "actorKind", "actorID", "actorSigningPublicKey", "authorizationNonce",
    "authorizationExpiresAt", "idempotencyKey", "expectedRevision", "signature"
  ], [], "Noctweb record provenance");
  if (!actorKinds.has(value.actorKind)) throw new TypeError("Noctweb provenance actor kind is invalid.");
  validateActorID(value.actorID, value.actorKind);
  requireBase64(value.actorSigningPublicKey, value.actorKind === "publisher" ? 32 : 1_952, "Noctweb provenance public key");
  requireBase64(value.authorizationNonce, 32, "Noctweb provenance nonce");
  requireCanonicalTimestamp(value.authorizationExpiresAt, "Noctweb provenance expiry");
  requireBase64(value.idempotencyKey, 32, "Noctweb provenance idempotency key");
  requireInteger(value.expectedRevision, "Noctweb provenance expected revision", 0, Number.MAX_SAFE_INTEGER);
  requireBase64(value.signature, value.actorKind === "publisher" ? 64 : 3_309, "Noctweb provenance signature");
  return value;
}

export async function verifyNoctwebDataRecordProvenanceV1({
  crypto,
  subtle = globalThis.crypto?.subtle,
  origin,
  record
}) {
  requireDataCrypto(crypto, false);
  validateNoctwebDataOriginV1(origin);
  validateNoctwebDataRecordV1(record);
  const originPublicKey = requireBase64(
    origin.publisherSigningPublicKey,
    noctwebDataV1Limits.publisherPublicKeyBytes,
    "publisher public key"
  );
  if (origin.publisherID !== await noctwebDataPublisherID(crypto, originPublicKey)) return false;
  if (record.databaseID !== await noctwebDataDatabaseID(crypto, origin)) return false;
  const proof = record.provenance;
  const publicKey = requireBase64(
    proof.actorSigningPublicKey,
    proof.actorKind === "publisher" ? 32 : 1_952,
    "Noctweb provenance public key"
  );
  if (proof.actorKind === "publisher") {
    if (proof.actorID !== origin.publisherID ||
        !equalBytes(publicKey, originPublicKey)) {
      return false;
    }
  } else if (proof.actorID !== await noctwebDataAccountID(crypto, record.databaseID, publicKey)) {
    return false;
  }
  const authorization = {
    actorKind: proof.actorKind,
    actorID: proof.actorID,
    nonce: proof.authorizationNonce,
    expiresAt: proof.authorizationExpiresAt,
    signature: proof.signature
  };
  const request = {
    databaseID: record.databaseID,
    collection: record.collection,
    recordID: record.recordID,
    ...(record.ownerAccountID === undefined ? {} : { ownerAccountID: record.ownerAccountID }),
    payload: record.payload,
    expectedRevision: proof.expectedRevision,
    idempotencyKey: proof.idempotencyKey,
    authorization
  };
  const transcript = noctwebDataTranscriptsV1.putRecord(request);
  const signature = requireBase64(
    proof.signature,
    proof.actorKind === "publisher" ? 64 : 3_309,
    "Noctweb provenance signature"
  );
  if (proof.actorKind === "publisher") {
    requireSubtle(subtle);
    const key = await subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return subtle.verify({ name: "Ed25519" }, key, signature, transcript);
  }
  if (typeof crypto?.verify !== "function") {
    throw new TypeError("Noctweb account provenance requires ML-DSA-65 verification.");
  }
  return Boolean(await crypto.verify(transcript, signature, publicKey));
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
  requireExactRecord(value, ["actorKind", "actorID", "nonce", "expiresAt", "signature"], [], "Noctweb data authorization");
  if (!actorKinds.has(value.actorKind)) throw new TypeError("Noctweb data actor kind is invalid.");
  validateActorID(value.actorID, value.actorKind);
  requireBase64(value.nonce, noctwebDataV1Limits.nonceBytes, "Noctweb data nonce");
  requireCanonicalTimestamp(value.expiresAt, "Noctweb data authorization expiry");
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
  requireExactRecord(value, ["databaseID", "origin", "collections", "idempotencyKey", "signature"], [], "Noctweb database request");
  validateDatabaseID(value.databaseID);
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
  validateNoctwebDataEncryptedPayloadBytesV1(payload);
  requireInteger(value.expectedRevision, "Noctweb expected revision", 0, Number.MAX_SAFE_INTEGER);
  requireBase64(value.idempotencyKey, noctwebDataV1Limits.idempotencyKeyBytes, "Noctweb record idempotency key");
  validateNoctwebDataAuthorizationV1(value.authorization);
  if (value.authorization.actorKind === "account" &&
      value.ownerAccountID !== value.authorization.actorID) {
    throw new TypeError("Noctweb account writes must name their exact owner namespace.");
  }
  return value;
}

export function validateNoctwebDataRecordGetRequestV1(value) {
  requireExactRecord(value, ["databaseID", "collection", "recordID"], ["ownerAccountID", "authorization"], "Noctweb record get");
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  if (value.ownerAccountID !== undefined) validateAccountID(value.ownerAccountID);
  if (value.authorization !== undefined) validateNoctwebDataAuthorizationV1(value.authorization);
  if (value.authorization?.actorKind === "account" &&
      value.ownerAccountID !== value.authorization.actorID) {
    throw new TypeError("Noctweb account reads must name their exact owner namespace.");
  }
  return value;
}

export function validateNoctwebDataRecordListRequestV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "limit"],
    ["afterRecordID", "ownerAccountID", "authorization"],
    "Noctweb record list"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  if (value.afterRecordID !== undefined) validateRecordID(value.afterRecordID);
  if (value.ownerAccountID !== undefined) validateAccountID(value.ownerAccountID);
  requireInteger(value.limit, "Noctweb record list limit", 1, noctwebDataV1Limits.maximumPage);
  if (value.authorization !== undefined) validateNoctwebDataAuthorizationV1(value.authorization);
  if (value.authorization?.actorKind === "account" &&
      value.ownerAccountID !== value.authorization.actorID) {
    throw new TypeError("Noctweb account reads must name their exact owner namespace.");
  }
  return value;
}

export function validateNoctwebDataRecordDeleteRequestV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "recordID", "expectedRevision", "idempotencyKey", "authorization"],
    ["ownerAccountID"],
    "Noctweb record deletion"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  if (value.ownerAccountID !== undefined) validateAccountID(value.ownerAccountID);
  requireInteger(value.expectedRevision, "Noctweb deleted revision", 1, Number.MAX_SAFE_INTEGER);
  requireBase64(value.idempotencyKey, noctwebDataV1Limits.idempotencyKeyBytes, "Noctweb deletion idempotency key");
  validateNoctwebDataAuthorizationV1(value.authorization);
  if (value.authorization.actorKind === "account" &&
      value.ownerAccountID !== value.authorization.actorID) {
    throw new TypeError("Noctweb account deletions must name their exact owner namespace.");
  }
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
    ["databaseID", "collection", "recordID", "payload", "revision", "createdAt", "updatedAt", "provenance"],
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
  validateNoctwebDataEncryptedPayloadBytesV1(payload);
  requireInteger(value.revision, "Noctweb record revision", 1, Number.MAX_SAFE_INTEGER);
  const created = new Date(requireCanonicalTimestamp(value.createdAt, "Noctweb record creation time")).getTime();
  const updated = new Date(requireCanonicalTimestamp(value.updatedAt, "Noctweb record update time")).getTime();
  if (updated < created) throw new TypeError("Noctweb record update predates creation.");
  validateNoctwebDataRecordProvenanceV1(value.provenance);
  if (value.provenance.expectedRevision + 1 !== value.revision) {
    throw new TypeError("Noctweb record provenance revision is invalid.");
  }
  if (value.provenance.actorKind === "account" &&
      value.ownerAccountID !== value.provenance.actorID) {
    throw new TypeError("Noctweb account provenance does not match the record owner.");
  }
  return value;
}

export function validateNoctwebDataRecordListV1(value) {
  requireExactRecord(value, ["records"], ["nextCursor"], "Noctweb record list");
  if (!Array.isArray(value.records) || value.records.length > noctwebDataV1Limits.maximumPage) {
    throw new TypeError("Noctweb record list exceeds its page bound.");
  }
  value.records.forEach(validateNoctwebDataRecordV1);
  if (value.nextCursor !== undefined) validateRecordID(value.nextCursor);
  for (let index = 1; index < value.records.length; index += 1) {
    if (value.records[index - 1].recordID >= value.records[index].recordID) {
      throw new TypeError("Noctweb record lists must be strictly ordered.");
    }
  }
  if (value.nextCursor !== undefined &&
      value.nextCursor !== value.records.at(-1)?.recordID) {
    throw new TypeError("Noctweb record list cursor must bind the last record.");
  }
  return value;
}

export function validateNoctwebDataDeleteReceiptV1(value) {
  requireExactRecord(
    value,
    ["databaseID", "collection", "recordID", "deletedRevision"],
    ["ownerAccountID"],
    "Noctweb deletion receipt"
  );
  validateDatabaseID(value.databaseID);
  validateCollectionName(value.collection);
  validateRecordID(value.recordID);
  if (value.ownerAccountID !== undefined) validateAccountID(value.ownerAccountID);
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
      appendString(request.databaseID),
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
      appendString(request.databaseID), appendString(request.collection), appendString(request.recordID),
      appendOptionalString(request.ownerAccountID)
    );
  },
  listRecords(request) {
    validateNoctwebDataRecordListRequestV1(request);
    return concatBytes(
      optionalAuthorizedDomain("org.noctweave.noctweb/data-list/v1", request.authorization),
      appendString(request.databaseID), appendString(request.collection),
      appendOptionalString(request.afterRecordID), appendOptionalString(request.ownerAccountID),
      uint64Bytes(request.limit)
    );
  },
  deleteRecord(request) {
    validateNoctwebDataRecordDeleteRequestV1(request);
    return concatBytes(
      authorizedDomain("org.noctweave.noctweb/data-delete/v1", request.authorization),
      appendString(request.databaseID), appendString(request.collection), appendString(request.recordID),
      appendOptionalString(request.ownerAccountID), uint64Bytes(request.expectedRevision),
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
  const expiresAt = authorizationExpiry(input.expiresAt);
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
    expiresAt,
    signature: base64(new Uint8Array(actor.kind === "publisher"
      ? noctwebDataV1Limits.publisherSignatureBytes
      : noctwebDataV1Limits.accountSignatureBytes))
  };
  let draft;
  let transcript;
  if (operation === "put") {
    if (!(input.payload instanceof Uint8Array || input.payload instanceof ArrayBuffer || ArrayBuffer.isView(input.payload))) {
      throw new TypeError("Noctweb records require an encrypted payload envelope.");
    }
    const payload = bytes(input.payload, "Noctweb encrypted record payload");
    validateNoctwebDataEncryptedPayloadBytesV1(payload);
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
      ...(input.ownerAccountID === undefined ? {} : { ownerAccountID: validateAccountID(input.ownerAccountID) }),
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
  const expiresAt = authorizationExpiry(input.expiresAt);
  const emptyAuthorization = {
    actorKind: actor.kind,
    actorID: actor.id,
    nonce: base64(nonce),
    expiresAt,
    signature: base64(new Uint8Array(actor.kind === "publisher"
      ? noctwebDataV1Limits.publisherSignatureBytes
      : noctwebDataV1Limits.accountSignatureBytes))
  };
  const draft = operation === "get" ? {
    databaseID: validateDatabaseID(databaseID),
    collection: validateCollectionName(input.collection),
    recordID: validateRecordID(input.recordID),
    ...(input.ownerAccountID === undefined ? {} : { ownerAccountID: validateAccountID(input.ownerAccountID) }),
    authorization: emptyAuthorization
  } : {
    databaseID: validateDatabaseID(databaseID),
    collection: validateCollectionName(input.collection),
    ...(input.afterRecordID === undefined ? {} : { afterRecordID: validateRecordID(input.afterRecordID) }),
    ...(input.ownerAccountID === undefined ? {} : { ownerAccountID: validateAccountID(input.ownerAccountID) }),
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
    appendData(requireBase64(authorization.nonce, 32, "authorization nonce")),
    uint64Bytes(timestampSeconds(authorization.expiresAt, "authorization expiry"))
  );
}

function optionalAuthorizedDomain(name, authorization) {
  return authorization === undefined
    ? concatBytes(domain(name), Uint8Array.of(0))
    : concatBytes(domain(name), Uint8Array.of(1), appendString(authorization.actorKind),
      appendString(authorization.actorID), appendData(requireBase64(authorization.nonce, 32, "authorization nonce")),
      uint64Bytes(timestampSeconds(authorization.expiresAt, "authorization expiry")));
}

export function noctwebDataEncryptedPayloadAADV1({
  databaseID,
  collection,
  recordID,
  ownerAccountID,
  revision,
  keyID
}) {
  return concatBytes(
    domain("org.noctweave.noctweb/encrypted-payload/v1"),
    appendString(validateDatabaseID(databaseID)),
    appendString(validateCollectionName(collection)),
    appendString(validateRecordID(recordID)),
    appendOptionalString(ownerAccountID === undefined ? undefined : validateAccountID(ownerAccountID)),
    uint64Bytes(requireInteger(revision, "Noctweb encrypted payload revision", 1, Number.MAX_SAFE_INTEGER)),
    appendData(exactBytes(keyID, 32, "Noctweb payload key ID"))
  );
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

function authorizationExpiry(value) {
  if (value !== undefined) return requireCanonicalTimestamp(value, "Noctweb authorization expiry");
  const nowSeconds = Math.floor(Date.now() / 1_000);
  return swiftISODate(new Date(
    (nowSeconds + noctwebDataV1Limits.authorizationLifetimeSeconds) * 1_000
  ));
}

function timestampSeconds(value, label) {
  return Math.floor(new Date(requireCanonicalTimestamp(value, label)).getTime() / 1_000);
}

function requirePayloadCrypto(crypto) {
  requireDataCrypto(crypto, true);
  if (typeof crypto?.aesGcmEncrypt !== "function" || typeof crypto?.aesGcmDecrypt !== "function") {
    throw new TypeError("Noctweb encrypted payloads require AES-256-GCM.");
  }
  return crypto;
}

function equalBytes(left, right) {
  const a = bytes(left, "left bytes");
  const b = bytes(right, "right bytes");
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < a.byteLength; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
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

function recordAuthorMatchesPolicy(record, policy) {
  const proof = record.provenance;
  switch (policy.writePolicy) {
  case "publisher":
    return proof.actorKind === "publisher";
  case "owner":
    return proof.actorKind === "account" && proof.actorID === record.ownerAccountID;
  case "owner-or-publisher":
    return proof.actorKind === "publisher" ||
      (proof.actorKind === "account" && proof.actorID === record.ownerAccountID);
  default:
    return false;
  }
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
