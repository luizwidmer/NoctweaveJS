import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";
import {
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  NoctwebDataAccountAuthorityV1,
  NoctwebDataPageCapabilityV1,
  NoctwebDataPublisherAuthorityV1,
  WebCryptoPrimitives,
  base64,
  decodeNoctwebDataJSON,
  decryptNoctwebDataJSONV1,
  encryptNoctwebDataJSONV1,
  noctwebDataAccountID,
  noctwebDataDatabaseID,
  noctwebDataPublisherID,
  noctwebDataTranscriptsV1,
  relayRequests,
  validateNoctwebDataRecordListV1,
  validateNoctwebDataRecordPutRequestV1,
  verifyNoctwebDataRecordProvenanceV1
} from "../src/index.js";

const wasmModulePath = new URL("../wasm/dist/noctweave_oqs.js", import.meta.url);

test("Swift and JavaScript derive the same origin and account identifiers", async () => {
  const primitives = new WebCryptoPrimitives();
  const publisherKey = Uint8Array.from({ length: 32 }, (_, index) => index);
  const publisherID = await noctwebDataPublisherID(primitives, publisherKey);
  assert.equal(
    publisherID,
    "nwpub1_95a0e7e50deed5ca358e0f56637306094399af16c8d8c127a0f4dd742d372db5"
  );
  const origin = {
    version: 1,
    relaySuffix: ".vector",
    siteLabel: "shop",
    publisherID,
    publisherSigningPublicKey: base64(publisherKey)
  };
  const databaseID = await noctwebDataDatabaseID(primitives, origin);
  assert.equal(
    databaseID,
    "nwdb1_ffb36f4bf6d9b191831320522c1ccf8a0fc6d74d225bf847b638cf377f8cad4c"
  );
  const accountKey = Uint8Array.from(
    { length: 1_952 },
    (_, index) => (index * 17 + 3) % 256
  );
  assert.equal(
    await noctwebDataAccountID(primitives, databaseID, accountKey),
    "nwa1_8910a1946435943581132c38d336d1de871f28e0e20b22fccb3eff58c38b8d6d"
  );
});

test("publisher authority creates an isolated database and drives bounded relay CRUD", async () => {
  const publisher = await NoctwebDataPublisherAuthorityV1.generate({
    relaySuffix: ".market",
    siteLabel: "tea"
  });
  const databaseID = await publisher.databaseID();
  const primitives = new WebCryptoPrimitives();
  const payloadKey = primitives.randomBytes(32);
  const create = await publisher.createDatabaseRequest([
    { name: "carts", readPolicy: "owner", writePolicy: "owner" },
    { name: "products", readPolicy: "public", writePolicy: "publisher" }
  ]);
  const calls = [];
  let record;
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      calls.push(request);
      assert.equal(request.module, "nw.noctweb-data");
      assert.deepEqual(Object.keys(request.body), ["request"]);
      switch (request.method) {
      case "create":
        return response(relaySuccess(request, { database: { databaseID, created: true } }));
      case "put": {
        const put = request.body.request;
        record = {
          databaseID,
          collection: put.collection,
          recordID: put.recordID,
          payload: put.payload,
          revision: put.expectedRevision + 1,
          createdAt: "2026-08-13T10:00:00Z",
          updatedAt: "2026-08-13T10:00:00Z",
          provenance: provenanceFor(put, publisher.origin.publisherSigningPublicKey)
        };
        return response(relaySuccess(request, { record }));
      }
      case "get":
        return response(relaySuccess(request, { record }));
      case "list":
        return response(relaySuccess(request, { records: { records: [record] } }));
      case "delete":
        return response(relaySuccess(request, {
          deletion: {
            databaseID,
            collection: record.collection,
            recordID: record.recordID,
            ...(record.ownerAccountID === undefined ? {} : {
              ownerAccountID: record.ownerAccountID
            }),
            deletedRevision: record.revision
          }
        }));
      default:
        throw new Error("Unexpected Noctweb data method.");
      }
    },
    authToken: "0123456789ab"
  });

  assert.deepEqual(await client.createNoctwebDatabase(create), { databaseID, created: true });
  const payload = await encryptNoctwebDataJSONV1({
    crypto: primitives,
    key: payloadKey,
    databaseID,
    collection: "products",
    recordID: "green-tea",
    revision: 1,
    value: { name: "Green Tea", price: 12 }
  });
  const put = await publisher.putRequest({
    collection: "products", recordID: "green-tea", payload, expectedRevision: 0
  });
  const stored = await client.putNoctwebRecord(put);
  assert.equal(await verifyNoctwebDataRecordProvenanceV1({
    crypto: primitives,
    origin: publisher.origin,
    record: stored
  }), true);
  assert.deepEqual(await decryptNoctwebDataJSONV1({ crypto: primitives, key: payloadKey, record: stored }), {
    name: "Green Tea",
    price: 12
  });
  assert.equal((await client.getNoctwebRecord(await publisher.getRequest({
    collection: "products",
    recordID: "green-tea"
  }))).recordID, "green-tea");
  assert.equal((await client.listNoctwebRecords(await publisher.listRequest({
    collection: "products",
    limit: 8
  }))).records.length, 1);
  assert.throws(
    () => validateNoctwebDataRecordListV1({ records: [stored, stored] }),
    /strictly ordered/u
  );
  assert.equal((await client.deleteNoctwebRecord(await publisher.deleteRequest({
    collection: "products",
    recordID: "green-tea",
    expectedRevision: 1
  }))).deletedRevision, 1);
  assert.deepEqual(calls.map(({ method }) => method), ["create", "put", "get", "list", "delete"]);
  assert.ok(calls.every(({ authToken }) => authToken === "0123456789ab"));
});

test("relay client rejects a structurally valid but request-substituted database receipt", async () => {
  const publisher = await NoctwebDataPublisherAuthorityV1.generate({
    relaySuffix: ".binding",
    siteLabel: "site"
  });
  const requestBody = await publisher.createDatabaseRequest([
    { name: "records", readPolicy: "public", writePolicy: "publisher" }
  ]);
  const client = new NoctweaveRelayClient("https://relay.example", {
    authToken: "0123456789ab",
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      return response(relaySuccess(request, {
        database: { databaseID: `nwdb1_${"00".repeat(32)}`, created: true }
      }));
    }
  });
  await assert.rejects(
    client.createNoctwebDatabase(requestBody),
    /does not match its request/u
  );
});

test("account authority uses a fresh per-database ML-DSA-65 key and signs owner records", {
  skip: !existsSync(wasmModulePath)
}, async () => {
  const oqsFactory = (await import(wasmModulePath)).default;
  const adapter = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const crypto = new NoctweaveCryptoSuite({ pqc: adapter, webcrypto: new WebCryptoPrimitives() });
  const databaseID = `nwdb1_${"ab".repeat(32)}`;
  const account = await NoctwebDataAccountAuthorityV1.generate({ crypto, databaseID });
  try {
    assert.match(account.accountID, /^nwa1_[0-9a-f]{64}$/u);
    const registration = await account.registrationRequest();
    assert.equal(
      adapter.verify(
        noctwebDataTranscriptsV1.registerAccount(registration),
        Buffer.from(registration.signature, "base64"),
        Buffer.from(registration.accountSigningPublicKey, "base64")
      ),
      true
    );
    assert.deepEqual(
      relayRequests.registerNoctwebAccount(registration).body,
      { request: registration }
    );

    const payloadKey = crypto.randomBytes(32);
    const encryptedPayload = await encryptNoctwebDataJSONV1({
      crypto,
      key: payloadKey,
      databaseID,
      collection: "carts",
      recordID: "current",
      ownerAccountID: account.accountID,
      revision: 1,
      value: { sku: "green-tea", quantity: 2 }
    });
    const put = await account.putRequest({
      collection: "carts",
      recordID: "current",
      ownerAccountID: account.accountID,
      payload: encryptedPayload
    });
    assert.equal(
      adapter.verify(
        noctwebDataTranscriptsV1.putRecord(put),
        Buffer.from(put.authorization.signature, "base64"),
        account.publicKey
      ),
      true
    );
    assert.equal(put.ownerAccountID, account.accountID);
    await assert.rejects(
      account.getRequest({ collection: "carts", recordID: "current" }),
      /exact owner namespace/u
    );
  } finally {
    account.destroy();
    assert.ok(account.secretKey.every((octet) => octet === 0));
  }
});

test("site data validation rejects oversized, malformed, and unknown record fields", async () => {
  const publisher = await NoctwebDataPublisherAuthorityV1.generate({
    relaySuffix: ".bounds",
    siteLabel: "site"
  });
  const primitives = new WebCryptoPrimitives();
  const databaseID = await publisher.databaseID();
  const payload = await encryptNoctwebDataJSONV1({
    crypto: primitives,
    key: primitives.randomBytes(32),
    databaseID,
    collection: "items",
    recordID: "one",
    revision: 1,
    value: { value: 1 }
  });
  const valid = await publisher.putRequest({
    collection: "items",
    recordID: "one",
    payload
  });
  assert.equal(validateNoctwebDataRecordPutRequestV1(valid), valid);
  assert.throws(
    () => validateNoctwebDataRecordPutRequestV1({ ...valid, unexpected: true }),
    /current protocol fields/u
  );
  assert.throws(
    () => validateNoctwebDataRecordPutRequestV1({
      ...valid,
      payload: base64(new TextEncoder().encode('{"plaintext":true}'))
    }),
    /encrypted payload/u
  );
  assert.throws(
    () => validateNoctwebDataRecordPutRequestV1({
      ...valid,
      payload: base64(new Uint8Array(64 * 1_024 + 1))
    }),
    /size bound/u
  );
  assert.throws(
    () => decodeNoctwebDataJSON(new TextEncoder().encode('{"value":1,"value":2}')),
    /Duplicate JSON field/u
  );
});

test("page capability exposes only origin-bound JSON operations", {
  skip: !existsSync(wasmModulePath)
}, async () => {
  const oqsFactory = (await import(wasmModulePath)).default;
  const adapter = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const crypto = new NoctweaveCryptoSuite({ pqc: adapter, webcrypto: new WebCryptoPrimitives() });
  const publisher = await NoctwebDataPublisherAuthorityV1.generate({
    crypto,
    relaySuffix: ".pages",
    siteLabel: "store"
  });
  const databaseID = await publisher.databaseID();
  const account = await NoctwebDataAccountAuthorityV1.generate({ crypto, databaseID });
  const payloadKey = crypto.randomBytes(32);
  let current;
  let lastGetRequest;
  let lastListRequest;
  const relay = {
    async putNoctwebRecord(request) {
      assert.equal(request.ownerAccountID, account.accountID);
      current = {
        databaseID,
        collection: request.collection,
        recordID: request.recordID,
        ownerAccountID: account.accountID,
        payload: request.payload,
        revision: 1,
        createdAt: "2026-08-13T10:00:00Z",
        updatedAt: "2026-08-13T10:00:00Z",
        provenance: provenanceFor(request, base64(account.publicKey))
      };
      return current;
    },
    async getNoctwebRecord(request) {
      lastGetRequest = request;
      return current;
    },
    async listNoctwebRecords(request) {
      lastListRequest = request;
      return { records: [current] };
    },
    async deleteNoctwebRecord(request) {
      return {
        databaseID,
        collection: request.collection,
        recordID: request.recordID,
        ownerAccountID: request.ownerAccountID,
        deletedRevision: request.expectedRevision
      };
    }
  };
  try {
    const capability = await NoctwebDataPageCapabilityV1.create({
      relay,
      account,
      origin: publisher.origin,
      encryptionKey: payloadKey,
      collections: [
        { name: "catalog", readPolicy: "public", writePolicy: "publisher" },
        { name: "carts", readPolicy: "public", writePolicy: "owner" },
        { name: "private", readPolicy: "owner", writePolicy: "owner" }
      ]
    });
    assert.equal(capability.accountID, account.accountID);
    assert.equal(capability.account, undefined);
    const stored = await capability.put("carts", "active", { sku: "tea" });
    assert.deepEqual(stored.value, { sku: "tea" });
    assert.deepEqual((await capability.get("carts", "active")).value, { sku: "tea" });
    assert.equal(lastGetRequest.ownerAccountID, account.accountID);
    assert.equal((await capability.list("carts")).records.length, 1);
    assert.equal(lastListRequest.ownerAccountID, account.accountID);
    assert.equal((await capability.delete("carts", "active", { expectedRevision: 1 })).deletedRevision, 1);

    const targetedPayload = await encryptNoctwebDataJSONV1({
      crypto,
      key: payloadKey,
      databaseID,
      collection: "catalog",
      recordID: "targeted",
      ownerAccountID: account.accountID,
      revision: 1,
      value: { message: "for this page account" }
    });
    const targetedPut = await publisher.putRequest({
      databaseID,
      collection: "catalog",
      recordID: "targeted",
      ownerAccountID: account.accountID,
      payload: targetedPayload
    });
    current = {
      databaseID,
      collection: "catalog",
      recordID: "targeted",
      ownerAccountID: account.accountID,
      payload: targetedPut.payload,
      revision: 1,
      createdAt: "2026-08-13T10:00:00Z",
      updatedAt: "2026-08-13T10:00:00Z",
      provenance: provenanceFor(targetedPut, publisher.origin.publisherSigningPublicKey)
    };
    assert.deepEqual(
      (await capability.get("catalog", "targeted", { ownerScope: "account" })).value,
      { message: "for this page account" }
    );
    assert.equal(lastGetRequest.ownerAccountID, account.accountID);
    assert.equal((await capability.list("catalog", { ownerScope: "account" })).records.length, 1);
    assert.equal(lastListRequest.ownerAccountID, account.accountID);
    await assert.rejects(
      capability.get("private", "active", { ownerScope: "global" }),
      /require the page account/u
    );
    await assert.rejects(
      capability.get("catalog", "targeted", { ownerScope: "other" }),
      /owner scope/u
    );
    await assert.rejects(
      capability.put("catalog", "tea", { price: 12 }),
      /read-only/u
    );
    await assert.rejects(
      capability.get("unknown", "record"),
      /not available/u
    );
    capability.destroy();
    capability.destroy();
    assert.throws(() => capability.accountID, /destroyed/u);
    await assert.rejects(capability.get("carts", "active"), /destroyed/u);
  } finally {
    account.destroy();
  }
});

test("record provenance rejects an origin publisher ID not derived from its key", async () => {
  const primitives = new WebCryptoPrimitives();
  const publisher = await NoctwebDataPublisherAuthorityV1.generate({
    crypto: primitives,
    relaySuffix: ".origin-binding",
    siteLabel: "site"
  });
  const databaseID = await publisher.databaseID();
  const request = await publisher.putRequest({
    databaseID,
    collection: "items",
    recordID: "one",
    payload: await encryptNoctwebDataJSONV1({
      crypto: primitives,
      key: new Uint8Array(32).fill(7),
      databaseID,
      collection: "items",
      recordID: "one",
      revision: 1,
      value: { value: 1 }
    })
  });
  const record = {
    databaseID,
    collection: request.collection,
    recordID: request.recordID,
    payload: request.payload,
    revision: 1,
    createdAt: "2026-08-13T10:00:00Z",
    updatedAt: "2026-08-13T10:00:00Z",
    provenance: provenanceFor(request, publisher.origin.publisherSigningPublicKey)
  };
  assert.equal(await verifyNoctwebDataRecordProvenanceV1({
    crypto: primitives,
    origin: {
      ...publisher.origin,
      publisherID: `nwpub1_${"00".repeat(32)}`
    },
    record
  }), false);
});

function relaySuccess(request, body) {
  return {
    requestID: request.requestID,
    module: request.module,
    version: request.version,
    method: request.method,
    status: "success",
    body,
    error: null
  };
}

function provenanceFor(request, actorSigningPublicKey) {
  return {
    actorKind: request.authorization.actorKind,
    actorID: request.authorization.actorID,
    actorSigningPublicKey,
    authorizationNonce: request.authorization.nonce,
    authorizationExpiresAt: request.authorization.expiresAt,
    idempotencyKey: request.idempotencyKey,
    expectedRevision: request.expectedRevision,
    signature: request.authorization.signature
  };
}

function response(value) {
  const body = JSON.stringify(value);
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(body).byteLength)
    }
  });
}
