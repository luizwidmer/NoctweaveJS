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
  encodeNoctwebDataJSON,
  noctwebDataAccountID,
  noctwebDataDatabaseID,
  noctwebDataPublisherID,
  noctwebDataTranscriptsV1,
  relayRequests,
  validateNoctwebDataRecordPutRequestV1
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
          revision: 1,
          createdAt: "2026-08-13T10:00:00Z",
          updatedAt: "2026-08-13T10:00:00Z"
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
            deletedRevision: record.revision
          }
        }));
      default:
        throw new Error("Unexpected Noctweb data method.");
      }
    }
  });

  assert.deepEqual(await client.createNoctwebDatabase(create), { databaseID, created: true });
  const put = await publisher.putRequest({
    collection: "products",
    recordID: "green-tea",
    payload: { name: "Green Tea", price: 12 },
    expectedRevision: 0
  });
  const stored = await client.putNoctwebRecord(put);
  assert.deepEqual(decodeNoctwebDataJSON(Buffer.from(stored.payload, "base64")), {
    name: "Green Tea",
    price: 12
  });
  assert.equal((await client.getNoctwebRecord(await publisher.getRequest({
    collection: "products",
    recordID: "green-tea"
  }))).recordID, "green-tea");
  assert.equal((await client.listNoctwebRecords(await publisher.listRequest({
    collection: "products",
    limit: 10
  }))).records.length, 1);
  assert.equal((await client.deleteNoctwebRecord(await publisher.deleteRequest({
    collection: "products",
    recordID: "green-tea",
    expectedRevision: 1
  }))).deletedRevision, 1);
  assert.deepEqual(calls.map(({ method }) => method), ["create", "put", "get", "list", "delete"]);
  assert.ok(calls.every(({ authToken }) => authToken === null));
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

    const put = await account.putRequest({
      collection: "carts",
      recordID: "current",
      ownerAccountID: account.accountID,
      payload: { sku: "green-tea", quantity: 2 }
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
  const valid = await publisher.putRequest({
    collection: "items",
    recordID: "one",
    payload: encodeNoctwebDataJSON({ value: 1 })
  });
  assert.equal(validateNoctwebDataRecordPutRequestV1(valid), valid);
  assert.throws(
    () => validateNoctwebDataRecordPutRequestV1({ ...valid, unexpected: true }),
    /current protocol fields/u
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
  const databaseID = `nwdb1_${"cd".repeat(32)}`;
  const account = await NoctwebDataAccountAuthorityV1.generate({ crypto, databaseID });
  let current;
  const relay = {
    async registerNoctwebAccount(request) {
      assert.equal(request.accountID, account.accountID);
      return { databaseID, accountID: account.accountID, created: true };
    },
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
        updatedAt: "2026-08-13T10:00:00Z"
      };
      return current;
    },
    async getNoctwebRecord() { return current; },
    async listNoctwebRecords() { return { records: [current] }; },
    async deleteNoctwebRecord(request) {
      return {
        databaseID,
        collection: request.collection,
        recordID: request.recordID,
        deletedRevision: request.expectedRevision
      };
    }
  };
  try {
    const capability = await NoctwebDataPageCapabilityV1.create({
      relay,
      account,
      collections: [
        { name: "catalog", readPolicy: "public", writePolicy: "publisher" },
        { name: "carts", readPolicy: "owner", writePolicy: "owner" }
      ]
    });
    assert.equal(capability.accountID, account.accountID);
    assert.equal(capability.account, undefined);
    const stored = await capability.put("carts", "active", { sku: "tea" });
    assert.deepEqual(stored.value, { sku: "tea" });
    assert.deepEqual((await capability.get("carts", "active")).value, { sku: "tea" });
    assert.equal((await capability.list("carts")).records.length, 1);
    assert.equal((await capability.delete("carts", "active", { expectedRevision: 1 })).deletedRevision, 1);
    await assert.rejects(
      capability.put("catalog", "tea", { price: 12 }),
      /read-only/u
    );
    await assert.rejects(
      capability.get("unknown", "record"),
      /not available/u
    );
  } finally {
    account.destroy();
  }
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
