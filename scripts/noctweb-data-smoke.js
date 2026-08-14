import {
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  NoctwebDataAccountAuthorityV1,
  NoctwebDataPublisherAuthorityV1,
  WebCryptoPrimitives,
  decryptNoctwebDataJSONV1,
  encryptNoctwebDataJSONV1,
  verifyNoctwebDataRecordProvenanceV1
} from "../src/index.js";

const endpoint = process.argv[2] ?? "http://127.0.0.1:9340";
const suffix = process.argv[3] ?? ".testdata";
const authToken = process.env.NOCTWEAVE_RELAY_AUTH_TOKEN;
if (typeof authToken !== "string" || authToken.length < 12) {
  throw new Error("Set NOCTWEAVE_RELAY_AUTH_TOKEN to the relay publisher/access password.");
}
const oqsFactory = (await import(new URL("../wasm/dist/noctweave_oqs.js", import.meta.url))).default;
const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
const crypto = new NoctweaveCryptoSuite({ pqc, webcrypto: new WebCryptoPrimitives() });
const relay = new NoctweaveRelayClient(endpoint, { crypto, authToken });
const publisher = await NoctwebDataPublisherAuthorityV1.generate({
  crypto,
  relaySuffix: suffix,
  siteLabel: `smoke-${Date.now().toString(36)}`
});
const databaseID = await publisher.databaseID();
const payloadKey = crypto.randomBytes(32);
const database = await relay.createNoctwebDatabase(await publisher.createDatabaseRequest([
  { name: "catalog", readPolicy: "public", writePolicy: "publisher" },
  { name: "carts", readPolicy: "owner", writePolicy: "owner" }
]));
const account = await NoctwebDataAccountAuthorityV1.generate({ crypto, databaseID });

try {
  const accountReceipt = await relay.registerNoctwebAccount(await account.registrationRequest());
  const productPayload = await encryptNoctwebDataJSONV1({
    crypto,
    key: payloadKey,
    databaseID,
    collection: "catalog",
    recordID: "tea",
    revision: 1,
    value: { name: "Tea", price: 12 }
  });
  const product = await relay.putNoctwebRecord(await publisher.putRequest({
    collection: "catalog",
    recordID: "tea",
    payload: productPayload
  }));
  const publicCatalog = await relay.listNoctwebRecords({
    databaseID,
    collection: "catalog",
    limit: 8
  });
  const cartPayload = await encryptNoctwebDataJSONV1({
    crypto,
    key: payloadKey,
    databaseID,
    collection: "carts",
    recordID: "active",
    ownerAccountID: account.accountID,
    revision: 1,
    value: { sku: "tea", quantity: 2 }
  });
  const cart = await relay.putNoctwebRecord(await account.putRequest({
    collection: "carts",
    recordID: "active",
    ownerAccountID: account.accountID,
    payload: cartPayload
  }));
  const fetchedCart = await relay.getNoctwebRecord(await account.getRequest({
    collection: "carts",
    recordID: "active",
    ownerAccountID: account.accountID
  }));
  await relay.deleteNoctwebRecord(await account.deleteRequest({
    collection: "carts",
    recordID: "active",
    ownerAccountID: account.accountID,
    expectedRevision: cart.revision
  }));
  console.log(JSON.stringify({
    endpoint,
    databaseCreated: database.created,
    accountCreated: accountReceipt.created,
    catalogCount: publicCatalog.records.length,
    product: await decryptNoctwebDataJSONV1({ crypto, key: payloadKey, record: product }),
    cart: await decryptNoctwebDataJSONV1({ crypto, key: payloadKey, record: fetchedCart }),
    productProvenanceVerified: await verifyNoctwebDataRecordProvenanceV1({
      crypto,
      origin: publisher.origin,
      record: product
    }),
    cartProvenanceVerified: await verifyNoctwebDataRecordProvenanceV1({
      crypto,
      origin: publisher.origin,
      record: fetchedCart
    }),
    ownerScoped: fetchedCart.ownerAccountID === account.accountID,
    deleteConfirmed: true
  }, null, 2));
} finally {
  account.destroy();
}
