import {
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  NoctweaveRelayClient,
  NoctwebDataAccountAuthorityV1,
  NoctwebDataPublisherAuthorityV1,
  WebCryptoPrimitives,
  decodeNoctwebDataJSON
} from "../src/index.js";

const endpoint = process.argv[2] ?? "http://127.0.0.1:9340";
const suffix = process.argv[3] ?? ".testdata";
const oqsFactory = (await import(new URL("../wasm/dist/noctweave_oqs.js", import.meta.url))).default;
const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
const crypto = new NoctweaveCryptoSuite({ pqc, webcrypto: new WebCryptoPrimitives() });
const relay = new NoctweaveRelayClient(endpoint, { crypto });
const publisher = await NoctwebDataPublisherAuthorityV1.generate({
  crypto,
  relaySuffix: suffix,
  siteLabel: `smoke-${Date.now().toString(36)}`
});
const databaseID = await publisher.databaseID();
const database = await relay.createNoctwebDatabase(await publisher.createDatabaseRequest([
  { name: "catalog", readPolicy: "public", writePolicy: "publisher" },
  { name: "carts", readPolicy: "owner", writePolicy: "owner" }
]));
const account = await NoctwebDataAccountAuthorityV1.generate({ crypto, databaseID });

try {
  const accountReceipt = await relay.registerNoctwebAccount(await account.registrationRequest());
  const product = await relay.putNoctwebRecord(await publisher.putRequest({
    collection: "catalog",
    recordID: "tea",
    payload: { name: "Tea", price: 12 }
  }));
  const publicCatalog = await relay.listNoctwebRecords({
    databaseID,
    collection: "catalog",
    limit: 10
  });
  const cart = await relay.putNoctwebRecord(await account.putRequest({
    collection: "carts",
    recordID: "active",
    ownerAccountID: account.accountID,
    payload: { sku: "tea", quantity: 2 }
  }));
  const fetchedCart = await relay.getNoctwebRecord(await account.getRequest({
    collection: "carts",
    recordID: "active"
  }));
  await relay.deleteNoctwebRecord(await account.deleteRequest({
    collection: "carts",
    recordID: "active",
    expectedRevision: cart.revision
  }));
  console.log(JSON.stringify({
    endpoint,
    databaseCreated: database.created,
    accountCreated: accountReceipt.created,
    catalogCount: publicCatalog.records.length,
    product: decodeNoctwebDataJSON(Buffer.from(product.payload, "base64")),
    cart: decodeNoctwebDataJSON(Buffer.from(fetchedCart.payload, "base64")),
    ownerScoped: fetchedCart.ownerAccountID === account.accountID,
    deleteConfirmed: true
  }, null, 2));
} finally {
  account.destroy();
}
