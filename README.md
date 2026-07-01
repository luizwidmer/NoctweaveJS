# NoctweaveJS

NoctweaveJS is a small JavaScript client for simple web applications that need to talk to Noctweave relays and persist client-side state. It targets browsers, workers, and Node-backed web apps.

This package covers relay transport, storage, browser-safe symmetric primitives, and an optional liboqs WASM adapter for Noctweave's post-quantum public-key operations. The WASM surface is intentionally narrow: ML-KEM-768 for KEM and ML-DSA-65 for signatures.

## Install

```sh
npm install @noctweave/js-client
```

For local repository development:

```sh
cd NoctweaveJS
npm test
```

Build the optional liboqs WASM module after installing Emscripten:

```sh
source ~/emsdk/emsdk_env.sh
npm run build:oqs-wasm
```

## Relay Client

```js
import { NoctweaveRelayClient, relayRequests } from "@noctweave/js-client";

const relay = new NoctweaveRelayClient("https://relay.example");

const health = await relay.health();
const info = await relay.info();

const response = await relay.send(
  relayRequests.fetch({
    inboxId: "nw1...",
    routingToken: "nw1...",
    maxCount: 20,
    longPollTimeoutSeconds: 10,
    accessProof: signedProof
  })
);
```

Supported web transports are `http`, `https`, `ws`, and `wss`. Raw TCP relays are intentionally not supported in browser JavaScript.

For a quick live relay smoke test:

```sh
npm run smoke:relay -- --relay http://127.0.0.1:9339
```

This verifies HTTP relay connectivity, creates a WASM-signed inbox registration, submits an encoded envelope, fetches the inbox, and checks that the encoded payload round-trips. It is a transport/mailbox/proof test; it does not yet create a full encrypted chat session visible inside the native app.

## Browser Demo

Run a local browser client:

```sh
npm run dev:browser-client
```

Open `http://127.0.0.1:5173/examples/browser-client/`. The demo generates WASM ML-DSA/ML-KEM keys in the browser, registers a test inbox, pairs by copy/pasting contact codes, sends ML-KEM/AES-GCM encrypted messages, verifies ML-DSA envelope signatures, and fetches/decrypts messages from the relay. A local Node proxy is used only to avoid browser CORS restrictions while testing relays.

To test two browser clients on one machine, open:

- `http://127.0.0.1:5173/examples/browser-client/?profile=alice`
- `http://127.0.0.1:5173/examples/browser-client/?profile=bob`

Create an inbox in each profile, copy Alice's contact code into Bob and Bob's into Alice, then send from one profile and press `Fetch Messages` on the other.

## Storage Choices

Browser `localStorage`:

```js
import { BrowserLocalStorageStore, NoctweaveStateRepository } from "@noctweave/js-client";

const store = new BrowserLocalStorageStore({ namespace: "my-app:noctweave" });
const repo = new NoctweaveStateRepository(store);

await repo.save({ activeRelay: "https://relay.example" });
const state = await repo.load();
```

IndexedDB:

```js
import { IndexedDBNoctweaveStore } from "@noctweave/js-client";

const store = new IndexedDBNoctweaveStore({
  databaseName: "my-app",
  storeName: "noctweave"
});
```

Database adapter:

```js
import { DatabaseNoctweaveStore } from "@noctweave/js-client";

const store = new DatabaseNoctweaveStore({
  get: (key) => db.noctweaveState.findUnique({ where: { key } }),
  set: (key, value) => db.noctweaveState.upsert({
    where: { key },
    update: { value },
    create: { key, value }
  }),
  delete: (key) => db.noctweaveState.delete({ where: { key } }),
  clear: () => db.noctweaveState.deleteMany()
});
```

## Web Client Wrapper

```js
import { MemoryNoctweaveStore, NoctweaveWebClient } from "@noctweave/js-client";

const client = new NoctweaveWebClient({
  relay: "https://relay.example",
  store: new MemoryNoctweaveStore()
});

await client.saveState({ selectedRelay: "https://relay.example" });
await client.health();
```

## Crypto Suite

Use WebCrypto for symmetric operations and the bundled liboqs WASM adapter for post-quantum keys:

```js
import oqsFactory from "./wasm/dist/noctweave_oqs.js";
import { NoctweaveCryptoSuite } from "@noctweave/js-client";

const cryptoSuite = await NoctweaveCryptoSuite.fromOQSWasmFactory(oqsFactory, {
  wasmOptions: {
    locateFile: (path) => `/assets/${path}`
  }
});

const signing = cryptoSuite.generateSigningKeypair();
const kem = cryptoSuite.generateKemKeypair();
const encapsulated = cryptoSuite.encapsulate(kem.publicKey);
const plaintextKey = await cryptoSuite.hkdfSha256({
  ikm: encapsulated.sharedSecret,
  info: "noctweave-message",
  length: 32
});
```

The native Swift core and the JS/WASM adapter use the same algorithm profile:

- KEM: `ML-KEM-768`, public key `1184`, secret key `2400`, ciphertext `1088`, shared secret `32`.
- Signatures: `ML-DSA-65`, public key `1952`, secret key `4032`, max signature `3309`.

## Security Notes

- Relay responses and stored records are untrusted until your application verifies them.
- Local browser storage is not secure against a compromised browser profile, extension, or OS account.
- Store only ciphertext or non-sensitive state unless an application-specific threat model accepts the risk.
- The WASM adapter validates key and ciphertext lengths before calling liboqs.
- WebCrypto remains responsible for AES-GCM, HKDF/SHA-256, and random bytes.
- A browser runtime cannot protect secrets from a compromised browser, extension, JavaScript supply chain, or OS account.
