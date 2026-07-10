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

## NoctweaveJS Client

The production-oriented browser client is separate from the protocol demo. Run it with:

```sh
npm run dev:client
```

Open `http://127.0.0.1:5173/client/`. First run guides the user through:

1. acknowledging browser security boundaries;
2. creating an AES-256-GCM encrypted local profile;
3. verifying a client-facing HTTP/HTTPS/WS/WSS relay;
4. generating ML-DSA-65 signing and access keys plus an ML-KEM-768 agreement key;
5. registering the inbox and entering the client shell.

The client currently exposes identity, signed contact-code, relay, lock, and reset surfaces. Contacts and full direct-chat UX are intentionally the next client slice; use the browser demo for current end-to-end messaging interoperability tests.

## Browser Protocol Demo

Run a local browser client:

```sh
npm run dev:browser-client
```

Open `http://127.0.0.1:5173/examples/browser-client/`. The demo generates WASM ML-DSA/ML-KEM keys in the browser, registers a test inbox, pairs by copy/pasting contact codes, sends ML-KEM/AES-GCM encrypted messages, verifies ML-DSA envelope signatures, and fetches/decrypts messages from the relay. A local Node proxy is used only to avoid browser CORS restrictions while testing relays.

The browser client includes a small address book, hidden-by-default contact code display, manual and automatic fetch controls, encrypted local profile storage, password-protected profile export/import, contact deletion, and a compact diagnostics log. It is still a development client and has not received an independent security audit.

To test two browser clients on one machine, open:

- `http://127.0.0.1:5173/examples/browser-client/?profile=alice`
- `http://127.0.0.1:5173/examples/browser-client/?profile=bob`

Create an inbox in each profile, copy Alice's contact code into Bob and Bob's into Alice, then send from one profile and press `Fetch` on the other or enable `Auto-fetch`.

## Storage Choices

Browser `localStorage` with encryption at the storage boundary:

```js
import {
  BrowserLocalStorageStore,
  EncryptedNoctweaveStore,
  NoctweaveStateRepository
} from "@noctweave/js-client";

const backend = new BrowserLocalStorageStore({ namespace: "my-app:noctweave" });
const applicationManagedKeyBytes = await loadApplicationKey(); // exactly 32 bytes
const store = new EncryptedNoctweaveStore(backend, {
  keyBytes: applicationManagedKeyBytes
});
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

`BrowserLocalStorageStore`, `IndexedDBNoctweaveStore`, and
`DatabaseNoctweaveStore` are bounded raw adapters; they do not encrypt values by
themselves. Wrap any adapter in `EncryptedNoctweaveStore` before persisting
identity, contact, conversation, or key material. Supply either a 32-byte key
managed outside that adapter, or a strong passphrase with a unique persisted
salt and an explicit supported PBKDF2 iteration count.

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
- Raw storage adapters are plaintext. Use `EncryptedNoctweaveStore` for sensitive state and keep its key outside the wrapped adapter.
- The WASM adapter validates key and ciphertext lengths before calling liboqs.
- Relay requests reject redirects and omit ambient credentials to reduce cross-origin credential leakage.
- WebCrypto remains responsible for AES-GCM, HKDF/SHA-256, and random bytes.
- A browser runtime cannot protect secrets from a compromised browser, extension, JavaScript supply chain, or OS account.
