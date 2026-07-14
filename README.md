# NoctweaveJS

NoctweaveJS is the JavaScript implementation and reference browser client for Noctweave. It includes relay transport, bounded storage adapters, browser-safe cryptography, post-quantum liboqs WASM bindings, and a working encrypted direct-messaging application. The library targets browsers, workers, and Node-backed web apps.

The WASM surface is intentionally narrow: ML-KEM-768 for KEM and ML-DSA-65 for signatures. WebCrypto provides AES-256-GCM, HKDF, HMAC, hashing, and secure randomness.

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

Production applications can supply deployment policy without changing protocol
invariants:

```js
const relay = new NoctweaveRelayClient("https://relay.example", {
  policy: {
    timeoutMs: 12_000,
    defaultTCPPort: 9339,
    maxRequestBytes: 1024 * 1024,
    maxResponseBytes: 2 * 1024 * 1024
  }
});
```

These values remain constrained by exported absolute ceilings in
`relayClientPolicyLimits`. Cryptographic key sizes, signature sizes, padding
buckets, authentication bounds, and wire-format maxima are protocol/security
invariants and are deliberately not configurable.

Supported web transports are `http`, `https`, `ws`, and `wss`. Raw TCP relays are intentionally not supported in browser JavaScript.

For a quick live relay smoke test:

```sh
npm run smoke:relay -- --relay http://127.0.0.1:9339
```

This verifies HTTP relay connectivity, creates a WASM-signed inbox registration, submits an encoded envelope, fetches the inbox, and checks that the encoded payload round-trips.

## NoctweaveJS Client

The repository includes a complete minimal direct-messaging client, separate from the lower-level protocol demo. Run it with:

```sh
npm run dev:client
```

Open `http://127.0.0.1:5173/client/`. First run guides the user through:

1. acknowledging browser security boundaries;
2. creating an AES-256-GCM encrypted local profile;
3. verifying a client-facing HTTP/HTTPS/WS/WSS relay;
4. generating ML-DSA-65 signing and access keys plus an ML-KEM-768 agreement key;
5. registering the inbox and entering the client shell.

After setup, the client provides:

- a verified contact book with optional local aliases and contact deletion;
- signed contact-code reveal, copy, download, and file import;
- durable one-to-one encrypted conversations with unread badges and search;
- send retry state and safe skipped-message ratchet recovery;
- manual and automatic inbox sync while the page is visible;
- multiple verified relay records and live health checks;
- encrypted profile export/import, lock, and local reset.

Fetched envelopes are acknowledged only after successful verification,
decryption, and local persistence. Failed or unknown envelopes remain available
for a later safe retry.

Test a real encrypted round trip against a running HTTP relay:

```sh
npm run smoke:client -- --relay http://127.0.0.1:9340
```

The smoke test creates two identities, verifies their pairing material, sends
and decrypts in both directions, and acknowledges both messages.

## Desktop Client

The same client is packaged as a small Electrobun desktop application using the
operating system WebView. Chromium/CEF is not bundled. The desktop shell keeps
the existing encrypted profile, contact book, post-quantum WASM, and messaging
code; only HTTP/HTTPS relay requests cross a bounded typed bridge to the Bun
process so browser CORS does not interfere. WebSocket and WSS connections remain
direct from the client view.

Install dependencies and run a development build:

```sh
cd NoctweaveJS
bun install
bun run desktop:dev
```

Create the distributable for the current operating system:

```sh
bun run desktop:build
```

The package includes the Noctweave app icon for macOS, Windows, and Linux.
After changing `desktop/assets/app-icon.png`, regenerate native formats with
`bun run desktop:icons` before building.

Electrobun supports macOS, Windows, and Linux. Build each release on its target
operating system so native signing and packaging can be applied there. Local
builds are intentionally unsigned; release builds must use the platform's code
signing and notarization process before distribution.

### Native build workflow

`.github/workflows/noctweavejs-desktop-release.yml` builds the client on native
macOS ARM64, Windows x64, and Ubuntu x64 runners. It runs only when manually
dispatched or when a `v*` tag is pushed. Manual runs retain downloadable workflow
artifacts for 14 days. Tagged runs additionally create or update a **draft**
GitHub Release with SHA-256 manifests and GitHub provenance attestations.

The workflow does not publish a release automatically and does not currently
sign the applications. Configure Apple signing/notarization and Windows
Authenticode credentials before treating these artifacts as distribution
builds.

### Desktop boundary

- The Electrobun package uses the operating system WebView and does not expose
  the profile to ordinary browser extensions.
- HTTP/HTTPS relay requests cross a bounded native bridge; WS/WSS remains in the
  WebView. Raw TCP is not enabled by this client.
- Profile contents remain AES-256-GCM encrypted at rest. Plaintext necessarily
  exists while the profile is unlocked and in use.
- Install only signed releases from a trusted source. A compromised OS account,
  modified binary, platform WebView, or JavaScript dependency can read unlocked
  data. Local development builds are unsigned and are not distribution builds.

## Browser Protocol Demo

Run a local browser client:

```sh
npm run dev:browser-client
```

Open `http://127.0.0.1:5173/examples/browser-client/`. The demo generates WASM ML-DSA/ML-KEM keys in the browser, registers a test inbox, pairs by copy/pasting contact codes, sends ML-KEM/AES-GCM encrypted messages, verifies ML-DSA envelope signatures, and fetches/decrypts messages from the relay. A local Node proxy is used only to avoid browser CORS restrictions while testing relays.

The protocol demo includes a compact address book, manual and automatic fetch controls, encrypted local profile storage, and diagnostics intended for interoperability work. The `client/` application should be used for normal browser-client evaluation. Neither surface has received an independent security audit.

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

### Browser boundary

- Relay responses and stored records are untrusted until your application verifies them.
- Local browser storage is not secure against a compromised browser profile, extension, or OS account.
- Clearing site data removes the profile; export an encrypted backup first if it
  must be recoverable.
- Raw storage adapters are plaintext. Use `EncryptedNoctweaveStore` for sensitive state and keep its key outside the wrapped adapter.
- The WASM adapter validates key and ciphertext lengths before calling liboqs.
- Relay requests reject redirects and omit ambient credentials to reduce cross-origin credential leakage.
- WebCrypto remains responsible for AES-GCM, HKDF/SHA-256, and random bytes.
- A browser runtime cannot protect secrets from a compromised browser, extension, JavaScript supply chain, or OS account.
