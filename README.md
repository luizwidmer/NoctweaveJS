# NoctweaveJS

NoctweaveJS is the JavaScript implementation and reference browser client for Noctweave. It includes relay transport, bounded storage adapters, browser-safe cryptography, post-quantum liboqs WASM bindings, and a working encrypted direct-messaging application. The library targets browsers, workers, and Node-backed web apps.

Noctweave 1.0 is a clean protocol origin. Pre-1.0 persisted shapes and wire
paths are rejected rather than upgraded or retained as runtime fallbacks.

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
import {
  NoctweaveRelayClient,
  buildSyncMailboxRequest
} from "@noctweave/js-client";

const relay = new NoctweaveRelayClient("https://relay.example");

const health = await relay.health();
const info = await relay.info();

const request = await buildSyncMailboxRequest({
  inboxId: identity.inboxId,
  consumerId: identity.localEndpoint.mailboxRoutes[routeKey].consumerId,
  cursor: identity.localEndpoint.mailboxRoutes[routeKey].cursor,
  maxCount: 20,
  longPollTimeoutSeconds: 10,
  // Decrypt this route-only credential from application storage. It is not
  // the endpoint signing key.
  consumerSigningKey: routeSigningKey,
  pqc,
  crypto: webCrypto
});
const response = await relay.syncMailbox(request);
```

`localEndpoint` belongs only to the current disposable identity generation. It
is not a durable device record and is never authorized across generations.

Mailbox v2 uses an opaque route-scoped consumer ID and an independent
route-only ML-DSA key. Registration requires both the inbox authority proof
and route-key possession proof. Adding a later consumer also requires an
active consumer sponsor proof; an all-revoked mailbox requires the explicit
creation of a fresh inbox and identity generation rather than an account-style
recovery flow. Use `buildRegisterMailboxConsumerRequest`,
`buildCommitMailboxCursorRequest`, and `buildRevokeMailboxConsumerRequest` for
the other authenticated operations. Mailbox-v2 cursor synchronization is the
1.0 path; destructive inbox-wide fetch/acknowledgement is not a fallback.
Consumer IDs and relay-issued cursors are canonical JSON strings on the wire,
matching Swift `RawRepresentable` encoding; `{ rawValue: ... }` is not an
accepted request, response, or proof-transcript shape.
The browser identity flow requires the relay `info` response to advertise valid
`nw.core:2` and `nw.mailbox:2` capabilities before it creates an inbox.
Because JSON numbers cannot losslessly represent every Swift `UInt64`, the JS
validators fail closed if a relay sequence exceeds `Number.MAX_SAFE_INTEGER`.

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
This is a low-level relay-transport probe, not 1.0 mailbox-sync conformance.
The production `client/` uses mailbox v2.

## Certified Direct-v4

Fresh JavaScript identity generations and contacts use the same bounded
certified direct-v4 profile as the Swift implementation. A v4 contact offer
carries the current generation authority plus a signed endpoint-set checkpoint
and one preferred certified endpoint. The endpoint owns independent ML-DSA signing,
ML-KEM agreement, and signed-prekey material; active ratchet state is keyed by
that endpoint rather than shared across the identity generation.

Reusable signed contact codes are not the 1.0 pairing surface because repeated
use exposes correlatable generation, endpoint, inbox, and relay material. The
one-use, expiring, purpose-bound PQ rendezvous model avoids those fields in its
public offer; wiring that rendezvous into the client pairing flow remains
unfinished.

Each relationship derives different opaque endpoint handles and
relationship-blinded certificate references. Those values, both manifest
epochs, the logical event ID, and `nw.wire-payload.v2` are authenticated by the
direct-v4 context. The envelope sender field is the pairwise sender handle, not
a reusable endpoint or identity identifier. Application content is encoded as
an immutable `WirePayloadV2` event in an NPAD-v2 frame. Standard text and
attachment projections are strictly validated; unknown visible types preserve
their authenticated event and use the encrypted fallback, while unknown silent
types advance the ratchet without creating a chat bubble. The receiver verifies
the certified endpoint, endpoint-signed prekey package, signed prekey,
envelope signature, pairwise context, and payload before committing
ratchet progress. Signed-prekey freshness gates only contact/new-session
bootstrap. The stable generation-scoped endpoint authorization is separate
from the short-lived package. `prepareNativeDirectV4Identity` renews the
package during its two-day lead window without creating another endpoint or
using account/recovery authority. Up to four prior private prekeys remain
available only through their signed expiry for delayed bootstraps. Reopening
an endpoint validates package-publication integrity, and an
already established endpoint-bound ratchet is not destroyed by later prekey
publication expiry.

Pre-v4 contacts and NPAD-v1 direct frames are rejected. Direct-v4 never probes
an obsolete decoder or falls back to identity-key messaging. This first slice intentionally supports one preferred
endpoint per contact. Endpoint manifests therefore advertise
`maxActiveEndpoints: 1` even though local endpoint-set storage has a larger
structural bound. Direct-v4 negotiates and transcript-binds `nw.core:2`,
`nw.endpoints:2`, `nw.events:2`, and `nw.prekeys:2`; known optional modules are
disabled unless explicitly added by a wired caller and do not affect the
direct-v4 digest. Multi-endpoint fan-out and the closed JavaScript control-event
application path remain later work; extensible application content cannot be
used to invoke a security control.

The deterministic Swift/JavaScript binding, authenticated-data, and signature
transcript fixture is
`../NoctweaveDocumentation/test_vectors/direct_v4_pairwise_binding.json`.
The profile is pre-1.0 and has not received an external security audit.

## NoctweaveJS Client

The repository includes a complete minimal direct-messaging client, separate from the lower-level protocol demo. Run it with:

```sh
npm run dev:client
```

Open `http://127.0.0.1:5173/client/`. First run guides the user through:

1. acknowledging browser security boundaries;
2. creating an AES-256-GCM encrypted local profile;
3. verifying a client-facing HTTP/HTTPS/WS/WSS relay;
4. generating a disposable identity generation plus independent ML-DSA-65/ML-KEM-768 endpoint keys;
5. registering the inbox, generating a fresh ML-DSA mailbox credential for that relay/inbox route, binding its opaque consumer, and entering the client shell.

After setup, the client provides:

- a verified contact book with optional local aliases and contact deletion;
- signed contact-code reveal, copy, download, and file import;
- durable one-to-one encrypted conversations with unread badges and search;
- local echo backed by a durably stored logical event ID, client transaction
  ID, and exact retry envelope; safe skipped-message ratchet recovery;
- manual and automatic inbox sync while the page is visible;
- multiple verified relay records and live health checks;
- encrypted local storage, lock, and destructive local reset; live endpoint
  export/import is intentionally unavailable because it would clone active
  keys, ratchets, routes, and cursors.

Sending and receiving are storage transactions around cloned ratchet state. A
sender persists the advanced chain and exact signed ciphertext before relay
submission; an interrupted retry replays that ciphertext without re-encryption.
A receiver persists the decoded event and advanced receive chain before its
mailbox cursor can move. A storage failure restores the in-memory candidate so
the relay event remains retryable.

Complete local identity deletion uses a separate durable
`identityDeletionPending` lifecycle marker in addition to the exact inbox
retirement requests. The marker remains set after the last relay accepts
retirement, so a crash before local key deletion resumes by deleting the old
generation instead of reopening it. This browser action retires and deletes a
generation; it does not create a replacement and therefore is not an identity
burn.

Each endpoint's route cursor advances only after successful verification,
decryption, and durable local persistence. Replay receipts scope logical event
IDs to the authenticated relationship, so unrelated contacts cannot collide in
a global event namespace. Cursor commits are journaled locally and retried
without switching to an inbox-wide acknowledgement path. Envelopes interrupted
by local state, storage, or crypto-runtime failure remain
available for a later safe retry. Permanently invalid remote envelopes use a
bounded plaintext-free dead-letter receipt so they cannot block later ordered
events. A new 1.0 profile creates a fresh generation-bounded endpoint and a
separate route-specific consumer ID and signing key before relay binding. Active ratchet
state is never copied between endpoints, and endpoint signing keys are never
reused for fresh relay authentication. Each route also
persists its numeric
committed sequence beside the opaque cursor. The client rejects internal batch
gaps and any first event or empty `nextSequence` that does not continue exactly
from that durable sequence before it changes messages, ratchets, or cursor
state.

Test a real encrypted round trip against a running HTTP relay:

```sh
npm run smoke:client -- --relay http://127.0.0.1:9340
```

The smoke test creates two identities, verifies their pairing material, and
sends and decrypts in both directions. It is a narrow transport/crypto probe,
not the mailbox-v2 or rendezvous reference flow.

## Desktop Client

The same client is packaged as a small Electrobun desktop application using the
operating system WebView. Chromium/CEF is not bundled. The desktop shell keeps
the existing encrypted profile, contact book, post-quantum WASM, and messaging
code; only HTTP/HTTPS relay requests cross a bounded typed bridge to the Bun
process so browser CORS does not interfere. WebSocket and WSS connections remain
direct from the client view.

Install dependencies and run the desktop client:

```sh
cd NoctweaveJS
bun install --frozen-lockfile
bun run desktop:dev
```

### Build a native client from source

NoctweaveJS does not publish official desktop binaries. Build the client on the
operating system and architecture where it will run; Electrobun packages the
native target provided by the host machine.

Install Git and Bun 1.3.14, clone this repository, then run:

```sh
cd NoctweaveJS
bun install --frozen-lockfile
bun test
bun run typecheck:desktop
bun run desktop:icons
bun run desktop:build
```

The distributable is written to `NoctweaveJS/artifacts/`. Repeat this process on
macOS, Windows, or Linux for each platform you need. Electrobun currently
targets macOS 14+, Windows 11+, and Ubuntu 22.04+.

The package includes the Noctweave app icon for macOS, Windows, and Linux.
After changing `desktop/assets/app-icon.png`, regenerate native formats with
`bun run desktop:icons` before building.

Local builds are intentionally unsigned. Sign and notarize redistributed builds
with your own platform identity. You can record checksums with
`shasum -a 256 artifacts/*` on macOS/Linux or
`Get-FileHash .\artifacts\* -Algorithm SHA256` in Windows PowerShell.

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
This protocol demo is not the 1.0 reference flow. Use `client/` for the
endpoint-scoped mailbox-v2 path; rendezvous pairing integration remains open.

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
- Clearing site data permanently removes the live profile. Noctweave does not
  export identity keys, active ratchets, route authority, or cursors as a
  recoverable account backup. Only an explicitly created inert, read-only
  history projection may be transferred.
- Raw storage adapters are plaintext. Use `EncryptedNoctweaveStore` for sensitive state and keep its key outside the wrapped adapter.
- The WASM adapter validates key and ciphertext lengths before calling liboqs.
- Relay requests reject redirects and omit ambient credentials to reduce cross-origin credential leakage.
- WebCrypto remains responsible for AES-GCM, HKDF/SHA-256, and random bytes.
- A browser runtime cannot protect secrets from a compromised browser, extension, JavaScript supply chain, or OS account.
