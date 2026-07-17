# NoctweaveJS

NoctweaveJS is the JavaScript implementation of the Noctweave 1.0 protocol
base. It provides bounded HTTP/WebSocket relay access, post-quantum pairwise
contact establishment, direct-message cryptography, opaque route packets, and
encrypted local storage.

The protocol has no network-visible persona or reusable account identity. A
persona is only a local UI/storage label. Every contact pairing creates fresh
ML-DSA, ML-KEM, endpoint, prekey, payload-key, and route material scoped to
that one relationship.

## Install and verify

```sh
npm install
npm test
npm run typecheck:desktop
```

The checked-in liboqs WASM artifact is the reference post-quantum runtime. To
rebuild it, provide an Emscripten toolchain and run:

```sh
npm run build:oqs-wasm
```

## Relay client

The current relay delivery surface is opaque-route v2:

- `createOpaqueRoute`
- `renewOpaqueRoute`
- `teardownOpaqueRoute`
- `enqueueOpaqueRoute`
- `syncOpaqueRoute`
- `commitOpaqueRoute`

Route creation returns relay-authoritative state. Enqueue accepts independently
padded, end-to-end encrypted packets. Synchronization returns an ordered batch
and opaque cursors. Committing a cursor advances only that route's durable read
position; it is not a plaintext receipt or a peer-read signal.

```js
import {
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  makeOpaqueRouteCreateRequestV2,
  makeOpaqueRouteSyncRequestV2,
  swiftISODate
} from "@noctweave/js-client";

const crypto = new WebCryptoPrimitives();
const relay = new NoctweaveRelayClient("https://relay.example", { crypto });
const capabilities = await createOpaqueRouteClientCapabilityMaterialV2(crypto);
const issuedAt = new Date();
const lease = createOpaqueRouteLeaseV2({
  issuedAt: swiftISODate(issuedAt),
  expiresAt: swiftISODate(new Date(issuedAt.getTime() + 60 * 60 * 1000)),
  policy: createOpaqueRoutePolicyV2({
    paddingBucket: 4096,
    retentionBucket: 3600,
    quotaBucket: 64
  })
});
const transition = await makeOpaqueRouteCreateRequestV2({
  crypto,
  capabilities,
  lease,
  idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
  nonce: await createOpaqueRouteProofNonceV2(crypto)
});

const created = await relay.createOpaqueRoute({
  transition,
  renewCapability: capabilities.renewCapability
});

const request = await makeOpaqueRouteSyncRequestV2({
  crypto,
  capabilities,
  limit: 64
});
const batch = await relay.syncOpaqueRoute({
  request,
  readCredential: capabilities.readCredential
});

console.log(created.opaqueRouteV2.status, batch.opaqueRouteSyncV2.hasMore);
```

`send()` is still available as the bounded transport primitive, but it accepts
only request kinds in the current JavaScript protocol surface and rejects
unknown or obsolete operation names before network I/O.

Run a complete create/enqueue/sync/commit/teardown probe against a local relay:

```sh
npm run smoke:relay -- --relay http://127.0.0.1:9340
```

## Pairwise contact establishment

`createContactPairingInvitationV2` creates a short-lived, one-use PQ
rendezvous. The invitation discloses no relationship identity or receive
route. After the encrypted rendezvous is established, both sides exchange
fresh relationship-scoped introductions and mutually confirm the transcript.

`NoctweaveBrowserPairingService.preparePairingParticipant` registers the fresh
opaque receive route and retains all read, renewal, teardown, and payload
secrets locally. A peer introduction receives only the send authority and the
payload key needed for that relationship. The local persona label is never
copied into the introduction: callers may supply an explicit relationship
pseudonym, otherwise the service uses the fixed `Noctweave peer` label.

The browser and desktop shells store:

- a local persona label;
- independent pairwise relationships;
- one-use pending rendezvous state;
- encrypted protocol state through `EncryptedNoctweaveStore`.

They do not mint a persona-wide protocol key, provider identity, recovery
authority, or cross-contact route identifier.

## Storage

Raw adapters (`MemoryNoctweaveStore`, `BrowserLocalStorageStore`,
`IndexedDBNoctweaveStore`, and `DatabaseNoctweaveStore`) store the values they
receive. Wrap sensitive state with `EncryptedNoctweaveStore` and keep its key
outside the same backing store.

```js
import {
  EncryptedNoctweaveStore,
  IndexedDBNoctweaveStore,
  NoctweaveStateRepository,
  WebCryptoPrimitives
} from "@noctweave/js-client";

const crypto = new WebCryptoPrimitives();
const encrypted = new EncryptedNoctweaveStore(
  new IndexedDBNoctweaveStore(),
  { key: crypto.randomBytes(32), crypto }
);
const repository = new NoctweaveStateRepository(encrypted);
```

## Transport and security boundaries

- Browser clients support explicit HTTP(S) and WebSocket(S) relay endpoints.
- Raw TCP endpoints fail explicitly in the browser client.
- Request and response byte ceilings are enforced before unbounded allocation.
- HTTP redirects, ambient credentials, referrers, and caching are disabled.
- Relay errors are classified without echoing response bodies or bearer data.
- Opaque route authority proofs are verified locally before submission.
- Route responses are exact-field decoded and bound to the initiating request.
- Unknown application content may be retained; unknown control semantics never
  mutate state.

Noctweave relays route and retain ciphertext. They are not plaintext processors,
key escrow services, identity providers, or required notification providers.
