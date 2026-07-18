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

Every relay operation uses one exact correlated envelope:

```text
request:  requestID, module, version, method, body, authToken
response: requestID, module, version, method, status, body, error
```

There is no alternate health endpoint, tagged legacy body, or uncorrelated
response form. Relationship delivery uses opaque-route v2:

- `createOpaqueRoute`
- `renewOpaqueRoute`
- `teardownOpaqueRoute`
- `enqueueOpaqueRoute`
- `syncOpaqueRoute`
- `commitOpaqueRoute`

One-use contact rendezvous uses the separate identity-blind
`nw.rendezvous-transport@2` surface:

- `registerRendezvousTransportV2`
- `appendRendezvousTransportV2`
- `syncRendezvousTransportV2`
- `deleteRendezvousTransportV2`

Route creation returns relay-authoritative state. Enqueue accepts independently
padded, end-to-end encrypted packets. Every synchronized packet carries a
monotonic sequence plus previous/current record digests, and every batch binds
its start, continuation, high watermark, and retention floor. The client
recomputes that chain and rejects omissions, reordering, substitution, and
cursor regression before commit. `LocalOpaqueReceiveRouteV2` persists the
opaque cursor together with `committedSequence` and `committedRecordDigest`;
the initial values are zero and cannot be inferred from a global identity.

`NoctweaveWebClient.syncOpaqueRoute(localReceiveRoute)` is the state-aware
entry point. After the application has durably processed the returned packets,
`commitOpaqueRoute({ localReceiveRoute, batch, durablyProcessed: true })`
returns the advanced local route record. The lower-level
`NoctweaveRelayClient` exposes exact relay submissions for integrations that
already own equivalent durable state handling. Committing a cursor advances
only that route's durable read position; it is not a plaintext receipt or a
peer-read signal.

```js
import {
  NoctweaveRelayClient,
  WebCryptoPrimitives,
  createOpaqueRouteClientCapabilityMaterialV2,
  createOpaqueRouteIdempotencyKeyV2,
  createOpaqueRouteLeaseV2,
  createOpaqueRoutePolicyV2,
  createOpaqueRouteProofNonceV2,
  createRendezvousRelayAdapterV2,
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
const createRequest = await makeOpaqueRouteCreateRequestV2({
  crypto,
  capabilities,
  lease,
  idempotencyKey: await createOpaqueRouteIdempotencyKeyV2(crypto),
  nonce: await createOpaqueRouteProofNonceV2(crypto)
});

const created = await relay.createOpaqueRoute({
  request: createRequest,
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

console.log(created.status, batch.hasMore);
```

`createRendezvousRelayAdapterV2({ crypto, offer })` deterministically derives
one route capability and two directional lanes from the invitation's one-use
transport capability. Publish, read, and delete authorities are independent;
the relay receives no relationship key, endpoint binding, or contact
identifier. The adapter wraps both the PQ open and encrypted session frames in
authenticated outer buckets of 4096, 16384, 65536, or 131072 bytes.

```js
const transport = await createRendezvousRelayAdapterV2({ crypto, offer });
await relay.registerRendezvousTransportV2(transport.registrationRequest);

const outbound = await transport.sealOpen({ open });
await relay.appendRendezvousTransportV2(outbound);

const incoming = await relay.syncRendezvousTransportV2(
  transport.syncRequest({ receivingAs: "offerer" })
);
for (const frame of incoming.frames) {
  await transport.open({ frame, direction: "responderToOfferer" });
}

for (const request of transport.deletionRequests()) {
  await relay.deleteRendezvousTransportV2(request);
}
```

The application deletes both temporary lanes when pairing finishes or is
abandoned. Registration is bounded to ten minutes; each lane accepts at most
32 frames and 2 MiB of fixed-bucket ciphertext.

`send()` is the bounded transport primitive. It accepts only the exact current
module/version/method envelope and rejects any other field set before network
I/O.

Run a complete create/enqueue/sync/commit/teardown probe against a local relay:

```sh
npm run smoke:relay -- --relay http://127.0.0.1:9340
```

## Pairwise contact establishment

`createContactPairingInvitationV2` creates a short-lived, one-use PQ
rendezvous. The invitation discloses no relationship identity or receive
route. After the encrypted rendezvous is established, both sides exchange
fresh relationship-scoped introductions and mutually confirm the transcript.
Each introduction carries one disposable relationship authority, one
`RelationshipEndpointBindingV4`, and pairwise routes. There is no endpoint
set, device registry, generation log, checkpoint, or endpoint-revocation API.

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
- Endpoint manifests advertise exact module and application-content major-version
  capabilities; two-field manifests without `contentTypes` are invalid.
- Direct-v4 authenticates the shared content families in its session transcript
  and refuses outbound application or receipt types the peer did not advertise.
- Relationship route updates, targeted route probes, and endpoint-prekey updates
  use independently signed, relationship-scoped control frames.
- Unknown application content may be retained. Unknown authenticated controls are
  quarantined, and malformed known controls fail closed without mutating state.

Noctweave relays route and retain ciphertext. They are not plaintext processors,
key escrow services, identity providers, or required notification providers.
