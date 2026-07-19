# NoctweaveJS

NoctweaveJS is the JavaScript implementation of the Noctweave 1.0 protocol
base. It provides bounded HTTP/WebSocket relay access, post-quantum pairwise
contact establishment, direct-message cryptography, opaque route packets, and
encrypted local storage.

The protocol has no network-visible persona or reusable global identity. A
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

Encrypted attachment storage uses the exact `nw.blobs@1` request builders:

- `relayRequests.uploadAttachment`
- `relayRequests.fetchAttachment`

An upload requires a base64-encoded 32-byte `idempotencyKey`. Keep the complete
request unchanged for retries. While the relay retains an
`(attachmentId, chunkIndex)` coordinate, the same key and canonical body
returns the original chunk without refreshing TTL or rewriting blob storage;
any key, payload, or requested-TTL change is a non-retryable conflict. Use a
fresh attachment UUID for replacement content. The payload must already be
end-to-end encrypted; the relay request never carries plaintext or its content
key.

Route creation returns relay-authoritative state. Enqueue accepts independently
padded, end-to-end encrypted packets. Every synchronized packet carries a
monotonic sequence plus previous/current record digests, and every batch binds
its start, continuation, high watermark, and retention floor. The client
recomputes that chain and rejects omissions, reordering, substitution, and
cursor regression before commit. `LocalOpaqueReceiveRouteV2` persists the
opaque cursor together with `committedSequence` and `committedRecordDigest`;
the initial values are zero and cannot be inferred from a global identity.

`NoctweaveWebClient.syncOpaqueRoute(localReceiveRoute)` is the state-aware
entry point. Commit requires a real application persistence transaction:

```js
const synced = await client.syncOpaqueRoute(localReceiveRoute);
const committed = await client.commitOpaqueRoute({
  localReceiveRoute,
  batch: synced.batch,
  persistLocalState: async ({ localReceiveRoute: candidate, batch }) => {
    // Atomically store `candidate`, its reassembly snapshot, and every local
    // effect derived from `batch` as one encrypted application record before
    // this callback resolves.
    await encryptedStore.set(routeStateKey, {
      localReceiveRoute: candidate,
      appliedBatchDigest: batch.nextRecordDigest,
      effects: deriveApplicationEffects(batch)
    });
  }
});
localReceiveRoute = committed.localReceiveRoute;
```

The relay cursor commit happens only after that callback succeeds and is
best-effort; `committed.relayCommit.status === "deferred"` is safe to retry.
A boolean assertion cannot substitute for durable storage. The lower-level
`NoctweaveRelayClient` exposes exact relay submissions for integrations that
already own equivalent durable state handling. Committing a cursor advances
only that route's durable read position. The persisted route includes a bounded
1 MiB exact reassembly snapshot so fragmented bundles survive restarts; it is
not a plaintext receipt or a peer-read signal.

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

Relay operators can use the bounded `nw.federation@1` methods
`registerFederationNode` and `listFederationNodes`. Their exact directories
contain relay endpoints and operator metadata only; they carry no persona,
relationship, or global identity. Federation coordinates relay discovery and
policy. Ordinary user-message delivery remains direct to the endpoint selected
from the peer's relationship-encrypted route set and is never forwarded between
relays.

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
`RelationshipEndpointBindingV4`, and pairwise routes. There is no global
endpoint registry, generation log, checkpoint, or endpoint-revocation API.

`NoctweaveBrowserPairingService.preparePairingParticipant` registers the fresh
opaque receive route and retains all read, renewal, teardown, and payload
secrets locally. A peer introduction receives only the send authority and the
payload key needed for that relationship. The local persona label is never
copied into the introduction: callers may supply an explicit relationship
pseudonym, otherwise the service uses the fixed `Noctweave peer` label.

The browser service exposes independent crash-resumable participant flows:

1. The offerer calls `prepareOffererPairing`; the responder imports only its
   invitation and calls `prepareResponderPairing`.
2. Persist the returned `persona` after every call. Its pending record contains
   only that participant's private state and an exact encrypted outbox.
3. Publish each `outboundTransportFrames` entry without rebuilding it. After
   durable relay acceptance, remove it with `acknowledgePairingOutbound`.
4. Feed received rendezvous frames to `processPairingFrame`. After a restart,
   call `resumePairing` and retry the unchanged outbox.
5. Once mutual confirmation is complete, call `finalizePairing`, persist the
   returned relationship, and submit its `rendezvousDeletionRequests`.
6. If the flow is abandoned, call `cancelPairing` and submit the same bounded
   lane-deletion requests.

The checked-in browser shell performs this pump for either role, persists every
returned participant state before continuing, resumes pending work after
unlock/restart, and removes terminal pending state only after lane deletion is
prepared. Its UI exposes retry, finalize, and cancel without rendering pairing
IDs, bearer capabilities, private keys, or the peer's local persona label.

There is deliberately no `establishPairing` production helper: one process
must never receive both participants' private relationship state.

The browser and desktop shells store:

- a local persona label;
- independent pairwise relationships;
- one-use pending rendezvous state;
- encrypted protocol state through `EncryptedNoctweaveStore`.

They do not mint a persona-wide protocol key, provider identity, recovery
authority, or cross-contact route identifier.

## Durable pairwise messaging

`DurablePairwiseMessagingRuntimeV2` journals one relationship's encrypted
events, exact retry packets, ratchets, route/lifecycle state, and receive cursor. Its
rollback anchor is mandatory and relationship-local. Host-local policy is
stored in that same monotonic relationship record; `blocked` is terminal and
an older aggregate vault cannot restore it to accepted. This does not publish
policy or create protocol identity. Completed histories, quarantines, retired-route evidence,
and unused sessions compact without removing pending or in-flight dependencies.
Transient relay failure remains retryable after any number of attempts, and a
logical send is relay-accepted once at least one independently attempted route
accepts its complete bundle.

Ordinary browser storage cannot honestly provide the required monotonic CAS,
so the browser shell leaves durable messaging unavailable unless its embedding
host supplies `noctweaveRelationshipStateAnchorStoreFactory`. The Electrobun
client supplies that boundary on macOS:

- the encrypted local persona aggregate uses one fixed host application-state
  slot. Its random vault scope and salt come only from the authenticated slot,
  never a URL, profile name, or Web Storage selector. The slot is local storage
  coordination, not a persona or protocol identity;
- aggregate burn advances `active -> burning -> burned`. `burning` cannot be
  unlocked for ordinary use or replaced with a fresh scope; it can only decrypt
  into the terminal recovery path. Every relationship is then blocked and
  tombstoned before aggregate ciphertext is removed, and relay cleanup begins
  only afterward. Fresh post-burn initialization requires CAS from the
  authenticated burned generation;
- the WebView encrypts each relationship record with the unlocked vault key;
- Bun receives only the relationship ID that binds a fixed application scope and the
  `EncryptedNoctweaveStore` envelope, never message content, decrypted protocol
  state, WebView storage keys, URL profile names, or the vault key; changing
  those WebView details cannot mint a new burn scope, and this remains a local
  encryption boundary rather than anonymity from the desktop host;
- a fsynced filesystem journal uses hashed scope identifiers, stages the
  ciphertext and transition, and a fail-closed scope lock serializes competing
  host processes without race-prone stale-lock reclamation;
- macOS Keychain stores the OS-protected current generation, host-computed
  ciphertext digest, and permanent burn tombstone, and is the transaction
  commit point;
- startup recovery completes or aborts interrupted commits and destructive
  relationship burns; a valid older ciphertext cannot be paired with the
  newer Keychain generation, and restored files cannot resurrect a burned
  relationship scope.

This boundary assumes the user's macOS login Keychain is available and that
the operating system and logged-in user session are not compromised. A locked,
missing, reset, or conflicting Keychain item is an availability failure; the
client does not recreate authority over existing relationship files.

The macOS `security` command has no generic-password stdin form. The host never
passes a secret through it: the Keychain value contains only opaque hashed
scope metadata, generations, digests, erasure state, and a corruption
checksum. Encryption keys and plaintext remain in the WebView. The Keychain
item itself—not that checksum—is the independent rollback authority.

The current Linux and Windows Electrobun builds have no audited OS-backed
monotonic coordinator and therefore fail closed for durable messaging. A file,
Web Storage, or IndexedDB HMAC stored beside its ciphertext is not accepted as
rollback resistance.

Swift and JavaScript freeze the direct-v4 root/session KDF in
`NoctweaveDocumentation/test_vectors/direct_v4_root_session_v1.json`. The JS
test imports the implementation module directly; the derivation helper is
intentionally absent from the package's public index.

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
- Signed-prekey freshness gates only a new bootstrap at its authenticated send
  time. Established sessions remain valid after prekey expiry, and bounded
  retired private prekeys admit delayed pre-expiry bootstraps within the receive
  retention window.
- Relationship route updates, targeted route probes, and endpoint-prekey updates
  use independently signed, relationship-scoped control frames.
- Unknown application content may be retained. Unknown authenticated controls are
  quarantined, and malformed known controls fail closed without mutating state.

Noctweave relays route and retain ciphertext. They are not plaintext processors,
key escrow services, identity providers, or required notification providers.
