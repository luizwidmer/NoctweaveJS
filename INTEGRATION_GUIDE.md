# NoctweaveJS integration guide

[← Project overview](README.md)

Examples and commands use the repository root as their working directory.
The [security overview](README.md#security-and-privacy) describes the host,
storage, and transport requirements that apply throughout this guide.

[Hardware security-key unlock](#hardware-security-key-unlock) · [Experimental calls](#experimental-calls) · [Relay client](#relay-client) · [Noctweb site data](#noctweb-site-data) · [Pairwise contact establishment](#pairwise-contact-establishment) · [Durable pairwise messaging](#durable-pairwise-messaging) · [Storage](#storage)

## Hardware security-key unlock

In the client **Settings → Security keys**, confirm the current vault passphrase, name the key, and choose **Register key**. A compatible FIDO2 authenticator must support user verification and the PRF extension (or CTAP2 `hmac-secret` through the native SDK). Enrollment creates the credential and verifies a fresh assertion before storing an authenticated, encrypted passphrase wrapper. Up to eight keys can be registered. The hardware-key PIN is entered only in the desktop app; a browser presents its own trusted WebAuthn prompt.

Ordinary key unlock retains the vault passphrase as an explicit recovery method. On macOS desktop, **Keep key connected** additionally requires a registered USB key throughout the unlocked session. Enabling or disabling it requires the passphrase and a fresh key assertion. While it is enabled, the vault rejects passphrase-only unlock. Removal or a failed connection monitor locks the vault; reinsertion requires a new key verification. Add spare keys before enabling this option, or authenticate and disable it before changing the active key.

**Settings → Security keys → Lock-screen privacy** can hide the security-key controls on the waiting screen. The waiting passphrase form disappears and clears its input when the key flow starts; cancellation or key removal restores it. Older hidden-passphrase preferences no longer conceal the waiting form. Confirm the current vault passphrase and choose **Save lock-screen privacy**; an active connection requirement also needs a fresh key assertion. There is no hidden-method menu or icon action. On macOS desktop, connecting a USB key starts its normal authentication flow while the app is active and locked. Cancelling does not repeatedly prompt for the same attachment. In a browser, choose the ordinary **Unlock** action with the passphrase field empty to start WebAuthn; browsers do not expose passive USB attachment discovery here. Unlock errors are neutral. Visibility preferences never change encryption, passphrase recovery policy, or the optional connection requirement. OS/browser authentication prompts may identify the method once its ceremony starts.

The native Apple client's duress action plans are not part of this JavaScript vault. This vault remains passphrase encrypted: deleting a cached key would not make retained ciphertext unrecoverable because the passphrase can derive that key again.

This option controls app access. The existing vault is still passphrase encrypted, and this feature is not tamper-resistant licensing against someone who controls the host or modifies the app. Browsers, NFC, Linux desktop, and Windows desktop do not expose continuous presence in this implementation. Browser PRF support depends on both the browser and the authenticator; unsupported combinations report an error instead of falling back silently. Browser and desktop credentials have different RP scopes and must be enrolled separately.

The macOS build bundles `NoctweaveSecurityKeyBridge`, built from `../NoctweaveSecurityKeys` in the parent Noctweave checkout. Alternatively, set `NOCTWEAVE_SECURITY_KEYS_PACKAGE` to that package's absolute path. A full Xcode installation with Swift 6.1 or later is required. The package includes the official YubiKit Swift 1.3.0 library source and a documented read-only USB attachment accessor; it does not configure/reset your key or implement PIV/OTP.

NoctweaveJS remains Apache-2.0 licensed. The separately bundled helper is AGPL-3.0-or-later and includes YubiKit's Apache-2.0 license and notices. Distributions must also provide the corresponding helper source as required by its license. No key credential or unlock operation changes Noctweave protocol identities or messaging encryption.

## Experimental calls

Call setup requires the full `NoctweaveCryptoSuite`: WebCrypto supplies
AES-GCM/HKDF while the checked-in liboqs WASM adapter supplies ML-KEM-768.
Plain `WebCryptoPrimitives` intentionally cannot create or answer a call.

```js
const local = enableCallV1(createProtocolCapabilityManifest());
if (!supportsCallV1(local) || !supportsCallV1(peerManifest)) {
  throw new Error("Calls were not negotiated");
}

const pending = await createPendingCallOfferV1({
  crypto: suite,
  tracks: [{
    trackID: 1,
    mediaKind: "audio",
    direction: "sendReceive",
    codecs: [callCodecV1.opus]
  }],
  candidates: [transportCandidate]
});

const content = createCallSignalEncodedContentV1(pending.offerSignal);
// Send `content` as an ordinary direct-v4 encrypted application event.
```

The peer uses `answerCallOfferV1`; the initiator uses
`acceptCallAnswerV1`. `CallMediaSenderV1` and `CallMediaReceiverV1` then seal
already encoded codec frames into fixed buckets and enforce directional epoch
keys plus replay windows. A product must supply capture/playback and WebRTC,
datagram, or WebSocket transport adapters. The package does not claim that an
ordinary Noctweave message relay is a media relay.

The Swift and JavaScript implementations consume the same `call_v1.json`
canonical KDF/media vector. Full semantics are in the public
[Call Protocol v1](https://github.com/luizwidmer/Noctweave/blob/main/NoctweaveDocumentation/call_protocol_v1.md).

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

An operator may also expose the default-off `nw.pairing-lobby@1` shortcut:

- `acquirePairingLobbyV1`
- `listPairingLobbyV1`
- `releasePairingLobbyV1`

`PairingLobbyHostSessionV1` and `PairingLobbyRequesterSessionV1` generate fresh
ML-DSA/ML-KEM authorities, signed two-minute announcements, disposable
realtime routes, and encrypted approval responses. The browser shell exposes
**Be visible** and **Find people**, then feeds an accepted one-use link into
the unchanged rendezvous flow. Compare the displayed badge in person; it is a
short human check, not a relay identity. Listings contain no persona label and
the relay never receives the plaintext invitation.

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

Noctweave Net content hosting uses the typed `nw.net-host@1` client:

```js
const hosted = await relay.putNetHostObject({
  payload: signedCapsuleBytes,
  ttlSeconds: 86_400
}, {
  expectedHostSigningPublicKey
});

const fetched = await relay.getNetHostObject(hosted.objectID, {
  expectedHostSigningPublicKey
});
const present = await relay.hasNetHostObject(hosted.objectID);

await relay.releaseNetHostObject({
  objectID: hosted.objectID,
  releaseCapability: hosted.releaseCapability
});
```

The client derives the lowercase SHA-256 object ID from the exact bytes,
generates a 32-byte release capability and idempotency key, verifies the
returned content address and byte count, and verifies the relay's Ed25519
hosting receipt before reporting a stored or fetched object. Pass the
32-byte key advertised by the selected relay as `expectedHostSigningPublicKey`
to bind that receipt to the relay identity rather than merely verifying its
self-described key. The default bounded request budget carries the full 1 MiB
host-object profile after base64 and JSON expansion. Preserve
`releaseCapability` in protected
publisher state; the relay receives only its domain-separated digest until a
release request. A hosting receipt means **stored by this relay until the
stated bound**, not publisher identity, site safety, consensus finality, or
continued availability.

## Noctweb site data

`nw.noctweb-data@1` gives verified sites a bounded document database without
granting page code arbitrary SQL or relay credentials. Publisher tooling
creates the fixed collection schema and seeds publisher-owned records:

```js
import {
  NoctwebDataAccountAuthorityV1,
  NoctwebDataPageCapabilityV1,
  NoctwebDataPublisherAuthorityV1,
  NoctweaveRelayClient
} from "@noctweave/js-client";

const crypto = applicationNoctweaveCryptoSuite; // WebCrypto + liboqs WASM
const provisioningRelay = new NoctweaveRelayClient("https://relay.example", {
  crypto,
  authToken: operatorSuppliedPublisherPassword
});
const collections = [
  { name: "catalog", readPolicy: "public", writePolicy: "publisher" },
  { name: "carts", readPolicy: "owner", writePolicy: "owner" }
];
const publisher = await NoctwebDataPublisherAuthorityV1.generate({
  crypto,
  relaySuffix: ".atelier",
  siteLabel: "shop"
});
const database = await provisioningRelay.createNoctwebDatabase(
  await publisher.createDatabaseRequest(collections)
);

const account = await NoctwebDataAccountAuthorityV1.generate({
  crypto,
  databaseID: database.databaseID
});
await provisioningRelay.registerNoctwebAccount(
  await account.registrationRequest()
);
const relay = new NoctweaveRelayClient("https://relay.example", { crypto });
const encryptionKey = crypto.randomBytes(32); // persist separately from relay state
const data = await NoctwebDataPageCapabilityV1.create({
  relay,
  account,
  origin: publisher.origin,
  encryptionKey,
  collections
});
await data.put("carts", "active", { sku: "tea", quantity: 2 });
```

The Browser host must persist the account key pair in encrypted,
rollback-aware state and inject only the resulting origin-bound capability as
`window.noctweb.data`. Hosted JavaScript never receives the authority object,
payload key, or operator password. Database creation is a separately
configured, default-off relay capability. Creation and account registration
require the publisher/access password; record operations do not. Every record
payload is canonical AES-256-GCM ciphertext and every returned revision is
verified against its retained publisher or ML-DSA account provenance before
decryption.
For public collections, `get` and `list` accept `ownerScope: "account"` for
publisher-written records targeted to the current page account or
`ownerScope: "global"` for the unowned namespace. The default remains global
for publisher-only collections and account-scoped for visitor-writable ones;
the page capability never permits an arbitrary account identifier.
Call `destroy()` on each injected page data capability when its document is
revoked or navigated away; this overwrites the capability's copied payload key
and permanently disables that object. Relay timestamps are observations only,
not author-signed freshness evidence.
Use `npm run smoke:noctweb-data -- https://relay.example .atelier` for a live
publisher/account CRUD check after setting `NOCTWEAVE_RELAY_AUTH_TOKEN`.
Exact policies, limits, and metadata exposure are documented in the
[service specification](https://github.com/luizwidmer/Noctweave/blob/main/NoctweaveDocumentation/noctweb_data_service_v1.md).

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

Against a relay started with realtime routes, rendezvous, and the explicit
pairing-lobby switch, exercise a real two-client ML-KEM/ML-DSA approval and
encrypted one-use-link transfer:

```sh
npm run smoke:pairing-lobby -- --relay http://127.0.0.1:9340
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
prepared. It checks the invitation's encoded relay before acceptance, polls an
active rendezvous once per second, and automatically finalizes a mutually
verified relationship. Its UI exposes share, copy, paste-and-pair, retry, and
cancel actions without rendering pairing IDs, bearer capabilities, private
keys, or the peer's local persona label. Raw invitation text is an advanced
fallback rather than the primary workflow.

When the relay advertises `nw.pairing-lobby@1`, the same screen can discover a
currently visible peer by badge and request explicit approval. The shortcut is
hidden behind capability discovery and falls back to the existing QR, share,
file, and paste paths when the operator leaves the module disabled.

Group access requests and welcome packages use bounded `.noctgroup` files by
default. The browser validates the exact artifact prefix and UTF-8 payload
before importing it. Web Share is used only after an explicit user action;
otherwise the package is downloaded locally. Raw clipboard exchange remains a
visible fallback because clipboard retention is controlled by the operating
system.

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
  `EncryptedNoctweaveStore` envelope during normal operation, never message
  content, decrypted protocol state, WebView storage keys, URL profile names,
  or the vault key; changing those WebView details cannot mint a new burn scope,
  and this remains a local encryption boundary rather than anonymity from the
  desktop host;
- a user-approved attachment export is the sole deliberate plaintext exception:
  the WebView first requests a native destination-folder chooser, then a one-use,
  short-lived capability carries at most 3 MiB to Bun; Bun rechecks the
  authenticated byte count and SHA-256, refuses overwrites and symlinks, writes
  the requested local file with mode `0600`, and never logs its content;
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
`test/fixtures/protocol/direct_v4_root_session_v1.json`. The JS
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
