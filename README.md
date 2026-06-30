# NoctweaveJS

NoctweaveJS is a small JavaScript client for simple web applications that need to talk to Noctweave relays and persist client-side state. It targets browsers, workers, and Node-backed web apps.

This package currently covers relay transport and storage. It does not yet implement the full post-quantum message/session engine in JavaScript; use it for diagnostics, inbox polling, web dashboards, or applications that provide their own audited crypto/WASM adapter.

## Install

```sh
npm install @noctweave/js-client
```

For local repository development:

```sh
cd NoctweaveJS
npm test
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

## Security Notes

- Relay responses and stored records are untrusted until your application verifies them.
- Local browser storage is not secure against a compromised browser profile, extension, or OS account.
- Store only ciphertext or non-sensitive state unless an application-specific threat model accepts the risk.
- Full Noctweave message encryption requires the protocol crypto layer; this package does not downgrade or replace it.
