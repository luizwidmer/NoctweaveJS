# Contributing to NoctweaveJS

NoctweaveJS implements security-sensitive protocol and persistence behavior. Keep changes narrow, preserve relationship-scoped identity boundaries, and add focused tests for every wire-format, cryptographic, storage, or relay behavior change.

## Development setup

```sh
bun install --frozen-lockfile
npm test
npm run typecheck:desktop
```

Before opening a pull request, also verify the package manifest:

```sh
npm pack --dry-run
```

Protocol changes must remain interoperable with the canonical Noctweave specification and Swift implementation in the [Noctweave repository](https://github.com/luizwidmer/Noctweave). Never add protocol accounts, global identities, server-side decryption, plaintext secret storage, silent downgrade behavior, or cross-relationship key reuse.

## Licensing

Contributions to the main project are accepted under Apache-2.0. Files under `examples/` remain MIT licensed. The shared protocol vectors under `test/fixtures/protocol/` retain their CC-BY-SA-4.0 notice.

