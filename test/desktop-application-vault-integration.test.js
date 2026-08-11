import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { HostAnchoredBrowserApplicationVaultV2 } from "../client/messaging-service.js";
import { DesktopRelationshipStateStore } from "../desktop/bun/relationship-state-store.js";
import { DesktopRelationshipStateAnchorStore } from "../desktop/view/relationship-state-anchor.ts";

test("desktop persona vault creates, persists, unlocks, updates, and burns through the real host bridge", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-desktop-vault-"));
  const secureVault = new MemorySecureVault();
  const host = new DesktopRelationshipStateStore({
    rootDirectory,
    secureVault,
    capability: { available: true, kind: "test-secure-vault", reason: null }
  });
  const requests = {
    relationshipStateCapability: async () => host.capabilityReport(),
    relationshipStateErasureStatus: (scope) => host.erasureStatus(scope),
    loadRelationshipState: (scope) => host.load(scope),
    commitRelationshipState: (request) => host.commit(request),
    destroyRelationshipState: (request) => host.destroy(request)
  };
  const factory = async ({ relationshipID, anchorKey, stateKey }) =>
    new DesktopRelationshipStateAnchorStore({ requests, relationshipID, anchorKey, stateKey });
  const options = {
    crypto: {
      sha256: async (data) => new Uint8Array(
        await globalThis.crypto.subtle.digest("SHA-256", data)
      )
    },
    storageCrypto: globalThis.crypto,
    stateAnchorStoreFactory: factory
  };
  const passphrase = "desktop vault integration passphrase";

  try {
    const persona = { displayName: "Desktop Integration", relationships: [] };
    const created = new HostAnchoredBrowserApplicationVaultV2(options);
    assert.deepEqual(await created.inspect(), { status: "empty", vaultScopeID: null });
    assert.deepEqual((await created.initialize({ passphrase, persona })).persona, persona);
    assert.equal((await created.inspect()).status, "active");
    created.lock();

    const reopened = new HostAnchoredBrowserApplicationVaultV2(options);
    assert.deepEqual((await reopened.unlock({ passphrase })).persona, persona);
    const updated = { displayName: "Desktop Integration", relationships: [], revision: 2 };
    await reopened.save(updated);
    reopened.lock();
    assert.deepEqual(
      (await new HostAnchoredBrowserApplicationVaultV2(options).unlock({ passphrase })).persona,
      updated
    );

    const burner = new HostAnchoredBrowserApplicationVaultV2(options);
    await burner.beginBurn();
    await burner.finishBurn();
    assert.equal((await burner.inspect()).status, "burned");
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

class MemorySecureVault {
  constructor() {
    this.records = new Map();
  }

  async get({ service, account }) {
    return this.records.get(`${service}\u0000${account}`) ?? null;
  }

  async set({ service, account, value }) {
    this.records.set(`${service}\u0000${account}`, value);
  }

  async delete({ service, account }) {
    this.records.delete(`${service}\u0000${account}`);
  }
}
