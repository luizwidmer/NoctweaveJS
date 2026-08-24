import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { UITestFileVault } from "../desktop/bun/ui-test-file-vault.ts";

test("UI-test file vault persists isolated non-Keychain anchors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweavejs-ui-test-vault-"));
  const vault = new UITestFileVault(directory);
  const scope = { service: "test.service", account: "relationship" };
  try {
    assert.equal(await vault.get(scope), null);
    await vault.set({ ...scope, value: "anchor-one" });
    assert.equal(await vault.get(scope), "anchor-one");
    await vault.set({ ...scope, value: "anchor-two" });
    assert.equal(await vault.get(scope), "anchor-two");

    const files = await readdir(directory);
    assert.equal(files.length, 1);
    assert.equal(await readFile(join(directory, files[0]), "utf8"), "anchor-two");

    await vault.delete(scope);
    assert.equal(await vault.get(scope), null);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
