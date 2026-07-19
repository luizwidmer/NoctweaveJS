import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  DesktopRelationshipStateStore,
  relationshipStateScope
} from "../desktop/bun/relationship-state-store.js";

const relationshipID = "12345678-1234-4234-9234-123456789ABC";

test("desktop host commits ciphertext with a Keychain CAS and detects filesystem rollback", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-"));
  const secureVault = new MemorySecureVault();
  const scope = {
    profileName: "test-profile",
    relationshipID,
    anchorKey: "relationship-anchor",
    stateKey: "relationship-state"
  };
  try {
    const store = hostStore({ rootDirectory, secureVault });
    assert.deepEqual(await store.load(scope), { anchor: null, encryptedRecord: null });

    const firstRecord = encryptedRecord(1);
    const first = await store.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(1),
      encryptedRecord: firstRecord
    });
    assert.equal(first.generation, 1);
    assert.deepEqual(await store.load(scope), {
      anchor: first,
      encryptedRecord: firstRecord
    });

    const paths = relationshipStateScope(scope, { rootDirectory }).paths;
    const generationOneFile = await readFile(paths.state, "utf8");
    for (const plaintextScope of Object.values(scope)) {
      assert.equal(generationOneFile.includes(plaintextScope), false);
      assert.equal(secureVault.values().some((value) => value.includes(plaintextScope)), false);
    }
    const secondRecord = encryptedRecord(2);
    const second = await store.commit({
      ...scope,
      expectedAnchor: first,
      nextGeneration: 2,
      nextStateDigest: digest(2),
      encryptedRecord: secondRecord
    });
    assert.equal(second.generation, 2);

    await writeFile(paths.state, generationOneFile, "utf8");
    await assert.rejects(
      () => hostStore({ rootDirectory, secureVault }).load(scope),
      /rolled back or replaced/
    );
    await assert.rejects(() => store.commit({
      ...scope,
      expectedAnchor: first,
      nextGeneration: 2,
      nextStateDigest: digest(9),
      encryptedRecord: encryptedRecord(9)
    }), /compare-and-swap failed|rolled back or replaced/);

    const tampered = JSON.parse(await readFile(paths.state, "utf8"));
    tampered.encryptedRecord = encryptedRecord(8);
    await writeFile(paths.state, JSON.stringify(tampered), "utf8");
    await assert.rejects(
      () => hostStore({ rootDirectory, secureVault }).load(scope),
      /encrypted-record digest verification failed/
    );
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

test("desktop host crash journal completes secure commit and destruction", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-recovery-"));
  const secureVault = new MemorySecureVault();
  const scope = {
    profileName: "recovery-profile",
    relationshipID,
    anchorKey: "recovery-anchor",
    stateKey: "recovery-state"
  };
  try {
    const initialStore = hostStore({ rootDirectory, secureVault });
    const first = await initialStore.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(3),
      encryptedRecord: encryptedRecord(3)
    });

    const commitCrash = hostStore({
      rootDirectory,
      secureVault,
      faultInjector: failOnceAt("afterSecureCommit")
    });
    await assert.rejects(() => commitCrash.commit({
      ...scope,
      expectedAnchor: first,
      nextGeneration: 2,
      nextStateDigest: digest(4),
      encryptedRecord: encryptedRecord(4)
    }), /injected afterSecureCommit crash/);

    const paths = relationshipStateScope(scope, { rootDirectory }).paths;
    const crashJournal = await readFile(paths.transaction, "utf8");
    for (const plaintextScope of Object.values(scope)) {
      assert.equal(crashJournal.includes(plaintextScope), false);
    }

    const recoveredStore = hostStore({ rootDirectory, secureVault });
    const recovered = await recoveredStore.load(scope);
    assert.equal(recovered.anchor.generation, 2);
    assert.deepEqual(recovered.encryptedRecord, encryptedRecord(4));

    const destroyCrash = hostStore({
      rootDirectory,
      secureVault,
      faultInjector: failOnceAt("afterSecureDestroy")
    });
    await assert.rejects(() => destroyCrash.destroy({
      ...scope,
      expectedAnchor: recovered.anchor
    }), /injected afterSecureDestroy crash/);
    await assert.rejects(
      () => hostStore({ rootDirectory, secureVault }).load(scope),
      /erased and cannot be initialized again/
    );
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

test("desktop burn retains an authoritative tombstone and rejects restored state", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-burn-"));
  const secureVault = new MemorySecureVault();
  const scope = {
    profileName: "burn-profile",
    relationshipID,
    anchorKey: "burn-anchor",
    stateKey: "burn-state"
  };
  try {
    const store = hostStore({ rootDirectory, secureVault });
    const anchor = await store.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(10),
      encryptedRecord: encryptedRecord(10)
    });
    const paths = relationshipStateScope(scope, { rootDirectory }).paths;
    const restoredPersonaState = await readFile(paths.state, "utf8");

    assert.deepEqual(await store.destroy({ ...scope, expectedAnchor: anchor }), {
      destroyed: true
    });
    assert.equal(secureVault.countMatching((key) => key.includes(".anchor\u0000")), 1);

    await writeFile(paths.state, restoredPersonaState, { encoding: "utf8", mode: 0o600 });
    assert.deepEqual(await hostStore({ rootDirectory, secureVault }).erasureStatus(scope), {
      erased: true
    });
    await assert.rejects(() => readFile(paths.state, "utf8"), (error) => error.code === "ENOENT");
    await assert.rejects(() => hostStore({ rootDirectory, secureVault }).load(scope),
      /erased and cannot be initialized again/);
    await assert.rejects(() => hostStore({ rootDirectory, secureVault }).commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(11),
      encryptedRecord: encryptedRecord(11)
    }), /erased and cannot be initialized again/);
    assert.deepEqual(await store.destroy({ ...scope, expectedAnchor: anchor }), {
      destroyed: true,
      alreadyDestroyed: true
    });
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

test("desktop stores serialize one relationship scope across host instances", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-lock-"));
  const secureVault = new MemorySecureVault();
  const scope = {
    profileName: "lock-profile",
    relationshipID,
    anchorKey: "lock-anchor",
    stateKey: "lock-state"
  };
  const entered = deferred();
  const resume = deferred();
  try {
    const firstStore = hostStore({
      rootDirectory,
      secureVault,
      faultInjector: async (stage) => {
        if (stage !== "afterJournal") return;
        entered.resolve();
        await resume.promise;
      }
    });
    const firstCommit = firstStore.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(12),
      encryptedRecord: encryptedRecord(12)
    });
    await entered.promise;

    await assert.rejects(
      () => hostStore({ rootDirectory, secureVault }).load(scope),
      /lock is already held; refusing unsafe recovery/
    );
    resume.resolve();
    const committed = await firstCommit;
    assert.equal(committed.generation, 1);
    assert.equal((await hostStore({ rootDirectory, secureVault }).load(scope)).anchor.generation, 1);
  } finally {
    resume.resolve();
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

test("desktop burn scope cannot be changed by URL profiles or browser storage keys", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-fixed-scope-"));
  const secureVault = new MemorySecureVault();
  const original = {
    profileName: "profile-a",
    relationshipID,
    anchorKey: "anchor-a",
    stateKey: "state-a"
  };
  const alternate = {
    profileName: "profile-b",
    relationshipID,
    anchorKey: "anchor-b",
    stateKey: "state-b"
  };
  try {
    const store = hostStore({ rootDirectory, secureVault });
    const anchor = await store.commit({
      ...original,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(14),
      encryptedRecord: encryptedRecord(14)
    });
    assert.deepEqual(
      relationshipStateScope(original, { rootDirectory }),
      relationshipStateScope(alternate, { rootDirectory })
    );
    await store.destroy({ ...alternate, expectedAnchor: anchor });
    assert.deepEqual(await store.erasureStatus(original), { erased: true });
    await assert.rejects(() => store.commit({
      ...alternate,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(15),
      encryptedRecord: encryptedRecord(15)
    }), /erased and cannot be initialized again/);
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

test("desktop local burn succeeds with missing or corrupt ciphertext", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-corrupt-burn-"));
  const secureVault = new MemorySecureVault();
  const scope = { relationshipID };
  try {
    const store = hostStore({ rootDirectory, secureVault });
    await store.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(16),
      encryptedRecord: encryptedRecord(16)
    });
    const paths = relationshipStateScope(scope, { rootDirectory }).paths;
    await writeFile(paths.state, "corrupt", { encoding: "utf8", mode: 0o600 });
    assert.deepEqual(await store.destroy({ ...scope, expectedAnchor: null }), {
      destroyed: true
    });
    assert.deepEqual(await store.erasureStatus(scope), { erased: true });
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

test("desktop host rejects symlink and non-private relationship records", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-file-policy-"));
  const secureVault = new MemorySecureVault();
  const scope = { relationshipID };
  try {
    const store = hostStore({ rootDirectory, secureVault });
    await store.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(17),
      encryptedRecord: encryptedRecord(17)
    });
    const paths = relationshipStateScope(scope, { rootDirectory }).paths;
    await chmod(paths.state, 0o644);
    await assert.rejects(() => store.load(scope), /not a private bounded regular file/);
    const target = join(rootDirectory, "target.json");
    await writeFile(target, "{}", { encoding: "utf8", mode: 0o600 });
    await rm(paths.state);
    await symlink(target, paths.state);
    await assert.rejects(() => store.load(scope), (error) =>
      error?.code === "ELOOP" || /symbolic link/iu.test(error?.message ?? ""));
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

test("desktop host never accepts plaintext or resets state after secure authority loss", async () => {
  const rootDirectory = await mkdtemp(join(tmpdir(), "noctweave-anchor-loss-"));
  const secureVault = new MemorySecureVault();
  const scope = {
    profileName: "loss-profile",
    relationshipID,
    anchorKey: "loss-anchor",
    stateKey: "loss-state"
  };
  try {
    const store = hostStore({ rootDirectory, secureVault });
    await assert.rejects(() => store.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(5),
      encryptedRecord: { plaintext: true }
    }), /accepts only encrypted Noctweave records|fields are invalid/);
    const first = await store.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(6),
      encryptedRecord: encryptedRecord(6)
    });
    assert.equal(first.generation, 1);
    secureVault.deleteMatching((key) => key.includes(".anchor\u0000"));
    await assert.rejects(() => store.load(scope), /diverged/);
    await assert.rejects(() => store.commit({
      ...scope,
      expectedAnchor: null,
      nextGeneration: 1,
      nextStateDigest: digest(7),
      encryptedRecord: encryptedRecord(7)
    }), /generations diverged|compare-and-swap/);
  } finally {
    await rm(rootDirectory, { recursive: true, force: true });
  }
});

function hostStore({ rootDirectory, secureVault, faultInjector = null }) {
  return new DesktopRelationshipStateStore({
    rootDirectory,
    secureVault,
    faultInjector,
    capability: { available: true, kind: "test-secure-vault", reason: null }
  });
}

function digest(marker) {
  return Buffer.alloc(32, marker).toString("base64");
}

function encryptedRecord(marker) {
  return {
    __noctweaveEncrypted: 1,
    version: 1,
    algorithm: "AES-256-GCM",
    nonce: Buffer.alloc(12, marker).toString("base64"),
    ciphertext: Buffer.alloc(64, marker).toString("base64")
  };
}

function failOnceAt(expectedStage) {
  let failed = false;
  return async (stage) => {
    if (!failed && stage === expectedStage) {
      failed = true;
      throw new Error(`injected ${stage} crash`);
    }
  };
}

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

  deleteMatching(predicate) {
    for (const key of this.records.keys()) {
      if (predicate(key)) this.records.delete(key);
    }
  }

  countMatching(predicate) {
    return [...this.records.keys()].filter(predicate).length;
  }

  values() {
    return [...this.records.values()];
  }
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}
