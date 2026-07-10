import assert from "node:assert/strict";
import test from "node:test";
import { decryptPortableProfile, encryptPortableProfile } from "../src/index.js";

test("portable profile encryption hides private state and round trips", async () => {
  const source = {
    identity: { secretKey: "do-not-store-in-plaintext" },
    messages: [{ text: "private message" }]
  };
  const packageData = await encryptPortableProfile(source, "correct horse battery staple");
  const serialized = JSON.stringify(packageData);

  assert.equal(serialized.includes("do-not-store-in-plaintext"), false);
  assert.equal(serialized.includes("private message"), false);
  assert.deepEqual(
    await decryptPortableProfile(packageData, "correct horse battery staple"),
    source
  );
});

test("portable profile decryption fails closed for wrong passwords and malformed metadata", async () => {
  const packageData = await encryptPortableProfile({ value: "secret" }, "correct horse battery staple");

  await assert.rejects(
    () => decryptPortableProfile(packageData, "the wrong profile password"),
    /could not be decrypted/
  );
  await assert.rejects(
    () => decryptPortableProfile({ ...packageData, version: 99 }, "correct horse battery staple"),
    /Unsupported encrypted profile format/
  );
  await assert.rejects(
    () => decryptPortableProfile({
      ...packageData,
      encrypted: { ...packageData.encrypted, nonce: "AA==" }
    }, "correct horse battery staple"),
    /metadata is malformed/
  );
});

test("portable profile creation requires a nontrivial passphrase", async () => {
  await assert.rejects(
    () => encryptPortableProfile({ value: "secret" }, "short"),
    /at least 12 characters/
  );
});
