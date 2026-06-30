import assert from "node:assert/strict";
import test from "node:test";
import { WebCryptoPrimitives } from "../src/index.js";

test("webcrypto primitives hash, derive, and encrypt with standard browser APIs", async () => {
  const crypto = new WebCryptoPrimitives();

  const digest = await crypto.sha256("abc");
  assert.equal(Buffer.from(digest).toString("hex"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  const hkdf = await crypto.hkdfSha256({
    ikm: new Uint8Array(32).fill(1),
    salt: new Uint8Array(16).fill(2),
    info: "noctweave",
    length: 32
  });
  assert.equal(hkdf.byteLength, 32);

  const key = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array(12).fill(8);
  const aad = new TextEncoder().encode("route");
  const plaintext = new TextEncoder().encode("secret");
  const ciphertext = await crypto.aesGcmEncrypt({ key, nonce, plaintext, additionalData: aad });
  assert.notDeepEqual(ciphertext, plaintext);

  const decrypted = await crypto.aesGcmDecrypt({ key, nonce, ciphertext, additionalData: aad });
  assert.deepEqual(decrypted, plaintext);
});
