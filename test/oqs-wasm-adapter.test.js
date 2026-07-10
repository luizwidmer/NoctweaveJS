import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { NoctweaveOQSWasmAdapter } from "../src/index.js";

const fixture = JSON.parse(
  await readFile(new URL("./fixtures/native-liboqs-profile.json", import.meta.url), "utf8")
);

test("oqs wasm adapter matches native Swift/liboqs profile and marshals memory", () => {
  const module = createFakeOQSModule(fixture);
  const adapter = new NoctweaveOQSWasmAdapter(module);

  assert.deepEqual(adapter.profile(), {
    kem: fixture.kem,
    signature: fixture.signature
  });

  const kem = adapter.generateKemKeypair();
  assert.equal(kem.publicKey.byteLength, fixture.kem.publicKeyLength);
  assert.equal(kem.secretKey.byteLength, fixture.kem.secretKeyLength);

  const encapsulated = adapter.encapsulate(kem.publicKey);
  assert.equal(encapsulated.ciphertext.byteLength, fixture.kem.ciphertextLength);
  assert.equal(encapsulated.sharedSecret.byteLength, fixture.kem.sharedSecretLength);
  assert.deepEqual(adapter.decapsulate(encapsulated.ciphertext, kem.secretKey), encapsulated.sharedSecret);

  const signing = adapter.generateSigningKeypair();
  const message = new TextEncoder().encode("hello");
  const signature = adapter.sign(message, signing.secretKey);
  assert.equal(signature.byteLength, fixture.signature.signatureLength);
  assert.equal(adapter.verify(message, signature, signing.publicKey), true);
  assert.equal(adapter.verify(new TextEncoder().encode("tampered"), signature, signing.publicKey), false);
  assertAllocatedRangesWereZeroed(module);
});

test("oqs wasm adapter self test clears temporary heap allocations", () => {
  const module = createFakeOQSModule(fixture);
  const adapter = new NoctweaveOQSWasmAdapter(module);

  assert.deepEqual(adapter.selfTest(), {
    kemSharedSecretsMatch: true,
    signatureVerified: true
  });
  assertAllocatedRangesWereZeroed(module);
});

test("oqs wasm adapter rejects substituted profiles and failed allocations", () => {
  const substituted = structuredClone(fixture);
  substituted.kem.algorithm = "ML-KEM-512";
  assert.throws(
    () => new NoctweaveOQSWasmAdapter(createFakeOQSModule(substituted)),
    /does not match Noctweave/
  );

  const module = createFakeOQSModule(fixture);
  const adapter = new NoctweaveOQSWasmAdapter(module);
  module._malloc = () => 0;
  assert.throws(() => adapter.generateKemKeypair(), /allocation failed/);
});

test("oqs wasm adapter bounds signed messages and requires fixed ML-DSA signatures", () => {
  const module = createFakeOQSModule(fixture);
  const adapter = new NoctweaveOQSWasmAdapter(module);
  const signing = adapter.generateSigningKeypair();

  assert.throws(
    () => adapter.sign(new Uint8Array(512 * 1024 + 1), signing.secretKey),
    /must not exceed/
  );
  assert.throws(
    () => adapter.verify(new Uint8Array(), new Uint8Array(12), signing.publicKey),
    /signature must be 3309 bytes/
  );
});

function createFakeOQSModule(profile) {
  const memory = new ArrayBuffer(1024 * 1024);
  const HEAPU8 = new Uint8Array(memory);
  const HEAPU32 = new Uint32Array(memory);
  const allocations = [];
  let offset = 16;

  const json = new TextEncoder().encode(JSON.stringify({ kem: profile.kem, signature: profile.signature }) + "\0");
  HEAPU8.set(json, offset);
  const profilePtr = offset;
  offset += json.byteLength;

  const fill = (ptr, length, seed) => {
    for (let index = 0; index < length; index++) {
      HEAPU8[ptr + index] = (seed + index) & 0xff;
    }
  };
  const same = (ptr, value) => {
    const expected = value instanceof Uint8Array ? value : new TextEncoder().encode(value);
    for (let index = 0; index < expected.byteLength; index++) {
      if (HEAPU8[ptr + index] !== expected[index]) {
        return false;
      }
    }
    return true;
  };

  return {
    HEAPU8,
    HEAPU32,
    __allocations: allocations,
    _malloc(length) {
      const ptr = offset;
      offset += Math.max(length, 1) + 16;
      allocations.push({ ptr, length: Math.max(length, 1) });
      return ptr;
    },
    _free() {},
    _noctweave_memzero(ptr, length) {
      HEAPU8.fill(0, ptr, ptr + length);
    },
    _noctweave_oqs_init() {
      return 0;
    },
    _noctweave_oqs_profile_json() {
      return profilePtr;
    },
    _noctweave_kem_keypair(publicKeyPtr, secretKeyPtr) {
      fill(publicKeyPtr, profile.kem.publicKeyLength, 11);
      fill(secretKeyPtr, profile.kem.secretKeyLength, 17);
      return 0;
    },
    _noctweave_kem_encaps(ciphertextPtr, sharedSecretPtr, publicKeyPtr, publicKeyLength) {
      if (publicKeyLength !== profile.kem.publicKeyLength) {
        return -1;
      }
      fill(ciphertextPtr, profile.kem.ciphertextLength, HEAPU8[publicKeyPtr]);
      fill(sharedSecretPtr, profile.kem.sharedSecretLength, 41);
      return 0;
    },
    _noctweave_kem_decaps(sharedSecretPtr, ciphertextPtr, ciphertextLength, secretKeyPtr, secretKeyLength) {
      if (ciphertextLength !== profile.kem.ciphertextLength || secretKeyLength !== profile.kem.secretKeyLength) {
        return -1;
      }
      fill(sharedSecretPtr, profile.kem.sharedSecretLength, 41 + HEAPU8[ciphertextPtr] - HEAPU8[secretKeyPtr] + 6);
      fill(sharedSecretPtr, profile.kem.sharedSecretLength, 41);
      return 0;
    },
    _noctweave_sig_keypair(publicKeyPtr, secretKeyPtr) {
      fill(publicKeyPtr, profile.signature.publicKeyLength, 61);
      fill(secretKeyPtr, profile.signature.secretKeyLength, 67);
      return 0;
    },
    _noctweave_sig_sign(signaturePtr, signatureLengthPtr, messagePtr, messageLength, secretKeyPtr, secretKeyLength) {
      if (secretKeyLength !== profile.signature.secretKeyLength || secretKeyPtr === 0) {
        return -1;
      }
      const messagePrefix = HEAPU8[messagePtr] ?? 0;
      fill(signaturePtr, profile.signature.signatureLength, messagePrefix);
      HEAPU32[signatureLengthPtr >> 2] = profile.signature.signatureLength;
      return 0;
    },
    _noctweave_sig_verify(messagePtr, messageLength, signaturePtr, signatureLength, publicKeyPtr, publicKeyLength) {
      if (
        publicKeyLength !== profile.signature.publicKeyLength ||
        signatureLength !== profile.signature.signatureLength ||
        publicKeyPtr === 0
      ) {
        return -1;
      }
      return HEAPU8[signaturePtr] === (HEAPU8[messagePtr] ?? 0) ? 0 : -3;
    }
  };
}

function assertAllocatedRangesWereZeroed(module) {
  for (const { ptr, length } of module.__allocations) {
    const range = module.HEAPU8.subarray(ptr, ptr + length);
    assert.equal(
      range.every((byte) => byte === 0),
      true,
      `allocated WASM heap range ${ptr}..${ptr + length} was not zeroed`
    );
  }
}
