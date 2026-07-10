import { bytes } from "./webcrypto.js";

const DEFAULT_PROFILE = Object.freeze({
  kem: Object.freeze({
    algorithm: "ML-KEM-768",
    publicKeyLength: 1184,
    secretKeyLength: 2400,
    ciphertextLength: 1088,
    sharedSecretLength: 32
  }),
  signature: Object.freeze({
    algorithm: "ML-DSA-65",
    publicKeyLength: 1952,
    secretKeyLength: 4032,
    signatureLength: 3309
  })
});
const MAX_SIGNED_MESSAGE_BYTES = 512 * 1024;
const MAX_PROFILE_JSON_BYTES = 2 * 1024;
const REQUIRED_EXPORTS = Object.freeze([
  "_malloc",
  "_free",
  "_noctweave_oqs_init",
  "_noctweave_kem_keypair",
  "_noctweave_kem_encaps",
  "_noctweave_kem_decaps",
  "_noctweave_sig_keypair",
  "_noctweave_sig_sign",
  "_noctweave_sig_verify"
]);

export class OQSWasmError extends Error {
  constructor(message, code) {
    super(code === undefined ? message : `${message} (${code})`);
    this.name = "OQSWasmError";
    this.code = code;
  }
}

export class NoctweaveOQSWasmAdapter {
  static async fromFactory(factory, options = {}) {
    const module = await factory(options);
    return new NoctweaveOQSWasmAdapter(module);
  }

  constructor(module) {
    this.module = module;
    for (const name of REQUIRED_EXPORTS) {
      this.#requireFunction(name);
    }
    this.#assertOk(this.module._noctweave_oqs_init(), "liboqs WASM initialization failed");
    const profile = this.#readProfile();
    this.#assertExpectedProfile(profile);
    Object.defineProperty(this, "profileValue", {
      value: Object.freeze({
        kem: Object.freeze({ ...profile.kem }),
        signature: Object.freeze({ ...profile.signature })
      }),
      writable: false,
      configurable: false
    });
  }

  profile() {
    return structuredClone(this.profileValue);
  }

  generateKemKeypair() {
    const profile = this.profileValue.kem;
    return this.#withOutputPairs(
      [
        ["publicKey", profile.publicKeyLength],
        ["secretKey", profile.secretKeyLength]
      ],
      (out) => this.module._noctweave_kem_keypair(out.publicKey.ptr, out.secretKey.ptr)
    );
  }

  encapsulate(publicKey) {
    const profile = this.profileValue.kem;
    this.#assertLength(publicKey, profile.publicKeyLength, "publicKey");
    return this.#withInputOutput(
      { publicKey },
      [
        ["ciphertext", profile.ciphertextLength],
        ["sharedSecret", profile.sharedSecretLength]
      ],
      (input, out) =>
        this.module._noctweave_kem_encaps(
          out.ciphertext.ptr,
          out.sharedSecret.ptr,
          input.publicKey.ptr,
          input.publicKey.length
        )
    );
  }

  decapsulate(ciphertext, secretKey) {
    const profile = this.profileValue.kem;
    this.#assertLength(ciphertext, profile.ciphertextLength, "ciphertext");
    this.#assertLength(secretKey, profile.secretKeyLength, "secretKey");
    return this.#withInputOutput(
      { ciphertext, secretKey },
      [["sharedSecret", profile.sharedSecretLength]],
      (input, out) =>
        this.module._noctweave_kem_decaps(
          out.sharedSecret.ptr,
          input.ciphertext.ptr,
          input.ciphertext.length,
          input.secretKey.ptr,
          input.secretKey.length
        )
    ).sharedSecret;
  }

  generateSigningKeypair() {
    const profile = this.profileValue.signature;
    return this.#withOutputPairs(
      [
        ["publicKey", profile.publicKeyLength],
        ["secretKey", profile.secretKeyLength]
      ],
      (out) => this.module._noctweave_sig_keypair(out.publicKey.ptr, out.secretKey.ptr)
    );
  }

  sign(message, secretKey) {
    const profile = this.profileValue.signature;
    this.#assertMaximumLength(message, MAX_SIGNED_MESSAGE_BYTES, "message");
    this.#assertLength(secretKey, profile.secretKeyLength, "secretKey");
    const signatureLengthPtr = this.#allocate(4, "signature length");
    this.#heapU32()[signatureLengthPtr >> 2] = profile.signatureLength;
    let signatureBuffer;
    try {
      const result = this.#withInputOutput(
        { message, secretKey },
        [["signature", profile.signatureLength]],
        (input, out) =>
          this.module._noctweave_sig_sign(
            out.signature.ptr,
            signatureLengthPtr,
            input.message.ptr,
            input.message.length,
            input.secretKey.ptr,
            input.secretKey.length
          )
      );
      const signatureLength = this.#heapU32()[signatureLengthPtr >> 2];
      if (signatureLength !== profile.signatureLength) {
        throw new OQSWasmError("liboqs returned an invalid ML-DSA-65 signature length");
      }
      signatureBuffer = result.signature;
      return signatureBuffer.slice(0, signatureLength);
    } finally {
      wipeBytes(signatureBuffer);
      this.#zero(signatureLengthPtr, 4);
      this.module._free(signatureLengthPtr);
    }
  }

  verify(message, signature, publicKey) {
    const profile = this.profileValue.signature;
    this.#assertMaximumLength(message, MAX_SIGNED_MESSAGE_BYTES, "message");
    this.#assertLength(signature, profile.signatureLength, "signature");
    this.#assertLength(publicKey, profile.publicKeyLength, "publicKey");
    const input = this.#allocInputs({ message, signature, publicKey });
    try {
      const status = this.module._noctweave_sig_verify(
        input.message.ptr,
        input.message.length,
        input.signature.ptr,
        input.signature.length,
        input.publicKey.ptr,
        input.publicKey.length
      );
      return status === 0;
    } finally {
      this.#freeInputs(input);
    }
  }

  selfTest() {
    const kem = this.generateKemKeypair();
    const encapsulated = this.encapsulate(kem.publicKey);
    const decapsulated = this.decapsulate(encapsulated.ciphertext, kem.secretKey);

    const sig = this.generateSigningKeypair();
    const message = new TextEncoder().encode("noctweave-oqs-wasm-self-test");
    const signature = this.sign(message, sig.secretKey);
    const verified = this.verify(message, signature, sig.publicKey);

    try {
      return {
        kemSharedSecretsMatch: equalBytes(encapsulated.sharedSecret, decapsulated),
        signatureVerified: verified
      };
    } finally {
      wipeBytes(kem.secretKey);
      wipeBytes(encapsulated.sharedSecret);
      wipeBytes(decapsulated);
      wipeBytes(sig.secretKey);
      wipeBytes(message);
      wipeBytes(signature);
    }
  }

  #withOutputPairs(definitions, operation) {
    const output = this.#allocOutputs(definitions);
    try {
      this.#assertOk(operation(output), "liboqs operation failed");
      return Object.fromEntries(definitions.map(([name]) => [name, this.#read(output[name].ptr, output[name].length)]));
    } finally {
      this.#freeOutputs(output);
    }
  }

  #withInputOutput(inputs, outputs, operation) {
    const input = this.#allocInputs(inputs);
    const output = this.#allocOutputs(outputs);
    try {
      this.#assertOk(operation(input, output), "liboqs operation failed");
      return Object.fromEntries(outputs.map(([name]) => [name, this.#read(output[name].ptr, output[name].length)]));
    } finally {
      this.#freeOutputs(output);
      this.#freeInputs(input);
    }
  }

  #allocInputs(inputs) {
    const allocated = {};
    try {
      for (const [name, value] of Object.entries(inputs)) {
        const input = bytes(value, name);
        const ptr = this.#allocate(input.byteLength || 1, name);
        this.#heapU8().set(input, ptr);
        allocated[name] = { ptr, length: input.byteLength };
      }
      return allocated;
    } catch (error) {
      this.#freeInputs(allocated);
      throw error;
    }
  }

  #freeInputs(inputs) {
    for (const input of Object.values(inputs)) {
      this.#zero(input.ptr, input.length);
      this.module._free(input.ptr);
    }
  }

  #allocOutputs(definitions) {
    const allocated = {};
    try {
      for (const [name, length] of definitions) {
        const ptr = this.#allocate(length || 1, name);
        allocated[name] = { ptr, length };
      }
      return allocated;
    } catch (error) {
      this.#freeOutputs(allocated);
      throw error;
    }
  }

  #freeOutputs(outputs) {
    for (const output of Object.values(outputs)) {
      this.#zero(output.ptr, output.length);
      this.module._free(output.ptr);
    }
  }

  #read(ptr, length) {
    this.#assertHeapRange(ptr, length);
    return new Uint8Array(this.#heapU8().slice(ptr, ptr + length));
  }

  #zero(ptr, length) {
    if (length <= 0) {
      return;
    }
    if (typeof this.module._noctweave_memzero === "function") {
      this.module._noctweave_memzero(ptr, length);
    } else {
      this.#heapU8().fill(0, ptr, ptr + length);
    }
  }

  #readProfile() {
    if (typeof this.module._noctweave_oqs_profile_json !== "function") {
      return DEFAULT_PROFILE;
    }
    const ptr = this.module._noctweave_oqs_profile_json();
    const heap = this.#heapU8();
    if (!Number.isSafeInteger(ptr) || ptr <= 0 || ptr >= heap.byteLength) {
      throw new OQSWasmError("WASM module returned an invalid profile pointer");
    }
    let end = ptr;
    const limit = Math.min(heap.byteLength, ptr + MAX_PROFILE_JSON_BYTES);
    while (end < limit && heap[end] !== 0) {
      end++;
    }
    if (end === limit) {
      throw new OQSWasmError("WASM profile is missing a bounded terminator");
    }
    try {
      return JSON.parse(new TextDecoder().decode(heap.slice(ptr, end)));
    } catch {
      throw new OQSWasmError("WASM module returned an invalid profile");
    }
  }

  #assertLength(value, expectedLength, name) {
    const input = bytes(value, name);
    if (input.byteLength !== expectedLength) {
      throw new TypeError(`${name} must be ${expectedLength} bytes`);
    }
  }

  #assertMaximumLength(value, maximumLength, name) {
    const input = bytes(value, name);
    if (input.byteLength > maximumLength) {
      throw new TypeError(`${name} must not exceed ${maximumLength} bytes`);
    }
  }

  #assertExpectedProfile(profile) {
    for (const family of ["kem", "signature"]) {
      if (!profile || typeof profile[family] !== "object" || profile[family] === null) {
        throw new OQSWasmError(`WASM module is missing the ${family} profile`);
      }
      for (const [name, expected] of Object.entries(DEFAULT_PROFILE[family])) {
        if (profile[family][name] !== expected) {
          throw new OQSWasmError(`WASM ${family} profile does not match Noctweave`);
        }
      }
    }
  }

  #allocate(length, label) {
    if (!Number.isSafeInteger(length) || length <= 0) {
      throw new OQSWasmError(`Invalid WASM allocation length for ${label}`);
    }
    const ptr = this.module._malloc(length);
    if (!Number.isSafeInteger(ptr) || ptr <= 0) {
      throw new OQSWasmError(`WASM allocation failed for ${label}`);
    }
    this.#assertHeapRange(ptr, length);
    return ptr;
  }

  #assertHeapRange(ptr, length) {
    const heapLength = this.#heapU8().byteLength;
    if (!Number.isSafeInteger(ptr) || !Number.isSafeInteger(length) || ptr < 0 || length < 0 || ptr > heapLength - length) {
      throw new OQSWasmError("WASM memory range is outside the exported heap");
    }
  }

  #assertOk(status, message) {
    if (status !== 0) {
      throw new OQSWasmError(message, status);
    }
  }

  #heapU8() {
    if (!this.module.HEAPU8) {
      throw new OQSWasmError("WASM module does not expose HEAPU8");
    }
    return this.module.HEAPU8;
  }

  #heapU32() {
    if (!this.module.HEAPU32) {
      throw new OQSWasmError("WASM module does not expose HEAPU32");
    }
    return this.module.HEAPU32;
  }

  #requireFunction(name) {
    if (typeof this.module[name] !== "function") {
      throw new OQSWasmError(`WASM module does not expose ${name}`);
    }
  }
}

function equalBytes(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < a.byteLength; index++) {
    difference |= a[index] ^ b[index];
  }
  return difference === 0;
}

function wipeBytes(value) {
  if (value instanceof Uint8Array) {
    value.fill(0);
  }
}
