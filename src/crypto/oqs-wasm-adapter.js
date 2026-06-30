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
    this.#requireFunction("_malloc");
    this.#requireFunction("_free");
    this.#requireFunction("_noctweave_oqs_init");
    this.#assertOk(this.module._noctweave_oqs_init(), "liboqs WASM initialization failed");
    this.profileValue = this.#readProfile();
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
    this.#assertLength(secretKey, profile.secretKeyLength, "secretKey");
    const signatureLengthPtr = this.module._malloc(4);
    this.#heapU32()[signatureLengthPtr >> 2] = profile.signatureLength;
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
      return result.signature.slice(0, signatureLength);
    } finally {
      this.#zero(signatureLengthPtr, 4);
      this.module._free(signatureLengthPtr);
    }
  }

  verify(message, signature, publicKey) {
    const profile = this.profileValue.signature;
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

    return {
      kemSharedSecretsMatch: equalBytes(encapsulated.sharedSecret, decapsulated),
      signatureVerified: verified
    };
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
    return Object.fromEntries(
      Object.entries(inputs).map(([name, value]) => {
        const input = bytes(value, name);
        const ptr = this.module._malloc(input.byteLength || 1);
        this.#heapU8().set(input, ptr);
        return [name, { ptr, length: input.byteLength }];
      })
    );
  }

  #freeInputs(inputs) {
    for (const input of Object.values(inputs)) {
      this.#zero(input.ptr, input.length);
      this.module._free(input.ptr);
    }
  }

  #allocOutputs(definitions) {
    return Object.fromEntries(
      definitions.map(([name, length]) => {
        const ptr = this.module._malloc(length || 1);
        return [name, { ptr, length }];
      })
    );
  }

  #freeOutputs(outputs) {
    for (const output of Object.values(outputs)) {
      this.#zero(output.ptr, output.length);
      this.module._free(output.ptr);
    }
  }

  #read(ptr, length) {
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
    let end = ptr;
    while (heap[end] !== 0) {
      end++;
    }
    return JSON.parse(new TextDecoder().decode(heap.slice(ptr, end)));
  }

  #assertLength(value, expectedLength, name) {
    const input = bytes(value, name);
    if (input.byteLength !== expectedLength) {
      throw new TypeError(`${name} must be ${expectedLength} bytes`);
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
