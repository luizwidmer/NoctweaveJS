import { NoctweaveOQSWasmAdapter } from "./oqs-wasm-adapter.js";
import { WebCryptoPrimitives } from "./webcrypto.js";

export class NoctweaveCryptoSuite {
  static async fromOQSWasmFactory(factory, options = {}) {
    const pqc = await NoctweaveOQSWasmAdapter.fromFactory(factory, options.wasmOptions ?? {});
    return new NoctweaveCryptoSuite({
      pqc,
      webcrypto: options.webcrypto ?? new WebCryptoPrimitives(options)
    });
  }

  constructor({ pqc, webcrypto = new WebCryptoPrimitives() }) {
    this.pqc = pqc;
    this.webcrypto = webcrypto;
  }

  profile() {
    return this.pqc.profile();
  }

  randomBytes(length) {
    return this.webcrypto.randomBytes(length);
  }

  sha256(data) {
    return this.webcrypto.sha256(data);
  }

  hkdfSha256(input) {
    return this.webcrypto.hkdfSha256(input);
  }

  aesGcmEncrypt(input) {
    return this.webcrypto.aesGcmEncrypt(input);
  }

  aesGcmDecrypt(input) {
    return this.webcrypto.aesGcmDecrypt(input);
  }

  generateKemKeypair() {
    return this.pqc.generateKemKeypair();
  }

  encapsulate(publicKey) {
    return this.pqc.encapsulate(publicKey);
  }

  decapsulate(ciphertext, secretKey) {
    return this.pqc.decapsulate(ciphertext, secretKey);
  }

  generateSigningKeypair() {
    return this.pqc.generateSigningKeypair();
  }

  sign(message, secretKey) {
    return this.pqc.sign(message, secretKey);
  }

  verify(message, signature, publicKey) {
    return this.pqc.verify(message, signature, publicKey);
  }
}
