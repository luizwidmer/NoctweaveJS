const textEncoder = new TextEncoder();

export function bytes(value, label = "value") {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === "string") {
    return textEncoder.encode(value);
  }
  throw new TypeError(`${label} must be a Uint8Array, ArrayBuffer, typed array, or string`);
}

export class WebCryptoPrimitives {
  constructor({ crypto = globalThis.crypto } = {}) {
    if (!crypto?.subtle || !crypto?.getRandomValues) {
      throw new Error("WebCrypto is required");
    }
    this.crypto = crypto;
    this.subtle = crypto.subtle;
  }

  randomBytes(length) {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new TypeError("length must be a non-negative safe integer");
    }
    const output = new Uint8Array(length);
    this.crypto.getRandomValues(output);
    return output;
  }

  async sha256(data) {
    const digest = await this.subtle.digest("SHA-256", bytes(data, "data"));
    return new Uint8Array(digest);
  }

  async hmacSha256({ key, data }) {
    const cryptoKey = await this.subtle.importKey(
      "raw",
      bytes(key, "key"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signature = await this.subtle.sign("HMAC", cryptoKey, bytes(data, "data"));
    return new Uint8Array(signature);
  }

  async hkdfSha256({ ikm, salt = new Uint8Array(), info = new Uint8Array(), length }) {
    if (!Number.isSafeInteger(length) || length <= 0) {
      throw new TypeError("length must be a positive safe integer");
    }
    const key = await this.subtle.importKey("raw", bytes(ikm, "ikm"), "HKDF", false, ["deriveBits"]);
    const bits = await this.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: bytes(salt, "salt"),
        info: bytes(info, "info")
      },
      key,
      length * 8
    );
    return new Uint8Array(bits);
  }

  async aesGcmEncrypt({ key, nonce, plaintext, additionalData = undefined }) {
    const cryptoKey = await this.importAesGcmKey(key, ["encrypt"]);
    const encrypted = await this.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: bytes(nonce, "nonce"),
        additionalData: additionalData === undefined ? undefined : bytes(additionalData, "additionalData")
      },
      cryptoKey,
      bytes(plaintext, "plaintext")
    );
    return new Uint8Array(encrypted);
  }

  async aesGcmDecrypt({ key, nonce, ciphertext, additionalData = undefined }) {
    const cryptoKey = await this.importAesGcmKey(key, ["decrypt"]);
    const decrypted = await this.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: bytes(nonce, "nonce"),
        additionalData: additionalData === undefined ? undefined : bytes(additionalData, "additionalData")
      },
      cryptoKey,
      bytes(ciphertext, "ciphertext")
    );
    return new Uint8Array(decrypted);
  }

  async importAesGcmKey(key, usages) {
    const keyBytes = bytes(key, "key");
    if (![16, 24, 32].includes(keyBytes.byteLength)) {
      throw new TypeError("AES-GCM key must be 128, 192, or 256 bits");
    }
    return this.subtle.importKey("raw", keyBytes, "AES-GCM", false, usages);
  }
}
