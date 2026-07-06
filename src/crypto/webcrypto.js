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
    const keyBytes = copyBytes(key, "key");
    try {
      const cryptoKey = await this.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const signature = await this.subtle.sign("HMAC", cryptoKey, bytes(data, "data"));
      return new Uint8Array(signature);
    } finally {
      wipeBytes(keyBytes);
    }
  }

  async hkdfSha256({ ikm, salt = new Uint8Array(), info = new Uint8Array(), length }) {
    if (!Number.isSafeInteger(length) || length <= 0) {
      throw new TypeError("length must be a positive safe integer");
    }
    const ikmBytes = copyBytes(ikm, "ikm");
    try {
      const key = await this.subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveBits"]);
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
    } finally {
      wipeBytes(ikmBytes);
    }
  }

  async aesGcmEncrypt({ key, nonce, plaintext, additionalData = undefined }) {
    const cryptoKey = await this.importAesGcmKey(key, ["encrypt"]);
    const plaintextBytes = copyBytes(plaintext, "plaintext");
    try {
      const encrypted = await this.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: bytes(nonce, "nonce"),
          additionalData: additionalData === undefined ? undefined : bytes(additionalData, "additionalData")
        },
        cryptoKey,
        plaintextBytes
      );
      return new Uint8Array(encrypted);
    } finally {
      wipeBytes(plaintextBytes);
    }
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
    const keyBytes = copyBytes(key, "key");
    if (![16, 24, 32].includes(keyBytes.byteLength)) {
      wipeBytes(keyBytes);
      throw new TypeError("AES-GCM key must be 128, 192, or 256 bits");
    }
    try {
      return await this.subtle.importKey("raw", keyBytes, "AES-GCM", false, usages);
    } finally {
      wipeBytes(keyBytes);
    }
  }
}

function copyBytes(value, label = "value") {
  return new Uint8Array(bytes(value, label));
}

function wipeBytes(value) {
  value.fill(0);
}
