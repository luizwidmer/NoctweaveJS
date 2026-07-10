import { EncryptedNoctweaveStore, MemoryNoctweaveStore } from "./storage.js";

const FORMAT = "org.noctweave.profile-vault";
const VERSION = 1;
const DEFAULT_ITERATIONS = 310_000;
const MIN_PASSPHRASE_LENGTH = 12;
const MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024;

export async function encryptPortableProfile(value, passphrase, options = {}) {
  const crypto = options.crypto ?? globalThis.crypto;
  requireCrypto(crypto);
  validateNewPassphrase(passphrase);
  const iterations = validateIterations(options.iterations ?? DEFAULT_ITERATIONS);
  const salt = randomBytes(crypto, 16);
  const backend = new MemoryNoctweaveStore();
  const store = new EncryptedNoctweaveStore(backend, {
    crypto,
    passphrase,
    salt,
    iterations
  });
  try {
    await store.set("portable-profile", value);
    const encrypted = await backend.get("portable-profile");
    const ciphertext = decodeBase64Strict(encrypted?.ciphertext, "profile ciphertext");
    if (ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Encrypted profile exceeds the 2 MB limit.");
    }
    ciphertext.fill(0);
    return {
      format: FORMAT,
      version: VERSION,
      kdf: {
        name: "PBKDF2-SHA256",
        iterations,
        salt: bytesToBase64(salt)
      },
      encrypted
    };
  } finally {
    salt.fill(0);
  }
}

export async function decryptPortableProfile(profilePackage, passphrase, options = {}) {
  const crypto = options.crypto ?? globalThis.crypto;
  requireCrypto(crypto);
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("Profile passphrase is required.");
  }
  validatePortablePackage(profilePackage);
  const salt = decodeBase64Strict(profilePackage.kdf.salt, "profile salt");
  const nonce = decodeBase64Strict(profilePackage.encrypted.nonce, "profile nonce");
  const ciphertext = decodeBase64Strict(profilePackage.encrypted.ciphertext, "profile ciphertext");
  try {
    if (salt.byteLength !== 16 || nonce.byteLength !== 12) {
      throw new Error("Encrypted profile metadata is malformed.");
    }
    if (ciphertext.byteLength < 16 || ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Encrypted profile size is invalid.");
    }
    const backend = new MemoryNoctweaveStore([["portable-profile", profilePackage.encrypted]]);
    const store = new EncryptedNoctweaveStore(backend, {
      crypto,
      passphrase,
      salt,
      iterations: validateIterations(profilePackage.kdf.iterations)
    });
    return await store.get("portable-profile");
  } catch (error) {
    if (error instanceof Error && /metadata|size|iterations|passphrase is required/.test(error.message)) {
      throw error;
    }
    throw new Error("Profile could not be decrypted. Check the passphrase and file integrity.");
  } finally {
    salt.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
  }
}

export const portableProfileLimits = Object.freeze({
  minimumPassphraseLength: MIN_PASSPHRASE_LENGTH,
  maximumCiphertextBytes: MAX_CIPHERTEXT_BYTES
});

function validatePortablePackage(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Encrypted profile package is malformed.");
  }
  if (value.format !== FORMAT || value.version !== VERSION) {
    throw new Error("Unsupported encrypted profile format.");
  }
  if (value.kdf?.name !== "PBKDF2-SHA256") {
    throw new Error("Unsupported encrypted profile KDF.");
  }
  if (value.encrypted?.__noctweaveEncrypted !== 1 ||
      value.encrypted?.version !== 1 ||
      value.encrypted?.algorithm !== "AES-256-GCM") {
    throw new Error("Unsupported encrypted profile cipher.");
  }
}

function validateNewPassphrase(value) {
  if (typeof value !== "string" || value.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Profile passphrase must contain at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  if (new TextEncoder().encode(value).byteLength > 1024) {
    throw new Error("Profile passphrase is too long.");
  }
}

function validateIterations(value) {
  const iterations = Number(value);
  if (!Number.isSafeInteger(iterations) || iterations < 100_000 || iterations > 10_000_000) {
    throw new Error("Profile KDF iterations must be between 100000 and 10000000.");
  }
  return iterations;
}

function requireCrypto(crypto) {
  if (!crypto?.subtle || typeof crypto.getRandomValues !== "function") {
    throw new Error("WebCrypto is required for encrypted profiles.");
  }
}

function randomBytes(crypto, length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function decodeBase64Strict(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 3_000_000 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  let bytes;
  if (typeof Buffer !== "undefined") {
    bytes = new Uint8Array(Buffer.from(value, "base64"));
  } else {
    const binary = atob(value);
    bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
  }
  if (bytesToBase64(bytes) !== value) {
    bytes.fill(0);
    throw new Error(`Invalid ${label}.`);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
