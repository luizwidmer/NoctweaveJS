import test from "node:test";
import assert from "node:assert/strict";
import { createSecurityKeyEntry, openWithSecurityKey, validateSecurityKeyEntries, parseSecurityKeyCBOR,
  base64URL, decodeBase64URL, verifySecurityKeyRegistration, securityKeyAuthenticator } from "../client/security-keys.js";
import { SecurityKeyFixture } from "./helpers/security-key-fixture.js";

const passphrase = "this passphrase stays encrypted";
const scope = "local-vault-1";
async function enroll(key = new SecurityKeyFixture()) {
  const entry = await createSecurityKeyEntry({ passphrase, name: "Daily key", keys: [], scope, authenticator: key });
  return { entry, key };
}

test("FIDO2 registration proves possession and PRF decrypts only the bound vault", async () => {
  const { entry, key } = await enroll();
  assert.equal(entry.counter, 1);
  assert.equal(key.calls, 2);
  assert.equal(JSON.stringify(entry).includes(passphrase), false);
  const opened = await openWithSecurityKey({ keys: [entry], scope, authenticator: key });
  assert.equal(opened.passphrase, passphrase);
  assert.equal(opened.key.counter, 2);
  await assert.rejects(() => openWithSecurityKey({ keys: [entry], scope: "substituted", authenticator: key }));
});

test("wrong hardware, PRF output, RP, origin, and wrapped ciphertext cannot decrypt", async () => {
  const { entry, key } = await enroll();
  await assert.rejects(() => openWithSecurityKey({ keys: [entry], scope, authenticator: new SecurityKeyFixture() }));
  for (const field of ["rpID", "origin", "wrappedPassphrase", "publicKey"]) {
    const changed = { ...entry, [field]: field === "rpID" || field === "origin" ? "wrong.invalid" : base64URL(new Uint8Array(field === "publicKey" ? 65 : 48)) };
    await assert.rejects(() => openWithSecurityKey({ keys: [changed], scope, authenticator: key }));
  }
  key.seed.fill(9);
  await assert.rejects(() => openWithSecurityKey({ keys: [entry], scope, authenticator: key }));
});

test("requires touch and verification, refuses synced credentials and missing PRF", async () => {
  for (const flags of [0, 1, 4, 0x0d, 0x15, 0x25]) {
    const key = new SecurityKeyFixture(); key.flags = flags;
    await assert.rejects(() => enroll(key));
  }
  const key = new SecurityKeyFixture(); key.prf = false;
  await assert.rejects(() => enroll(key), /PRF/);
});

test("rejects replayed assertions, platform attachment, expired and substituted client data", async () => {
  const { entry, key } = await enroll();
  let captured;
  key.transform = (response) => { captured = response; return response; };
  await openWithSecurityKey({ keys: [entry], scope, authenticator: key });
  key.transform = () => captured;
  await assert.rejects(() => openWithSecurityKey({ keys: [entry], scope, authenticator: key }));
  for (const field of ["challenge", "origin", "type", "crossOrigin", "topOrigin"]) {
    const device = new SecurityKeyFixture();
    device.transform = (response) => {
      const client = JSON.parse(new TextDecoder().decode(decodeBase64URL(response.response.clientDataJSON)));
      client[field] = field === "crossOrigin" ? true : "changed";
      response.response.clientDataJSON = base64URL(new TextEncoder().encode(JSON.stringify(client)));
      return response;
    };
    await assert.rejects(() => enroll(device));
  }
  const device = new SecurityKeyFixture();
  const challenge = base64URL(crypto.getRandomValues(new Uint8Array(32)));
  const response = await device.create({ rp: { id: device.rpID }, challenge });
  const ceremony = { ...device, challenge, expiresAt: Date.now() - 1 };
  await assert.rejects(() => verifySecurityKeyRegistration(response, ceremony));
  response.authenticatorAttachment = "platform";
  await assert.rejects(() => verifySecurityKeyRegistration(response, { ...ceremony, expiresAt: Date.now() + 60_000 }));
});

test("abort prevents a late successful response from producing a vault secret", async () => {
  const { entry, key } = await enroll();
  const controller = new AbortController();
  key.beforeGet = async () => { controller.abort(); };
  await assert.rejects(() => openWithSecurityKey({ keys: [entry], scope, authenticator: key, signal: controller.signal }), /abort/i);
});

test("bounded credential and CBOR parsers reject malformed persisted data", async () => {
  const { entry } = await enroll();
  for (const changed of [{ ...entry, nonce: "" }, { ...entry, counter: -1 }, { ...entry, extra: true }, { ...entry, prfSalt: "a=" }]) {
    assert.throws(() => validateSecurityKeyEntries([changed]));
  }
  assert.throws(() => validateSecurityKeyEntries([entry, entry]));
  for (const bytes of [[0xa2, 1, 1, 1, 2], [0x9f, 0xff], [0x98, 65], [0x18, 1], [0x58, 0xff]]) {
    assert.throws(() => parseSecurityKeyCBOR(new Uint8Array(bytes)));
  }
  assert.equal(securityKeyAuthenticator(), null);
});


test("desktop presence providers do not retain a PIN after verification", async () => {
  const original = globalThis.__noctweaveDesktopSecurityKeys;
  const received = [];
  globalThis.__noctweaveDesktopSecurityKeys = {
    available: true, continuousPresence: true, rpID: "local.invalid", origin: "https://local.invalid",
    request: async (request) => { received.push(request.pin); return { credential: {} }; },
    cancel: async () => {}, presence: async () => ({ present: false }), releasePresence: async () => {}
  };
  try {
    const { securityKeyAuthenticator } = await import("../client/security-keys.js");
    const provider = securityKeyAuthenticator({ pin: "test-only PIN" });
    await provider.create({});
    await provider.get({});
    await provider.get({});
    assert.deepEqual(received, ["test-only PIN", "test-only PIN", ""]);
    const cancelled = securityKeyAuthenticator({ pin: "discard me" });
    cancelled.clearPIN();
    await cancelled.get({});
    assert.equal(received.at(-1), "");
  } finally {
    if (original === undefined) delete globalThis.__noctweaveDesktopSecurityKeys;
    else globalThis.__noctweaveDesktopSecurityKeys = original;
  }
});
