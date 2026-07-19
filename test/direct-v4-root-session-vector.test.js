import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { webcrypto } from "node:crypto";

import { deriveDirectV4RootSessionMaterial } from "../src/crypto/noctweave-native-message.js";
import { WebCryptoPrimitives } from "../src/crypto/webcrypto.js";
import * as publicAPI from "../src/index.js";

const fixtureURL = new URL(
  "../../NoctweaveDocumentation/test_vectors/direct_v4_root_session_v1.json",
  import.meta.url
);

test("direct-v4 root and session derivation matches the shared Swift/JavaScript vector", async () => {
  const fixture = JSON.parse(await readFile(fixtureURL, "utf8"));
  const sharedSecret = fromHex(fixture.sharedSecretHex);
  const negotiatedCapabilitiesDigest = fromHex(fixture.negotiatedCapabilitiesDigestHex);
  const crypto = new WebCryptoPrimitives({ crypto: webcrypto });
  const placeholder = Buffer.alloc(32).toString("base64");
  const binding = {
    relationshipId: fixture.relationshipId,
    localEndpointHandle: { rawValue: placeholder },
    peerEndpointHandle: { rawValue: Buffer.alloc(32, 1).toString("base64") },
    localBindingReferenceDigest: Buffer.alloc(32, 2).toString("base64"),
    peerBindingReferenceDigest: Buffer.alloc(32, 3).toString("base64"),
    cipherSuite: fixture.cipherSuite,
    negotiatedCapabilitiesDigest: Buffer.from(negotiatedCapabilitiesDigest).toString("base64")
  };

  const derived = await deriveDirectV4RootSessionMaterial({
    crypto,
    sharedSecret,
    binding
  });
  try {
    assert.equal(fixture.profile, "nw.direct-v4-root-session-v1");
    assert.equal(derived.rootInfo.byteLength, fixture.expectedRootInfoBytes);
    assert.equal(toHex(derived.rootInfo), fixture.expectedRootInfoHex);
    assert.equal(toHex(derived.rootKey), fixture.expectedRootKeyHex);
    assert.equal(derived.sessionTranscript.byteLength, fixture.expectedSessionTranscriptBytes);
    assert.equal(toHex(derived.sessionTranscript), fixture.expectedSessionTranscriptHex);
    assert.equal(toHex(derived.sessionDigest), fixture.expectedSessionDigestHex);
    assert.equal(derived.sessionId, fixture.expectedSessionIdBase64);

    const rootInfoText = new TextDecoder().decode(derived.rootInfo.subarray(0, 60));
    assert.equal(rootInfoText.endsWith(fixture.relationshipId.toLowerCase()), true);
    assert.equal(Object.hasOwn(publicAPI, "deriveDirectV4RootSessionMaterial"), false);
  } finally {
    sharedSecret.fill(0);
    negotiatedCapabilitiesDigest.fill(0);
    derived.rootInfo.fill(0);
    derived.rootKey.fill(0);
    derived.sessionTranscript.fill(0);
    derived.sessionDigest.fill(0);
  }
});

function fromHex(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 ||
      !/^[0-9a-f]+$/u.test(value)) {
    throw new TypeError("Vector hex must be lowercase and canonical.");
  }
  return new Uint8Array(Buffer.from(value, "hex"));
}

function toHex(value) {
  return Buffer.from(value).toString("hex");
}
