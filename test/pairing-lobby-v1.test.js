import assert from "node:assert/strict";
import test from "node:test";
import {
  PairingLobbyHostSessionV1,
  PairingLobbyRequesterSessionV1,
  PairingLobbyV1Error,
  WebCryptoPrimitives,
  base64,
  pairingLobbyBadgeV1,
  relayRequests,
  verifyPairingLobbyListingV1
} from "../src/index.js";

const at = "2033-05-18T03:33:20Z";

test("same-relay pairing accepts an encrypted one-use link and rejects replay", async () => {
  const crypto = testCrypto();
  const host = await PairingLobbyHostSessionV1.create({ crypto, at });
  const lease = relayLease(host);
  const listing = await verifyPairingLobbyListingV1(crypto, lease, { at });
  const requester = await PairingLobbyRequesterSessionV1.create({ crypto, listing: lease, at });

  assert.equal(requester.hostBadge.displayText, host.badge.displayText);
  const pending = await host.openRequest(requester.requestAppendRequest.payload, { at });
  assert.equal(pending.requesterBadge.displayText, requester.requesterBadge.displayText);

  const pairingLink = "noctweave://pair?payload=one-use-pairing-package";
  const append = await host.decisionAppendRequest({
    pending,
    decision: "accepted",
    pairingLink,
    at
  });
  assert.equal(Buffer.from(append.payload, "base64").includes(Buffer.from(pairingLink)), false);
  const response = await requester.openResponse(append.payload, { at });
  assert.equal(response.decision, "accepted");
  assert.equal(response.pairingLink, pairingLink);

  await assert.rejects(
    () => requester.openResponse(append.payload, { at }),
    (error) => error instanceof PairingLobbyV1Error && error.code === "replay"
  );
  await assert.rejects(
    () => host.openRequest(requester.requestAppendRequest.payload, { at }),
    (error) => error instanceof PairingLobbyV1Error && error.code === "replay"
  );
  host.dispose();
  requester.dispose();
});

test("same-relay pairing supports explicit rejection without leaking invitation bytes", async () => {
  const crypto = testCrypto();
  const host = await PairingLobbyHostSessionV1.create({ crypto, at });
  const requester = await PairingLobbyRequesterSessionV1.create({
    crypto,
    listing: relayLease(host),
    at
  });
  const pending = await host.openRequest(requester.requestAppendRequest.payload, { at });
  const append = await host.decisionAppendRequest({ pending, decision: "rejected", at });
  const response = await requester.openResponse(append.payload, { at });
  assert.deepEqual({ decision: response.decision, pairingLink: response.pairingLink }, {
    decision: "rejected",
    pairingLink: ""
  });
});

test("same-relay pairing fails closed on ciphertext tampering and expired listings", async () => {
  const crypto = testCrypto();
  const host = await PairingLobbyHostSessionV1.create({ crypto, at });
  const lease = relayLease(host);
  const requester = await PairingLobbyRequesterSessionV1.create({ crypto, listing: lease, at });
  const tampered = Buffer.from(requester.requestAppendRequest.payload, "base64");
  tampered[tampered.length - 2] ^= 0x80;
  await assert.rejects(() => host.openRequest(tampered, { at }));
  await assert.rejects(
    () => verifyPairingLobbyListingV1(crypto, lease, { at: "2033-05-18T03:35:21Z" }),
    (error) => error instanceof PairingLobbyV1Error && error.code === "expired"
  );
});

test("badge and relay envelopes match the Swift protocol surface", async () => {
  const badge = await pairingLobbyBadgeV1(
    new WebCryptoPrimitives(),
    new Uint8Array(1_952).fill(0x41)
  );
  assert.deepEqual(badge, {
    words: "Acorn Harbor",
    comparisonCode: "788982",
    displayText: "Acorn Harbor · 788982"
  });
  const leaseID = base64(new Uint8Array(16).fill(1));
  const leaseCapability = base64(new Uint8Array(32).fill(2));
  assert.deepEqual(
    { ...relayRequests.listPairingLobbyV1(), requestID: "<dynamic>" },
    {
      requestID: "<dynamic>",
      module: "nw.pairing-lobby",
      version: 1,
      method: "list",
      body: { request: {} },
      authToken: null
    }
  );
  assert.equal(relayRequests.releasePairingLobbyV1({ leaseID, leaseCapability }).method, "release");
});

function relayLease(host) {
  return {
    leaseID: host.leaseAcquireRequest.leaseID,
    announcement: host.leaseAcquireRequest.announcement,
    expiresAt: "2033-05-18T03:35:20Z"
  };
}

function testCrypto() {
  const webcrypto = new WebCryptoPrimitives();
  let sequence = 1;
  return {
    randomBytes(length) {
      const output = new Uint8Array(length);
      for (let index = 0; index < length; index += 1) {
        output[index] = ((sequence + index) % 254) + 1;
      }
      sequence += 1;
      return output;
    },
    sha256: (data) => webcrypto.sha256(data),
    hkdfSha256: (input) => webcrypto.hkdfSha256(input),
    aesGcmEncrypt: (input) => webcrypto.aesGcmEncrypt(input),
    aesGcmDecrypt: (input) => webcrypto.aesGcmDecrypt(input),
    generateKemKeypair() {
      const marker = ((sequence += 1) % 254) + 1;
      return {
        publicKey: new Uint8Array(1_184).fill(marker),
        secretKey: new Uint8Array(2_400).fill(marker)
      };
    },
    encapsulate(publicKey) {
      return {
        ciphertext: new Uint8Array(1_088).fill(publicKey[0]),
        sharedSecret: new Uint8Array(32).fill(publicKey[0] ^ 0x5a)
      };
    },
    decapsulate(ciphertext, secretKey) {
      assert.equal(ciphertext[0], secretKey[0]);
      return new Uint8Array(32).fill(secretKey[0] ^ 0x5a);
    },
    generateSigningKeypair() {
      const marker = ((sequence += 1) % 254) + 1;
      return {
        publicKey: new Uint8Array(1_952).fill(marker),
        secretKey: new Uint8Array(4_032).fill(marker)
      };
    },
    async sign(message, secretKey) {
      return expandedSignature(await webcrypto.sha256(concat(message, Uint8Array.of(secretKey[0]))));
    },
    async verify(message, signature, publicKey) {
      const expected = expandedSignature(await webcrypto.sha256(concat(message, Uint8Array.of(publicKey[0]))));
      return Buffer.from(signature).equals(Buffer.from(expected));
    }
  };
}

function expandedSignature(digest) {
  return Uint8Array.from({ length: 3_309 }, (_, index) => digest[index % digest.length]);
}

function concat(...values) {
  const output = new Uint8Array(values.reduce((total, value) => total + value.byteLength, 0));
  let offset = 0;
  for (const value of values) { output.set(value, offset); offset += value.byteLength; }
  return output;
}
