import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  WebCryptoPrimitives,
  createContactPairingInvitationV2,
  decodeNoctweavePairingLinkV1,
  encodeNoctweavePairingLinkV1,
  noctweavePairingLinkV1Prefix
} from "../src/index.js";

test("pairing link binds a validated invitation to an exact relay endpoint", async () => {
  const crypto = await testCrypto();
  const { invitation } = await createContactPairingInvitationV2({
    crypto,
    createdAt: "2026-07-28T12:00:00Z",
    expiresAt: "2026-07-28T12:10:00Z"
  });
  const encoded = await encodeNoctweavePairingLinkV1({
    crypto,
    relay: "http://127.0.0.1:9440",
    invitation
  });

  assert.ok(encoded.startsWith(noctweavePairingLinkV1Prefix));
  const decoded = await decodeNoctweavePairingLinkV1({ crypto, encoded });
  assert.deepEqual(decoded.relay, {
    host: "127.0.0.1",
    port: 9440,
    useTLS: false,
    transport: "http"
  });
  assert.deepEqual(decoded.invitation, invitation);
});

test("pairing link rejects mutation and non-canonical wrapping", async () => {
  const crypto = await testCrypto();
  const { invitation } = await createContactPairingInvitationV2({
    crypto,
    createdAt: "2026-07-28T12:00:00Z",
    expiresAt: "2026-07-28T12:10:00Z"
  });
  const encoded = await encodeNoctweavePairingLinkV1({
    crypto,
    relay: "https://relay.example",
    invitation
  });

  await assert.rejects(
    decodeNoctweavePairingLinkV1({
      crypto,
      encoded: `${encoded.slice(0, -1)}${encoded.endsWith("A") ? "B" : "A"}`
    })
  );
  await assert.rejects(
    decodeNoctweavePairingLinkV1({ crypto, encoded: ` ${encoded}` })
  );
});

async function testCrypto() {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  return new NoctweaveCryptoSuite({
    pqc,
    webcrypto: new WebCryptoPrimitives()
  });
}
