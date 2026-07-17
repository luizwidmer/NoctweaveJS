import assert from "node:assert/strict";
import test from "node:test";
import oqsFactory from "../wasm/dist/noctweave_oqs.js";
import {
  ContactPairingV2Error,
  NoctweaveCryptoSuite,
  NoctweaveOQSWasmAdapter,
  WebCryptoPrimitives,
  createContactPairingInvitationV2,
  decodeContactPairingInvitationV2,
  encodeContactPairingInvitationV2,
  establishContactPairingV2,
  prepareContactPairingParticipantV2,
  validatePairwiseRelationshipV2
} from "../src/index.js";

const createdAt = "2026-07-16T12:00:00Z";
const openedAt = "2026-07-16T12:01:00Z";
const expiresAt = "2026-07-16T12:10:00Z";
const relay = { host: "127.0.0.1", port: 9_339, useTLS: false, transport: "http" };

test("one-use pairing mints unrelated PQ authorities and stores only pairwise state", async () => {
  const { crypto, pqc } = await primitives();
  const made = await createContactPairingInvitationV2({ crypto, createdAt, expiresAt });
  const encoded = await encodeContactPairingInvitationV2({ crypto, invitation: made.invitation });
  const invitation = await decodeContactPairingInvitationV2({ crypto, encoded });
  const offerer = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    displayName: "Alice for Bob",
    relay,
    createdAt
  });
  const responder = await prepareContactPairingParticipantV2({
    crypto,
    pqc,
    displayName: "Bob for Alice",
    relay,
    createdAt
  });
  const result = await establishContactPairingV2({
    crypto,
    pqc,
    pending: made.pending,
    invitation,
    offerer,
    responder,
    at: openedAt
  });

  assert.equal(result.offererRelationship.relationshipID, result.relationshipID);
  assert.equal(result.responderRelationship.relationshipID, result.relationshipID);
  assert.equal(result.offererRelationship.peerIdentity.displayName, "Bob for Alice");
  assert.equal(result.responderRelationship.peerIdentity.displayName, "Alice for Bob");
  assert.notEqual(
    result.offererRelationship.localIdentity.signing.publicKey,
    result.responderRelationship.localIdentity.signing.publicKey
  );
  assert.notEqual(
    result.offererRelationship.localReceiveRoutes[0].clientCapabilities.routeID.rawValue,
    result.responderRelationship.localReceiveRoutes[0].clientCapabilities.routeID.rawValue
  );
  for (const relationship of [result.offererRelationship, result.responderRelationship]) {
    await validatePairwiseRelationshipV2({ crypto, pqc, relationship });
    const persisted = JSON.stringify(relationship);
    for (const forbidden of ["reusableAddress", "accessFingerprint", "profileSigningKey", "publicRoute"]) {
      assert.equal(persisted.includes(forbidden), false, forbidden);
    }
    assert.equal(relationship.peerIdentity.allowContinuity, false);
  }

  await assert.rejects(
    () => establishContactPairingV2({
      crypto,
      pqc,
      pending: result.pending,
      invitation,
      offerer,
      responder,
      ledger: result.ledger,
      at: openedAt
    }),
    /alreadyRedeemed/
  );
});

test("pairing invitations are strict, canonical, and contain no reusable identity or route", async () => {
  const { crypto } = await primitives();
  const made = await createContactPairingInvitationV2({ crypto, createdAt, expiresAt });
  const encoded = await encodeContactPairingInvitationV2({ crypto, invitation: made.invitation });
  const decodedText = Buffer.from(encoded, "base64").toString("utf8");
  for (const forbidden of [
    "displayName",
    "signingPublicKey",
    "agreementPublicKey",
    "endpoint",
    "routeID",
    "relay",
    "reusableAddress"
  ]) {
    assert.equal(decodedText.includes(forbidden), false, forbidden);
  }
  const extended = JSON.parse(decodedText);
  extended.legacy = true;
  await assert.rejects(
    () => decodeContactPairingInvitationV2({
      crypto,
      encoded: Buffer.from(JSON.stringify(extended)).toString("base64")
    }),
    ContactPairingV2Error
  );
});

async function primitives() {
  const pqc = await NoctweaveOQSWasmAdapter.fromFactory(oqsFactory);
  const webcrypto = new WebCryptoPrimitives();
  return {
    pqc,
    crypto: new NoctweaveCryptoSuite({ pqc, webcrypto })
  };
}
