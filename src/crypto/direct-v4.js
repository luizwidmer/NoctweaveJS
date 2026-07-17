import {
  createProtocolCapabilityManifest,
  directV4CipherSuite,
  negotiateDirectV4Capabilities,
  validateProtocolCapabilityManifest
} from "../architecture-v2.js";
import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./swift-canonical.js";

const encoder = new TextEncoder();
const DIRECT_VERSION = 4;
const ARCHITECTURE_VERSION = 2;
const ML_DSA_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_SECRET_KEY_BYTES = 4_032;
const ML_DSA_SIGNATURE_BYTES = 3_309;
const ML_KEM_PUBLIC_KEY_BYTES = 1_184;
const ML_KEM_SECRET_KEY_BYTES = 2_400;
const DIGEST_BYTES = 32;
const PREKEY_MAX_AGE_MS = 8 * 86_400_000;
const PREKEY_FUTURE_SKEW_MS = 5 * 60_000;
const PREKEY_RENEWAL_LEAD_MS = 2 * 86_400_000;
const MAX_RETIRED_SIGNED_PREKEYS = 4;
const BECH32_CHARSET = Array.from("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

export const nativeDirectV4 = Object.freeze({
  version: DIRECT_VERSION,
  architectureVersion: ARCHITECTURE_VERSION,
  payloadFormat: "nw.wire-payload.v2",
  cipherSuite: directV4CipherSuite
});

export async function inboxIdForAccessPublicKey({ crypto, publicKey }) {
  if (typeof crypto?.sha256 !== "function") {
    throw new TypeError("Inbox derivation requires SHA-256.");
  }
  const key = publicKey instanceof Uint8Array
    ? publicKey
    : decodeBase64(publicKey, "inbox access public key", ML_DSA_PUBLIC_KEY_BYTES);
  if (key.byteLength !== ML_DSA_PUBLIC_KEY_BYTES) {
    throw new Error("Invalid inbox access public key.");
  }
  const digest = await crypto.sha256(key);
  if (!(digest instanceof Uint8Array) || digest.byteLength !== DIGEST_BYTES) {
    throw new Error("Inbox access-key hashing failed.");
  }
  return bech32Encode("noctweave", digest);
}

export async function prepareNativeDirectV4Identity({
  crypto,
  pqc,
  identity,
  issuedAt = swiftISODate()
}) {
  requireCrypto(crypto, pqc);
  requireRecord(identity, "Native identity");
  validateKeypair(identity.signing, "identity signing", ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SECRET_KEY_BYTES);
  validateKeypair(identity.agreement, "identity agreement", ML_KEM_PUBLIC_KEY_BYTES, ML_KEM_SECRET_KEY_BYTES);
  if (!canonicalUUID(identity.identityGenerationId)) {
    identity.identityGenerationId = swiftUUID();
  }
  if (!identity.localEndpoint) {
    const signing = pqc.generateSigningKeypair();
    const agreement = pqc.generateKemKeypair();
    identity.localEndpoint = {
      id: swiftUUID(),
      identityGenerationId: identity.identityGenerationId,
      signing: serializeKeypair(signing),
      agreement: serializeKeypair(agreement),
      signingFingerprint: base64(await crypto.sha256(signing.publicKey)),
      mailboxRoutes: {},
      createdAt: issuedAt
    };
  }
  const local = identity.localEndpoint;
  validateLocalEndpoint(local, identity.identityGenerationId);
  const artifactNames = [
    "endpointSetManifest",
    "endpointSetCheckpoint",
    "certifiedGenerationEndpoint"
  ];
  const artifactCount = artifactNames.filter((name) => identity[name] != null).length;
  if (artifactCount !== 0 && artifactCount !== artifactNames.length) {
    throw new Error("Direct-v4 identity artifacts are incomplete.");
  }
  if (artifactCount === artifactNames.length) {
    await renewNativeDirectV4PrekeyIfNeeded({
      crypto,
      pqc,
      identity,
      now: Date.parse(issuedAt)
    });
    return identity;
  }

  if (local.prekeys != null) {
    throw new Error("Direct-v4 prekey state exists without its certified endpoint.");
  }
  const prekeyPair = pqc.generateKemKeypair();
  validateGeneratedKeypair(prekeyPair, "endpoint signed prekey");
  const prekeyId = swiftUUID();
  const prekeyExpiresAt = swiftISODate(new Date(Date.parse(issuedAt) + PREKEY_MAX_AGE_MS));
  const signedPrekeyPayload = {
    id: prekeyId,
    issuedAt,
    publicKey: base64(prekeyPair.publicKey),
    expiresAt: prekeyExpiresAt
  };
  const signedPrekeySignature = signCanonical(
    pqc,
    signedPrekeyPayload,
    local.signing.secretKey,
    "endpoint signed prekey"
  );
  local.prekeys = {
    signedPrekeyId: prekeyId,
    signedPrekeyPublicKey: base64(prekeyPair.publicKey),
    signedPrekeyPrivateKey: base64(prekeyPair.secretKey),
    signedPrekeySignature,
    signedPrekeyIssuedAt: issuedAt,
    signedPrekeyExpiresAt: prekeyExpiresAt,
    retiredSignedPrekeys: [],
    oneTimePrekeys: []
  };

  const capabilities = createProtocolCapabilityManifest();
  const endpointRecord = {
    id: local.id,
    identityGenerationId: identity.identityGenerationId,
    signingPublicKey: local.signing.publicKey,
    agreementPublicKey: local.agreement.publicKey,
    capabilities,
    addedEpoch: 0,
    addedAt: local.createdAt
  };
  const manifestPayload = {
    version: ARCHITECTURE_VERSION,
    identityGenerationId: identity.identityGenerationId,
    identityFingerprint: identity.signingFingerprint,
    epoch: 0,
    endpoints: [endpointRecord],
    issuedAt
  };
  const endpointSetManifest = {
    ...manifestPayload,
    signature: signCanonical(
      pqc,
      manifestPayload,
      identity.signing.secretKey,
      "endpoint manifest"
    )
  };
  const manifestDigest = base64(await crypto.sha256(canonicalJsonBytes(endpointSetManifest)));
  const prekeyBundle = {
    version: ARCHITECTURE_VERSION,
    identityFingerprint: local.signingFingerprint,
    signedPrekey: {
      id: prekeyId,
      publicKey: local.prekeys.signedPrekeyPublicKey,
      issuedAt,
      expiresAt: prekeyExpiresAt,
      signature: signedPrekeySignature
    },
    oneTimePrekeys: [],
    createdAt: issuedAt
  };
  const endpointPayload = {
    version: DIRECT_VERSION,
    identityGenerationId: identity.identityGenerationId,
    identityAuthorityPublicKey: identity.signing.publicKey,
    manifestEpoch: 0,
    manifestDigest,
    endpointId: local.id,
    signingPublicKey: local.signing.publicKey,
    agreementPublicKey: local.agreement.publicKey,
    capabilities,
    issuedAt
  };
  const authoritySignature = signCanonical(
    pqc,
    endpointPayload,
    identity.signing.secretKey,
    "certified endpoint authority"
  );
  const possessionPayload = {
    authoritySignature,
    endpoint: endpointPayload,
    purpose: "Noctweave/certified-generation-endpoint-possession/v4"
  };
  const possessionSignature = signCanonical(
      pqc,
      possessionPayload,
      local.signing.secretKey,
      "certified endpoint possession"
    );
  const endpointAuthorizationDigest = base64(await crypto.sha256(canonicalJsonBytes({
    authoritySignature,
    endpoint: endpointPayload,
    possessionSignature
  })));
  const prekeyPackageSignature = signCanonical(
    pqc,
    endpointSignedPrekeyPackagePayload({ endpointAuthorizationDigest, bundle: prekeyBundle }),
    local.signing.secretKey,
    "endpoint signed prekey package"
  );
  const endpoint = {
    ...withoutVersion(endpointPayload),
    prekeyBundle,
    prekeyPackageSignature,
    authoritySignature,
    possessionSignature
  };
  const checkpointPayload = {
    version: DIRECT_VERSION,
    identityGenerationId: identity.identityGenerationId,
    identityFingerprint: identity.signingFingerprint,
    epoch: 0,
    manifestDigest,
    issuedAt
  };
  identity.endpointSetManifest = endpointSetManifest;
  identity.certifiedGenerationEndpoint = endpoint;
  identity.endpointSetCheckpoint = {
    ...checkpointPayload,
    signature: signCanonical(
      pqc,
      checkpointPayload,
      identity.signing.secretKey,
      "endpoint manifest checkpoint"
    )
  };
  return identity;
}

export async function renewNativeDirectV4PrekeyIfNeeded({
  crypto,
  pqc,
  identity,
  now = Date.now()
}) {
  requireCrypto(crypto, pqc);
  const local = identity?.localEndpoint;
  const endpoint = identity?.certifiedGenerationEndpoint;
  const prekeys = local?.prekeys;
  if (!local || !endpoint || !prekeys || endpoint.endpointId !== local.id ||
      endpoint.identityGenerationId !== identity.identityGenerationId) {
    throw new Error("A prepared local direct-v4 endpoint is required for prekey renewal.");
  }
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  if (!Number.isFinite(nowMs)) {
    throw new Error("Direct-v4 prekey renewal time is invalid.");
  }
  await validatePreparedIdentity({ crypto, pqc, identity });
  const retired = Array.isArray(prekeys.retiredSignedPrekeys)
    ? prekeys.retiredSignedPrekeys
    : [];
  prekeys.retiredSignedPrekeys = retired.filter((record) =>
    Number.isFinite(Date.parse(record?.expiresAt)) && Date.parse(record.expiresAt) > nowMs
  );
  if (prekeys.retiredSignedPrekeys.length > MAX_RETIRED_SIGNED_PREKEYS) {
    throw new Error("Direct-v4 retained signed-prekey state exceeds its bound.");
  }
  for (const record of prekeys.retiredSignedPrekeys) {
    if (!canonicalUUID(record.id) || Date.parse(record.expiresAt) <= Date.parse(record.issuedAt) ||
        Date.parse(record.expiresAt) - Date.parse(record.issuedAt) > PREKEY_MAX_AGE_MS) {
      throw new Error("Direct-v4 retained signed-prekey record is malformed.");
    }
    decodeBase64(record.publicKey, "retained signed prekey public key", ML_KEM_PUBLIC_KEY_BYTES);
    decodeBase64(record.privateKey, "retained signed prekey private key", ML_KEM_SECRET_KEY_BYTES);
    verifyCanonical(
      pqc,
      signedPrekeyPayload(record),
      record.signature,
      local.signing.publicKey,
      "retained endpoint signed prekey"
    );
  }
  const currentExpiryMs = Date.parse(prekeys.signedPrekeyExpiresAt);
  if (!Number.isFinite(currentExpiryMs)) {
    throw new Error("Direct-v4 signed-prekey expiry is invalid.");
  }
  if (currentExpiryMs > nowMs + PREKEY_RENEWAL_LEAD_MS) {
    return false;
  }
  if (nowMs < currentExpiryMs) {
    if (prekeys.retiredSignedPrekeys.length >= MAX_RETIRED_SIGNED_PREKEYS) {
      throw new Error("Direct-v4 retained signed-prekey capacity is exhausted.");
    }
    prekeys.retiredSignedPrekeys.push({
      id: prekeys.signedPrekeyId,
      publicKey: prekeys.signedPrekeyPublicKey,
      privateKey: prekeys.signedPrekeyPrivateKey,
      signature: prekeys.signedPrekeySignature,
      issuedAt: prekeys.signedPrekeyIssuedAt,
      expiresAt: prekeys.signedPrekeyExpiresAt
    });
  }

  const issuedAt = swiftISODate(new Date(nowMs));
  const expiresAt = swiftISODate(new Date(nowMs + PREKEY_MAX_AGE_MS));
  const keypair = pqc.generateKemKeypair();
  validateGeneratedKeypair(keypair, "renewed endpoint signed prekey");
  const id = swiftUUID();
  const publicKey = base64(keypair.publicKey);
  const privateKey = base64(keypair.secretKey);
  keypair.secretKey.fill(0);
  const signature = signCanonical(
    pqc,
    signedPrekeyPayload({ id, publicKey, issuedAt, expiresAt }),
    local.signing.secretKey,
    "renewed endpoint signed prekey"
  );
  prekeys.signedPrekeyId = id;
  prekeys.signedPrekeyPublicKey = publicKey;
  prekeys.signedPrekeyPrivateKey = privateKey;
  prekeys.signedPrekeySignature = signature;
  prekeys.signedPrekeyIssuedAt = issuedAt;
  prekeys.signedPrekeyExpiresAt = expiresAt;

  const bundle = {
    version: ARCHITECTURE_VERSION,
    identityFingerprint: local.signingFingerprint,
    signedPrekey: { id, publicKey, issuedAt, expiresAt, signature },
    oneTimePrekeys: [],
    createdAt: issuedAt
  };
  const endpointAuthorizationDigest = await certifiedEndpointAuthorizationDigest({
    crypto,
    endpoint
  });
  identity.certifiedGenerationEndpoint = {
    ...endpoint,
    prekeyBundle: bundle,
    prekeyPackageSignature: signCanonical(
      pqc,
      endpointSignedPrekeyPackagePayload({ endpointAuthorizationDigest, bundle }),
      local.signing.secretKey,
      "endpoint signed prekey package"
    )
  };
  return true;
}

export function makeCertifiedNativeContactOffer({ pqc, identity, relayEndpoint }) {
  requireRecord(identity, "Native identity");
  const endpoint = identity.certifiedGenerationEndpoint;
  const checkpoint = identity.endpointSetCheckpoint;
  if (!endpoint || !checkpoint || !canonicalUUID(identity.identityGenerationId)) {
    throw new Error("Identity is not prepared for certified direct-v4 contacts.");
  }
  const unsigned = {
    version: DIRECT_VERSION,
    displayName: identity.displayName,
    inboxId: identity.inboxId,
    relay: relayEndpoint,
    signingPublicKey: identity.signing.publicKey,
    agreementPublicKey: identity.agreement.publicKey,
    inboxAccessPublicKey: identity.access?.publicKey,
    identityGenerationId: identity.identityGenerationId,
    endpointSetCheckpoint: checkpoint,
    preferredGenerationEndpoint: endpoint,
    fingerprint: identity.signingFingerprint
  };
  if (unsigned.inboxAccessPublicKey == null) {
    delete unsigned.inboxAccessPublicKey;
  }
  return {
    ...unsigned,
    signature: signCanonical(pqc, unsigned, identity.signing.secretKey, "contact offer")
  };
}

export async function verifyCertifiedNativeContactOffer({ crypto, pqc, offer, now = Date.now() }) {
  requireCrypto(crypto, pqc);
  validateCertifiedOfferShape(offer);
  const identityPublicKey = decodeBase64(
    offer.signingPublicKey,
    "identity signing public key",
    ML_DSA_PUBLIC_KEY_BYTES
  );
  const identityFingerprint = base64(await crypto.sha256(identityPublicKey));
  if (identityFingerprint !== offer.fingerprint) {
    throw new Error("Contact fingerprint does not match its signing key.");
  }
  if (offer.inboxAccessPublicKey != null && offer.inboxId !== await inboxIdForAccessPublicKey({
    crypto,
    publicKey: offer.inboxAccessPublicKey
  })) {
    throw new Error("Contact inbox does not match its access key.");
  }
  verifyCanonical(
    pqc,
    unsignedCertifiedOffer(offer),
    offer.signature,
    offer.signingPublicKey,
    "contact offer"
  );
  const checkpoint = offer.endpointSetCheckpoint;
  const endpoint = offer.preferredGenerationEndpoint;
  validateCheckpointStructure(checkpoint);
  verifyCanonical(
    pqc,
    checkpointPayload(checkpoint),
    checkpoint.signature,
    offer.signingPublicKey,
    "endpoint manifest checkpoint"
  );
  if (checkpoint.identityFingerprint !== offer.fingerprint ||
      checkpoint.identityGenerationId !== offer.identityGenerationId ||
      endpoint.identityGenerationId !== offer.identityGenerationId ||
      endpoint.identityAuthorityPublicKey !== offer.signingPublicKey ||
      endpoint.manifestEpoch !== checkpoint.epoch ||
      endpoint.manifestDigest !== checkpoint.manifestDigest) {
    throw new Error("Certified endpoint does not match its identity checkpoint.");
  }
  validateEndpointStructure(endpoint, now);
  const endpointPayloadValue = certifiedEndpointPayload(endpoint);
  verifyCanonical(
    pqc,
    endpointPayloadValue,
    endpoint.authoritySignature,
    offer.signingPublicKey,
    "certified endpoint authority"
  );
  verifyCanonical(
    pqc,
    {
      authoritySignature: endpoint.authoritySignature,
      endpoint: endpointPayloadValue,
      purpose: "Noctweave/certified-generation-endpoint-possession/v4"
    },
    endpoint.possessionSignature,
    endpoint.signingPublicKey,
    "certified endpoint possession"
  );
  const endpointAuthorizationDigest = await certifiedEndpointAuthorizationDigest({
    crypto,
    endpoint
  });
  verifyCanonical(
    pqc,
    endpointSignedPrekeyPackagePayload({
      endpointAuthorizationDigest,
      bundle: endpoint.prekeyBundle
    }),
    endpoint.prekeyPackageSignature,
    endpoint.signingPublicKey,
    "endpoint signed prekey package"
  );
  verifyCanonical(
    pqc,
    signedPrekeyPayload(endpoint.prekeyBundle.signedPrekey),
    endpoint.prekeyBundle.signedPrekey.signature,
    endpoint.signingPublicKey,
    "endpoint signed prekey"
  );
  const endpointFingerprint = base64(await crypto.sha256(decodeBase64(
    endpoint.signingPublicKey,
    "endpoint signing public key",
    ML_DSA_PUBLIC_KEY_BYTES
  )));
  if (endpoint.prekeyBundle.identityFingerprint !== endpointFingerprint) {
    throw new Error("Certified endpoint prekey fingerprint is invalid.");
  }
  return offer;
}

export function contactFromNativeOffer(offer, alias) {
  if (offer?.version !== DIRECT_VERSION) {
    throw new Error("Only direct-v4 certified contact offers are supported.");
  }
  const contact = {
    alias: alias || undefined,
    displayName: offer.displayName,
    inboxId: offer.inboxId,
    relay: offer.relay,
    fingerprint: offer.fingerprint,
    signingPublicKey: offer.signingPublicKey,
    agreementPublicKey: offer.agreementPublicKey,
    inboxAccessPublicKey: offer.inboxAccessPublicKey,
    version: DIRECT_VERSION,
    identityGenerationId: offer.identityGenerationId,
    endpointSetCheckpoint: offer.endpointSetCheckpoint,
    preferredGenerationEndpoint: offer.preferredGenerationEndpoint
  };
  return contact;
}

export function isCertifiedNativeContact(contact) {
  return contact?.version === DIRECT_VERSION &&
    canonicalUUID(contact.identityGenerationId) &&
    contact.endpointSetCheckpoint != null &&
    contact.preferredGenerationEndpoint != null;
}

export async function certifiedEndpointDigest({ crypto, endpoint }) {
  return base64(await crypto.sha256(canonicalJsonBytes(endpoint)));
}

export async function certifiedEndpointAuthorizationDigest({ crypto, endpoint }) {
  const reference = {
    authoritySignature: endpoint.authoritySignature,
    endpoint: certifiedEndpointPayload(endpoint),
    possessionSignature: endpoint.possessionSignature
  };
  return base64(await crypto.sha256(canonicalJsonBytes(reference)));
}

export async function derivePairwiseEndpointBindingV4({
  crypto,
  localIdentityGenerationId,
  localIdentitySigningPublicKey,
  localEndpoint,
  peerIdentityGenerationId,
  peerIdentitySigningPublicKey,
  peerEndpoint
}) {
  if (!canonicalUUID(localIdentityGenerationId) || !canonicalUUID(peerIdentityGenerationId) ||
      localEndpoint?.identityGenerationId !== localIdentityGenerationId ||
      peerEndpoint?.identityGenerationId !== peerIdentityGenerationId) {
    throw new Error("Pairwise endpoint identity generation is invalid.");
  }
  decodeBase64(
    localIdentitySigningPublicKey,
    "local identity signing key",
    ML_DSA_PUBLIC_KEY_BYTES
  );
  decodeBase64(
    peerIdentitySigningPublicKey,
    "peer identity signing key",
    ML_DSA_PUBLIC_KEY_BYTES
  );
  // A continuity rotation changes the identity signing key but not the
  // identity generation. Pairwise relationship and endpoint handles must
  // therefore remain stable within that generation; burn creates fresh IDs.
  const localDescriptor = encoder.encode(localIdentityGenerationId.toLowerCase());
  const peerDescriptor = encoder.encode(peerIdentityGenerationId.toLowerCase());
  const ordered = compareBytes(localDescriptor, peerDescriptor) < 0
    ? [localDescriptor, peerDescriptor]
    : [peerDescriptor, localDescriptor];
  const relationshipDigest = await crypto.sha256(concatBytes(
    encoder.encode("Noctweave/pairwise-relationship/v4"),
    ordered[0],
    ordered[1]
  ));
  const relationshipId = uuidFromBytes(relationshipDigest.subarray(0, 16));
  const localCertificateDigest = decodeBase64(
    await certifiedEndpointAuthorizationDigest({ crypto, endpoint: localEndpoint }),
    "local endpoint digest",
    DIGEST_BYTES
  );
  const peerCertificateDigest = decodeBase64(
    await certifiedEndpointAuthorizationDigest({ crypto, endpoint: peerEndpoint }),
    "peer endpoint digest",
    DIGEST_BYTES
  );
  const negotiation = await negotiateNativeDirectV4({
    crypto,
    localEndpoint,
    peerEndpoint
  });
  return {
    relationshipId,
    localEndpointHandle: {
      rawValue: base64(await endpointHandleDigest({
        crypto,
        relationshipId,
        generationId: localIdentityGenerationId,
        endpoint: localEndpoint
      }))
    },
    peerEndpointHandle: {
      rawValue: base64(await endpointHandleDigest({
        crypto,
        relationshipId,
        generationId: peerIdentityGenerationId,
        endpoint: peerEndpoint
      }))
    },
    localCertificateReferenceDigest: base64(await crypto.sha256(concatBytes(
      encoder.encode("Noctweave/pairwise-certificate-reference/v4"),
      encoder.encode(relationshipId.toLowerCase()),
      localCertificateDigest
    ))),
    peerCertificateReferenceDigest: base64(await crypto.sha256(concatBytes(
      encoder.encode("Noctweave/pairwise-certificate-reference/v4"),
      encoder.encode(relationshipId.toLowerCase()),
      peerCertificateDigest
    ))),
    cipherSuite: negotiation.manifest.cipherSuite,
    negotiatedCapabilitiesDigest: negotiation.digest
  };
}

export async function negotiateNativeDirectV4({ crypto, localEndpoint, peerEndpoint }) {
  if (typeof crypto?.sha256 !== "function") {
    throw new TypeError("Direct-v4 negotiation requires SHA-256.");
  }
  const manifest = negotiateDirectV4Capabilities(
    localEndpoint?.capabilities,
    peerEndpoint?.capabilities
  );
  const digest = base64(await crypto.sha256(canonicalJsonBytes(manifest)));
  return Object.freeze({ manifest, digest });
}

export async function deriveNativeDirectV4Binding({ crypto, identity, contact }) {
  if (!isCertifiedNativeContact(contact) || !identity?.certifiedGenerationEndpoint) {
    throw new Error("Certified direct-v4 endpoints are required.");
  }
  return derivePairwiseEndpointBindingV4({
    crypto,
    localIdentityGenerationId: identity.identityGenerationId,
    localIdentitySigningPublicKey: identity.signing.publicKey,
    localEndpoint: identity.certifiedGenerationEndpoint,
    peerIdentityGenerationId: contact.identityGenerationId,
    peerIdentitySigningPublicKey: contact.signingPublicKey,
    peerEndpoint: contact.preferredGenerationEndpoint
  });
}

export async function directV4ConversationId({ crypto, localEndpoint, peerEndpoint, binding }) {
  validateBindingNegotiation(binding);
  const localEntry = concatBytes(
    encoder.encode(binding.localEndpointHandle.rawValue),
    decodeBase64(localEndpoint.agreementPublicKey, "local endpoint agreement key", ML_KEM_PUBLIC_KEY_BYTES)
  );
  const peerEntry = concatBytes(
    encoder.encode(binding.peerEndpointHandle.rawValue),
    decodeBase64(peerEndpoint.agreementPublicKey, "peer endpoint agreement key", ML_KEM_PUBLIC_KEY_BYTES)
  );
  const ordered = compareBytes(localEntry, peerEntry) < 0 ? [localEntry, peerEntry] : [peerEntry, localEntry];
  return base64(await crypto.sha256(concatBytes(
    encoder.encode("Noctweave/direct-endpoint-conversation/v4"),
    directV4SessionBindingBytes(binding),
    ordered[0],
    ordered[1]
  )));
}

export function directV4EndpointSession({ contact, identity, binding }) {
  const local = identity.certifiedGenerationEndpoint;
  const peer = contact.preferredGenerationEndpoint;
  return {
    contactFingerprint: contact.fingerprint,
    localEndpointId: local.endpointId,
    localEndpointHandle: binding.localEndpointHandle,
    localCertificateReferenceDigest: binding.localCertificateReferenceDigest,
    localManifestEpoch: local.manifestEpoch,
    peerEndpointId: peer.endpointId,
    peerEndpointHandle: binding.peerEndpointHandle,
    peerCertificateReferenceDigest: binding.peerCertificateReferenceDigest,
    peerManifestEpoch: peer.manifestEpoch,
    cipherSuite: binding.cipherSuite,
    negotiatedCapabilitiesDigest: binding.negotiatedCapabilitiesDigest
  };
}

export function makeDirectV4AuthenticatedContext({ eventId = swiftUUID(), endpointSession }) {
  if (!canonicalUUID(eventId)) {
    throw new Error("Direct-v4 event ID is invalid.");
  }
  validateEndpointSession(endpointSession);
  return {
    purpose: "directV4",
    directV4: {
      version: DIRECT_VERSION,
      payloadFormat: nativeDirectV4.payloadFormat,
      cipherSuite: endpointSession.cipherSuite,
      negotiatedCapabilitiesDigest: endpointSession.negotiatedCapabilitiesDigest,
      eventId,
      senderEndpointHandle: endpointSession.localEndpointHandle.rawValue,
      senderCertificateDigest: endpointSession.localCertificateReferenceDigest,
      recipientEndpointHandle: endpointSession.peerEndpointHandle.rawValue,
      senderManifestEpoch: endpointSession.localManifestEpoch,
      recipientManifestEpoch: endpointSession.peerManifestEpoch,
      recipientCertificateDigest: endpointSession.peerCertificateReferenceDigest
    }
  };
}

export function validateInboundDirectV4Context({ context, endpointSession }) {
  validateEndpointSession(endpointSession);
  const direct = context?.purpose === "directV4" ? context.directV4 : null;
  if (!direct || direct.version !== DIRECT_VERSION ||
      direct.payloadFormat !== nativeDirectV4.payloadFormat || !canonicalUUID(direct.eventId) ||
      direct.cipherSuite !== endpointSession.cipherSuite ||
      direct.negotiatedCapabilitiesDigest !== endpointSession.negotiatedCapabilitiesDigest ||
      direct.senderEndpointHandle !== endpointSession.peerEndpointHandle.rawValue ||
      direct.senderCertificateDigest !== endpointSession.peerCertificateReferenceDigest ||
      direct.recipientEndpointHandle !== endpointSession.localEndpointHandle.rawValue ||
      direct.recipientCertificateDigest !== endpointSession.localCertificateReferenceDigest ||
      direct.senderManifestEpoch !== endpointSession.peerManifestEpoch ||
      direct.recipientManifestEpoch !== endpointSession.localManifestEpoch) {
    throw new Error("Direct-v4 authenticated context does not match the endpoint session.");
  }
  return direct;
}

export async function createEndpointRemovalProofV4({
  crypto,
  pqc,
  identity,
  issuedAt = swiftISODate()
}) {
  const endpoint = identity?.certifiedGenerationEndpoint;
  const manifest = identity?.endpointSetManifest;
  if (!endpoint || !manifest || manifest.epoch !== endpoint.manifestEpoch) {
    throw new Error("A current certified endpoint is required for revocation.");
  }
  const revokedEpoch = endpoint.manifestEpoch + 1;
  const endpoints = manifest.endpoints.map((record) => record.id === endpoint.endpointId
    ? { ...record, revokedEpoch, revokedAt: issuedAt }
    : record);
  const revokedPayload = {
    version: ARCHITECTURE_VERSION,
    identityGenerationId: manifest.identityGenerationId,
    identityFingerprint: manifest.identityFingerprint,
    epoch: revokedEpoch,
    previousManifestDigest: await certifiedEndpointDigest({ crypto, endpoint: manifest }),
    endpoints,
    issuedAt
  };
  const revokedManifest = {
    ...revokedPayload,
    signature: signCanonical(pqc, revokedPayload, identity.signing.secretKey, "revoked manifest")
  };
  const payload = {
    identityGenerationId: endpoint.identityGenerationId,
    endpointId: endpoint.endpointId,
    certificateDigest: await certifiedEndpointAuthorizationDigest({ crypto, endpoint }),
    manifestEpoch: revokedEpoch,
    manifestDigest: base64(await crypto.sha256(canonicalJsonBytes(revokedManifest))),
    issuedAt
  };
  return {
    ...payload,
    signature: signCanonical(pqc, payload, identity.signing.secretKey, "endpoint revocation")
  };
}

export async function verifyEndpointRemovalProofV4({ crypto, pqc, contact, revocation }) {
  requireRecord(revocation, "Endpoint revocation");
  const endpoint = contact?.preferredGenerationEndpoint;
  if (!endpoint || revocation.identityGenerationId !== endpoint.identityGenerationId ||
      revocation.endpointId !== endpoint.endpointId ||
      revocation.manifestEpoch <= endpoint.manifestEpoch ||
      Date.parse(revocation.issuedAt) < Date.parse(endpoint.issuedAt) ||
      revocation.certificateDigest !== await certifiedEndpointAuthorizationDigest({
        crypto,
        endpoint
      })) {
    throw new Error("Endpoint revocation does not match the certified endpoint.");
  }
  decodeBase64(revocation.manifestDigest, "revoked manifest digest", DIGEST_BYTES);
  verifyCanonical(
    pqc,
    revocationPayload(revocation),
    revocation.signature,
    contact.signingPublicKey,
    "endpoint revocation"
  );
  return revocation;
}

export async function assertContactEndpointActive({
  crypto,
  pqc,
  contact,
  verifySignature = true
}) {
  if (contact?.endpointRevocation == null) {
    return;
  }
  if (!verifySignature || !pqc) {
    throw new Error("Certified endpoint has been revoked.");
  }
  await verifyEndpointRemovalProofV4({
    crypto,
    pqc,
    contact,
    revocation: contact.endpointRevocation
  });
  throw new Error("Certified endpoint has been revoked.");
}

export function assertCertifiedEndpointPrekeyFresh({ endpoint, now = Date.now() }) {
  validateEndpointStructure(endpoint, now);
  return endpoint.prekeyBundle.signedPrekey;
}

function withoutVersion(endpointPayload) {
  const { version: _version, ...endpoint } = endpointPayload;
  return endpoint;
}

function certifiedEndpointPayload(endpoint) {
  return {
    version: DIRECT_VERSION,
    identityGenerationId: endpoint.identityGenerationId,
    identityAuthorityPublicKey: endpoint.identityAuthorityPublicKey,
    manifestEpoch: endpoint.manifestEpoch,
    manifestDigest: endpoint.manifestDigest,
    endpointId: endpoint.endpointId,
    signingPublicKey: endpoint.signingPublicKey,
    agreementPublicKey: endpoint.agreementPublicKey,
    capabilities: endpoint.capabilities,
    issuedAt: endpoint.issuedAt
  };
}

function endpointSignedPrekeyPackagePayload({ endpointAuthorizationDigest, bundle }) {
  return {
    purpose: "Noctweave/endpoint-signed-prekey-package/v4",
    endpointAuthorizationDigest,
    bundle
  };
}

function checkpointPayload(checkpoint) {
  return {
    version: DIRECT_VERSION,
    identityGenerationId: checkpoint.identityGenerationId,
    identityFingerprint: checkpoint.identityFingerprint,
    epoch: checkpoint.epoch,
    manifestDigest: checkpoint.manifestDigest,
    issuedAt: checkpoint.issuedAt
  };
}

function signedPrekeyPayload(prekey) {
  return {
    id: prekey.id,
    publicKey: prekey.publicKey,
    issuedAt: prekey.issuedAt,
    expiresAt: prekey.expiresAt
  };
}

function unsignedCertifiedOffer(offer) {
  const unsigned = {
    version: offer.version,
    displayName: offer.displayName,
    inboxId: offer.inboxId,
    relay: offer.relay,
    signingPublicKey: offer.signingPublicKey,
    agreementPublicKey: offer.agreementPublicKey,
    identityGenerationId: offer.identityGenerationId,
    endpointSetCheckpoint: offer.endpointSetCheckpoint,
    preferredGenerationEndpoint: offer.preferredGenerationEndpoint,
    fingerprint: offer.fingerprint
  };
  if (offer.inboxAccessPublicKey != null) {
    unsigned.inboxAccessPublicKey = offer.inboxAccessPublicKey;
  }
  return unsigned;
}

function revocationPayload(revocation) {
  return {
    identityGenerationId: revocation.identityGenerationId,
    endpointId: revocation.endpointId,
    certificateDigest: revocation.certificateDigest,
    manifestEpoch: revocation.manifestEpoch,
    manifestDigest: revocation.manifestDigest,
    issuedAt: revocation.issuedAt
  };
}

async function validatePreparedIdentity({ crypto, pqc, identity }) {
  const local = identity.localEndpoint;
  const endpoint = identity.certifiedGenerationEndpoint;
  if (endpoint.endpointId !== local.id ||
      endpoint.identityGenerationId !== identity.identityGenerationId ||
      endpoint.signingPublicKey !== local.signing.publicKey ||
      endpoint.agreementPublicKey !== local.agreement.publicKey ||
      endpoint.prekeyBundle?.signedPrekey?.id !== local.prekeys?.signedPrekeyId ||
      endpoint.prekeyBundle?.signedPrekey?.publicKey !== local.prekeys?.signedPrekeyPublicKey ||
      endpoint.prekeyBundle?.signedPrekey?.signature !== local.prekeys?.signedPrekeySignature ||
      endpoint.prekeyBundle?.signedPrekey?.issuedAt !== local.prekeys?.signedPrekeyIssuedAt ||
      endpoint.prekeyBundle?.signedPrekey?.expiresAt !== local.prekeys?.signedPrekeyExpiresAt) {
    throw new Error("Persisted certified endpoint does not match the local endpoint.");
  }
  const offer = makeCertifiedNativeContactOffer({
    pqc,
    identity,
    relayEndpoint: { host: "validation.invalid", port: 1, useTLS: false, transport: "http" }
  });
  await verifyCertifiedNativeContactOffer({
    crypto,
    pqc,
    offer,
    now: Date.parse(endpoint.prekeyBundle.createdAt)
  });
}

function validateCheckpointStructure(checkpoint) {
  requireRecord(checkpoint, "Endpoint manifest checkpoint");
  if (checkpoint.version !== DIRECT_VERSION ||
      !canonicalUUID(checkpoint.identityGenerationId) ||
      !Number.isSafeInteger(checkpoint.epoch) || checkpoint.epoch < 0 ||
      !Number.isFinite(Date.parse(checkpoint.issuedAt))) {
    throw new Error("Endpoint manifest checkpoint is malformed.");
  }
  decodeBase64(checkpoint.identityFingerprint, "checkpoint identity fingerprint", DIGEST_BYTES);
  decodeBase64(checkpoint.manifestDigest, "checkpoint manifest digest", DIGEST_BYTES);
  decodeBase64(checkpoint.signature, "checkpoint signature", ML_DSA_SIGNATURE_BYTES);
}

function validateCertifiedOfferShape(offer) {
  requireRecord(offer, "Certified contact offer");
  if (offer.version !== DIRECT_VERSION || !boundedString(offer.displayName, 512) ||
      !boundedString(offer.inboxId, 256) || !canonicalUUID(offer.identityGenerationId) ||
      !offer.relay || typeof offer.relay !== "object" ||
      offer.endpointSetCheckpoint == null || offer.preferredGenerationEndpoint == null) {
    throw new Error("Certified contact offer is malformed.");
  }
  decodeBase64(offer.signingPublicKey, "identity signing public key", ML_DSA_PUBLIC_KEY_BYTES);
  decodeBase64(offer.agreementPublicKey, "identity agreement public key", ML_KEM_PUBLIC_KEY_BYTES);
  if (offer.inboxAccessPublicKey != null) {
    decodeBase64(offer.inboxAccessPublicKey, "inbox access public key", ML_DSA_PUBLIC_KEY_BYTES);
  }
  decodeBase64(offer.fingerprint, "identity fingerprint", DIGEST_BYTES);
  decodeBase64(offer.signature, "contact offer signature", ML_DSA_SIGNATURE_BYTES);
}

function validateEndpointStructure(endpoint, now) {
  requireRecord(endpoint, "Certified generation endpoint");
  if (!canonicalUUID(endpoint.identityGenerationId) || !canonicalUUID(endpoint.endpointId) ||
      !Number.isSafeInteger(endpoint.manifestEpoch) || endpoint.manifestEpoch < 0 ||
      !Number.isFinite(Date.parse(endpoint.issuedAt))) {
    throw new Error("Certified generation endpoint is malformed.");
  }
  decodeBase64(endpoint.identityAuthorityPublicKey, "endpoint identity authority", ML_DSA_PUBLIC_KEY_BYTES);
  decodeBase64(endpoint.manifestDigest, "endpoint manifest digest", DIGEST_BYTES);
  decodeBase64(endpoint.signingPublicKey, "endpoint signing key", ML_DSA_PUBLIC_KEY_BYTES);
  decodeBase64(endpoint.agreementPublicKey, "endpoint agreement key", ML_KEM_PUBLIC_KEY_BYTES);
  decodeBase64(endpoint.authoritySignature, "endpoint authority signature", ML_DSA_SIGNATURE_BYTES);
  decodeBase64(endpoint.possessionSignature, "endpoint possession signature", ML_DSA_SIGNATURE_BYTES);
  decodeBase64(
    endpoint.prekeyPackageSignature,
    "endpoint signed prekey package signature",
    ML_DSA_SIGNATURE_BYTES
  );
  validateProtocolCapabilityManifest(endpoint.capabilities);
  const bundle = endpoint.prekeyBundle;
  if (bundle?.version !== ARCHITECTURE_VERSION || !Array.isArray(bundle.oneTimePrekeys) ||
      bundle.oneTimePrekeys.length !== 0 || !Number.isFinite(Date.parse(bundle.createdAt))) {
    throw new Error("Certified endpoint prekey bundle is malformed.");
  }
  const signedPrekey = bundle.signedPrekey;
  if (!canonicalUUID(signedPrekey?.id) || !Number.isFinite(Date.parse(signedPrekey?.issuedAt)) ||
      !Number.isFinite(Date.parse(signedPrekey?.expiresAt))) {
    throw new Error("Certified endpoint signed prekey is malformed.");
  }
  decodeBase64(bundle.identityFingerprint, "prekey identity fingerprint", DIGEST_BYTES);
  decodeBase64(signedPrekey.publicKey, "signed prekey public key", ML_KEM_PUBLIC_KEY_BYTES);
  decodeBase64(signedPrekey.signature, "signed prekey signature", ML_DSA_SIGNATURE_BYTES);
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  if (!Number.isFinite(nowMs)) {
    throw new Error("Certified endpoint freshness time is invalid.");
  }
  const issuedAtMs = Date.parse(signedPrekey.issuedAt);
  const expiresAtMs = Date.parse(signedPrekey.expiresAt);
  const createdAtMs = Date.parse(bundle.createdAt);
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > PREKEY_MAX_AGE_MS ||
      issuedAtMs > nowMs + PREKEY_FUTURE_SKEW_MS || nowMs >= expiresAtMs ||
      createdAtMs < issuedAtMs || createdAtMs > expiresAtMs ||
      createdAtMs > nowMs + PREKEY_FUTURE_SKEW_MS) {
    throw new Error("Certified endpoint prekey bundle is expired.");
  }
}

function validateLocalEndpoint(local, generationId) {
  requireRecord(local, "Local endpoint");
  if (!canonicalUUID(local.id) || local.identityGenerationId !== generationId ||
      !Number.isFinite(Date.parse(local.createdAt))) {
    throw new Error("Local endpoint is malformed.");
  }
  validateKeypair(local.signing, "endpoint signing", ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SECRET_KEY_BYTES);
  validateKeypair(local.agreement, "endpoint agreement", ML_KEM_PUBLIC_KEY_BYTES, ML_KEM_SECRET_KEY_BYTES);
}

function validateEndpointSession(session) {
  requireRecord(session, "Direct-v4 endpoint session");
  if (!canonicalUUID(session.localEndpointId) || !canonicalUUID(session.peerEndpointId) ||
      !Number.isSafeInteger(session.localManifestEpoch) || session.localManifestEpoch < 0 ||
      !Number.isSafeInteger(session.peerManifestEpoch) || session.peerManifestEpoch < 0) {
    throw new Error("Direct-v4 endpoint session is malformed.");
  }
  for (const handle of [session.localEndpointHandle, session.peerEndpointHandle]) {
    decodeBase64(handle?.rawValue, "pairwise endpoint handle", DIGEST_BYTES);
  }
  for (const digest of [
    session.localCertificateReferenceDigest,
    session.peerCertificateReferenceDigest,
    session.negotiatedCapabilitiesDigest
  ]) {
    decodeBase64(digest, "pairwise certificate reference", DIGEST_BYTES);
  }
  if (session.cipherSuite !== directV4CipherSuite) {
    throw new Error("Direct-v4 endpoint session cipher suite is invalid.");
  }
}

function validateBindingNegotiation(binding) {
  if (binding?.cipherSuite !== directV4CipherSuite) {
    throw new Error("Direct-v4 binding cipher suite is invalid.");
  }
  decodeBase64(
    binding.negotiatedCapabilitiesDigest,
    "direct-v4 negotiated capabilities digest",
    DIGEST_BYTES
  );
}

export function directV4SessionBindingBytes(binding) {
  validateBindingNegotiation(binding);
  return concatBytes(
    encoder.encode("Noctweave/direct-v4-session-binding/v1"),
    encoder.encode(binding.cipherSuite),
    decodeBase64(
      binding.negotiatedCapabilitiesDigest,
      "direct-v4 negotiated capabilities digest",
      DIGEST_BYTES
    )
  );
}

async function endpointHandleDigest({ crypto, relationshipId, generationId, endpoint }) {
  return crypto.sha256(concatBytes(
    encoder.encode("Noctweave/pairwise-endpoint-handle/v4"),
    encoder.encode(relationshipId.toLowerCase()),
    encoder.encode(generationId.toLowerCase()),
    encoder.encode(endpoint.endpointId.toLowerCase()),
    decodeBase64(endpoint.signingPublicKey, "endpoint signing key", ML_DSA_PUBLIC_KEY_BYTES)
  ));
}

function signCanonical(pqc, payload, secretKeyValue, label) {
  const secretKey = decodeBase64(secretKeyValue, `${label} secret key`, ML_DSA_SECRET_KEY_BYTES);
  try {
    const signature = pqc.sign(canonicalJsonBytes(payload), secretKey);
    if (!(signature instanceof Uint8Array) || signature.byteLength !== ML_DSA_SIGNATURE_BYTES) {
      throw new Error(`${label} signing returned an invalid signature.`);
    }
    return base64(signature);
  } finally {
    secretKey.fill(0);
  }
}

function verifyCanonical(pqc, payload, signatureValue, publicKeyValue, label) {
  const signature = decodeBase64(signatureValue, `${label} signature`, ML_DSA_SIGNATURE_BYTES);
  const publicKey = decodeBase64(publicKeyValue, `${label} public key`, ML_DSA_PUBLIC_KEY_BYTES);
  if (!pqc.verify(canonicalJsonBytes(payload), signature, publicKey)) {
    throw new Error(`${label} signature failed verification.`);
  }
}

function requireCrypto(crypto, pqc) {
  if (typeof crypto?.sha256 !== "function" || typeof pqc?.sign !== "function" ||
      typeof pqc?.verify !== "function" || typeof pqc?.generateSigningKeypair !== "function" ||
      typeof pqc?.generateKemKeypair !== "function") {
    throw new TypeError("Direct-v4 requires compatible post-quantum and SHA-256 primitives.");
  }
}

function validateGeneratedKeypair(pair, label) {
  if (!(pair?.publicKey instanceof Uint8Array) || !(pair?.secretKey instanceof Uint8Array) ||
      pair.publicKey.byteLength !== ML_KEM_PUBLIC_KEY_BYTES ||
      pair.secretKey.byteLength !== ML_KEM_SECRET_KEY_BYTES) {
    throw new Error(`${label} generation failed.`);
  }
}

function validateKeypair(pair, label, publicBytes, secretBytes) {
  requireRecord(pair, `${label} keypair`);
  decodeBase64(pair.publicKey, `${label} public key`, publicBytes);
  decodeBase64(pair.secretKey, `${label} secret key`, secretBytes);
}

function serializeKeypair(pair) {
  return { publicKey: base64(pair.publicKey), secretKey: base64(pair.secretKey) };
}

function decodeBase64(value, label, exactBytes) {
  if (typeof value !== "string" || value.length === 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  const decoded = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  if (decoded.byteLength !== exactBytes || base64(decoded) !== value) {
    throw new Error(`Invalid ${label}.`);
  }
  return decoded;
}

function concatBytes(...values) {
  const length = values.reduce((sum, value) => sum + value.byteLength, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.byteLength;
  }
  return result;
}

function compareBytes(left, right) {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return left.byteLength === right.byteLength ? 0 : left.byteLength < right.byteLength ? -1 : 1;
}

function uuidFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 16) {
    throw new Error("Relationship digest is invalid.");
  }
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function bech32Encode(hrp, data) {
  const words = convertBech32Bits(data, 8, 5, true);
  const values = [...words, ...bech32Checksum(hrp, words)];
  return `${hrp}1${values.map((value) => BECH32_CHARSET[value]).join("")}`;
}

function bech32Checksum(hrp, data) {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const checksum = bech32Polymod(values) ^ 1;
  return Array.from({ length: 6 }, (_, index) =>
    (checksum >>> (5 * (5 - index))) & 31
  );
}

function bech32HrpExpand(value) {
  return [
    ...Array.from(value, (character) => character.charCodeAt(0) >> 5),
    0,
    ...Array.from(value, (character) => character.charCodeAt(0) & 31)
  ];
}

function bech32Polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = (((checksum & 0x1ffffff) << 5) ^ value) >>> 0;
    for (let index = 0; index < 5; index += 1) {
      if ((top >>> index) & 1) checksum = (checksum ^ BECH32_GENERATOR[index]) >>> 0;
    }
  }
  return checksum >>> 0;
}

function convertBech32Bits(data, from, to, pad) {
  let accumulator = 0;
  let bits = 0;
  const output = [];
  const maximum = (1 << to) - 1;
  const maximumAccumulator = (1 << (from + to - 1)) - 1;
  for (const value of data) {
    if (value < 0 || (value >> from) !== 0) {
      throw new Error("Inbox address input is invalid.");
    }
    accumulator = ((accumulator << from) | value) & maximumAccumulator;
    bits += from;
    while (bits >= to) {
      bits -= to;
      output.push((accumulator >> bits) & maximum);
    }
  }
  if (pad && bits > 0) output.push((accumulator << (to - bits)) & maximum);
  return output;
}

function canonicalUUID(value) {
  return typeof value === "string" &&
    /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(value);
}

function boundedString(value, maximumBytes) {
  return typeof value === "string" && value.trim() === value && value.length > 0 &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
}
