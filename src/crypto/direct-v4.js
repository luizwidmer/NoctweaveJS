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

export const nativeDirectV4 = Object.freeze({
  version: DIRECT_VERSION,
  architectureVersion: ARCHITECTURE_VERSION,
  payloadFormat: "nw.wire-payload.v2",
  cipherSuite: directV4CipherSuite
});

export async function preparePairwiseDirectV4Identity({
  crypto,
  pqc,
  localIdentity,
  issuedAt = swiftISODate()
}) {
  const identity = localIdentity;
  requireCrypto(crypto, pqc);
  requireRecord(identity, "Local pairwise identity");
  if (identity.version !== 2 || identity.scope !== "pairwise" ||
      !canonicalUUID(identity.id) || identity.createdAt !== issuedAt) {
    throw new Error("Direct-v4 authority must be freshly scoped to one pairwise relationship.");
  }
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
    await renewPairwiseDirectV4PrekeyIfNeeded({
      crypto,
      pqc,
      localIdentity: identity,
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

export async function renewPairwiseDirectV4PrekeyIfNeeded({
  crypto,
  pqc,
  localIdentity,
  now = Date.now()
}) {
  const identity = localIdentity;
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

/// Verifies the current direct-v4 checkpoint and the one endpoint certificate
/// selected by that checkpoint. Signed carriers share this primitive instead
/// of implementing subtly different endpoint-validation paths.
export async function verifyCertifiedGenerationEndpointV4({
  crypto,
  pqc,
  identityGenerationId,
  identitySigningPublicKey,
  endpointSetCheckpoint,
  preferredEndpoint,
  now = Date.now()
}) {
  if (typeof crypto?.sha256 !== "function" || typeof pqc?.verify !== "function") {
    throw new TypeError("Certified endpoint verification requires SHA-256 and ML-DSA verification.");
  }
  if (!canonicalUUID(identityGenerationId)) {
    throw new Error("Certified endpoint identity generation is malformed.");
  }
  const identityPublicKey = decodeBase64(
    identitySigningPublicKey,
    "identity signing public key",
    ML_DSA_PUBLIC_KEY_BYTES
  );
  const checkpoint = validateEndpointSetCheckpointV4(endpointSetCheckpoint);
  const endpoint = validateCertifiedGenerationEndpointV4(preferredEndpoint, now);
  const identityFingerprint = base64(await crypto.sha256(identityPublicKey));
  verifyCanonical(
    pqc,
    checkpointPayload(checkpoint),
    checkpoint.signature,
    identitySigningPublicKey,
    "endpoint manifest checkpoint"
  );
  if (checkpoint.identityFingerprint !== identityFingerprint ||
      checkpoint.identityGenerationId !== identityGenerationId ||
      endpoint.identityGenerationId !== identityGenerationId ||
      endpoint.identityAuthorityPublicKey !== identitySigningPublicKey ||
      endpoint.manifestEpoch !== checkpoint.epoch ||
      endpoint.manifestDigest !== checkpoint.manifestDigest) {
    throw new Error("Certified endpoint does not match its identity checkpoint.");
  }
  const endpointPayloadValue = certifiedEndpointPayload(endpoint);
  verifyCanonical(
    pqc,
    endpointPayloadValue,
    endpoint.authoritySignature,
    identitySigningPublicKey,
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
  return Object.freeze({
    identityFingerprint,
    endpointSetCheckpoint: checkpoint,
    preferredEndpoint: endpoint
  });
}

export function isPeerPairwiseIdentityV2(peerIdentity) {
  return peerIdentity?.version === 2 &&
    canonicalUUID(peerIdentity.relationshipID) &&
    canonicalUUID(peerIdentity.generationID) &&
    peerIdentity.endpointSetCheckpoint != null &&
    peerIdentity.preferredEndpoint != null &&
    peerIdentity.sendRoutes?.relationshipID === peerIdentity.relationshipID;
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
  relationshipID,
  localIdentityGenerationId,
  localEndpoint,
  localEndpointHandle,
  peerIdentityGenerationId,
  peerEndpoint,
  peerEndpointHandle
}) {
  if (!canonicalUUID(relationshipID) || !canonicalUUID(localIdentityGenerationId) ||
      !canonicalUUID(peerIdentityGenerationId) ||
      localEndpoint?.identityGenerationId !== localIdentityGenerationId ||
      peerEndpoint?.identityGenerationId !== peerIdentityGenerationId) {
    throw new Error("Pairwise endpoint identity generation is invalid.");
  }
  decodeBase64(localEndpointHandle?.rawValue, "local pairwise endpoint handle", DIGEST_BYTES);
  decodeBase64(peerEndpointHandle?.rawValue, "peer pairwise endpoint handle", DIGEST_BYTES);
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
    relationshipId: relationshipID,
    localEndpointHandle: { rawValue: localEndpointHandle.rawValue },
    peerEndpointHandle: { rawValue: peerEndpointHandle.rawValue },
    localCertificateReferenceDigest: base64(await crypto.sha256(concatBytes(
      encoder.encode("Noctweave/pairwise-certificate-reference/v4"),
      encoder.encode(relationshipID.toLowerCase()),
      localCertificateDigest
    ))),
    peerCertificateReferenceDigest: base64(await crypto.sha256(concatBytes(
      encoder.encode("Noctweave/pairwise-certificate-reference/v4"),
      encoder.encode(relationshipID.toLowerCase()),
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

export async function derivePairwiseDirectV4Binding({ crypto, localIdentity, peerIdentity }) {
  if (!isPeerPairwiseIdentityV2(peerIdentity) || !localIdentity?.certifiedGenerationEndpoint ||
      localIdentity.scope !== "pairwise" || localIdentity.relationshipID !== peerIdentity.relationshipID) {
    throw new Error("Certified direct-v4 endpoints are required.");
  }
  return derivePairwiseEndpointBindingV4({
    crypto,
    relationshipID: peerIdentity.relationshipID,
    localIdentityGenerationId: localIdentity.identityGenerationId,
    localEndpoint: localIdentity.certifiedGenerationEndpoint,
    localEndpointHandle: localIdentity.endpointHandle,
    peerIdentityGenerationId: peerIdentity.generationID,
    peerEndpoint: peerIdentity.preferredEndpoint,
    peerEndpointHandle: peerIdentity.sendRoutes.ownerEndpointHandle
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

export function pairwiseDirectV4EndpointSession({ peerIdentity, localIdentity, binding }) {
  const local = localIdentity.certifiedGenerationEndpoint;
  const peer = peerIdentity.preferredEndpoint;
  return {
    relationshipID: peerIdentity.relationshipID,
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

export async function createEndpointRemovalProofV4({
  crypto,
  pqc,
  localIdentity,
  issuedAt = swiftISODate()
}) {
  const identity = localIdentity;
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

export async function verifyEndpointRemovalProofV4({ crypto, pqc, peerIdentity, revocation }) {
  requireRecord(revocation, "Endpoint revocation");
  const endpoint = peerIdentity?.preferredEndpoint;
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
    peerIdentity.signingPublicKey,
    "endpoint revocation"
  );
  return revocation;
}

export async function assertPeerEndpointActive({
  crypto,
  pqc,
  peerIdentity,
  verifySignature = true
}) {
  if (peerIdentity?.endpointRevocation == null) {
    return;
  }
  if (!verifySignature || !pqc) {
    throw new Error("Certified endpoint has been revoked.");
  }
  await verifyEndpointRemovalProofV4({
    crypto,
    pqc,
    peerIdentity,
    revocation: peerIdentity.endpointRevocation
  });
  throw new Error("Certified endpoint has been revoked.");
}

export function assertCertifiedEndpointPrekeyFresh({ endpoint, now = Date.now() }) {
  validateCertifiedGenerationEndpointV4(endpoint, now);
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
  await verifyCertifiedGenerationEndpointV4({
    crypto,
    pqc,
    identityGenerationId: identity.identityGenerationId,
    identitySigningPublicKey: identity.signing.publicKey,
    endpointSetCheckpoint: identity.endpointSetCheckpoint,
    preferredEndpoint: endpoint,
    now: Date.parse(endpoint.prekeyBundle.createdAt)
  });
}

export function validateEndpointSetCheckpointV4(checkpoint) {
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
  return checkpoint;
}

export function validateCertifiedGenerationEndpointV4(endpoint, now = Date.now()) {
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
  return endpoint;
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
