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

/// Prepares one disposable relationship authority and exactly one endpoint.
/// The result deliberately has no reusable endpoint registry, certificate
/// chain, or revocation history.
export async function preparePairwiseDirectV4Identity({
  crypto,
  pqc,
  localIdentity,
  capabilities,
  issuedAt = swiftISODate()
}) {
  const identity = localIdentity;
  requireCrypto(crypto, pqc);
  requireExactRecord(identity, [
    "version",
    "scope",
    "id",
    "relationshipPseudonym",
    "signing",
    "agreement",
    "signingFingerprint",
    "createdAt"
  ], "Local pairwise identity", [
    "localEndpoint",
    "endpointBinding",
    "relationshipID",
    "endpointHandle"
  ]);
  if (identity.version !== 2 || identity.scope !== "pairwise" ||
      !canonicalUUID(identity.id) || identity.createdAt !== issuedAt ||
      typeof identity.relationshipPseudonym !== "string" ||
      identity.relationshipPseudonym.trim() !== identity.relationshipPseudonym ||
      identity.relationshipPseudonym.length === 0 ||
      encoder.encode(identity.relationshipPseudonym).byteLength > 512) {
    throw new Error("Direct-v4 authority must be freshly scoped to one pairwise relationship.");
  }
  validateKeypair(identity.signing, "relationship signing", ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SECRET_KEY_BYTES);
  validateKeypair(identity.agreement, "relationship agreement", ML_KEM_PUBLIC_KEY_BYTES, ML_KEM_SECRET_KEY_BYTES);
  decodeBase64(identity.signingFingerprint, "relationship signing fingerprint", DIGEST_BYTES);
  if (identity.signingFingerprint !== base64(await crypto.sha256(decodeBase64(
    identity.signing.publicKey,
    "relationship signing public key",
    ML_DSA_PUBLIC_KEY_BYTES
  )))) {
    throw new Error("Direct-v4 relationship authority fingerprint is invalid.");
  }
  const endpointCapabilities = capabilities === undefined
    ? validateProtocolCapabilityManifest(
      identity.endpointBinding?.capabilities ?? createProtocolCapabilityManifest()
    )
    : validateProtocolCapabilityManifest(capabilities);

  if (!identity.localEndpoint) {
    const signing = pqc.generateSigningKeypair();
    const agreement = pqc.generateKemKeypair();
    validateSigningKeypair(signing, "relationship endpoint signing");
    validateGeneratedKemKeypair(agreement, "relationship endpoint agreement");
    identity.localEndpoint = {
      signing: serializeKeypair(signing),
      agreement: serializeKeypair(agreement),
      signingFingerprint: base64(await crypto.sha256(signing.publicKey)),
      createdAt: issuedAt
    };
    signing.secretKey.fill(0);
    agreement.secretKey.fill(0);
  }
  validateLocalEndpoint(identity.localEndpoint);

  if (identity.endpointBinding != null) {
    if (JSON.stringify(identity.endpointBinding.capabilities) !== JSON.stringify(endpointCapabilities)) {
      throw new Error("Prepared relationship endpoint capabilities cannot be replaced.");
    }
    await validatePreparedIdentity({ crypto, pqc, identity });
    await renewPairwiseDirectV4PrekeyIfNeeded({
      crypto,
      pqc,
      localIdentity: identity,
      now: Date.parse(issuedAt)
    });
    return identity;
  }
  if (identity.localEndpoint.prekeys != null) {
    throw new Error("Direct-v4 prekey state exists without its relationship endpoint binding.");
  }

  const prekey = createSignedPrekey({ pqc, endpoint: identity.localEndpoint, issuedAt });
  identity.localEndpoint.prekeys = localPrekeyState(prekey);
  const endpointPayload = {
    version: DIRECT_VERSION,
    signingPublicKey: identity.localEndpoint.signing.publicKey,
    agreementPublicKey: identity.localEndpoint.agreement.publicKey,
    capabilities: endpointCapabilities,
    issuedAt
  };
  const authoritySignature = signCanonical(
    pqc,
    endpointPayload,
    identity.signing.secretKey,
    "relationship endpoint authority"
  );
  const endpointAuthorizationDigest = base64(await crypto.sha256(canonicalJsonBytes({
    endpoint: endpointPayload,
    authoritySignature
  })));
  const prekeyBundle = publicPrekeyBundle(identity.localEndpoint, prekey, issuedAt);
  identity.endpointBinding = {
    ...endpointPayload,
    prekeyBundle,
    prekeyPackageSignature: signCanonical(
      pqc,
      endpointPrekeyPackagePayload({ endpointAuthorizationDigest, bundle: prekeyBundle }),
      identity.localEndpoint.signing.secretKey,
      "relationship endpoint prekey package"
    ),
    authoritySignature
  };
  await validatePreparedIdentity({ crypto, pqc, identity });
  return identity;
}

export async function renewPairwiseDirectV4PrekeyIfNeeded({
  crypto,
  pqc,
  localIdentity,
  now = Date.now()
}) {
  requireCrypto(crypto, pqc);
  const identity = localIdentity;
  const local = identity?.localEndpoint;
  const binding = identity?.endpointBinding;
  const prekeys = local?.prekeys;
  if (!local || !binding || !prekeys ||
      binding.signingPublicKey !== local.signing.publicKey ||
      binding.agreementPublicKey !== local.agreement.publicKey) {
    throw new Error("A prepared local direct-v4 relationship endpoint is required for prekey renewal.");
  }
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  if (!Number.isFinite(nowMs)) throw new Error("Direct-v4 prekey renewal time is invalid.");
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
  for (const record of prekeys.retiredSignedPrekeys) validateRetiredPrekey(pqc, local, record);

  const currentExpiryMs = Date.parse(prekeys.signedPrekeyExpiresAt);
  if (!Number.isFinite(currentExpiryMs)) throw new Error("Direct-v4 signed-prekey expiry is invalid.");
  if (currentExpiryMs > nowMs + PREKEY_RENEWAL_LEAD_MS) return false;
  if (nowMs < currentExpiryMs) {
    if (prekeys.retiredSignedPrekeys.length >= MAX_RETIRED_SIGNED_PREKEYS) {
      throw new Error("Direct-v4 retained signed-prekey capacity is exhausted.");
    }
    prekeys.retiredSignedPrekeys.push(currentPrivatePrekey(prekeys));
  }

  const issuedAt = swiftISODate(new Date(nowMs));
  const prekey = createSignedPrekey({ pqc, endpoint: local, issuedAt });
  setCurrentPrekey(prekeys, prekey);
  const bundle = publicPrekeyBundle(local, prekey, issuedAt);
  const endpointAuthorizationDigest = await relationshipEndpointAuthorizationDigestV4({
    crypto,
    endpointBinding: binding
  });
  identity.endpointBinding = {
    ...binding,
    prekeyBundle: bundle,
    prekeyPackageSignature: signCanonical(
      pqc,
      endpointPrekeyPackagePayload({ endpointAuthorizationDigest, bundle }),
      local.signing.secretKey,
      "relationship endpoint prekey package"
    )
  };
  await validatePreparedIdentity({ crypto, pqc, identity });
  return true;
}

export async function verifyRelationshipEndpointBindingV4({
  crypto,
  pqc,
  authoritySigningPublicKey,
  endpointBinding,
  now = Date.now()
}) {
  if (typeof crypto?.sha256 !== "function" || typeof pqc?.verify !== "function") {
    throw new TypeError("Relationship endpoint verification requires SHA-256 and ML-DSA verification.");
  }
  decodeBase64(authoritySigningPublicKey, "relationship authority signing key", ML_DSA_PUBLIC_KEY_BYTES);
  const binding = validateRelationshipEndpointBindingV4(endpointBinding, now);
  verifyCanonical(
    pqc,
    endpointAuthorityPayload(binding),
    binding.authoritySignature,
    authoritySigningPublicKey,
    "relationship endpoint authority"
  );
  const endpointAuthorizationDigest = await relationshipEndpointAuthorizationDigestV4({
    crypto,
    endpointBinding: binding
  });
  verifyCanonical(
    pqc,
    endpointPrekeyPackagePayload({
      endpointAuthorizationDigest,
      bundle: binding.prekeyBundle
    }),
    binding.prekeyPackageSignature,
    binding.signingPublicKey,
    "relationship endpoint prekey package"
  );
  verifyCanonical(
    pqc,
    signedPrekeyPayload(binding.prekeyBundle.signedPrekey),
    binding.prekeyBundle.signedPrekey.signature,
    binding.signingPublicKey,
    "relationship endpoint signed prekey"
  );
  const relationshipSigningKeyDigest = base64(await crypto.sha256(decodeBase64(
    binding.signingPublicKey,
    "relationship endpoint signing key",
    ML_DSA_PUBLIC_KEY_BYTES
  )));
  if (binding.prekeyBundle.relationshipSigningKeyDigest !== relationshipSigningKeyDigest) {
    throw new Error("Relationship endpoint prekey signing-key digest is invalid.");
  }
  return binding;
}

export function isPeerPairwiseIdentityV2(peerIdentity) {
  const fields = [
    "version",
    "id",
    "relationshipID",
    "relationshipPseudonym",
    "signingPublicKey",
    "agreementPublicKey",
    "endpointBinding",
    "sendRoutes",
    "createdAt"
  ];
  return peerIdentity != null && typeof peerIdentity === "object" && !Array.isArray(peerIdentity) &&
    Object.keys(peerIdentity).length === fields.length &&
    fields.every((field) => Object.hasOwn(peerIdentity, field)) &&
    peerIdentity.version === 2 &&
    canonicalUUID(peerIdentity.id) &&
    canonicalUUID(peerIdentity.relationshipID) &&
    typeof peerIdentity.relationshipPseudonym === "string" &&
    peerIdentity.relationshipPseudonym.trim() === peerIdentity.relationshipPseudonym &&
    peerIdentity.relationshipPseudonym.length > 0 &&
    peerIdentity.endpointBinding != null &&
    peerIdentity.sendRoutes?.relationshipID === peerIdentity.relationshipID;
}

/// Stable across signed-prekey renewal, but unique to this disposable
/// relationship endpoint authorization.
export async function relationshipEndpointAuthorizationDigestV4({ crypto, endpointBinding }) {
  if (typeof crypto?.sha256 !== "function") throw new TypeError("Endpoint digest requires SHA-256.");
  validateRelationshipEndpointBindingV4(
    endpointBinding,
    endpointBinding?.prekeyBundle?.createdAt
  );
  const reference = {
    endpoint: endpointAuthorityPayload(endpointBinding),
    authoritySignature: endpointBinding.authoritySignature
  };
  return base64(await crypto.sha256(canonicalJsonBytes(reference)));
}

export async function derivePairwiseEndpointBindingV4({
  crypto,
  relationshipID,
  localEndpointBinding,
  localEndpointHandle,
  peerEndpointBinding,
  peerEndpointHandle
}) {
  if (!canonicalUUID(relationshipID)) throw new Error("Pairwise relationship ID is invalid.");
  decodeBase64(localEndpointHandle?.rawValue, "local pairwise endpoint handle", DIGEST_BYTES);
  decodeBase64(peerEndpointHandle?.rawValue, "peer pairwise endpoint handle", DIGEST_BYTES);
  if (localEndpointHandle.rawValue === peerEndpointHandle.rawValue) {
    throw new Error("Pairwise endpoint handles must be distinct.");
  }
  const localAuthorization = decodeBase64(
    await relationshipEndpointAuthorizationDigestV4({ crypto, endpointBinding: localEndpointBinding }),
    "local endpoint authorization digest",
    DIGEST_BYTES
  );
  const peerAuthorization = decodeBase64(
    await relationshipEndpointAuthorizationDigestV4({ crypto, endpointBinding: peerEndpointBinding }),
    "peer endpoint authorization digest",
    DIGEST_BYTES
  );
  const negotiation = await negotiateNativeDirectV4({
    crypto,
    localEndpoint: localEndpointBinding,
    peerEndpoint: peerEndpointBinding
  });
  return {
    relationshipId: relationshipID,
    localEndpointHandle: { rawValue: localEndpointHandle.rawValue },
    peerEndpointHandle: { rawValue: peerEndpointHandle.rawValue },
    localBindingReferenceDigest: await relationshipBindingReferenceDigest({
      crypto,
      relationshipID,
      authorizationDigest: localAuthorization
    }),
    peerBindingReferenceDigest: await relationshipBindingReferenceDigest({
      crypto,
      relationshipID,
      authorizationDigest: peerAuthorization
    }),
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
  if (!isPeerPairwiseIdentityV2(peerIdentity) || !localIdentity?.endpointBinding ||
      localIdentity.scope !== "pairwise" || localIdentity.relationshipID !== peerIdentity.relationshipID) {
    throw new Error("Direct-v4 relationship endpoint bindings are required.");
  }
  return derivePairwiseEndpointBindingV4({
    crypto,
    relationshipID: peerIdentity.relationshipID,
    localEndpointBinding: localIdentity.endpointBinding,
    localEndpointHandle: localIdentity.endpointHandle,
    peerEndpointBinding: peerIdentity.endpointBinding,
    peerEndpointHandle: peerIdentity.sendRoutes.ownerEndpointHandle
  });
}

export function directV4ConversationId({ binding }) {
  validateBindingNegotiation(binding);
  return binding.relationshipId.toLowerCase();
}

export function pairwiseDirectV4EndpointSession({ peerIdentity, binding }) {
  const session = {
    relationshipID: peerIdentity.relationshipID,
    localEndpointHandle: binding.localEndpointHandle,
    localBindingReferenceDigest: binding.localBindingReferenceDigest,
    peerEndpointHandle: binding.peerEndpointHandle,
    peerBindingReferenceDigest: binding.peerBindingReferenceDigest
  };
  validateEndpointSessionIdentity(session);
  return session;
}

export function assertRelationshipEndpointPrekeyFresh({ endpointBinding, now = Date.now() }) {
  validateRelationshipEndpointBindingV4(endpointBinding, now);
  return endpointBinding.prekeyBundle.signedPrekey;
}

export function validateRelationshipEndpointBindingV4(endpointBinding, now = Date.now()) {
  requireExactRecord(endpointBinding, [
    "version",
    "signingPublicKey",
    "agreementPublicKey",
    "capabilities",
    "prekeyBundle",
    "prekeyPackageSignature",
    "issuedAt",
    "authoritySignature"
  ], "Relationship endpoint binding");
  if (endpointBinding.version !== DIRECT_VERSION || !Number.isFinite(Date.parse(endpointBinding.issuedAt))) {
    throw new Error("Relationship endpoint binding is malformed.");
  }
  decodeBase64(endpointBinding.signingPublicKey, "endpoint signing key", ML_DSA_PUBLIC_KEY_BYTES);
  decodeBase64(endpointBinding.agreementPublicKey, "endpoint agreement key", ML_KEM_PUBLIC_KEY_BYTES);
  decodeBase64(endpointBinding.authoritySignature, "endpoint authority signature", ML_DSA_SIGNATURE_BYTES);
  decodeBase64(endpointBinding.prekeyPackageSignature, "endpoint prekey package signature", ML_DSA_SIGNATURE_BYTES);
  validateProtocolCapabilityManifest(endpointBinding.capabilities);
  validatePublicPrekeyBundle(endpointBinding.prekeyBundle, endpointBinding.issuedAt, now);
  return endpointBinding;
}

export function directV4SessionBindingBytes(binding) {
  validateBindingNegotiation(binding);
  return concatBytes(
    encoder.encode(binding.relationshipId.toLowerCase()),
    encoder.encode(binding.cipherSuite),
    decodeBase64(binding.negotiatedCapabilitiesDigest, "direct-v4 negotiated capabilities digest", DIGEST_BYTES)
  );
}

function endpointAuthorityPayload(endpointBinding) {
  return {
    version: DIRECT_VERSION,
    signingPublicKey: endpointBinding.signingPublicKey,
    agreementPublicKey: endpointBinding.agreementPublicKey,
    capabilities: endpointBinding.capabilities,
    issuedAt: endpointBinding.issuedAt
  };
}

function endpointPrekeyPackagePayload({ endpointAuthorizationDigest, bundle }) {
  return {
    purpose: "Noctweave/relationship-endpoint-prekey-package/v4",
    endpointAuthorizationDigest,
    bundle
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

function createSignedPrekey({ pqc, endpoint, issuedAt }) {
  const pair = pqc.generateKemKeypair();
  validateGeneratedKemKeypair(pair, "relationship endpoint signed prekey");
  const record = {
    id: swiftUUID(),
    publicKey: base64(pair.publicKey),
    privateKey: base64(pair.secretKey),
    issuedAt,
    expiresAt: swiftISODate(new Date(Date.parse(issuedAt) + PREKEY_MAX_AGE_MS))
  };
  pair.secretKey.fill(0);
  record.signature = signCanonical(
    pqc,
    signedPrekeyPayload(record),
    endpoint.signing.secretKey,
    "relationship endpoint signed prekey"
  );
  return record;
}

function publicPrekeyBundle(endpoint, prekey, createdAt) {
  return {
    version: ARCHITECTURE_VERSION,
    relationshipSigningKeyDigest: endpoint.signingFingerprint,
    signedPrekey: {
      id: prekey.id,
      publicKey: prekey.publicKey,
      issuedAt: prekey.issuedAt,
      expiresAt: prekey.expiresAt,
      signature: prekey.signature
    },
    oneTimePrekeys: [],
    createdAt
  };
}

function localPrekeyState(prekey) {
  return {
    signedPrekeyId: prekey.id,
    signedPrekeyPublicKey: prekey.publicKey,
    signedPrekeyPrivateKey: prekey.privateKey,
    signedPrekeySignature: prekey.signature,
    signedPrekeyIssuedAt: prekey.issuedAt,
    signedPrekeyExpiresAt: prekey.expiresAt,
    retiredSignedPrekeys: [],
    oneTimePrekeys: []
  };
}

function setCurrentPrekey(state, prekey) {
  state.signedPrekeyId = prekey.id;
  state.signedPrekeyPublicKey = prekey.publicKey;
  state.signedPrekeyPrivateKey = prekey.privateKey;
  state.signedPrekeySignature = prekey.signature;
  state.signedPrekeyIssuedAt = prekey.issuedAt;
  state.signedPrekeyExpiresAt = prekey.expiresAt;
}

function currentPrivatePrekey(state) {
  return {
    id: state.signedPrekeyId,
    publicKey: state.signedPrekeyPublicKey,
    privateKey: state.signedPrekeyPrivateKey,
    signature: state.signedPrekeySignature,
    issuedAt: state.signedPrekeyIssuedAt,
    expiresAt: state.signedPrekeyExpiresAt
  };
}

function validateRetiredPrekey(pqc, endpoint, record) {
  if (!canonicalUUID(record.id) || Date.parse(record.expiresAt) <= Date.parse(record.issuedAt) ||
      Date.parse(record.expiresAt) - Date.parse(record.issuedAt) > PREKEY_MAX_AGE_MS) {
    throw new Error("Direct-v4 retained signed-prekey record is malformed.");
  }
  decodeBase64(record.publicKey, "retained signed prekey public key", ML_KEM_PUBLIC_KEY_BYTES);
  decodeBase64(record.privateKey, "retained signed prekey private key", ML_KEM_SECRET_KEY_BYTES);
  verifyCanonical(pqc, signedPrekeyPayload(record), record.signature, endpoint.signing.publicKey,
    "retained relationship endpoint signed prekey");
}

function validatePublicPrekeyBundle(bundle, endpointIssuedAt, now) {
  requireExactRecord(bundle, [
    "version", "relationshipSigningKeyDigest", "signedPrekey", "oneTimePrekeys", "createdAt"
  ], "Relationship endpoint prekey bundle");
  if (bundle.version !== ARCHITECTURE_VERSION || !Array.isArray(bundle.oneTimePrekeys) ||
      bundle.oneTimePrekeys.length !== 0 || !Number.isFinite(Date.parse(bundle.createdAt)) ||
      Date.parse(bundle.createdAt) < Date.parse(endpointIssuedAt)) {
    throw new Error("Relationship endpoint prekey bundle is malformed.");
  }
  decodeBase64(
    bundle.relationshipSigningKeyDigest,
    "prekey relationship signing-key digest",
    DIGEST_BYTES
  );
  const signed = bundle.signedPrekey;
  requireExactRecord(signed, ["id", "publicKey", "issuedAt", "expiresAt", "signature"],
    "Relationship endpoint signed prekey");
  if (!canonicalUUID(signed.id) || !Number.isFinite(Date.parse(signed.issuedAt)) ||
      !Number.isFinite(Date.parse(signed.expiresAt))) {
    throw new Error("Relationship endpoint signed prekey is malformed.");
  }
  decodeBase64(signed.publicKey, "signed prekey public key", ML_KEM_PUBLIC_KEY_BYTES);
  decodeBase64(signed.signature, "signed prekey signature", ML_DSA_SIGNATURE_BYTES);
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  const issuedAtMs = Date.parse(signed.issuedAt);
  const expiresAtMs = Date.parse(signed.expiresAt);
  const createdAtMs = Date.parse(bundle.createdAt);
  if (!Number.isFinite(nowMs) || expiresAtMs <= issuedAtMs ||
      expiresAtMs - issuedAtMs > PREKEY_MAX_AGE_MS ||
      issuedAtMs > nowMs + PREKEY_FUTURE_SKEW_MS || nowMs >= expiresAtMs ||
      createdAtMs < issuedAtMs || createdAtMs > expiresAtMs ||
      createdAtMs > nowMs + PREKEY_FUTURE_SKEW_MS) {
    throw new Error("Relationship endpoint prekey bundle is expired.");
  }
}

async function validatePreparedIdentity({ crypto, pqc, identity }) {
  const local = identity.localEndpoint;
  const binding = identity.endpointBinding;
  const signed = binding.prekeyBundle?.signedPrekey;
  if (binding.signingPublicKey !== local.signing.publicKey ||
      binding.agreementPublicKey !== local.agreement.publicKey ||
      signed?.id !== local.prekeys?.signedPrekeyId ||
      signed?.publicKey !== local.prekeys?.signedPrekeyPublicKey ||
      signed?.signature !== local.prekeys?.signedPrekeySignature ||
      signed?.issuedAt !== local.prekeys?.signedPrekeyIssuedAt ||
      signed?.expiresAt !== local.prekeys?.signedPrekeyExpiresAt) {
    throw new Error("Persisted relationship endpoint binding does not match local endpoint state.");
  }
  await verifyRelationshipEndpointBindingV4({
    crypto,
    pqc,
    authoritySigningPublicKey: identity.signing.publicKey,
    endpointBinding: binding,
    now: Date.parse(binding.prekeyBundle.createdAt)
  });
}

async function relationshipBindingReferenceDigest({ crypto, relationshipID, authorizationDigest }) {
  return base64(await crypto.sha256(concatBytes(
    encoder.encode("Noctweave/relationship-endpoint-binding-reference/v4"),
    new Uint8Array([0]),
    encoder.encode(relationshipID.toLowerCase()),
    new Uint8Array([0]),
    authorizationDigest
  )));
}

function validateLocalEndpoint(endpoint) {
  requireExactRecord(endpoint, ["signing", "agreement", "signingFingerprint", "createdAt"],
    "Local relationship endpoint", ["prekeys"]);
  if (!Number.isFinite(Date.parse(endpoint.createdAt))) throw new Error("Local relationship endpoint is malformed.");
  validateKeypair(endpoint.signing, "endpoint signing", ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SECRET_KEY_BYTES);
  validateKeypair(endpoint.agreement, "endpoint agreement", ML_KEM_PUBLIC_KEY_BYTES, ML_KEM_SECRET_KEY_BYTES);
  decodeBase64(endpoint.signingFingerprint, "endpoint signing fingerprint", DIGEST_BYTES);
}

function validateBindingNegotiation(binding) {
  requireExactRecord(binding, [
    "relationshipId",
    "localEndpointHandle",
    "peerEndpointHandle",
    "localBindingReferenceDigest",
    "peerBindingReferenceDigest",
    "cipherSuite",
    "negotiatedCapabilitiesDigest"
  ], "Direct-v4 binding");
  if (!/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u.test(
    binding.relationshipId
  )) {
    throw new Error("Direct-v4 binding relationship is invalid.");
  }
  requireExactRecord(binding.localEndpointHandle, ["rawValue"], "Local endpoint handle");
  requireExactRecord(binding.peerEndpointHandle, ["rawValue"], "Peer endpoint handle");
  decodeBase64(binding.localEndpointHandle.rawValue, "local endpoint handle", DIGEST_BYTES);
  decodeBase64(binding.peerEndpointHandle.rawValue, "peer endpoint handle", DIGEST_BYTES);
  decodeBase64(binding.localBindingReferenceDigest, "local endpoint binding reference", DIGEST_BYTES);
  decodeBase64(binding.peerBindingReferenceDigest, "peer endpoint binding reference", DIGEST_BYTES);
  if (binding.cipherSuite !== directV4CipherSuite) throw new Error("Direct-v4 binding cipher suite is invalid.");
  decodeBase64(binding.negotiatedCapabilitiesDigest, "direct-v4 negotiated capabilities digest", DIGEST_BYTES);
}

function validateEndpointSessionIdentity(session) {
  requireExactRecord(session, [
    "relationshipID",
    "localEndpointHandle",
    "localBindingReferenceDigest",
    "peerEndpointHandle",
    "peerBindingReferenceDigest"
  ], "Direct endpoint session");
  if (!canonicalUUID(session.relationshipID)) {
    throw new Error("Direct endpoint session relationship is invalid.");
  }
  for (const [field, label] of [
    ["localEndpointHandle", "local endpoint handle"],
    ["peerEndpointHandle", "peer endpoint handle"]
  ]) {
    requireExactRecord(session[field], ["rawValue"], label);
    decodeBase64(session[field].rawValue, label, DIGEST_BYTES);
  }
  decodeBase64(
    session.localBindingReferenceDigest,
    "local endpoint binding reference",
    DIGEST_BYTES
  );
  decodeBase64(
    session.peerBindingReferenceDigest,
    "peer endpoint binding reference",
    DIGEST_BYTES
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

function validateGeneratedKemKeypair(pair, label) {
  if (!(pair?.publicKey instanceof Uint8Array) || !(pair?.secretKey instanceof Uint8Array) ||
      pair.publicKey.byteLength !== ML_KEM_PUBLIC_KEY_BYTES || pair.secretKey.byteLength !== ML_KEM_SECRET_KEY_BYTES) {
    throw new Error(`${label} creation failed.`);
  }
}

function validateSigningKeypair(pair, label) {
  if (!(pair?.publicKey instanceof Uint8Array) || !(pair?.secretKey instanceof Uint8Array) ||
      pair.publicKey.byteLength !== ML_DSA_PUBLIC_KEY_BYTES || pair.secretKey.byteLength !== ML_DSA_SECRET_KEY_BYTES) {
    throw new Error(`${label} creation failed.`);
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
  if (decoded.byteLength !== exactBytes || base64(decoded) !== value) throw new Error(`Invalid ${label}.`);
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

function canonicalUUID(value) {
  return typeof value === "string" &&
    /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(value);
}

function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
}

function requireExactRecord(value, required, label, optional = []) {
  requireRecord(value, label);
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (required.some((key) => !Object.hasOwn(value, key)) || keys.some((key) => !allowed.has(key))) {
    throw new TypeError(`${label} fields do not match the current protocol.`);
  }
}
