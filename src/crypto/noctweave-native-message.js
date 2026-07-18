import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./swift-canonical.js";
import {
  contentTypeCanonicalName,
  createConversationEvent,
  createTextEncodedContent,
  standardContentTypes,
  validateConversationEvent,
  validateEncodedContent
} from "../architecture-v2.js";

export class NoctweaveRemoteEnvelopeError extends Error {
  constructor(reason, message, options) {
    super(message, options);
    this.name = "NoctweaveRemoteEnvelopeError";
    this.reason = reason;
  }
}
import {
  assertRelationshipEndpointPrekeyFresh,
  derivePairwiseDirectV4Binding,
  directV4ConversationId,
  pairwiseDirectV4EndpointSession,
  directV4SessionBindingBytes,
  isPeerPairwiseIdentityV2,
  negotiateNativeDirectV4,
  verifyRelationshipEndpointBindingV4
} from "./direct-v4.js";
import {
  directEnvelopeV4AuthenticatedDataBytes,
  directEnvelopeV4SignableBytes,
  validateDirectBootstrapV4,
  validateDirectEnvelopeV4
} from "./noctweave-wire.js";
import {
  createApplicationWirePayloadV2,
  validateWirePayloadV2
} from "../relationship-control-v2.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const strictUTF8Decoder = new TextDecoder("utf-8", { fatal: true });
const unsafeDisplayControls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;
const NPAD_V2_MAGIC = new Uint8Array([0x4e, 0x50, 0x41, 0x44, 0x02]);
const NPAD_HEADER_BYTES = 9;
const MIN_PADDED_BYTES = 512;
const MAX_PADDED_BYTES = 65_536;
const MAX_SKIP = 64;
const ML_KEM_PUBLIC_KEY_BYTES = 1_184;
const ML_KEM_SECRET_KEY_BYTES = 2_400;
const ML_KEM_CIPHERTEXT_BYTES = 1_088;
const ML_DSA_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_SECRET_KEY_BYTES = 4_032;
const ML_DSA_SIGNATURE_BYTES = 3_309;
const PREKEY_MAX_AGE_MS = 8 * 86_400_000;
const PREKEY_FUTURE_SKEW_MS = 5 * 60_000;

export async function createNativeOutboundSession({
  crypto,
  pqc,
  localIdentity,
  peerIdentity,
  now = Date.now()
}) {
  requirePeerPairwiseIdentity(peerIdentity);
  await verifyRelationshipEndpointBindingV4({
    crypto,
    pqc,
    authoritySigningPublicKey: peerIdentity.signingPublicKey,
    endpointBinding: peerIdentity.endpointBinding,
    now
  });
  const peerEndpoint = peerIdentity.endpointBinding;
  assertRelationshipEndpointPrekeyFresh({ endpointBinding: peerEndpoint, now });
  const localEndpoint = localIdentity.endpointBinding;
  const binding = await derivePairwiseDirectV4Binding({ crypto, localIdentity, peerIdentity });
  const { manifest: negotiation } = await validateCurrentDirectV4Negotiation({
    crypto,
    localIdentity,
    peerIdentity,
    binding
  });
  validateNegotiatedPrekeyFreshness(
    peerEndpoint.prekeyBundle.signedPrekey,
    negotiation,
    now
  );
  const recipientKey = fromBase64(
    peerEndpoint.prekeyBundle.signedPrekey.publicKey,
    "peer signed prekey",
    ML_KEM_PUBLIC_KEY_BYTES,
    ML_KEM_PUBLIC_KEY_BYTES
  );
  const ownAgreementKey = fromBase64(
    localIdentity.localEndpoint.agreement.publicKey,
    "local endpoint agreement key",
    ML_KEM_PUBLIC_KEY_BYTES,
    ML_KEM_PUBLIC_KEY_BYTES
  );
  const encapsulated = pqc.encapsulate(recipientKey);
  try {
    const endpointSession = pairwiseDirectV4EndpointSession({ peerIdentity, localIdentity, binding });
    const conversation = await conversationFromSharedSecret({
      crypto,
      sharedSecret: encapsulated.sharedSecret,
      ownAgreementPublicKey: ownAgreementKey,
      peerAgreementPublicKey: fromBase64(
        peerEndpoint.agreementPublicKey,
        "peer endpoint agreement key",
        ML_KEM_PUBLIC_KEY_BYTES,
        ML_KEM_PUBLIC_KEY_BYTES
      ),
      relationshipID: peerIdentity.relationshipID,
      conversationId: directV4ConversationId({ binding }),
      endpointSession,
      binding
    });
    return {
      conversation,
      bootstrap: {
        kind: "signedPrekey",
        kemCiphertext: base64(encapsulated.ciphertext),
        prekey: {
          kind: "signed",
          id: peerEndpoint.prekeyBundle.signedPrekey.id
        }
      }
    };
  } finally {
    wipeBytes(encapsulated.sharedSecret);
    wipeBytes(ownAgreementKey);
  }
}

export async function createNativeInboundSession({
  crypto,
  pqc,
  localIdentity,
  peerIdentity,
  bootstrap,
  now = Date.now()
}) {
  requirePeerPairwiseIdentity(peerIdentity);
  await verifyRelationshipEndpointBindingV4({
    crypto,
    pqc,
    authoritySigningPublicKey: peerIdentity.signingPublicKey,
    endpointBinding: peerIdentity.endpointBinding,
    now
  });
  const local = localIdentity.localEndpoint;
  const localEndpoint = localIdentity.endpointBinding;
  const peerEndpoint = peerIdentity.endpointBinding;
  const validatedBootstrap = validateDirectBootstrapV4(bootstrap);
  if (validatedBootstrap.kind !== "signedPrekey") {
    throw new Error("Direct-v4 bootstrap does not target the local signed prekey.");
  }
  const prekeyRecord = localSignedPrekeyForBootstrap({
    pqc,
    local,
    prekeyId: validatedBootstrap.prekey.id,
    now
  });
  const prekeySecret = fromBase64(
    prekeyRecord.privateKey,
    "local endpoint signed prekey",
    ML_KEM_SECRET_KEY_BYTES,
    ML_KEM_SECRET_KEY_BYTES
  );
  let sharedSecret;
  try {
    sharedSecret = pqc.decapsulate(
      fromBase64(
        validatedBootstrap.kemCiphertext,
        "KEM ciphertext",
        ML_KEM_CIPHERTEXT_BYTES,
        ML_KEM_CIPHERTEXT_BYTES
      ),
      prekeySecret
    );
    const binding = await derivePairwiseDirectV4Binding({ crypto, localIdentity, peerIdentity });
    const { manifest: negotiation } = await validateCurrentDirectV4Negotiation({
      crypto,
      localIdentity,
      peerIdentity,
      binding
    });
    validateNegotiatedPrekeyFreshness(prekeyRecord, negotiation, now);
    return await conversationFromSharedSecret({
      crypto,
      sharedSecret,
      ownAgreementPublicKey: fromBase64(
        local.agreement.publicKey,
        "local endpoint agreement key",
        ML_KEM_PUBLIC_KEY_BYTES,
        ML_KEM_PUBLIC_KEY_BYTES
      ),
      peerAgreementPublicKey: fromBase64(
        peerEndpoint.agreementPublicKey,
        "peer endpoint agreement key",
        ML_KEM_PUBLIC_KEY_BYTES,
        ML_KEM_PUBLIC_KEY_BYTES
      ),
      relationshipID: peerIdentity.relationshipID,
      conversationId: directV4ConversationId({ binding }),
      endpointSession: pairwiseDirectV4EndpointSession({ peerIdentity, localIdentity, binding }),
      binding
    });
  } finally {
    wipeBytes(sharedSecret);
    wipeBytes(prekeySecret);
  }
}

function localSignedPrekeyForBootstrap({ pqc, local, prekeyId, now }) {
  const prekeys = local?.prekeys;
  const current = prekeys?.signedPrekeyId === prekeyId
    ? {
        id: prekeys.signedPrekeyId,
        publicKey: prekeys.signedPrekeyPublicKey,
        privateKey: prekeys.signedPrekeyPrivateKey,
        signature: prekeys.signedPrekeySignature,
        issuedAt: prekeys.signedPrekeyIssuedAt,
        expiresAt: prekeys.signedPrekeyExpiresAt
      }
    : null;
  const record = current ?? prekeys?.retiredSignedPrekeys?.find(({ id }) => id === prekeyId);
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  const issuedAtMs = Date.parse(record?.issuedAt);
  const expiresAtMs = Date.parse(record?.expiresAt);
  if (!record || !Number.isFinite(nowMs) || !Number.isFinite(issuedAtMs) ||
      !Number.isFinite(expiresAtMs) || expiresAtMs <= issuedAtMs ||
      expiresAtMs - issuedAtMs > PREKEY_MAX_AGE_MS || nowMs >= expiresAtMs ||
      issuedAtMs > nowMs + PREKEY_FUTURE_SKEW_MS) {
    throw new Error("Direct-v4 bootstrap targets an expired or unknown signed prekey.");
  }
  const signature = fromBase64(
    record.signature,
    "local signed prekey signature",
    ML_DSA_SIGNATURE_BYTES,
    ML_DSA_SIGNATURE_BYTES
  );
  const signingPublicKey = fromBase64(
    local.signing.publicKey,
    "local endpoint signing key",
    ML_DSA_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES
  );
  if (!pqc.verify(canonicalJsonBytes({
    id: record.id,
    publicKey: record.publicKey,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt
  }), signature, signingPublicKey)) {
    throw new Error("Direct-v4 local signed prekey signature is invalid.");
  }
  return record;
}

export async function encryptNativeTextEnvelope(options) {
  return encryptNativeEnvelopePayload({ ...options, content: null, relation: null });
}

// Encrypts one typed direct-v4 application event. Security-sensitive control
// payloads intentionally use a separate closed path and are never accepted by
// this extensible application API.
export async function encryptNativeApplicationEnvelope(options) {
  if (!isPeerPairwiseIdentityV2(options?.peerIdentity)) {
    throw new Error("Typed application envelopes require a verified pairwise peer.");
  }
  const eventKind = options.eventKind ?? "application";
  if (eventKind !== "application" && eventKind !== "receipt") {
    throw new Error("The extensible direct-v4 path accepts only application and receipt events.");
  }
  return encryptNativeEnvelopePayload({
    ...options,
    text: null,
    content: validateEncodedContent(options.content),
    relation: options.relation ?? null,
    eventKind
  });
}

async function encryptNativeEnvelopePayload({
  crypto,
  pqc,
  localIdentity,
  peerIdentity,
  conversation,
  text,
  content,
  relation,
  eventKind = "application",
  bootstrap = { kind: "none" },
  eventId = swiftUUID(),
  clientTransactionId = swiftUUID(),
  sentAt = swiftISODate()
}) {
  requirePeerPairwiseIdentity(peerIdentity);
  const negotiated = await validateCurrentDirectV4Negotiation({
    crypto,
    localIdentity,
    peerIdentity,
    endpointSession: conversation.endpointSession
  });
  const negotiation = negotiated.manifest;
  const binding = negotiated.binding;
  const outboundContent = content ?? createTextEncodedContent(text);
  if (!negotiatedContentTypeSupports(negotiation, outboundContent.type)) {
    throw new Error(
      `Peer relationship endpoint did not advertise ${contentTypeCanonicalName(outboundContent.type)}.`
    );
  }
  await verifyRelationshipEndpointBindingV4({
    crypto,
    pqc,
    authoritySigningPublicKey: peerIdentity.signingPublicKey,
    endpointBinding: peerIdentity.endpointBinding,
    now: Date.parse(sentAt)
  });
  const ownSigning = deserializeKeypair(
    localIdentity.localEndpoint.signing,
    {
    publicKeyBytes: ML_DSA_PUBLIC_KEY_BYTES,
    secretKeyBytes: ML_DSA_SECRET_KEY_BYTES,
    label: "local endpoint signing keypair"
  });
  const candidateSendChain = cloneChain(conversation.sendChain);
  const prepared = await nextMessageKey(crypto, candidateSendChain);
  const canonicalSentAt = swiftISODate(new Date(sentAt));
  const applicationEvent = createConversationEvent({
    id: eventId,
    clientTransactionId,
    conversationId: conversation.id,
    authorEndpointHandle: conversation.endpointSession.localEndpointHandle,
    createdAt: canonicalSentAt,
    kind: eventKind,
    content: outboundContent,
    relation: relation ?? undefined
  });
  const plaintext = encodePaddedDirectV4Application(
    applicationEvent,
    (length) => crypto.randomBytes(length)
  );
  validateNegotiatedApplicationLimits({
    event: applicationEvent,
    paddedBytes: plaintext.byteLength,
    negotiation
  });
  const validatedBootstrap = validateDirectBootstrapV4(bootstrap);
  const envelopeHeader = {
    version: 4,
    id: swiftUUID(),
    payloadFormat: "nw.wire-payload.v2",
    conversationId: conversation.id,
    sessionId: conversation.sessionId,
    eventId,
    senderEndpointHandle: conversation.endpointSession.localEndpointHandle,
    senderBindingDigest: conversation.endpointSession.localBindingReferenceDigest,
    recipientEndpointHandle: conversation.endpointSession.peerEndpointHandle,
    recipientBindingDigest: conversation.endpointSession.peerBindingReferenceDigest,
    cipherSuite: binding.cipherSuite,
    negotiatedCapabilitiesDigest: binding.negotiatedCapabilitiesDigest,
    bootstrap: validatedBootstrap,
    sentAt: canonicalSentAt,
    messageCounter: prepared.counter
  };
  const aad = directEnvelopeV4AuthenticatedDataBytes(envelopeHeader);
  const nonce = crypto.randomBytes(12);
  try {
    const encrypted = await crypto.aesGcmEncrypt({
      key: prepared.key,
      nonce,
      plaintext,
      additionalData: aad
    });
    const envelope = {
      ...envelopeHeader,
      payload: {
        nonce: base64(nonce),
        ciphertext: base64(encrypted.slice(0, -16)),
        tag: base64(encrypted.slice(-16))
      },
      signature: ""
    };
    const signature = pqc.sign(directEnvelopeV4SignableBytes(envelope), ownSigning.secretKey);
    if (!(signature instanceof Uint8Array) || signature.byteLength !== ML_DSA_SIGNATURE_BYTES) {
      throw new Error("ML-DSA signing returned an invalid signature.");
    }
    envelope.signature = base64(signature);
    commitChain(conversation.sendChain, candidateSendChain);
    return validateDirectEnvelopeV4(envelope);
  } finally {
    wipeBytes(ownSigning.secretKey);
    wipeBytes(prepared.key);
    wipeBytes(plaintext);
  }
}

export async function verifyNativeEnvelope({
  crypto,
  pqc,
  localIdentity,
  peerIdentity,
  conversation,
  envelope,
  binding = null
}) {
  requirePeerPairwiseIdentity(peerIdentity);
  const currentBinding = binding ?? (await validateCurrentDirectV4Negotiation({
    crypto,
    localIdentity,
    peerIdentity,
    endpointSession: conversation.endpointSession
  })).binding;
  const directEnvelope = await validateNativeEnvelope({
    peerIdentity,
    conversation,
    envelope,
    binding: currentBinding
  });
  await verifyRelationshipEndpointBindingV4({
    crypto,
    pqc,
    authoritySigningPublicKey: peerIdentity.signingPublicKey,
    endpointBinding: peerIdentity.endpointBinding,
    now: Date.parse(directEnvelope.sentAt)
  });
  const signature = fromBase64(
    directEnvelope.signature,
    "envelope signature",
    ML_DSA_SIGNATURE_BYTES,
    ML_DSA_SIGNATURE_BYTES
  );
  const signingPublicKey = fromBase64(
    peerIdentity.endpointBinding.signingPublicKey,
    "peer endpoint signing key",
    ML_DSA_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES
  );
  const valid = pqc.verify(
    directEnvelopeV4SignableBytes(directEnvelope, { allowUnsigned: false }),
    signature,
    signingPublicKey
  );
  if (!valid) {
    throw new NoctweaveRemoteEnvelopeError(
      "invalidAttribution",
      "Invalid signature for this relationship."
    );
  }
  return directEnvelope;
}

export async function decryptNativeApplicationEnvelope(options) {
  const decoded = await decryptNativeEnvelopePayload(options);
  if (decoded.kind !== "application" && decoded.kind !== "receipt") {
    throw new Error("Typed application decoding requires a direct-v4 envelope.");
  }
  return decoded;
}

// Text-oriented projection. Unknown visible application content becomes its
// authenticated fallback; silent content is returned as `null` and must not
// create a chat bubble.
export async function decryptNativeEnvelope(options) {
  const decoded = await decryptNativeEnvelopePayload(options);
  if (decoded.projection.kind === "text") {
    return decoded.projection.text;
  }
  return decoded.projection.disposition === "visible"
    ? decoded.projection.fallbackText
    : null;
}

async function decryptNativeEnvelopePayload({
  crypto,
  pqc,
  localIdentity,
  peerIdentity,
  conversation,
  envelope
}) {
  requirePeerPairwiseIdentity(peerIdentity);
  const negotiated = await validateCurrentDirectV4Negotiation({
    crypto,
    localIdentity,
    peerIdentity,
    endpointSession: conversation.endpointSession
  });
  const negotiation = negotiated.manifest;
  const directEnvelope = await verifyNativeEnvelope({
    crypto,
    pqc,
    localIdentity,
    peerIdentity,
    conversation,
    envelope,
    binding: negotiated.binding
  });
  const candidateReceiveChain = cloneChain(conversation.receiveChain);
  const key = await receiveMessageKey(
    crypto,
    candidateReceiveChain,
    Number(directEnvelope.messageCounter)
  );
  const ciphertext = concatBytes(
    fromBase64(directEnvelope.payload.ciphertext, "envelope ciphertext", MAX_PADDED_BYTES),
    fromBase64(directEnvelope.payload.tag, "envelope tag", 16, 16)
  );
  let plaintext;
  try {
    plaintext = await crypto.aesGcmDecrypt({
      key,
      nonce: fromBase64(directEnvelope.payload.nonce, "envelope nonce", 12, 12),
      ciphertext,
      additionalData: directEnvelopeV4AuthenticatedDataBytes(
        directEnvelopeHeader(directEnvelope)
      )
    });
    let decoded;
    try {
      const event = decodePaddedDirectV4Application(plaintext, directEnvelope);
      const projection = projectDirectV4Application(event);
      validateNegotiatedApplicationLimits({
        event,
        paddedBytes: plaintext.byteLength,
        negotiation
      });
      decoded = { kind: event.kind, event, projection };
    } catch (error) {
      throw new NoctweaveRemoteEnvelopeError(
        "unsupportedPayload",
        "The authenticated envelope contains an unsupported payload.",
        { cause: error }
      );
    }
    commitChain(conversation.receiveChain, candidateReceiveChain);
    return decoded;
  } finally {
    wipeBytes(key);
    wipeBytes(plaintext);
  }
}

export function pairwiseConversationKey(peerIdentity) {
  requirePeerPairwiseIdentity(peerIdentity);
  return `direct-v4:${peerIdentity.relationshipID}`;
}

export async function findPairwiseRelationshipForEnvelope({ crypto, relationships, envelope }) {
  if (!Array.isArray(relationships)) {
    throw new TypeError("Pairwise relationships must be an array.");
  }
  const directEnvelope = validateDirectEnvelopeV4(envelope);
  for (const relationship of relationships) {
    const localIdentity = relationship?.localIdentity;
    const peerIdentity = relationship?.peerIdentity;
    if (!isPeerPairwiseIdentityV2(peerIdentity) ||
        localIdentity?.relationshipID !== relationship?.relationshipID) continue;
    const binding = await derivePairwiseDirectV4Binding({ crypto, localIdentity, peerIdentity });
    if (binding.peerEndpointHandle.rawValue === directEnvelope.senderEndpointHandle.rawValue &&
        binding.localEndpointHandle.rawValue === directEnvelope.recipientEndpointHandle.rawValue) {
      return relationship;
    }
  }
  return null;
}

async function validateNativeEnvelope({ peerIdentity, conversation, envelope, binding }) {
  requirePeerPairwiseIdentity(peerIdentity);
  const directEnvelope = validateDirectEnvelopeV4(envelope);
  if (directEnvelope.conversationId !== conversation.id) {
    throw new Error("Envelope conversation does not match this relationship.");
  }
  if (directEnvelope.sessionId !== conversation.sessionId) {
    throw new Error("Envelope session does not match this conversation.");
  }
  const endpointSession = conversation.endpointSession;
  if (directEnvelope.senderEndpointHandle.rawValue !== endpointSession.peerEndpointHandle.rawValue ||
      directEnvelope.senderBindingDigest !== endpointSession.peerBindingReferenceDigest ||
      directEnvelope.recipientEndpointHandle.rawValue !== endpointSession.localEndpointHandle.rawValue ||
      directEnvelope.recipientBindingDigest !== endpointSession.localBindingReferenceDigest ||
      directEnvelope.cipherSuite !== binding.cipherSuite ||
      directEnvelope.negotiatedCapabilitiesDigest !== binding.negotiatedCapabilitiesDigest) {
    throw new Error("DirectEnvelopeV4 does not match the endpoint session.");
  }
  return directEnvelope;
}

function directEnvelopeHeader(envelope) {
  return {
    version: envelope.version,
    id: envelope.id,
    payloadFormat: envelope.payloadFormat,
    conversationId: envelope.conversationId,
    sessionId: envelope.sessionId,
    eventId: envelope.eventId,
    senderEndpointHandle: envelope.senderEndpointHandle,
    senderBindingDigest: envelope.senderBindingDigest,
    recipientEndpointHandle: envelope.recipientEndpointHandle,
    recipientBindingDigest: envelope.recipientBindingDigest,
    cipherSuite: envelope.cipherSuite,
    negotiatedCapabilitiesDigest: envelope.negotiatedCapabilitiesDigest,
    bootstrap: envelope.bootstrap,
    sentAt: envelope.sentAt,
    messageCounter: envelope.messageCounter
  };
}

function requirePeerPairwiseIdentity(peerIdentity) {
  if (!isPeerPairwiseIdentityV2(peerIdentity)) {
    throw new Error("A verified pairwise peer identity is required.");
  }
}

async function validateCurrentDirectV4Negotiation({
  crypto,
  localIdentity,
  peerIdentity,
  binding = null,
  endpointSession = null
}) {
  const localEndpoint = localIdentity?.endpointBinding;
  const peerEndpoint = peerIdentity?.endpointBinding;
  if (!localEndpoint || !peerEndpoint) {
    throw new Error("Direct-v4 relationship endpoint bindings are required for negotiation.");
  }
  const currentBinding = await derivePairwiseDirectV4Binding({
    crypto,
    localIdentity,
    peerIdentity
  });
  const negotiated = await negotiateNativeDirectV4({ crypto, localEndpoint, peerEndpoint });
  const transcript = endpointSession ?? binding;
  const bindingMatches = binding !== null &&
    binding.relationshipId === currentBinding.relationshipId &&
    binding.localEndpointHandle?.rawValue === currentBinding.localEndpointHandle.rawValue &&
    binding.peerEndpointHandle?.rawValue === currentBinding.peerEndpointHandle.rawValue &&
    binding.localBindingReferenceDigest === currentBinding.localBindingReferenceDigest &&
    binding.peerBindingReferenceDigest === currentBinding.peerBindingReferenceDigest &&
    binding.cipherSuite === currentBinding.cipherSuite &&
    binding.negotiatedCapabilitiesDigest === currentBinding.negotiatedCapabilitiesDigest;
  const sessionMatches = endpointSession !== null &&
    endpointSession.relationshipID === currentBinding.relationshipId &&
    endpointSession.localEndpointHandle?.rawValue === currentBinding.localEndpointHandle.rawValue &&
    endpointSession.peerEndpointHandle?.rawValue === currentBinding.peerEndpointHandle.rawValue &&
    endpointSession.localBindingReferenceDigest === currentBinding.localBindingReferenceDigest &&
    endpointSession.peerBindingReferenceDigest === currentBinding.peerBindingReferenceDigest;
  if (!transcript || !(bindingMatches || sessionMatches) ||
      currentBinding.cipherSuite !== negotiated.manifest.cipherSuite ||
      currentBinding.negotiatedCapabilitiesDigest !== negotiated.digest) {
    throw new Error("Direct-v4 capability transcript does not match the endpoint session.");
  }
  return Object.freeze({ manifest: negotiated.manifest, binding: currentBinding });
}

function negotiatedLimit(negotiation, moduleName, limitName) {
  const value = negotiation?.modules?.find(({ module }) => module === moduleName)
    ?.limits?.[limitName];
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Direct-v4 negotiated limit ${moduleName}.${limitName} is missing.`);
  }
  return value;
}

function negotiatedContentTypeSupports(negotiation, contentType) {
  return Array.isArray(negotiation?.contentTypes) && negotiation.contentTypes.some((capability) =>
    capability.authority === contentType.authority &&
    capability.name === contentType.name &&
    Array.isArray(capability.majorVersions) &&
    capability.majorVersions.includes(contentType.major));
}

function validateNegotiatedPrekeyFreshness(prekey, negotiation, now) {
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  const issuedAtMs = Date.parse(prekey?.issuedAt);
  const expiresAtMs = Date.parse(prekey?.expiresAt);
  const maximumAgeMs = negotiatedLimit(
    negotiation,
    "nw.direct",
    "maxPrekeyAgeSeconds"
  ) * 1_000;
  if (!Number.isFinite(nowMs) || !Number.isFinite(issuedAtMs) ||
      !Number.isFinite(expiresAtMs) || nowMs >= expiresAtMs ||
      issuedAtMs < nowMs - maximumAgeMs || issuedAtMs > nowMs + 5 * 60_000) {
    throw new Error("Direct-v4 signed prekey violates the negotiated freshness limit.");
  }
}

function validateNegotiatedApplicationLimits({ event, paddedBytes, negotiation }) {
  const content = validateEncodedContent(event.content);
  const payload = fromBase64(
    content.payload,
    "direct-v4 application payload",
    negotiatedLimit(negotiation, "nw.core", "maxContentPayloadBytes")
  );
  try {
    const maxParameterBytes = negotiatedLimit(
      negotiation,
      "nw.core",
      "maxContentParameterBytes"
    );
    if (paddedBytes > negotiatedLimit(negotiation, "nw.direct", "maxCiphertextBytes") ||
        Object.keys(content.parameters).length > negotiatedLimit(
          negotiation,
          "nw.core",
          "maxContentParameters"
        ) ||
        (content.fallbackText != null &&
          encoder.encode(content.fallbackText).byteLength > negotiatedLimit(
            negotiation,
            "nw.core",
            "maxFallbackBytes"
          )) ||
        Object.entries(content.parameters).some(([key, value]) =>
          encoder.encode(key).byteLength > maxParameterBytes ||
          encoder.encode(value).byteLength > maxParameterBytes)) {
      throw new Error("Direct-v4 message exceeds its negotiated capability limits.");
    }
  } finally {
    wipeBytes(payload);
  }
}

function validateChain(chain) {
  if (!chain || typeof chain !== "object" || Array.isArray(chain) ||
      !Number.isSafeInteger(chain.counter) || chain.counter < 0 ||
      !chain.skippedMessageKeys || typeof chain.skippedMessageKeys !== "object" ||
      Array.isArray(chain.skippedMessageKeys)) {
    throw new Error("Ratchet chain state is invalid.");
  }
  const keyData = fromBase64(chain.keyData, "chain key", 32, 32);
  wipeBytes(keyData);
  const skipped = Object.entries(chain.skippedMessageKeys);
  if (skipped.length > MAX_SKIP) {
    throw new Error("Ratchet skipped-key state exceeds its limit.");
  }
  for (const [counterText, encodedKey] of skipped) {
    const counter = Number(counterText);
    if (!Number.isSafeInteger(counter) || counter < 0 || counter >= chain.counter || String(counter) !== counterText) {
      throw new Error("Ratchet skipped-key counter is invalid.");
    }
    const key = fromBase64(encodedKey, "skipped message key", 32, 32);
    wipeBytes(key);
  }
}

function cloneChain(chain) {
  validateChain(chain);
  return {
    keyData: chain.keyData,
    counter: chain.counter,
    skippedMessageKeys: { ...chain.skippedMessageKeys }
  };
}

function commitChain(target, candidate) {
  target.keyData = candidate.keyData;
  target.counter = candidate.counter;
  target.skippedMessageKeys = { ...candidate.skippedMessageKeys };
}

function isBoundedString(value, maximumBytes) {
  return typeof value === "string" && value.length > 0 && encoder.encode(value).byteLength <= maximumBytes;
}

function isCanonicalSwiftUUID(value) {
  return typeof value === "string" &&
    /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(value);
}

async function conversationFromSharedSecret({
  crypto,
  sharedSecret,
  ownAgreementPublicKey,
  peerAgreementPublicKey,
  relationshipID,
  conversationId,
  endpointSession,
  binding
}) {
  if (!isBoundedString(conversationId, 256) || endpointSession == null || binding == null ||
      conversationId !== relationshipID.toLowerCase()) {
    throw new Error("A direct-v4 conversation binding is required.");
  }
  const directBinding = directV4SessionBindingBytes(binding);
  const rootInfo = concatBytes(
    encoder.encode("Noctweave/direct-v4/root"),
    encoder.encode(binding.relationshipId.toLowerCase()),
    fromBase64(
      binding.negotiatedCapabilitiesDigest,
      "direct-v4 negotiated capabilities digest",
      32,
      32
    )
  );
  const rootKey = await crypto.hkdfSha256({
    ikm: sharedSecret,
    salt: "NOCTWEAVE-ROOT",
    info: rootInfo,
    length: 32
  });
  const [sendLabel, receiveLabel] = labelsForAgreement(ownAgreementPublicKey, peerAgreementPublicKey);
  const sendKey = await crypto.hkdfSha256({
    ikm: rootKey,
    salt: "NOCTWEAVE-CHAIN",
    info: sendLabel,
    length: 32
  });
  const receiveKey = await crypto.hkdfSha256({
    ikm: rootKey,
    salt: "NOCTWEAVE-CHAIN",
    info: receiveLabel,
    length: 32
  });
  let sessionMaterial;
  let sessionHash;
  try {
    sessionMaterial = concatBytes(encoder.encode("NOCTWEAVE-SESSION"), directBinding, rootKey);
    sessionHash = await crypto.sha256(sessionMaterial);
    const conversation = {
      id: conversationId,
      relationshipID,
      sessionId: base64(sessionHash),
      rootKey: base64(rootKey),
      rootCounter: 0,
      sendChain: serializeChain(sendKey),
      receiveChain: serializeChain(receiveKey)
    };
    conversation.endpointSession = endpointSession;
    return conversation;
  } finally {
    wipeBytes(rootKey);
    wipeBytes(sendKey);
    wipeBytes(receiveKey);
    wipeBytes(sessionMaterial);
    wipeBytes(sessionHash);
    wipeBytes(rootInfo);
    wipeBytes(directBinding);
  }
}

async function nextMessageKey(crypto, chain) {
  validateChain(chain);
  const counter = Number(chain.counter ?? 0);
  if (counter >= Number.MAX_SAFE_INTEGER) {
    throw new Error("Message counter is exhausted.");
  }
  const keyData = fromBase64(chain.keyData, "chain key", 32, 32);
  const counterBytes = uint64BE(counter);
  const messageData = concatBytes(encoder.encode("MSG"), counterBytes);
  const chainData = concatBytes(encoder.encode("CK"), counterBytes);
  let nextChain;
  try {
    const messageKey = await crypto.hmacSha256({ key: keyData, data: messageData });
    nextChain = await crypto.hmacSha256({ key: keyData, data: chainData });
    chain.keyData = base64(nextChain);
    chain.counter = counter + 1;
    return { counter, key: messageKey };
  } finally {
    wipeBytes(keyData);
    wipeBytes(counterBytes);
    wipeBytes(messageData);
    wipeBytes(chainData);
    wipeBytes(nextChain);
  }
}

async function receiveMessageKey(crypto, chain, targetCounter) {
  validateChain(chain);
  if (!Number.isSafeInteger(targetCounter) || targetCounter < 0) {
    throw new Error("Envelope counter is invalid.");
  }
  const cached = chain.skippedMessageKeys[String(targetCounter)];
  if (cached) {
    delete chain.skippedMessageKeys[String(targetCounter)];
    return fromBase64(cached, "skipped message key", 32, 32);
  }
  const current = Number(chain.counter ?? 0);
  if (targetCounter < current) {
    throw new Error("Envelope counter was already processed.");
  }
  if (targetCounter - current > MAX_SKIP) {
    throw new Error("Envelope counter is outside the recovery window.");
  }
  while (Number(chain.counter ?? 0) < targetCounter) {
    const skipped = await nextMessageKey(crypto, chain);
    chain.skippedMessageKeys[String(skipped.counter)] = base64(skipped.key);
    wipeBytes(skipped.key);
  }
  const prepared = await nextMessageKey(crypto, chain);
  return prepared.key;
}

function encodePaddedDirectV4Application(eventValue, randomBytes) {
  const event = validateConversationEvent(eventValue);
  if (event.kind !== "application" && event.kind !== "receipt") {
    throw new TypeError("Only application and receipt events use the extensible direct-v4 codec.");
  }
  return encodePaddedBody(createApplicationWirePayloadV2(event), NPAD_V2_MAGIC, randomBytes);
}

function encodePaddedBody(body, magic, randomBytes) {
  const bodyData = canonicalJsonBytes(body);
  let padding;
  try {
    const paddedSize = paddedSizeFor(bodyData.byteLength);
    if (paddedSize > MAX_PADDED_BYTES) {
      throw new Error("Plaintext exceeds native message size limit.");
    }
    const paddingCount = paddedSize - NPAD_HEADER_BYTES - bodyData.byteLength;
    const output = new Uint8Array(paddedSize);
    output.set(magic, 0);
    output.set(uint32BE(bodyData.byteLength), magic.byteLength);
    output.set(bodyData, NPAD_HEADER_BYTES);
    if (paddingCount > 0) {
      padding = randomBytes(paddingCount);
      output.set(padding, NPAD_HEADER_BYTES + bodyData.byteLength);
    }
    return output;
  } finally {
    wipeBytes(bodyData);
    wipeBytes(padding);
  }
}

function decodePaddedDirectV4Application(data, envelope) {
  const body = validateWirePayloadV2(decodePaddedBody(data, NPAD_V2_MAGIC));
  if (body.kind !== "application") {
    throw new Error("Direct-v4 control and application payloads are separated.");
  }
  const event = validateConversationEvent(body.application);
  if (event.id !== envelope.eventId ||
      event.conversationId !== envelope.conversationId ||
      event.authorEndpointHandle.rawValue !== envelope.senderEndpointHandle.rawValue ||
      event.createdAt !== envelope.sentAt ||
      (event.kind !== "application" && event.kind !== "receipt")) {
    throw new Error("Direct-v4 wire payload does not match its authenticated envelope header.");
  }
  return event;
}

function projectDirectV4Application(event) {
  const canonicalType = contentTypeCanonicalName(event.content.type);
  if (event.kind === "receipt") {
    return projectDirectV4Receipt(event, canonicalType);
  }
  if (event.kind !== "application") {
    throw new Error("Direct-v4 controls cannot enter the extensible event projection.");
  }
  if (canonicalType === contentTypeCanonicalName(standardContentTypes.text)) {
    if (!isTextOrAttachmentRelation(event.relation) || event.content.disposition !== "visible" ||
        Object.keys(event.content.parameters).length !== 0) {
      throw new Error("Known direct-v4 text content is malformed.");
    }
    const textBytes = fromBase64(event.content.payload, "direct-v4 text payload", MAX_PADDED_BYTES);
    let text;
    try {
      text = strictUTF8Decoder.decode(textBytes);
    } catch {
      throw new Error("Direct-v4 text payload is not valid UTF-8.");
    } finally {
      wipeBytes(textBytes);
    }
    if (event.content.fallbackText !== text) {
      throw new Error("Direct-v4 text fallback does not match its payload.");
    }
    return Object.freeze({ kind: "text", text, disposition: "visible", fallbackText: text });
  }
  if (canonicalType === contentTypeCanonicalName(standardContentTypes.attachment)) {
    if (!isTextOrAttachmentRelation(event.relation) || event.content.disposition !== "visible" ||
        Object.keys(event.content.parameters).length !== 0) {
      throw new Error("Known direct-v4 attachment content is malformed.");
    }
    const descriptor = validateNativeAttachmentDescriptor(
      decodeCanonicalContentPayload(event.content, "direct-v4 attachment descriptor")
    );
    const fallbackText = attachmentFallbackText(descriptor);
    if (event.content.fallbackText !== fallbackText) {
      throw new Error("Direct-v4 attachment fallback does not match its descriptor.");
    }
    return Object.freeze({
      kind: "attachment",
      descriptor,
      disposition: "visible",
      fallbackText
    });
  }
  if (canonicalType === contentTypeCanonicalName(standardContentTypes.reaction)) {
    if (event.relation?.kind !== "reaction" || event.content.disposition !== "visible" ||
        Object.keys(event.content.parameters).length !== 0) {
      throw new Error("Known direct-v4 reaction content is malformed.");
    }
    const reaction = decodeCanonicalContentPayload(event.content, "direct-v4 reaction payload");
    if (!reaction || typeof reaction !== "object" || Array.isArray(reaction) ||
        Object.keys(reaction).join(",") !== "value" || typeof reaction.value !== "string" ||
        reaction.value.length === 0 || reaction.value.trim() !== reaction.value ||
        encoder.encode(reaction.value).byteLength > 64 || unsafeDisplayControls.test(reaction.value)) {
      throw new Error("Known direct-v4 reaction payload is malformed.");
    }
    const fallbackText = `Reacted ${reaction.value} to a message`;
    if (event.content.fallbackText !== fallbackText) {
      throw new Error("Direct-v4 reaction fallback does not match its payload.");
    }
    return Object.freeze({
      kind: "reaction",
      value: reaction.value,
      targetEventId: event.relation.targetEventId,
      disposition: "visible",
      fallbackText
    });
  }
  if (canonicalType === contentTypeCanonicalName(standardContentTypes.retraction)) {
    if (event.relation?.kind !== "retraction" || event.content.disposition !== "visible" ||
        Object.keys(event.content.parameters).length !== 0) {
      throw new Error("Known direct-v4 retraction content is malformed.");
    }
    const retraction = decodeCanonicalContentPayload(event.content, "direct-v4 retraction payload");
    const keys = retraction && typeof retraction === "object" && !Array.isArray(retraction)
      ? Object.keys(retraction).sort().join(",")
      : "";
    if ((keys !== "scope" && keys !== "reason,scope") ||
        retraction.scope !== "received-copies-may-remain" ||
        (retraction.reason != null &&
          (typeof retraction.reason !== "string" || retraction.reason.length === 0 ||
            retraction.reason.trim() !== retraction.reason ||
            encoder.encode(retraction.reason).byteLength > 512 ||
            unsafeDisplayControls.test(retraction.reason)))) {
      throw new Error("Known direct-v4 retraction payload is malformed.");
    }
    const fallbackText = "Message retracted; received copies may remain";
    if (event.content.fallbackText !== fallbackText) {
      throw new Error("Direct-v4 retraction fallback is not truthful.");
    }
    return Object.freeze({
      kind: "retraction",
      reason: retraction.reason ?? null,
      scope: retraction.scope,
      targetEventId: event.relation.targetEventId,
      disposition: "visible",
      fallbackText
    });
  }
  if (event.relation?.kind === "reaction" || event.relation?.kind === "retraction") {
    throw new Error("Reserved relation semantics require their standard content type.");
  }
  return Object.freeze({
    kind: "unsupported",
    type: event.content.type,
    disposition: event.content.disposition,
    fallbackText: event.content.fallbackText ?? `Unsupported message (${canonicalType})`
  });
}

function projectDirectV4Receipt(event, canonicalType) {
  if (event.relation != null || event.content.disposition !== "silent" ||
      event.content.fallbackText != null || Object.keys(event.content.parameters).length !== 0) {
    throw new Error("Known direct-v4 receipt content is malformed.");
  }
  const delivery = contentTypeCanonicalName(standardContentTypes.deliveryReceipt);
  const read = contentTypeCanonicalName(standardContentTypes.readReceipt);
  if (canonicalType !== delivery && canonicalType !== read) {
    throw new Error("Unknown receipt types fail closed.");
  }
  const receipt = decodeCanonicalContentPayload(event.content, "direct-v4 receipt payload");
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt) ||
      Object.keys(receipt).join(",") !== "targetEventId" ||
      !isCanonicalSwiftUUID(receipt.targetEventId) || receipt.targetEventId === event.id) {
    throw new Error("Known direct-v4 receipt payload is malformed.");
  }
  return Object.freeze({
    kind: canonicalType === delivery ? "deliveryReceipt" : "readReceipt",
    targetEventId: receipt.targetEventId,
    disposition: "silent",
    fallbackText: null
  });
}

function isTextOrAttachmentRelation(relation) {
  return relation == null || relation.kind === "reply" ||
    relation.kind === "replacement" || relation.kind === "reference";
}

function decodeCanonicalContentPayload(content, label) {
  const payload = fromBase64(content.payload, label, MAX_PADDED_BYTES);
  let canonical;
  try {
    const value = JSON.parse(strictUTF8Decoder.decode(payload));
    canonical = canonicalJsonBytes(value);
    if (compareBytes(payload, canonical) !== 0) {
      throw new Error(`${label} is not canonical JSON.`);
    }
    return value;
  } finally {
    wipeBytes(payload);
    wipeBytes(canonical);
  }
}

function validateNativeAttachmentDescriptor(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.fileName != null ||
      !isCanonicalSwiftUUID(value.id) || typeof value.mimeType !== "string" ||
      value.mimeType.length === 0 || encoder.encode(value.mimeType).byteLength > 128 ||
      !/^[\x20-\x3a\x3c-\x7e]+$/u.test(value.mimeType) ||
      !Number.isSafeInteger(value.byteCount) || value.byteCount <= 0 ||
      value.byteCount > 8 * 1024 * 1024 || !Number.isSafeInteger(value.chunkSize) ||
      value.chunkSize <= 0 || value.chunkSize > 64 * 1024 ||
      !Number.isSafeInteger(value.chunkCount) || value.chunkCount <= 0 || value.chunkCount > 128 ||
      Math.ceil(value.byteCount / value.chunkSize) !== value.chunkCount ||
      (value.relayTTLSeconds != null &&
        (!Number.isSafeInteger(value.relayTTLSeconds) || value.relayTTLSeconds <= 0))) {
    throw new Error("Direct-v4 attachment descriptor is invalid.");
  }
  const digest = fromBase64(value.sha256, "attachment SHA-256", 32, 32);
  wipeBytes(digest);
  return Object.freeze({ ...value });
}

function attachmentFallbackText(descriptor) {
  const mimeType = descriptor.mimeType.toLowerCase();
  if (mimeType.startsWith("audio/")) return "Voice message";
  if (mimeType.startsWith("image/")) return "Image";
  return "Attachment";
}

function decodePaddedBody(data, magic) {
  if (!(data instanceof Uint8Array) || data.byteLength < MIN_PADDED_BYTES ||
      data.byteLength > MAX_PADDED_BYTES || (data.byteLength & (data.byteLength - 1)) !== 0 ||
      !startsWith(data, magic)) {
    throw new Error("Message padding frame is invalid.");
  }
  const length = readUint32BE(data.subarray(magic.byteLength, NPAD_HEADER_BYTES));
  if (length <= 0 || length > data.byteLength - NPAD_HEADER_BYTES ||
      paddedSizeFor(length) !== data.byteLength) {
    throw new Error("Message padding frame length is invalid.");
  }
  return JSON.parse(decoder.decode(data.subarray(NPAD_HEADER_BYTES, NPAD_HEADER_BYTES + length)));
}

function labelsForAgreement(ourKey, theirKey) {
  return compareBytes(ourKey, theirKey) < 0 ? ["A", "B"] : ["B", "A"];
}

function serializeChain(keyData) {
  return { keyData: base64(keyData), counter: 0, skippedMessageKeys: {} };
}

function deserializeKeypair(keypair, profile) {
  return {
    publicKey: fromBase64(
      keypair?.publicKey,
      `${profile.label} public key`,
      profile.publicKeyBytes,
      profile.publicKeyBytes
    ),
    secretKey: fromBase64(
      keypair?.secretKey,
      `${profile.label} secret key`,
      profile.secretKeyBytes,
      profile.secretKeyBytes
    )
  };
}

function paddedSizeFor(bodyBytes) {
  const required = Math.max(MIN_PADDED_BYTES, bodyBytes + NPAD_HEADER_BYTES);
  let size = MIN_PADDED_BYTES;
  while (size < required && size < MAX_PADDED_BYTES) {
    size *= 2;
  }
  return size;
}

function uint32BE(value) {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ]);
}

function readUint32BE(bytes) {
  return ((bytes[0] << 24) >>> 0) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

function uint64BE(value) {
  const output = new Uint8Array(8);
  let remaining = BigInt(value);
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function startsWith(value, prefix) {
  for (let index = 0; index < prefix.byteLength; index++) {
    if (value[index] !== prefix[index]) {
      return false;
    }
  }
  return true;
}

function compareBytes(a, b) {
  const count = Math.min(a.byteLength, b.byteLength);
  for (let index = 0; index < count; index++) {
    if (a[index] !== b[index]) {
      return a[index] < b[index] ? -1 : 1;
    }
  }
  if (a.byteLength === b.byteLength) {
    return 0;
  }
  return a.byteLength < b.byteLength ? -1 : 1;
}

function fromBase64(value, label = "base64 value", maximumBytes = 128 * 1024, exactBytes = null) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > Math.ceil(maximumBytes / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  const binary = atob(value);
  if (binary.length > maximumBytes) {
    throw new Error(`${label} exceeds its size limit.`);
  }
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    output[index] = binary.charCodeAt(index);
  }
  if (base64(output) !== value || (exactBytes !== null && output.byteLength !== exactBytes)) {
    wipeBytes(output);
    throw new Error(`Invalid ${label}.`);
  }
  return output;
}

function concatBytes(a, b) {
  const output = new Uint8Array(a.byteLength + b.byteLength);
  output.set(a, 0);
  output.set(b, a.byteLength);
  return output;
}

function wipeBytes(value) {
  if (value instanceof Uint8Array) {
    value.fill(0);
    return;
  }
  if (value instanceof ArrayBuffer) {
    new Uint8Array(value).fill(0);
  }
}
