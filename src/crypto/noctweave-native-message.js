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
  assertCertifiedEndpointPrekeyFresh,
  assertContactEndpointActive,
  contactFromNativeOffer,
  deriveNativeDirectV4Binding,
  directV4ConversationId,
  directV4EndpointSession,
  directV4SessionBindingBytes,
  isCertifiedNativeContact,
  makeCertifiedNativeContactOffer,
  makeDirectV4AuthenticatedContext,
  negotiateNativeDirectV4,
  validateInboundDirectV4Context,
  verifyCertifiedNativeContactOffer
} from "./direct-v4.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const strictUTF8Decoder = new TextDecoder("utf-8", { fatal: true });
const unsafeDisplayControls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;
const NPAD_MAGIC = new Uint8Array([0x4e, 0x50, 0x41, 0x44, 0x01]);
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
const FINGERPRINT_BYTES = 32;
const MAX_CONTACT_CODE_BYTES = 64 * 1024;
const PREKEY_MAX_AGE_MS = 8 * 86_400_000;
const PREKEY_FUTURE_SKEW_MS = 5 * 60_000;

export async function createNativeOutboundSession({ crypto, pqc, identity, contact, now = Date.now() }) {
  assertNoDirectV4Fallback(contact);
  if (isCertifiedNativeContact(contact)) {
    await assertContactEndpointActive({ crypto, pqc, contact });
    const peerEndpoint = contact.preferredInstallationEndpoint;
    assertCertifiedEndpointPrekeyFresh({ endpoint: peerEndpoint, now });
    const localEndpoint = identity.certifiedInstallationEndpoint;
    const binding = await deriveNativeDirectV4Binding({ crypto, identity, contact });
    const negotiation = await validateCurrentDirectV4Negotiation({
      crypto,
      identity,
      contact,
      binding
    });
    validateNegotiatedPrekeyFreshness(
      peerEndpoint.prekeyBundle.signedPrekey,
      negotiation,
      now
    );
    const recipientKey = fromBase64(
      peerEndpoint.prekeyBundle.signedPrekey.publicKey,
      "contact signed prekey",
      ML_KEM_PUBLIC_KEY_BYTES,
      ML_KEM_PUBLIC_KEY_BYTES
    );
    const ownAgreementKey = fromBase64(
      identity.localInstallation.agreement.publicKey,
      "local installation agreement key",
      ML_KEM_PUBLIC_KEY_BYTES,
      ML_KEM_PUBLIC_KEY_BYTES
    );
    const encapsulated = pqc.encapsulate(recipientKey);
    try {
      const endpointSession = directV4EndpointSession({ contact, identity, binding });
      const conversation = await conversationFromSharedSecret({
        crypto,
        sharedSecret: encapsulated.sharedSecret,
        ownAgreementPublicKey: ownAgreementKey,
        contactAgreementPublicKey: fromBase64(
          peerEndpoint.agreementPublicKey,
          "contact endpoint agreement key",
          ML_KEM_PUBLIC_KEY_BYTES,
          ML_KEM_PUBLIC_KEY_BYTES
        ),
        contactFingerprint: contact.fingerprint,
        conversationId: await directV4ConversationId({
          crypto,
          localEndpoint,
          peerEndpoint,
          binding
        }),
        endpointSession
      });
      conversation.bootstrapPrekey = {
        kind: "signed",
        id: peerEndpoint.prekeyBundle.signedPrekey.id
      };
      return {
        conversation,
        kemCiphertext: encapsulated.ciphertext,
        prekey: conversation.bootstrapPrekey
      };
    } finally {
      wipeBytes(encapsulated.sharedSecret);
      wipeBytes(ownAgreementKey);
    }
  }
  const recipientKey = fromBase64(
    contact.agreementPublicKey,
    "contact agreement key",
    ML_KEM_PUBLIC_KEY_BYTES,
    ML_KEM_PUBLIC_KEY_BYTES
  );
  const ownAgreementKey = fromBase64(
    identity.agreement.publicKey,
    "local agreement key",
    ML_KEM_PUBLIC_KEY_BYTES,
    ML_KEM_PUBLIC_KEY_BYTES
  );
  const encapsulated = pqc.encapsulate(recipientKey);
  try {
    const conversation = await conversationFromSharedSecret({
      crypto,
      sharedSecret: encapsulated.sharedSecret,
      ownAgreementPublicKey: ownAgreementKey,
      contactAgreementPublicKey: recipientKey,
      contactFingerprint: contact.fingerprint
    });
    return { conversation, kemCiphertext: encapsulated.ciphertext };
  } finally {
    wipeBytes(encapsulated.sharedSecret);
    wipeBytes(ownAgreementKey);
  }
}

export async function createNativeInboundSession({
  crypto,
  pqc,
  identity,
  contact,
  kemCiphertext,
  prekey = null,
  now = Date.now()
}) {
  assertNoDirectV4Fallback(contact);
  if (isCertifiedNativeContact(contact)) {
    await assertContactEndpointActive({ crypto, pqc, contact });
    const local = identity.localInstallation;
    const localEndpoint = identity.certifiedInstallationEndpoint;
    const peerEndpoint = contact.preferredInstallationEndpoint;
    if (prekey?.kind !== "signed") {
      throw new Error("Direct-v4 bootstrap does not target the local signed prekey.");
    }
    const prekeyRecord = localSignedPrekeyForBootstrap({
      pqc,
      local,
      prekeyId: prekey.id,
      now
    });
    const prekeySecret = fromBase64(
      prekeyRecord.privateKey,
      "local installation signed prekey",
      ML_KEM_SECRET_KEY_BYTES,
      ML_KEM_SECRET_KEY_BYTES
    );
    let sharedSecret;
    try {
      sharedSecret = pqc.decapsulate(
        fromBase64(
          kemCiphertext,
          "KEM ciphertext",
          ML_KEM_CIPHERTEXT_BYTES,
          ML_KEM_CIPHERTEXT_BYTES
        ),
        prekeySecret
      );
      const binding = await deriveNativeDirectV4Binding({ crypto, identity, contact });
      const negotiation = await validateCurrentDirectV4Negotiation({
        crypto,
        identity,
        contact,
        binding
      });
      validateNegotiatedPrekeyFreshness(
        prekeyRecord,
        negotiation,
        now
      );
      return await conversationFromSharedSecret({
        crypto,
        sharedSecret,
        ownAgreementPublicKey: fromBase64(
          local.agreement.publicKey,
          "local installation agreement key",
          ML_KEM_PUBLIC_KEY_BYTES,
          ML_KEM_PUBLIC_KEY_BYTES
        ),
        contactAgreementPublicKey: fromBase64(
          peerEndpoint.agreementPublicKey,
          "contact endpoint agreement key",
          ML_KEM_PUBLIC_KEY_BYTES,
          ML_KEM_PUBLIC_KEY_BYTES
        ),
        contactFingerprint: contact.fingerprint,
        conversationId: await directV4ConversationId({
          crypto,
          localEndpoint,
          peerEndpoint,
          binding
        }),
        endpointSession: directV4EndpointSession({ contact, identity, binding })
      });
    } finally {
      wipeBytes(sharedSecret);
      wipeBytes(prekeySecret);
    }
  }
  const ownAgreement = deserializeKeypair(identity.agreement, {
    publicKeyBytes: ML_KEM_PUBLIC_KEY_BYTES,
    secretKeyBytes: ML_KEM_SECRET_KEY_BYTES,
    label: "local agreement keypair"
  });
  let sharedSecret;
  try {
    sharedSecret = pqc.decapsulate(
      fromBase64(
        kemCiphertext,
        "KEM ciphertext",
        ML_KEM_CIPHERTEXT_BYTES,
        ML_KEM_CIPHERTEXT_BYTES
      ),
      ownAgreement.secretKey
    );
    return await conversationFromSharedSecret({
      crypto,
      sharedSecret,
      ownAgreementPublicKey: ownAgreement.publicKey,
      contactAgreementPublicKey: fromBase64(
        contact.agreementPublicKey,
        "contact agreement key",
        ML_KEM_PUBLIC_KEY_BYTES,
        ML_KEM_PUBLIC_KEY_BYTES
      ),
      contactFingerprint: contact.fingerprint
    });
  } finally {
    wipeBytes(sharedSecret);
    wipeBytes(ownAgreement.secretKey);
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
  if (!isCertifiedNativeContact(options?.contact)) {
    throw new Error("Typed application envelopes require certified direct-v4 endpoints.");
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
  identity,
  contact,
  conversation,
  text,
  content,
  relation,
  eventKind = "application",
  kemCiphertext = null,
  prekey = null,
  eventId = swiftUUID(),
  clientTransactionId = swiftUUID(),
  sentAt = swiftISODate()
}) {
  assertNoDirectV4Fallback(contact);
  const directV4 = isCertifiedNativeContact(contact);
  const negotiation = directV4
    ? await validateCurrentDirectV4Negotiation({
      crypto,
      identity,
      contact,
      endpointSession: conversation.endpointSession
    })
    : null;
  if (directV4) {
    await assertContactEndpointActive({ crypto, pqc, contact });
  }
  const ownSigning = deserializeKeypair(
    directV4 ? identity.localInstallation.signing : identity.signing,
    {
    publicKeyBytes: ML_DSA_PUBLIC_KEY_BYTES,
    secretKeyBytes: ML_DSA_SECRET_KEY_BYTES,
    label: directV4 ? "local installation signing keypair" : "local signing keypair"
  });
  const candidateSendChain = cloneChain(conversation.sendChain);
  const prepared = await nextMessageKey(crypto, candidateSendChain);
  const canonicalSentAt = swiftISODate(new Date(sentAt));
  if (!directV4 && content != null) {
    throw new Error("Typed application envelopes cannot downgrade to the legacy wire format.");
  }
  const applicationEvent = directV4
    ? createConversationEvent({
      id: eventId,
      clientTransactionId,
      conversationId: conversation.id,
      authorInstallationHandle: conversation.endpointSession.localInstallationHandle,
      createdAt: canonicalSentAt,
      kind: eventKind,
      content: content ?? createTextEncodedContent(text),
      relation: relation ?? undefined
    })
    : null;
  const plaintext = directV4
    ? encodePaddedDirectV4Application(applicationEvent, (length) => crypto.randomBytes(length))
    : encodePaddedText(text, (length) => crypto.randomBytes(length));
  if (directV4) {
    validateNegotiatedApplicationLimits({
      event: applicationEvent,
      paddedBytes: plaintext.byteLength,
      negotiation
    });
  }
  const authenticatedContext = directV4
    ? makeDirectV4AuthenticatedContext({ eventId, endpointSession: conversation.endpointSession })
    : null;
  const aad = authenticatedData(
    conversation.id,
    conversation.sessionId,
    authenticatedContext,
    prepared.counter
  );
  const nonce = crypto.randomBytes(12);
  try {
    const encrypted = await crypto.aesGcmEncrypt({
      key: prepared.key,
      nonce,
      plaintext,
      additionalData: aad
    });
    const envelope = {
      id: swiftUUID(),
      conversationId: conversation.id,
      sessionId: conversation.sessionId,
      senderFingerprint: directV4
        ? conversation.endpointSession.localInstallationHandle.rawValue
        : identity.signingFingerprint,
      sentAt: canonicalSentAt,
      messageCounter: prepared.counter,
      payload: {
        nonce: base64(nonce),
        ciphertext: base64(encrypted.slice(0, -16)),
        tag: base64(encrypted.slice(-16))
      },
      signature: ""
    };
    if (authenticatedContext) {
      envelope.authenticatedContext = authenticatedContext;
    }
    if (kemCiphertext) {
      envelope.kemCiphertext = base64(kemCiphertext);
      const bootstrapPrekey = prekey ?? conversation.bootstrapPrekey;
      if (directV4 && bootstrapPrekey) {
        envelope.prekey = bootstrapPrekey;
      }
    }
    const signature = pqc.sign(canonicalEnvelopeBytes(envelope), ownSigning.secretKey);
    if (!(signature instanceof Uint8Array) || signature.byteLength !== ML_DSA_SIGNATURE_BYTES) {
      throw new Error("ML-DSA signing returned an invalid signature.");
    }
    envelope.signature = base64(signature);
    commitChain(conversation.sendChain, candidateSendChain);
    return envelope;
  } finally {
    wipeBytes(ownSigning.secretKey);
    wipeBytes(prepared.key);
    wipeBytes(plaintext);
  }
}

export async function verifyNativeEnvelope({ crypto, pqc, contact, conversation, envelope }) {
  assertNoDirectV4Fallback(contact);
  await validateNativeEnvelope({ crypto, contact, conversation, envelope });
  const directV4 = isCertifiedNativeContact(contact);
  if (directV4) {
    await assertContactEndpointActive({ crypto, pqc, contact });
  }
  const signature = fromBase64(
    envelope.signature,
    "envelope signature",
    ML_DSA_SIGNATURE_BYTES,
    ML_DSA_SIGNATURE_BYTES
  );
  const signingPublicKey = fromBase64(
    directV4 ? contact.preferredInstallationEndpoint.signingPublicKey : contact.signingPublicKey,
    directV4 ? "contact installation signing key" : "contact signing key",
    ML_DSA_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES
  );
  const valid = pqc.verify(
    canonicalEnvelopeBytes(envelope),
    signature,
    signingPublicKey
  );
  if (!valid) {
    throw new NoctweaveRemoteEnvelopeError(
      "invalidAttribution",
      `Invalid signature from ${contact.displayName}`
    );
  }
}

export async function decryptNativeApplicationEnvelope(options) {
  const decoded = await decryptNativeEnvelopePayload(options);
  if (decoded.kind !== "application" && decoded.kind !== "receipt") {
    throw new Error("Typed application decoding requires a direct-v4 envelope.");
  }
  return decoded;
}

// Compatibility projection for text-oriented callers. Unknown visible
// application content becomes its authenticated fallback; silent content is
// returned as `null` and must not create a chat bubble.
export async function decryptNativeEnvelope(options) {
  const decoded = await decryptNativeEnvelopePayload(options);
  if (decoded.kind === "legacyText") {
    return decoded.text;
  }
  if (decoded.projection.kind === "text") {
    return decoded.projection.text;
  }
  return decoded.projection.disposition === "visible"
    ? decoded.projection.fallbackText
    : null;
}

async function decryptNativeEnvelopePayload({ crypto, pqc, identity, contact, conversation, envelope }) {
  assertNoDirectV4Fallback(contact);
  const negotiation = isCertifiedNativeContact(contact)
    ? await validateCurrentDirectV4Negotiation({
      crypto,
      identity,
      contact,
      endpointSession: conversation.endpointSession
    })
    : null;
  await verifyNativeEnvelope({ crypto, pqc, contact, conversation, envelope });
  const directV4 = isCertifiedNativeContact(contact);
  const candidateReceiveChain = cloneChain(conversation.receiveChain);
  const key = await receiveMessageKey(crypto, candidateReceiveChain, Number(envelope.messageCounter));
  const ciphertext = concatBytes(
    fromBase64(envelope.payload.ciphertext, "envelope ciphertext", MAX_PADDED_BYTES),
    fromBase64(envelope.payload.tag, "envelope tag", 16, 16)
  );
  let plaintext;
  try {
    plaintext = await crypto.aesGcmDecrypt({
      key,
      nonce: fromBase64(envelope.payload.nonce, "envelope nonce", 12, 12),
      ciphertext,
      additionalData: authenticatedData(
        conversation.id,
        conversation.sessionId,
        envelope.authenticatedContext ?? null,
        Number(envelope.messageCounter)
      )
    });
    let decoded;
    try {
      if (directV4) {
        const event = decodePaddedDirectV4Application(plaintext, envelope);
        const projection = projectDirectV4Application(event);
        validateNegotiatedApplicationLimits({
          event,
          paddedBytes: plaintext.byteLength,
          negotiation
        });
        decoded = { kind: event.kind, event, projection };
      } else {
        decoded = { kind: "legacyText", text: decodePaddedText(plaintext) };
      }
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

export async function verifyNativeContactOffer({ crypto, pqc, offer }) {
  if (offer?.version === 4) {
    await verifyCertifiedNativeContactOffer({ crypto, pqc, offer });
    return;
  }
  validateContactOfferStructure(offer);
  const unsigned = unsignedContactOffer(offer);
  const signingPublicKey = fromBase64(
    offer.signingPublicKey,
    "contact signing key",
    ML_DSA_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES
  );
  const actualFingerprint = base64(await crypto.sha256(signingPublicKey));
  if (actualFingerprint !== offer.fingerprint) {
    throw new Error("Contact fingerprint does not match its signing key.");
  }
  if (!pqc.verify(
    canonicalJsonBytes(unsigned),
    fromBase64(
      offer.signature,
      "contact signature",
      ML_DSA_SIGNATURE_BYTES,
      ML_DSA_SIGNATURE_BYTES
    ),
    signingPublicKey
  )) {
    throw new Error("Contact offer signature failed verification.");
  }
}

export function makeNativeContactOffer({ pqc, identity, relayEndpoint }) {
  if (identity?.certifiedInstallationEndpoint != null) {
    return makeCertifiedNativeContactOffer({ pqc, identity, relayEndpoint });
  }
  const unsigned = {
    agreementPublicKey: identity.agreement.publicKey,
    displayName: identity.displayName,
    fingerprint: identity.signingFingerprint,
    inboxAccessPublicKey: identity.access.publicKey,
    inboxId: identity.inboxId,
    relay: relayEndpoint,
    signingPublicKey: identity.signing.publicKey,
    version: 3
  };
  const signingSecretKey = fromBase64(
    identity.signing.secretKey,
    "local signing secret key",
    ML_DSA_SECRET_KEY_BYTES,
    ML_DSA_SECRET_KEY_BYTES
  );
  try {
    const signature = pqc.sign(canonicalJsonBytes(unsigned), signingSecretKey);
    if (!(signature instanceof Uint8Array) || signature.byteLength !== ML_DSA_SIGNATURE_BYTES) {
      throw new Error("ML-DSA signing returned an invalid signature.");
    }
    return { ...unsigned, signature: base64(signature) };
  } finally {
    wipeBytes(signingSecretKey);
  }
}

export function encodeNativeContactCode(offer) {
  const encoded = encoder.encode(JSON.stringify(offer));
  if (encoded.byteLength > MAX_CONTACT_CODE_BYTES) {
    throw new Error("Contact code exceeds the 64 KB limit.");
  }
  return base64(encoded);
}

export function decodeNativeContactCode(code) {
  if (typeof code !== "string" || code.trim() !== code || code.length > 100_000) {
    throw new Error("Contact code is malformed or too large.");
  }
  const decoded = fromBase64(code, "contact code", MAX_CONTACT_CODE_BYTES);
  const offer = JSON.parse(decoder.decode(decoded));
  validateContactOfferStructure(offer);
  return offer;
}

export function nativeConversationKey(contact) {
  if (isCertifiedNativeContact(contact)) {
    const endpoint = contact.preferredInstallationEndpoint;
    return `direct-v4:${contact.fingerprint}:${endpoint.installationId}:${endpoint.manifestEpoch}`;
  }
  return contact.fingerprint;
}

export async function findNativeContactForEnvelope({ crypto, identity, contacts, envelope }) {
  if (!Array.isArray(contacts)) {
    throw new TypeError("Contacts must be an array.");
  }
  if (envelope?.authenticatedContext?.purpose !== "directV4") {
    return contacts.find((contact) => contact.fingerprint === envelope?.senderFingerprint) ?? null;
  }
  for (const contact of contacts) {
    if (!isCertifiedNativeContact(contact)) continue;
    const binding = await deriveNativeDirectV4Binding({ crypto, identity, contact });
    if (binding.peerInstallationHandle.rawValue === envelope.senderFingerprint &&
        binding.localInstallationHandle.rawValue ===
          envelope.authenticatedContext.directV4?.recipientInstallationHandle) {
      return contact;
    }
  }
  return null;
}

export function canonicalEnvelopeBytes(envelope) {
  const signable = {
    conversationId: envelope.conversationId,
    id: envelope.id,
    messageCounter: envelope.messageCounter,
    payload: envelope.payload,
    senderFingerprint: envelope.senderFingerprint,
    sentAt: envelope.sentAt
  };
  for (const key of ["authenticatedContext", "kemCiphertext", "prekey", "rootRatchet", "sessionId"]) {
    if (envelope[key] !== null && envelope[key] !== undefined) {
      signable[key] = envelope[key];
    }
  }
  return canonicalJsonBytes(signable);
}

export function nativeAuthenticatedDataBytes({
  conversationId,
  sessionId,
  authenticatedContext = null,
  messageCounter = 0
}) {
  return authenticatedData(
    conversationId,
    sessionId,
    authenticatedContext,
    messageCounter
  );
}

function unsignedContactOffer(offer) {
  const unsigned = {
    agreementPublicKey: offer.agreementPublicKey,
    displayName: offer.displayName,
    fingerprint: offer.fingerprint,
    inboxId: offer.inboxId,
    relay: offer.relay,
    signingPublicKey: offer.signingPublicKey,
    version: offer.version
  };
  if (offer.inboxAccessPublicKey !== null && offer.inboxAccessPublicKey !== undefined) {
    unsigned.inboxAccessPublicKey = offer.inboxAccessPublicKey;
  }
  return unsigned;
}

async function validateNativeEnvelope({ crypto, contact, conversation, envelope }) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("Envelope is malformed.");
  }
  if (envelope.conversationId !== conversation.id) {
    throw new Error("Envelope conversation does not match this contact.");
  }
  if ((envelope.sessionId ?? "") !== conversation.sessionId) {
    throw new Error("Envelope session does not match this conversation.");
  }
  if (!isBoundedString(envelope.conversationId, 256) ||
      !isCanonicalSwiftUUID(envelope.id) ||
      !isBoundedString(envelope.sessionId, 128) ||
      !isBoundedString(envelope.senderFingerprint, 128) ||
      !isBoundedString(envelope.sentAt, 64) ||
      !Number.isFinite(Date.parse(envelope.sentAt)) ||
      !Number.isSafeInteger(envelope.messageCounter) ||
      envelope.messageCounter < 0) {
    throw new Error("Envelope metadata is invalid.");
  }
  if (isCertifiedNativeContact(contact)) {
    validateInboundDirectV4Context({
      context: envelope.authenticatedContext,
      endpointSession: conversation.endpointSession
    });
    if (envelope.senderFingerprint !== conversation.endpointSession.peerInstallationHandle.rawValue) {
      throw new Error("Envelope sender does not match the pairwise installation handle.");
    }
    if (envelope.kemCiphertext != null &&
        (envelope.prekey?.kind !== "signed" || !isCanonicalSwiftUUID(envelope.prekey?.id))) {
      throw new Error("Direct-v4 bootstrap prekey reference is invalid.");
    }
  } else {
    const contactSigningKey = fromBase64(
      contact.signingPublicKey,
      "contact signing key",
      ML_DSA_PUBLIC_KEY_BYTES,
      ML_DSA_PUBLIC_KEY_BYTES
    );
    const expectedFingerprint = base64(await crypto.sha256(contactSigningKey));
    if (contact.fingerprint !== expectedFingerprint || envelope.senderFingerprint !== expectedFingerprint) {
      throw new Error("Envelope sender identity does not match the contact signing key.");
    }
  }
  const signature = fromBase64(
    envelope.signature,
    "envelope signature",
    ML_DSA_SIGNATURE_BYTES,
    ML_DSA_SIGNATURE_BYTES
  );
  const nonce = fromBase64(envelope.payload?.nonce, "envelope nonce", 12, 12);
  const tag = fromBase64(envelope.payload?.tag, "envelope tag", 16, 16);
  const ciphertext = fromBase64(
    envelope.payload?.ciphertext,
    "envelope ciphertext",
    MAX_PADDED_BYTES
  );
  let kemCiphertext;
  try {
    if (ciphertext.byteLength < MIN_PADDED_BYTES ||
        ciphertext.byteLength > MAX_PADDED_BYTES ||
        (ciphertext.byteLength & (ciphertext.byteLength - 1)) !== 0) {
      throw new Error("Envelope ciphertext padding bucket is invalid.");
    }
    if (envelope.kemCiphertext !== undefined && envelope.kemCiphertext !== null) {
      kemCiphertext = fromBase64(
        envelope.kemCiphertext,
        "KEM ciphertext",
        ML_KEM_CIPHERTEXT_BYTES,
        ML_KEM_CIPHERTEXT_BYTES
      );
    }
    if (canonicalEnvelopeBytes(envelope).byteLength > 512 * 1024) {
      throw new Error("Envelope signature payload exceeds its size limit.");
    }
  } finally {
    wipeBytes(signature);
    wipeBytes(nonce);
    wipeBytes(tag);
    wipeBytes(ciphertext);
    wipeBytes(kemCiphertext);
  }
}

function validateContactOfferStructure(offer) {
  if (!offer || typeof offer !== "object" || Array.isArray(offer) ||
      ![2, 3, 4].includes(offer.version) ||
      !isBoundedString(offer.displayName, 256) ||
      !isBoundedString(offer.inboxId, 256) ||
      !isBoundedString(offer.fingerprint, 128) ||
      !offer.relay || typeof offer.relay !== "object") {
    throw new Error("Contact offer is malformed.");
  }
  if (offer.version === 4) {
    if (!isCanonicalSwiftUUID(offer.identityGenerationId) ||
        offer.installationCheckpoint == null || offer.preferredInstallationEndpoint == null) {
      throw new Error("Certified contact offer is malformed.");
    }
  } else if ((offer.version === 2 && offer.inboxAccessPublicKey != null) ||
      (offer.version === 3 && offer.inboxAccessPublicKey == null) ||
      offer.identityGenerationId != null || offer.installationCheckpoint != null ||
      offer.preferredInstallationEndpoint != null) {
    throw new Error("Legacy contact offer version is inconsistent with its fields.");
  }
  const fields = [
    [offer.fingerprint, "contact fingerprint", FINGERPRINT_BYTES],
    [offer.signingPublicKey, "contact signing key", ML_DSA_PUBLIC_KEY_BYTES],
    [offer.agreementPublicKey, "contact agreement key", ML_KEM_PUBLIC_KEY_BYTES],
    [offer.signature, "contact signature", ML_DSA_SIGNATURE_BYTES]
  ];
  if (offer.inboxAccessPublicKey != null) {
    fields.push([offer.inboxAccessPublicKey, "contact inbox access key", ML_DSA_PUBLIC_KEY_BYTES]);
  }
  for (const [value, label, length] of fields) {
    const decoded = fromBase64(value, label, length, length);
    wipeBytes(decoded);
  }
}

function assertNoDirectV4Fallback(contact) {
  const carriesDirectV4State = contact?.version === 4 ||
    contact?.identityGenerationId != null ||
    contact?.installationCheckpoint != null ||
    contact?.preferredInstallationEndpoint != null;
  if (carriesDirectV4State && !isCertifiedNativeContact(contact)) {
    throw new Error("Certified direct-v4 endpoint capabilities are required; legacy fallback is forbidden.");
  }
}

async function validateCurrentDirectV4Negotiation({
  crypto,
  identity,
  contact,
  binding = null,
  endpointSession = null
}) {
  const localEndpoint = identity?.certifiedInstallationEndpoint;
  const peerEndpoint = contact?.preferredInstallationEndpoint;
  if (!localEndpoint || !peerEndpoint) {
    throw new Error("Certified direct-v4 endpoints are required for negotiation.");
  }
  const negotiated = await negotiateNativeDirectV4({ crypto, localEndpoint, peerEndpoint });
  const transcript = endpointSession ?? binding;
  if (!transcript || transcript.cipherSuite !== negotiated.manifest.cipherSuite ||
      transcript.negotiatedCapabilitiesDigest !== negotiated.digest) {
    throw new Error("Direct-v4 capability transcript does not match the endpoint session.");
  }
  return negotiated.manifest;
}

function negotiatedLimit(negotiation, moduleName, limitName) {
  const value = negotiation?.modules?.find(({ module }) => module === moduleName)
    ?.limits?.[limitName];
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Direct-v4 negotiated limit ${moduleName}.${limitName} is missing.`);
  }
  return value;
}

function validateNegotiatedPrekeyFreshness(prekey, negotiation, now) {
  const nowMs = typeof now === "number" ? now : new Date(now).getTime();
  const issuedAtMs = Date.parse(prekey?.issuedAt);
  const expiresAtMs = Date.parse(prekey?.expiresAt);
  const maximumAgeMs = negotiatedLimit(
    negotiation,
    "nw.prekeys",
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
    negotiatedLimit(negotiation, "nw.events", "maxContentPayloadBytes")
  );
  try {
    const maxParameterBytes = negotiatedLimit(
      negotiation,
      "nw.events",
      "maxContentParameterBytes"
    );
    if (paddedBytes > negotiatedLimit(negotiation, "nw.core", "maxCiphertextBytes") ||
        Object.keys(content.parameters).length > negotiatedLimit(
          negotiation,
          "nw.events",
          "maxContentParameters"
        ) ||
        (content.fallbackText != null &&
          encoder.encode(content.fallbackText).byteLength > negotiatedLimit(
            negotiation,
            "nw.events",
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
  contactAgreementPublicKey,
  contactFingerprint,
  conversationId = null,
  endpointSession = null
}) {
  const directBinding = endpointSession ? directV4SessionBindingBytes(endpointSession) : null;
  const rootInfo = directBinding
    ? concatBytes(encoder.encode("ROOT"), directBinding)
    : encoder.encode("ROOT");
  const rootKey = await crypto.hkdfSha256({
    ikm: sharedSecret,
    salt: "NOCTWEAVE-ROOT",
    info: rootInfo,
    length: 32
  });
  const [sendLabel, receiveLabel] = labelsForAgreement(ownAgreementPublicKey, contactAgreementPublicKey);
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
    sessionMaterial = directBinding
      ? concatBytes(encoder.encode("NOCTWEAVE-SESSION"), directBinding, rootKey)
      : concatBytes(encoder.encode("NOCTWEAVE-SESSION"), sharedSecret);
    sessionHash = await crypto.sha256(sessionMaterial);
    const conversation = {
      id: conversationId ?? await conversationIdForAgreement(
        crypto,
        ownAgreementPublicKey,
        contactAgreementPublicKey
      ),
      contactFingerprint,
      sessionId: base64(sessionHash),
      rootKey: base64(rootKey),
      rootCounter: 0,
      sendChain: serializeChain(sendKey),
      receiveChain: serializeChain(receiveKey)
    };
    if (endpointSession) {
      conversation.endpointSession = endpointSession;
    }
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

function authenticatedData(conversationId, sessionId, context = null, messageCounter = 0) {
  if (context?.purpose === "directV4") {
    return canonicalJsonBytes({
      version: 4,
      conversationId,
      sessionId,
      messageCounter,
      context
    });
  }
  return canonicalJsonBytes({ conversationId, sessionId, version: 1 });
}

function encodePaddedText(text, randomBytes) {
  if (typeof text !== "string") {
    throw new TypeError("Message text must be a string.");
  }
  return encodePaddedBody({ text, type: "text" }, NPAD_MAGIC, randomBytes);
}

function encodePaddedDirectV4Application(eventValue, randomBytes) {
  const event = validateConversationEvent(eventValue);
  if (event.kind !== "application" && event.kind !== "receipt") {
    throw new TypeError("Only application and receipt events use the extensible direct-v4 codec.");
  }
  return encodePaddedBody({
    version: 2,
    kind: "application",
    application: event
  }, NPAD_V2_MAGIC, randomBytes);
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

function decodePaddedText(data) {
  if (!(data instanceof Uint8Array) ||
      data.byteLength < MIN_PADDED_BYTES ||
      data.byteLength > MAX_PADDED_BYTES ||
      (data.byteLength & (data.byteLength - 1)) !== 0 ||
      !startsWith(data, NPAD_MAGIC)) {
    throw new Error("Message padding frame is invalid.");
  }
  const length = readUint32BE(data.subarray(NPAD_MAGIC.byteLength, NPAD_HEADER_BYTES));
  if (length <= 0 || length > data.byteLength - NPAD_HEADER_BYTES || paddedSizeFor(length) !== data.byteLength) {
    throw new Error("Message padding frame length is invalid.");
  }
  const bodyData = data.subarray(NPAD_HEADER_BYTES, NPAD_HEADER_BYTES + length);
  const body = JSON.parse(decoder.decode(bodyData));
  if (body.type !== "text" || typeof body.text !== "string") {
    throw new Error(`Unsupported native message body: ${body.type ?? "unknown"}`);
  }
  return body.text;
}

function decodePaddedDirectV4Application(data, envelope) {
  const body = decodePaddedBody(data, NPAD_V2_MAGIC);
  if (body?.version !== 2 || body.kind !== "application" || body.control != null) {
    throw new Error("Direct-v4 control and application payloads are separated.");
  }
  const event = validateConversationEvent(body.application);
  const direct = envelope.authenticatedContext?.directV4;
  if (event.id !== direct?.eventId ||
      event.conversationId !== envelope.conversationId ||
      event.authorInstallationHandle.rawValue !== direct.senderInstallationHandle ||
      event.createdAt !== envelope.sentAt ||
      (event.kind !== "application" && event.kind !== "receipt")) {
    throw new Error("Direct-v4 wire payload does not match its authenticated context.");
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

async function conversationIdForAgreement(crypto, ourKey, theirKey) {
  const ordered = compareBytes(ourKey, theirKey) <= 0 ? [ourKey, theirKey] : [theirKey, ourKey];
  return base64(await crypto.sha256(concatBytes(ordered[0], ordered[1])));
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
