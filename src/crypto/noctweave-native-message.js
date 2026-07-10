import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./swift-canonical.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const NPAD_MAGIC = new Uint8Array([0x4e, 0x50, 0x41, 0x44, 0x01]);
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

export async function createNativeOutboundSession({ crypto, pqc, identity, contact }) {
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

export async function createNativeInboundSession({ crypto, pqc, identity, contact, kemCiphertext }) {
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

export async function encryptNativeTextEnvelope({
  crypto,
  pqc,
  identity,
  contact,
  conversation,
  text,
  kemCiphertext = null,
  sentAt = swiftISODate()
}) {
  const ownSigning = deserializeKeypair(identity.signing, {
    publicKeyBytes: ML_DSA_PUBLIC_KEY_BYTES,
    secretKeyBytes: ML_DSA_SECRET_KEY_BYTES,
    label: "local signing keypair"
  });
  const candidateSendChain = cloneChain(conversation.sendChain);
  const prepared = await nextMessageKey(crypto, candidateSendChain);
  const plaintext = encodePaddedText(text, (length) => crypto.randomBytes(length));
  const aad = authenticatedData(conversation.id, conversation.sessionId);
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
      senderFingerprint: identity.signingFingerprint,
      sentAt,
      messageCounter: prepared.counter,
      payload: {
        nonce: base64(nonce),
        ciphertext: base64(encrypted.slice(0, -16)),
        tag: base64(encrypted.slice(-16))
      },
      signature: ""
    };
    if (kemCiphertext) {
      envelope.kemCiphertext = base64(kemCiphertext);
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

export async function decryptNativeEnvelope({ crypto, pqc, identity, contact, conversation, envelope }) {
  await validateNativeEnvelope({ crypto, contact, conversation, envelope });
  const signature = fromBase64(
    envelope.signature,
    "envelope signature",
    ML_DSA_SIGNATURE_BYTES,
    ML_DSA_SIGNATURE_BYTES
  );
  const signingPublicKey = fromBase64(
    contact.signingPublicKey,
    "contact signing key",
    ML_DSA_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES
  );
  const valid = pqc.verify(
    canonicalEnvelopeBytes(envelope),
    signature,
    signingPublicKey
  );
  if (!valid) {
    throw new Error(`Invalid signature from ${contact.displayName}`);
  }
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
      additionalData: authenticatedData(conversation.id, conversation.sessionId)
    });
    const text = decodePaddedText(plaintext);
    commitChain(conversation.receiveChain, candidateReceiveChain);
    return text;
  } finally {
    wipeBytes(key);
    wipeBytes(plaintext);
  }
}

export async function verifyNativeContactOffer({ crypto, pqc, offer }) {
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
  return contact.fingerprint;
}

export function canonicalEnvelopeBytes(envelope) {
  const signable = {
    conversationId: envelope.conversationId,
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
      !isBoundedString(envelope.sessionId, 128) ||
      !isBoundedString(envelope.senderFingerprint, 128) ||
      !isBoundedString(envelope.sentAt, 64) ||
      !Number.isFinite(Date.parse(envelope.sentAt)) ||
      !Number.isSafeInteger(envelope.messageCounter) ||
      envelope.messageCounter < 0) {
    throw new Error("Envelope metadata is invalid.");
  }
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
      offer.version !== 3 ||
      !isBoundedString(offer.displayName, 256) ||
      !isBoundedString(offer.inboxId, 256) ||
      !isBoundedString(offer.fingerprint, 128) ||
      !offer.relay || typeof offer.relay !== "object") {
    throw new Error("Contact offer is malformed.");
  }
  const fields = [
    [offer.fingerprint, "contact fingerprint", FINGERPRINT_BYTES],
    [offer.signingPublicKey, "contact signing key", ML_DSA_PUBLIC_KEY_BYTES],
    [offer.agreementPublicKey, "contact agreement key", ML_KEM_PUBLIC_KEY_BYTES],
    [offer.inboxAccessPublicKey, "contact inbox access key", ML_DSA_PUBLIC_KEY_BYTES],
    [offer.signature, "contact signature", ML_DSA_SIGNATURE_BYTES]
  ];
  for (const [value, label, length] of fields) {
    const decoded = fromBase64(value, label, length, length);
    wipeBytes(decoded);
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

async function conversationFromSharedSecret({
  crypto,
  sharedSecret,
  ownAgreementPublicKey,
  contactAgreementPublicKey,
  contactFingerprint
}) {
  const rootKey = await crypto.hkdfSha256({
    ikm: sharedSecret,
    salt: "NOCTWEAVE-ROOT",
    info: "ROOT",
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
    sessionMaterial = concatBytes(encoder.encode("NOCTWEAVE-SESSION"), sharedSecret);
    sessionHash = await crypto.sha256(sessionMaterial);
    return {
      id: await conversationIdForAgreement(crypto, ownAgreementPublicKey, contactAgreementPublicKey),
      contactFingerprint,
      sessionId: base64(sessionHash),
      rootKey: base64(rootKey),
      rootCounter: 0,
      sendChain: serializeChain(sendKey),
      receiveChain: serializeChain(receiveKey)
    };
  } finally {
    wipeBytes(rootKey);
    wipeBytes(sendKey);
    wipeBytes(receiveKey);
    wipeBytes(sessionMaterial);
    wipeBytes(sessionHash);
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

function authenticatedData(conversationId, sessionId) {
  return canonicalJsonBytes({ conversationId, sessionId, version: 1 });
}

function encodePaddedText(text, randomBytes) {
  if (typeof text !== "string") {
    throw new TypeError("Message text must be a string.");
  }
  const bodyData = canonicalJsonBytes({ text, type: "text" });
  let padding;
  try {
    const paddedSize = paddedSizeFor(bodyData.byteLength);
    if (paddedSize > MAX_PADDED_BYTES) {
      throw new Error("Plaintext exceeds native message size limit.");
    }
    const paddingCount = paddedSize - NPAD_HEADER_BYTES - bodyData.byteLength;
    const output = new Uint8Array(paddedSize);
    output.set(NPAD_MAGIC, 0);
    output.set(uint32BE(bodyData.byteLength), NPAD_MAGIC.byteLength);
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
