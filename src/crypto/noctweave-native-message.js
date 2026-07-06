import { base64, canonicalJsonBytes, swiftISODate, swiftUUID } from "./swift-canonical.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const NPAD_MAGIC = new Uint8Array([0x4e, 0x50, 0x41, 0x44, 0x01]);
const NPAD_HEADER_BYTES = 9;
const MIN_PADDED_BYTES = 512;
const MAX_PADDED_BYTES = 65_536;
const MAX_SKIP = 64;

export async function createNativeOutboundSession({ crypto, pqc, identity, contact }) {
  const encapsulated = pqc.encapsulate(fromBase64(contact.agreementPublicKey));
  try {
    const conversation = await conversationFromSharedSecret({
      crypto,
      sharedSecret: encapsulated.sharedSecret,
      ownAgreementPublicKey: fromBase64(identity.agreement.publicKey),
      contactAgreementPublicKey: fromBase64(contact.agreementPublicKey),
      contactFingerprint: contact.fingerprint
    });
    return { conversation, kemCiphertext: encapsulated.ciphertext };
  } finally {
    wipeBytes(encapsulated.sharedSecret);
  }
}

export async function createNativeInboundSession({ crypto, pqc, identity, contact, kemCiphertext }) {
  const ownAgreement = deserializeKeypair(identity.agreement);
  let sharedSecret;
  try {
    sharedSecret = pqc.decapsulate(fromBase64(kemCiphertext), ownAgreement.secretKey);
    return await conversationFromSharedSecret({
      crypto,
      sharedSecret,
      ownAgreementPublicKey: ownAgreement.publicKey,
      contactAgreementPublicKey: fromBase64(contact.agreementPublicKey),
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
  const ownSigning = deserializeKeypair(identity.signing);
  const prepared = await nextMessageKey(crypto, conversation.sendChain);
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
    envelope.signature = base64(pqc.sign(canonicalEnvelopeBytes(envelope), ownSigning.secretKey));
    return envelope;
  } finally {
    wipeBytes(ownSigning.secretKey);
    wipeBytes(prepared.key);
    wipeBytes(plaintext);
  }
}

export async function decryptNativeEnvelope({ crypto, pqc, identity, contact, conversation, envelope }) {
  const valid = pqc.verify(
    canonicalEnvelopeBytes(envelope),
    fromBase64(envelope.signature),
    fromBase64(contact.signingPublicKey)
  );
  if (!valid) {
    throw new Error(`Invalid signature from ${contact.displayName}`);
  }
  if (envelope.conversationId !== conversation.id) {
    throw new Error("Envelope conversation does not match this contact.");
  }
  if ((envelope.sessionId ?? "") !== conversation.sessionId) {
    throw new Error("Envelope session does not match this conversation.");
  }
  const key = await receiveMessageKey(crypto, conversation.receiveChain, Number(envelope.messageCounter));
  const ciphertext = concatBytes(fromBase64(envelope.payload.ciphertext), fromBase64(envelope.payload.tag));
  let plaintext;
  try {
    plaintext = await crypto.aesGcmDecrypt({
      key,
      nonce: fromBase64(envelope.payload.nonce),
      ciphertext,
      additionalData: authenticatedData(conversation.id, conversation.sessionId)
    });
    return decodePaddedText(plaintext);
  } finally {
    wipeBytes(key);
    wipeBytes(plaintext);
  }
}

export async function verifyNativeContactOffer({ crypto, pqc, offer }) {
  const unsigned = unsignedContactOffer(offer);
  const actualFingerprint = base64(await crypto.sha256(fromBase64(offer.signingPublicKey)));
  if (actualFingerprint !== offer.fingerprint) {
    throw new Error("Contact fingerprint does not match its signing key.");
  }
  if (!pqc.verify(canonicalJsonBytes(unsigned), fromBase64(offer.signature), fromBase64(offer.signingPublicKey))) {
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
  return {
    ...unsigned,
    signature: base64(pqc.sign(canonicalJsonBytes(unsigned), fromBase64(identity.signing.secretKey)))
  };
}

export function encodeNativeContactCode(offer) {
  return base64(encoder.encode(JSON.stringify(offer)));
}

export function decodeNativeContactCode(code) {
  return JSON.parse(decoder.decode(fromBase64(code.trim())));
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
  const counter = Number(chain.counter ?? 0);
  const keyData = fromBase64(chain.keyData);
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
  chain.skippedMessageKeys ??= {};
  const cached = chain.skippedMessageKeys[String(targetCounter)];
  if (cached) {
    delete chain.skippedMessageKeys[String(targetCounter)];
    return fromBase64(cached);
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
  let bodyData = data;
  if (data.byteLength >= NPAD_HEADER_BYTES && startsWith(data, NPAD_MAGIC)) {
    const length = readUint32BE(data.subarray(NPAD_MAGIC.byteLength, NPAD_HEADER_BYTES));
    bodyData = data.subarray(NPAD_HEADER_BYTES, NPAD_HEADER_BYTES + length);
  }
  const body = JSON.parse(decoder.decode(bodyData));
  if (body.type !== "text") {
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

function deserializeKeypair(keypair) {
  return {
    publicKey: fromBase64(keypair.publicKey),
    secretKey: fromBase64(keypair.secretKey)
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

function fromBase64(value) {
  const binary = atob(value);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    output[index] = binary.charCodeAt(index);
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
