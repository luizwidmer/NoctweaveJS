import { canonicalJsonBytes } from "./swift-canonical.js";

export function envelopeSignablePayload(envelope) {
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
  return signable;
}

export function envelopeSignableBytes(envelope) {
  return canonicalJsonBytes(envelopeSignablePayload(envelope));
}
