import {
  acknowledgeContactPairingOutboundV2,
  finalizeContactPairingV2,
  prepareContactPairingOffererV2,
  prepareContactPairingResponderV2,
  processContactPairingTransportFrameV2,
  resumeContactPairingV2
} from "../src/contact-pairing-v2.js";
import { createRendezvousRedemptionLedgerV2 } from "../src/rendezvous-v2.js";
import { swiftISODate } from "../src/crypto/swift-canonical.js";

// Test-only orchestration for exercising two independently persisted peers.
// Production APIs never accept both participants' private state in one call.
export async function runContactPairingConformanceV2({
  crypto,
  pqc,
  pending,
  invitation,
  offerer,
  responder,
  ledger = createRendezvousRedemptionLedgerV2(),
  at = swiftISODate()
}) {
  let offererState = await prepareContactPairingOffererV2({
    crypto,
    pqc,
    pending,
    invitation,
    participant: offerer,
    ledger,
    at
  });
  let responderState = await prepareContactPairingResponderV2({
    crypto,
    pqc,
    invitation,
    participant: responder,
    at
  });

  ({ sender: responderState, receiver: offererState } = await deliverOutbox({
    crypto, pqc, sender: responderState, receiver: offererState, at
  }));
  ({ sender: offererState, receiver: responderState } = await deliverOutbox({
    crypto, pqc, sender: offererState, receiver: responderState, at
  }));
  ({ sender: responderState, receiver: offererState } = await deliverOutbox({
    crypto, pqc, sender: responderState, receiver: offererState, at
  }));
  ({ sender: offererState, receiver: responderState } = await deliverOutbox({
    crypto, pqc, sender: offererState, receiver: responderState, at
  }));

  const offererFinal = await finalizeContactPairingV2({ crypto, pqc, state: offererState, at });
  const responderFinal = await finalizeContactPairingV2({ crypto, pqc, state: responderState, at });
  return Object.freeze({
    relationshipID: offererFinal.relationship.relationshipID,
    offererRelationship: offererFinal.relationship,
    responderRelationship: responderFinal.relationship,
    pending: offererState.pendingOffer,
    ledger: offererState.ledger
  });
}

async function deliverOutbox({ crypto, pqc, sender: senderValue, receiver: receiverValue, at }) {
  let sender = await resumeContactPairingV2({ crypto, pqc, state: senderValue });
  let receiver = await resumeContactPairingV2({ crypto, pqc, state: receiverValue });
  for (const outbound of [...sender.outboundTransportFrames]) {
    receiver = await processContactPairingTransportFrameV2({
      crypto,
      pqc,
      state: receiver,
      transportFrame: outbound.frame,
      at
    });
    sender = await acknowledgeContactPairingOutboundV2({
      crypto,
      pqc,
      state: sender,
      frameIDs: [outbound.frame.frameId.rawValue]
    });
  }
  return { sender, receiver };
}
