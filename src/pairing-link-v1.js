import { normalizeRelayEndpoint } from "./endpoint.js";
import { parseExactJSON } from "./strict-json.js";
import {
  base64,
  canonicalJsonBytes
} from "./crypto/swift-canonical.js";
import {
  decodeContactPairingInvitationV2,
  encodeContactPairingInvitationV2
} from "./contact-pairing-v2.js";

export const noctweavePairingLinkV1Prefix = "noctweave-pair-v1:";
export const noctweavePairingLinkV1MaximumCharacters = 96 * 1_024;

const decoder = new TextDecoder("utf-8", { fatal: true });
const wrapperFields = ["invitation", "relay", "version"];
const relayFields = [
  "directorySigningPublicKey",
  "host",
  "port",
  "tlsCertificateFingerprintSHA256",
  "transport",
  "useTLS"
];

export async function encodeNoctweavePairingLinkV1({
  crypto,
  relay,
  invitation
}) {
  const endpoint = normalizeRelayEndpoint(relay);
  const validatedInvitation = await decodeContactPairingInvitationV2({
    crypto,
    encoded: await encodeContactPairingInvitationV2({ crypto, invitation })
  });
  const wrapper = {
    version: 1,
    relay: {
      host: endpoint.host,
      port: endpoint.port,
      useTLS: endpoint.useTLS,
      transport: endpoint.transport,
      tlsCertificateFingerprintSHA256: null,
      directorySigningPublicKey: null
    },
    invitation: validatedInvitation
  };
  const value = noctweavePairingLinkV1Prefix + base64(canonicalJsonBytes(wrapper));
  if (value.length > noctweavePairingLinkV1MaximumCharacters) {
    throw new TypeError("Pairing link is too large.");
  }
  return value;
}

export async function decodeNoctweavePairingLinkV1({ crypto, encoded }) {
  if (typeof encoded !== "string" ||
      encoded.trim() !== encoded ||
      !encoded.startsWith(noctweavePairingLinkV1Prefix) ||
      encoded.length > noctweavePairingLinkV1MaximumCharacters) {
    throw new TypeError("Pairing link is malformed.");
  }
  const payload = decodeCanonicalBase64(
    encoded.slice(noctweavePairingLinkV1Prefix.length)
  );
  const wrapper = parseExactJSON(decoder.decode(payload));
  requireExactFields(wrapper, wrapperFields, "Pairing link");
  if (wrapper.version !== 1) throw new TypeError("Pairing link version is unsupported.");
  requireExactFields(wrapper.relay, relayFields, "Pairing relay");
  if (wrapper.relay.tlsCertificateFingerprintSHA256 !== null ||
      wrapper.relay.directorySigningPublicKey !== null) {
    throw new TypeError("Pinned relay pairing links are not supported by this client.");
  }
  const relay = normalizeRelayEndpoint(wrapper.relay);
  const invitation = await decodeContactPairingInvitationV2({
    crypto,
    encoded: base64(canonicalJsonBytes(wrapper.invitation))
  });
  return Object.freeze({ version: 1, relay: Object.freeze(relay), invitation });
}

function decodeCanonicalBase64(value) {
  if (!value || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new TypeError("Pairing link is malformed.");
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new TypeError("Pairing link is malformed.");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64(bytes) !== value) throw new TypeError("Pairing link is not canonical.");
  return bytes;
}

function requireExactFields(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== fields.join(",")) {
    throw new TypeError(`${label} fields are invalid.`);
  }
}
