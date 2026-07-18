import {
  contentTypeCanonicalName,
  createContentTypeId,
  createConversationEvent,
  createEncodedContent,
  validateContentTypeId,
  validateConversationEvent,
  validateRelationshipEndpointHandle
} from "./architecture-v2.js";
import { validateRelationshipEndpointBindingV4 } from "./crypto/direct-v4.js";
import { base64, canonicalJsonBytes, swiftUUID } from "./crypto/swift-canonical.js";
import { validatePairwiseRouteSetV2 } from "./pairwise-opaque-route-v2.js";
import { parseExactJSON } from "./strict-json.js";
import {
  equalBytes,
  freezeWire,
  requireBase64,
  requireCanonicalTimestamp,
  requireExactRecord,
  requireInteger,
  requireNonzeroFixedBase64
} from "./private-v2.js";

const decoder = new TextDecoder("utf-8", { fatal: true });
const relationshipUUID = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u;
const CONTROL_VERSION = 2;
const MAXIMUM_CONTROL_PAYLOAD_BYTES = 48 * 1_024;
const ML_DSA_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_SECRET_KEY_BYTES = 4_032;
const ML_DSA_SIGNATURE_BYTES = 3_309;

const controlNames = Object.freeze([
  "routeSetUpdate",
  "routeProbe",
  "endpointPrekeyUpdate"
]);

export const relationshipControlKindsV2 = Object.freeze(Object.fromEntries(
  controlNames.map((name) => [name, createContentTypeId({
    authority: "org.noctweave.control",
    name,
    major: CONTROL_VERSION,
    minor: 0
  })])
));

export const noctweaveRelationshipControlsV2 = Object.freeze({
  version: CONTROL_VERSION,
  maximumPayloadBytes: MAXIMUM_CONTROL_PAYLOAD_BYTES,
  knownKinds: Object.freeze([...controlNames])
});

export class RelationshipControlV2Error extends Error {
  constructor(code, message = code, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "RelationshipControlV2Error";
    this.code = code;
  }
}

export function createRelationshipRouteSetUpdateV2({ relationshipID, routeSet }) {
  return validateRelationshipRouteSetUpdateV2({ relationshipID, routeSet });
}

export function validateRelationshipRouteSetUpdateV2(value) {
  requireExactRecord(value, ["relationshipID", "routeSet"], [], "Relationship route-set update");
  const relationshipID = canonicalUUID(value.relationshipID, "Route-set update relationship");
  const routeSet = validatePairwiseRouteSetV2(value.routeSet);
  if (routeSet.relationshipID !== relationshipID) {
    throw new RelationshipControlV2Error(
      "invalidKnownControl",
      "Route-set update is scoped to a different relationship."
    );
  }
  return freezeWire({ relationshipID, routeSet });
}

export function createRelationshipRouteProbeV2({
  relationshipID,
  routeID,
  routeSetRevision,
  nonce = swiftUUID()
}) {
  return validateRelationshipRouteProbeV2({
    relationshipID,
    routeID,
    routeSetRevision,
    nonce
  });
}

export function validateRelationshipRouteProbeV2(value) {
  requireExactRecord(value, [
    "relationshipID",
    "routeID",
    "routeSetRevision",
    "nonce"
  ], [], "Relationship route probe");
  requireExactRecord(value.routeID, ["rawValue"], [], "Relationship route probe route ID");
  requireNonzeroFixedBase64(value.routeID.rawValue, 32, "Relationship route probe route ID");
  return freezeWire({
    relationshipID: canonicalUUID(value.relationshipID, "Route-probe relationship"),
    routeID: { rawValue: value.routeID.rawValue },
    routeSetRevision: requireInteger(
      value.routeSetRevision,
      "Route-probe route-set revision",
      0,
      Number.MAX_SAFE_INTEGER
    ),
    nonce: canonicalUUID(value.nonce, "Route-probe nonce")
  });
}

export function createRelationshipEndpointPrekeyUpdateV2({
  relationshipID,
  endpointBinding
}) {
  return validateRelationshipEndpointPrekeyUpdateV2({ relationshipID, endpointBinding });
}

export function validateRelationshipEndpointPrekeyUpdateV2(value) {
  requireExactRecord(value, [
    "relationshipID",
    "endpointBinding"
  ], [], "Relationship endpoint-prekey update");
  const endpointBinding = validateRelationshipEndpointBindingV4(
    value.endpointBinding,
    value.endpointBinding?.prekeyBundle?.createdAt
  );
  return freezeWire({
    relationshipID: canonicalUUID(value.relationshipID, "Endpoint-prekey update relationship"),
    endpointBinding
  });
}

export function relationshipControlKindV2(value) {
  const type = validateControlContentType(value);
  if (type.major !== CONTROL_VERSION || type.minor !== 0 ||
      !Object.hasOwn(relationshipControlKindsV2, type.name)) {
    return null;
  }
  return type.name;
}

export function createAuthenticatedRelationshipControlV2({
  pqc,
  kind,
  payload,
  relationshipID,
  eventID,
  senderEndpointHandle,
  issuedAt,
  senderSigningSecretKey,
  nonce = swiftUUID()
}) {
  if (!Object.hasOwn(relationshipControlKindsV2, kind)) {
    throw new RelationshipControlV2Error("unknownControl", "Control kind is not implemented.");
  }
  const validatedPayload = validateKnownPayload(kind, payload);
  const unsigned = {
    version: CONTROL_VERSION,
    type: relationshipControlKindsV2[kind],
    relationshipID: canonicalUUID(relationshipID, "Relationship control relationship"),
    eventID: canonicalUUID(eventID, "Relationship control event"),
    senderEndpointHandle: validateRelationshipEndpointHandle(senderEndpointHandle),
    issuedAt: requireCanonicalTimestamp(issuedAt, "Relationship control issue time"),
    nonce: canonicalUUID(nonce, "Relationship control nonce"),
    encodedPayload: base64(canonicalJsonBytes(validatedPayload))
  };
  if (validatedPayload.relationshipID !== unsigned.relationshipID) {
    throw new RelationshipControlV2Error(
      "invalidKnownControl",
      "Relationship control payload scope does not match its framing."
    );
  }
  const secretKey = requireBase64(
    senderSigningSecretKey,
    ML_DSA_SECRET_KEY_BYTES,
    "Relationship control signing key"
  );
  let signature;
  try {
    if (typeof pqc?.sign !== "function") {
      throw new TypeError("Relationship control creation requires ML-DSA signing.");
    }
    signature = pqc.sign(canonicalJsonBytes(unsigned), secretKey);
  } finally {
    secretKey.fill(0);
  }
  if (!(signature instanceof Uint8Array) || signature.byteLength !== ML_DSA_SIGNATURE_BYTES) {
    throw new RelationshipControlV2Error(
      "invalidKnownControl",
      "Relationship control signing returned an invalid signature."
    );
  }
  return validateAuthenticatedRelationshipControlV2({
    ...unsigned,
    signature: base64(signature)
  });
}

export function validateAuthenticatedRelationshipControlV2(value) {
  requireExactRecord(value, [
    "version",
    "type",
    "relationshipID",
    "eventID",
    "senderEndpointHandle",
    "issuedAt",
    "nonce",
    "encodedPayload",
    "signature"
  ], [], "Authenticated relationship control");
  if (value.version !== CONTROL_VERSION) {
    throw new RelationshipControlV2Error("invalidKnownControl", "Control version must be 2.");
  }
  const type = validateControlContentType(value.type);
  const payload = requireBase64(
    value.encodedPayload,
    undefined,
    "Relationship control payload"
  );
  if (payload.byteLength === 0 || payload.byteLength > MAXIMUM_CONTROL_PAYLOAD_BYTES) {
    throw new RelationshipControlV2Error("invalidKnownControl", "Control payload is outside its bounds.");
  }
  requireBase64(value.signature, ML_DSA_SIGNATURE_BYTES, "Relationship control signature");
  return freezeWire({
    version: CONTROL_VERSION,
    type,
    relationshipID: canonicalUUID(value.relationshipID, "Relationship control relationship"),
    eventID: canonicalUUID(value.eventID, "Relationship control event"),
    senderEndpointHandle: validateRelationshipEndpointHandle(value.senderEndpointHandle),
    issuedAt: requireCanonicalTimestamp(value.issuedAt, "Relationship control issue time"),
    nonce: canonicalUUID(value.nonce, "Relationship control nonce"),
    encodedPayload: value.encodedPayload,
    signature: value.signature
  });
}

export function authenticatedRelationshipControlV2SignablePayload(value) {
  const control = validateAuthenticatedRelationshipControlV2(value);
  return freezeWire({
    version: control.version,
    type: control.type,
    relationshipID: control.relationshipID,
    eventID: control.eventID,
    senderEndpointHandle: control.senderEndpointHandle,
    issuedAt: control.issuedAt,
    nonce: control.nonce,
    encodedPayload: control.encodedPayload
  });
}

export function authenticatedRelationshipControlV2SignableBytes(value) {
  return canonicalJsonBytes(authenticatedRelationshipControlV2SignablePayload(value));
}

export function verifyAuthenticatedRelationshipControlV2({
  pqc,
  control: controlValue,
  relationshipID,
  senderEndpointHandle,
  eventID,
  senderSigningPublicKey
}) {
  let control;
  try {
    control = validateAuthenticatedRelationshipControlV2(controlValue);
    if (control.relationshipID !== canonicalUUID(relationshipID, "Expected control relationship") ||
        control.eventID !== canonicalUUID(eventID, "Expected control event") ||
        control.senderEndpointHandle.rawValue !==
          validateRelationshipEndpointHandle(senderEndpointHandle).rawValue ||
        typeof pqc?.verify !== "function") {
      return false;
    }
    return pqc.verify(
      authenticatedRelationshipControlV2SignableBytes(control),
      requireBase64(control.signature, ML_DSA_SIGNATURE_BYTES, "Relationship control signature"),
      requireBase64(
        senderSigningPublicKey,
        ML_DSA_PUBLIC_KEY_BYTES,
        "Relationship control signing public key"
      )
    );
  } catch {
    return false;
  }
}

export function decodeKnownRelationshipControlV2(controlValue) {
  const control = validateAuthenticatedRelationshipControlV2(controlValue);
  const kind = relationshipControlKindV2(control.type);
  if (kind === null) return null;
  try {
    const value = decodeCanonicalPayload(control.encodedPayload, (payload) =>
      validateKnownPayload(kind, payload));
    if (value.relationshipID !== control.relationshipID) {
      throw new TypeError("Known relationship control payload has a different scope.");
    }
    return freezeWire({ kind, value });
  } catch (error) {
    throw new RelationshipControlV2Error(
      "invalidKnownControl",
      "Known relationship control payload is invalid.",
      error
    );
  }
}

export function createApplicationWirePayloadV2(application) {
  return validateWirePayloadV2({
    version: CONTROL_VERSION,
    kind: "application",
    application,
    control: null
  });
}

export function createRelationshipControlWirePayloadV2(control) {
  return validateWirePayloadV2({
    version: CONTROL_VERSION,
    kind: "control",
    application: null,
    control
  });
}

export function validateWirePayloadV2(value) {
  requireExactRecord(value, [
    "version",
    "kind",
    "application",
    "control"
  ], [], "Wire payload v2");
  if (value.version !== CONTROL_VERSION) {
    throw new RelationshipControlV2Error("invalidPayload", "Wire payload version must be 2.");
  }
  if (value.kind === "application") {
    if (value.control !== null) {
      throw new RelationshipControlV2Error("invalidPayload", "Application payload contains control state.");
    }
    const application = validateConversationEvent(value.application);
    if (application.kind === "control") {
      throw new RelationshipControlV2Error("invalidPayload", "Control events require control framing.");
    }
    return freezeWire({ version: CONTROL_VERSION, kind: "application", application, control: null });
  }
  if (value.kind === "control") {
    if (value.application !== null) {
      throw new RelationshipControlV2Error("invalidPayload", "Control payload contains application state.");
    }
    return freezeWire({
      version: CONTROL_VERSION,
      kind: "control",
      application: null,
      control: validateAuthenticatedRelationshipControlV2(value.control)
    });
  }
  throw new RelationshipControlV2Error("invalidPayload", "Wire payload kind is invalid.");
}

export function relationshipControlDispositionV2({
  pqc,
  wirePayload: wirePayloadValue,
  relationshipID,
  senderEndpointHandle,
  eventID,
  sentAt,
  receivedAt = sentAt,
  senderSigningPublicKey
}) {
  const wirePayload = validateWirePayloadV2(wirePayloadValue);
  if (wirePayload.kind !== "control") {
    throw new RelationshipControlV2Error("invalidKnownControl", "Wire payload is not a control.");
  }
  const control = wirePayload.control;
  const expectedRelationshipID = canonicalUUID(relationshipID, "Expected control relationship");
  const canonicalSentAt = requireCanonicalTimestamp(sentAt, "Control envelope send time");
  const canonicalReceivedAt = requireCanonicalTimestamp(receivedAt, "Control receipt time");
  if (Math.floor(Date.parse(control.issuedAt) / 1_000) !==
        Math.floor(Date.parse(canonicalSentAt) / 1_000) ||
      !verifyAuthenticatedRelationshipControlV2({
        pqc,
        control,
        relationshipID: expectedRelationshipID,
        senderEndpointHandle,
        eventID,
        senderSigningPublicKey
      })) {
    throw new RelationshipControlV2Error(
      "invalidKnownControl",
      "Relationship control authentication failed."
    );
  }
  const event = createConversationEvent({
    id: control.eventID,
    clientTransactionId: control.nonce,
    conversationId: expectedRelationshipID.toLowerCase(),
    authorEndpointHandle: control.senderEndpointHandle,
    createdAt: canonicalSentAt,
    kind: "control",
    content: createEncodedContent({
      type: control.type,
      parameters: { wirePayloadVersion: String(CONTROL_VERSION) },
      payload: requireBase64(control.encodedPayload, undefined, "Relationship control payload"),
      disposition: "silent"
    })
  });
  const known = decodeKnownRelationshipControlV2(control);
  if (known !== null) {
    return freezeWire({ kind: "control", control: known, event });
  }
  const reason = `Unsupported authenticated relationship control: ${contentTypeCanonicalName(control.type)}`;
  return freezeWire({
    kind: "quarantinedControl",
    quarantine: { event, receivedAt: canonicalReceivedAt, reason }
  });
}

function validateKnownPayload(kind, payload) {
  switch (kind) {
  case "routeSetUpdate": return validateRelationshipRouteSetUpdateV2(payload);
  case "routeProbe": return validateRelationshipRouteProbeV2(payload);
  case "endpointPrekeyUpdate": return validateRelationshipEndpointPrekeyUpdateV2(payload);
  default: throw new RelationshipControlV2Error("unknownControl", "Control kind is not implemented.");
  }
}

function validateControlContentType(value) {
  requireExactRecord(value, ["authority", "name", "major", "minor"], [], "Control content type");
  const type = validateContentTypeId(value);
  if (type.authority !== "org.noctweave.control") {
    throw new RelationshipControlV2Error(
      "invalidKnownControl",
      "Security controls require the Noctweave control authority."
    );
  }
  return type;
}

function decodeCanonicalPayload(encoded, validator) {
  const data = requireBase64(encoded, undefined, "Relationship control payload");
  let parsed;
  try {
    parsed = parseExactJSON(decoder.decode(data));
  } catch (error) {
    throw new TypeError("Relationship control payload is not canonical JSON.", { cause: error });
  }
  const value = validator(parsed);
  if (!equalBytes(data, canonicalJsonBytes(value))) {
    throw new TypeError("Relationship control payload is not canonically encoded.");
  }
  return value;
}

function canonicalUUID(value, label) {
  if (typeof value !== "string" || !relationshipUUID.test(value)) {
    throw new TypeError(`${label} must be a canonical UUID.`);
  }
  return value;
}
