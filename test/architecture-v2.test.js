import assert from "node:assert/strict";
import test from "node:test";
import {
  advanceDeliveryState,
  base64,
  canonicalJsonBytes,
  contentTypeCanonicalName,
  createContentTypeId,
  createConversationEvent,
  createDeliveryStateRecord,
  createProtocolCapabilityManifest,
  createTextEncodedContent,
  defaultActiveEndpointModules,
  generateRelationshipEndpointHandle,
  mayMutateControlState,
  negotiateProtocolCapabilities,
  protocolKnownModuleCatalog,
  standardContentTypes,
  validateConversationEvent,
  validateEncodedContent,
  validateProtocolCapabilityManifest
} from "../src/index.js";
import {
  createDeliveryReceiptEncodedContent,
  createReactionEncodedContent,
  createReadReceiptEncodedContent,
  createRetractionEncodedContent,
  directV4CipherSuite,
  negotiateDirectV4Capabilities,
  retractionFallbackText
} from "../src/architecture-v2.js";

const ids = Object.freeze({
  identityGenerationId: "25D6B258-9C3D-43B9-A6AB-F654B3089B4B",
  endpointId: "A12AA310-613D-4F86-8F45-28DC0D410F9F",
  relationshipId: "4A2D4951-C0CA-4B9D-94A4-2DC80B4AE8E0",
  nonce: "E141680A-06A0-4E36-B2D7-5AE72B6013CD",
  eventId: "2F942443-C62C-4D16-93C9-A38DFCB2D69C",
  transactionId: "829B0A7F-E921-4AF2-A365-1027F6AF6C98"
});

test("capability negotiation selects highest common versions and lower shared limits", () => {
  const local = createProtocolCapabilityManifest({
    modules: [
      { module: "nw.core", versions: [1, 2], status: "provisional", limits: {} },
      { module: "nw.opaque-route", versions: [1, 2], status: "provisional", limits: { maxPage: 256 } },
      { module: "nw.events", versions: [2], status: "provisional", limits: { maxEventBytes: 65_536 } }
    ]
  });
  const peer = createProtocolCapabilityManifest({
    modules: [
      { module: "nw.core", versions: [2], status: "stable", limits: {} },
      { module: "nw.opaque-route", versions: [2, 3], status: "stable", limits: { maxPage: 64 } },
      { module: "nw.routes", versions: [2], status: "provisional", limits: {} }
    ]
  });

  const negotiated = negotiateProtocolCapabilities(local, peer);
  assert.deepEqual(negotiated.modules.map(({ module, versions }) => ({ module, versions })), [
    { module: "nw.core", versions: [2] },
    { module: "nw.opaque-route", versions: [2] }
  ]);
  assert.equal(negotiated.modules[1].limits.maxPage, 64);
  assert.equal(Object.isFrozen(negotiated.modules), true);
});

test("direct-v4 negotiation is symmetric, bounded, and requires every implemented module", () => {
  const defaults = createProtocolCapabilityManifest();
  assert.equal(
    defaults.modules.find(({ module }) => module === "nw.relationship-endpoints").limits.maxActiveEndpoints,
    1
  );
  const constrained = createProtocolCapabilityManifest({
    modules: defaults.modules.map((module) => module.module === "nw.events"
      ? { ...module, limits: { maxContentPayloadBytes: 1_024 } }
      : module)
  });
  const forward = negotiateDirectV4Capabilities(defaults, constrained);
  const reverse = negotiateDirectV4Capabilities(constrained, defaults);
  assert.deepEqual(forward, reverse);
  assert.equal(forward.cipherSuite, directV4CipherSuite);
  assert.deepEqual(forward.modules.map(({ module, version }) => ({ module, version })), [
    { module: "nw.core", version: 2 },
    { module: "nw.relationship-endpoints", version: 2 },
    { module: "nw.events", version: 2 },
    { module: "nw.prekeys", version: 2 },
    { module: "nw.routes", version: 2 }
  ]);
  assert.equal(
    forward.modules.find(({ module }) => module === "nw.events").limits.maxContentPayloadBytes,
    1_024
  );
  assert.equal(
    forward.modules.find(({ module }) => module === "nw.relationship-endpoints").limits.maxActiveEndpoints,
    1
  );

  const optionalModulesEnabled = createProtocolCapabilityManifest({
    modules: [
      ...defaults.modules,
      protocolKnownModuleCatalog.find(({ module }) => module === "nw.groups"),
      protocolKnownModuleCatalog.find(({ module }) => module === "nw.privacy.onion")
    ]
  });
  assert.deepEqual(
    negotiateDirectV4Capabilities(defaults, optionalModulesEnabled),
    negotiateDirectV4Capabilities(defaults, defaults)
  );

  const overclaimedEndpoints = createProtocolCapabilityManifest({
    modules: defaults.modules.map((module) => module.module === "nw.relationship-endpoints"
      ? { ...module, limits: { maxActiveEndpoints: 16 } }
      : module)
  });
  assert.equal(
    negotiateDirectV4Capabilities(overclaimedEndpoints, overclaimedEndpoints)
      .modules.find(({ module }) => module === "nw.relationship-endpoints").limits.maxActiveEndpoints,
    1
  );

  const missingEvents = createProtocolCapabilityManifest({
    modules: defaults.modules.filter(({ module }) => module !== "nw.events")
  });
  assert.throws(
    () => negotiateDirectV4Capabilities(defaults, missingEvents),
    /requires nw\.events/
  );

  const incompatibleEvents = createProtocolCapabilityManifest({
    modules: defaults.modules.map((module) => module.module === "nw.events"
      ? { ...module, versions: [3] }
      : module)
  });
  assert.throws(
    () => negotiateDirectV4Capabilities(defaults, incompatibleEvents),
    /no shared nw\.events version/
  );
});

test("capability manifests are bounded and require the architecture-v2 core", () => {
  assert.equal(protocolKnownModuleCatalog.length, 14);
  assert.deepEqual(defaultActiveEndpointModules.map(({ module }) => module), [
    "nw.core",
    "nw.events",
    "nw.prekeys",
    "nw.relationship-endpoints",
    "nw.routes"
  ]);
  assert.deepEqual(createProtocolCapabilityManifest().modules, defaultActiveEndpointModules);
  assert.deepEqual(
    protocolKnownModuleCatalog.find(({ module }) => module === "nw.routes"),
    { module: "nw.routes", versions: [2], status: "stable", limits: {} }
  );
  for (const inactive of [
    "nw.opaque-route",
    "nw.rendezvous-transport",
    "nw.blobs",
    "nw.groups",
    "nw.wake",
    "nw.federation",
    "nw.privacy.hidden-retrieval",
    "nw.privacy.onion",
    "nw.privacy.mixnet"
  ]) {
    assert.equal(createProtocolCapabilityManifest().modules.some(({ module }) => module === inactive), false);
  }
  assert.throws(
    () => validateProtocolCapabilityManifest({
      architectureVersion: 2,
      modules: [{ module: "nw.events", versions: [2], status: "provisional", limits: {} }]
    }),
    /nw\.core version 2/
  );
  assert.throws(
    () => createProtocolCapabilityManifest({
      modules: [
        { module: "nw.core", versions: [2], status: "provisional", limits: {} },
        { module: "nw.core", versions: [2], status: "provisional", limits: {} }
      ]
    }),
    /unique/
  );
});

test("relationship endpoint handles match the Swift v2 derivation and remain opaque", async () => {
  const handle = await generateRelationshipEndpointHandle(ids);
  assert.equal(handle.rawValue, "03kx4/LQ+FBjGnQG/B/NTnX7Sj13lp5+O9NUKj2/ZBk=");
  assert.equal(Object.keys(handle).join(","), "rawValue");
  assert.equal(Object.isFrozen(handle), true);
});

test("content and conversation events use immutable bounded Swift-compatible wire records", async () => {
  const handle = await generateRelationshipEndpointHandle(ids);
  const content = createTextEncodedContent("hello from v2");
  const event = createConversationEvent({
    id: ids.eventId,
    clientTransactionId: ids.transactionId,
    conversationId: "relationship:test",
    authorEndpointHandle: handle,
    createdAt: "2026-07-16T12:34:56Z",
    kind: "application",
    content,
    relation: { kind: "reply", targetEventId: ids.transactionId }
  });

  assert.equal(event.content.payload, "aGVsbG8gZnJvbSB2Mg==");
  assert.equal(contentTypeCanonicalName(event.content.type), "org.noctweave/text:1.0");
  assert.equal(Object.isFrozen(event), true);
  assert.equal(Object.isFrozen(event.content), true);
  assert.equal(validateConversationEvent(JSON.parse(JSON.stringify(event))).id, ids.eventId);
  assert.throws(
    () => validateConversationEvent({ ...event, kind: "control" }),
    /Only application events/
  );
});

test("standard relations, reactions, truthful retractions, and receipts match Swift vectors", async () => {
  const handle = await generateRelationshipEndpointHandle(ids);
  const targetEventId = "11111111-2222-4333-8444-555555555555";
  const base = {
    id: ids.eventId,
    clientTransactionId: ids.transactionId,
    conversationId: "relationship:test",
    authorEndpointHandle: handle,
    createdAt: "2026-07-16T12:34:56Z"
  };

  for (const kind of ["reply", "replacement", "reference"]) {
    const event = createConversationEvent({
      ...base,
      kind: "application",
      content: createTextEncodedContent("revised text"),
      relation: { kind, targetEventId }
    });
    assert.equal(event.relation.kind, kind);
    assert.notEqual(event.id, event.relation.targetEventId);
  }

  const reaction = createReactionEncodedContent("👍");
  assert.equal(reaction.payload, base64(canonicalJsonBytes({ value: "👍" })));
  assert.equal(reaction.fallbackText, "Reacted 👍 to a message");
  const reactionEvent = createConversationEvent({
    ...base,
    kind: "application",
    content: reaction,
    relation: { kind: "reaction", targetEventId }
  });
  assert.equal(reactionEvent.relation.targetEventId, targetEventId);

  const retraction = createRetractionEncodedContent({ reason: "duplicate" });
  assert.equal(retraction.payload, base64(canonicalJsonBytes({
    reason: "duplicate",
    scope: "received-copies-may-remain"
  })));
  assert.equal(retraction.fallbackText, retractionFallbackText);
  createConversationEvent({
    ...base,
    kind: "application",
    content: retraction,
    relation: { kind: "retraction", targetEventId }
  });

  for (const content of [
    createDeliveryReceiptEncodedContent(targetEventId),
    createReadReceiptEncodedContent(targetEventId)
  ]) {
    assert.equal(content.payload, base64(canonicalJsonBytes({ targetEventId })));
    const receipt = createConversationEvent({
      ...base,
      kind: "receipt",
      content
    });
    assert.equal(receipt.content.disposition, "silent");
    assert.equal(receipt.relation, undefined);
  }
});

test("reserved relation and receipt semantics reject mismatch, self-reference, controls, and bad bounds", async () => {
  const handle = await generateRelationshipEndpointHandle(ids);
  const base = {
    id: ids.eventId,
    clientTransactionId: ids.transactionId,
    conversationId: "relationship:test",
    authorEndpointHandle: handle,
    createdAt: "2026-07-16T12:34:56Z",
    kind: "application"
  };
  const reaction = createReactionEncodedContent("👍");
  assert.throws(() => createConversationEvent({ ...base, content: reaction }), /matching content/);
  assert.throws(() => createConversationEvent({
    ...base,
    content: reaction,
    relation: { kind: "reply", targetEventId: ids.transactionId }
  }), /matching content/);
  const retraction = createRetractionEncodedContent();
  assert.throws(() => createConversationEvent({ ...base, content: retraction }), /matching content/);
  assert.throws(() => createConversationEvent({
    ...base,
    content: retraction,
    relation: { kind: "reference", targetEventId: ids.transactionId }
  }), /matching content/);
  assert.throws(() => createConversationEvent({
    ...base,
    content: createTextEncodedContent("spoof"),
    relation: { kind: "retraction", targetEventId: ids.transactionId }
  }), /matching content/);
  assert.throws(() => createConversationEvent({
    ...base,
    content: createTextEncodedContent("spoof"),
    relation: { kind: "reaction", targetEventId: ids.transactionId }
  }), /matching content/);
  assert.throws(() => createConversationEvent({
    ...base,
    content: createTextEncodedContent("self"),
    relation: { kind: "replacement", targetEventId: ids.eventId }
  }), /cannot target their own/);
  assert.throws(() => createConversationEvent({
    ...base,
    kind: "application",
    content: createReadReceiptEncodedContent(ids.transactionId)
  }), /cannot carry control or receipt/);
  assert.throws(() => createConversationEvent({
    ...base,
    createdAt: "2100-01-01T00:00:01Z",
    content: createTextEncodedContent("future")
  }), /time bounds/);
  assert.throws(() => createReactionEncodedContent(`bad\u0000reaction`), /protocol bounds/);
  assert.throws(() => createRetractionEncodedContent({ reason: `bad\u0000reason` }), /protocol bounds/);
});

test("unknown application types survive while unsupported control types fail closed", async () => {
  const handle = await generateRelationshipEndpointHandle(ids);
  const customType = createContentTypeId({ authority: "dev.example", name: "poll", major: 1, minor: 0 });
  assert.throws(
    () => createContentTypeId({ authority: "dev/example", name: "poll:spoof", major: 1 }),
    /delimiter/
  );
  const content = validateEncodedContent({
    type: customType,
    parameters: {},
    payload: "AQID",
    fallbackText: "Unsupported poll",
    disposition: "visible"
  });
  const application = createConversationEvent({
    id: ids.eventId,
    clientTransactionId: ids.transactionId,
    conversationId: "relationship:test",
    authorEndpointHandle: handle,
    createdAt: "2026-07-16T12:34:56Z",
    kind: "application",
    content
  });
  const controlType = createContentTypeId({
    authority: "org.noctweave.control",
    name: "future-policy",
    major: 1,
    minor: 0
  });
  const control = createConversationEvent({
    ...application,
    kind: "control",
    content: validateEncodedContent({
      type: controlType,
      parameters: {},
      payload: "AQID",
      disposition: "silent"
    })
  });

  assert.equal(application.content.fallbackText, "Unsupported poll");
  assert.equal(mayMutateControlState(control, [standardContentTypes.text]), false);
  assert.equal(mayMutateControlState(control, [controlType]), true);
});

test("relationship delivery state is monotonic and endpoint scoped", async () => {
  const handle = await generateRelationshipEndpointHandle(ids);
  const local = createDeliveryStateRecord({
    eventId: ids.eventId,
    destinationEndpoint: handle,
    state: "locallyPersisted",
    updatedAt: "2026-07-16T12:34:56Z"
  });
  const accepted = advanceDeliveryState(local, "relayAccepted", {
    updatedAt: "2026-07-16T12:35:00Z"
  });

  assert.equal(accepted.state, "relayAccepted");
  assert.equal(advanceDeliveryState(accepted, "locallyPersisted"), null);
  assert.equal(advanceDeliveryState(accepted, "peerEndpointStored", {
    updatedAt: "2026-07-16T12:34:59Z"
  }), null);
  assert.equal(local.state, "locallyPersisted");
});
