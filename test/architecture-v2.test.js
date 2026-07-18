import assert from "node:assert/strict";
import test from "node:test";
import {
  advanceDeliveryState,
  base64,
  canonicalJsonBytes,
  contentTypeCanonicalName,
  createContentTypeCapabilityV2,
  createContentTypeId,
  createConversationEvent,
  createDeliveryStateRecord,
  createProtocolCapabilityManifest,
  createTextEncodedContent,
  defaultActiveEndpointModules,
  defaultContentTypeCapabilities,
  generateRelationshipEndpointHandle,
  negotiateProtocolCapabilities,
  protocolKnownModuleCatalog,
  standardContentTypes,
  validateConversationEvent,
  validateEncodedContent,
  validateContentTypeCapabilityV2,
  validateProtocolCapabilityManifest,
  validateProtocolModuleCapability
} from "../src/index.js";
import {
  createDeliveryReceiptEncodedContent,
  createReactionEncodedContent,
  createReadReceiptEncodedContent,
  createRetractionEncodedContent,
  directV4CipherSuite,
  negotiateDirectV4Capabilities,
  retractionFallbackText,
  validateDirectV4NegotiatedCapabilityManifest
} from "../src/architecture-v2.js";

const ids = Object.freeze({
  relationshipId: "4A2D4951-C0CA-4B9D-94A4-2DC80B4AE8E0",
  nonce: "E141680A-06A0-4E36-B2D7-5AE72B6013CD",
  eventId: "2F942443-C62C-4D16-93C9-A38DFCB2D69C",
  transactionId: "829B0A7F-E921-4AF2-A365-1027F6AF6C98"
});

test("capability negotiation selects highest common versions and lower shared limits", () => {
  const pollLocal = createContentTypeCapabilityV2({
    authority: "org.example",
    name: "poll",
    majorVersions: [2, 1]
  });
  const pollPeer = createContentTypeCapabilityV2({
    authority: "org.example",
    name: "poll",
    majorVersions: [3, 2]
  });
  const local = createProtocolCapabilityManifest({
    modules: [
      { module: "nw.core", versions: [1, 2], status: "provisional", limits: {} },
      { module: "nw.opaque-route", versions: [1, 2], status: "provisional", limits: { maxPage: 256 } },
      { module: "nw.example-a", versions: [2], status: "provisional", limits: { maxEventBytes: 65_536 } }
    ],
    contentTypes: [...defaultContentTypeCapabilities, pollLocal]
  });
  const peer = createProtocolCapabilityManifest({
    modules: [
      { module: "nw.core", versions: [2], status: "stable", limits: {} },
      { module: "nw.opaque-route", versions: [2, 3], status: "stable", limits: { maxPage: 64 } },
      { module: "nw.example-b", versions: [2], status: "provisional", limits: {} }
    ],
    contentTypes: [...defaultContentTypeCapabilities, pollPeer]
  });

  const negotiated = negotiateProtocolCapabilities(local, peer);
  assert.deepEqual(negotiated.modules.map(({ module, versions }) => ({ module, versions })), [
    { module: "nw.core", versions: [2] },
    { module: "nw.opaque-route", versions: [2] }
  ]);
  assert.equal(negotiated.modules[1].limits.maxPage, 64);
  assert.deepEqual(
    negotiated.contentTypes.find(({ authority, name }) =>
      authority === "org.example" && name === "poll").majorVersions,
    [2]
  );
  assert.equal(Object.isFrozen(negotiated.modules), true);
});

test("direct-v4 negotiation is symmetric, bounded, and requires every implemented module", () => {
  const defaults = createProtocolCapabilityManifest();
  const constrained = createProtocolCapabilityManifest({
    modules: defaults.modules.map((module) => module.module === "nw.core"
      ? { ...module, limits: { ...module.limits, maxContentPayloadBytes: 1_024 } }
      : module)
  });
  const forward = negotiateDirectV4Capabilities(defaults, constrained);
  const reverse = negotiateDirectV4Capabilities(constrained, defaults);
  assert.deepEqual(forward, reverse);
  assert.equal(forward.cipherSuite, directV4CipherSuite);
  assert.deepEqual(Object.keys(forward), [
    "version",
    "architectureVersion",
    "cipherSuite",
    "modules",
    "contentTypes"
  ]);
  assert.deepEqual(forward.contentTypes, defaultContentTypeCapabilities);
  assert.deepEqual(forward.modules.map(({ module, version }) => ({ module, version })), [
    { module: "nw.core", version: 2 },
    { module: "nw.direct", version: 4 }
  ]);
  assert.equal(
    forward.modules.find(({ module }) => module === "nw.core").limits.maxContentPayloadBytes,
    1_024
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

  const overclaimedDirect = createProtocolCapabilityManifest({
    modules: defaults.modules.map((module) => module.module === "nw.direct"
      ? { ...module, limits: { ...module.limits, maxCiphertextBytes: 1_000_000 } }
      : module)
  });
  assert.equal(
    negotiateDirectV4Capabilities(overclaimedDirect, overclaimedDirect)
      .modules.find(({ module }) => module === "nw.direct").limits.maxCiphertextBytes,
    65_536
  );

  const missingDirect = createProtocolCapabilityManifest({
    modules: defaults.modules.filter(({ module }) => module !== "nw.direct")
  });
  assert.throws(
    () => negotiateDirectV4Capabilities(defaults, missingDirect),
    /requires nw\.direct/
  );

  const incompatibleDirect = createProtocolCapabilityManifest({
    modules: defaults.modules.map((module) => module.module === "nw.direct"
      ? { ...module, versions: [5] }
      : module)
  });
  assert.throws(
    () => negotiateDirectV4Capabilities(defaults, incompatibleDirect),
    /no shared nw\.direct version/
  );

  const localContent = createProtocolCapabilityManifest({
    contentTypes: [createContentTypeCapabilityV2({
      authority: "org.noctweave",
      name: "text",
      majorVersions: [1, 2]
    })]
  });
  const peerContent = createProtocolCapabilityManifest({
    contentTypes: [createContentTypeCapabilityV2({
      authority: "org.noctweave",
      name: "text",
      majorVersions: [2, 3]
    })]
  });
  assert.deepEqual(
    negotiateDirectV4Capabilities(localContent, peerContent).contentTypes,
    [{ authority: "org.noctweave", name: "text", majorVersions: [2] }]
  );
  const incompatibleContent = createProtocolCapabilityManifest({
    contentTypes: [createContentTypeCapabilityV2({
      authority: "org.noctweave",
      name: "text",
      majorVersions: [3]
    })]
  });
  assert.throws(
    () => negotiateDirectV4Capabilities(localContent, incompatibleContent),
    /requires a shared org\.noctweave\/text content family/
  );
  const oldShape = structuredClone(forward);
  delete oldShape.contentTypes;
  assert.throws(
    () => validateDirectV4NegotiatedCapabilityManifest(oldShape),
    /fields must match the current schema exactly/
  );
});

test("capability manifests are bounded and require the architecture-v2 core", () => {
  const defaults = createProtocolCapabilityManifest();
  assert.equal(protocolKnownModuleCatalog.length, 12);
  assert.deepEqual(defaultActiveEndpointModules.map(({ module }) => module), [
    "nw.core",
    "nw.direct"
  ]);
  assert.deepEqual(defaults.modules, defaultActiveEndpointModules);
  assert.deepEqual(defaults.contentTypes, defaultContentTypeCapabilities);
  assert.deepEqual(Object.keys(defaults), ["architectureVersion", "modules", "contentTypes"]);
  assert.deepEqual(
    protocolKnownModuleCatalog.find(({ module }) => module === "nw.direct"),
    { module: "nw.direct", versions: [4], status: "stable", limits: {} }
  );
  assert.deepEqual(
    protocolKnownModuleCatalog.find(({ module }) => module === "nw.open-discovery"),
    { module: "nw.open-discovery", versions: [1], status: "experimental", limits: {} }
  );
  assert.throws(
    () => validateProtocolModuleCapability({
      module: "nw.core",
      versions: [2],
      status: "stable",
      limits: null
    }),
    /limits must be an object/
  );
  for (const key of [" maxPage", "maxPage ", "max\u0000Page"]) {
    assert.throws(
      () => validateProtocolModuleCapability({
        module: "nw.core",
        versions: [2],
        status: "stable",
        limits: { [key]: 256 }
      }),
      /limit name.*protocol bounds/
    );
  }
  for (const inactive of [
    "nw.opaque-route",
    "nw.rendezvous-transport",
    "nw.blobs",
    "nw.groups",
    "nw.wake",
    "nw.federation",
    "nw.open-discovery",
    "nw.privacy.hidden-retrieval",
    "nw.privacy.onion",
    "nw.privacy.mixnet"
  ]) {
    assert.equal(createProtocolCapabilityManifest().modules.some(({ module }) => module === inactive), false);
  }
  assert.throws(
    () => validateProtocolCapabilityManifest({
      architectureVersion: 2,
      modules: [{ module: "nw.example-a", versions: [2], status: "provisional", limits: {} }],
      contentTypes: defaultContentTypeCapabilities
    }),
    /nw\.core version 2/
  );
  assert.throws(
    () => validateProtocolCapabilityManifest({
      architectureVersion: 2,
      modules: defaultActiveEndpointModules
    }),
    /fields must match the current schema exactly/
  );
  assert.throws(
    () => validateContentTypeCapabilityV2({
      authority: "org.example",
      name: "poll",
      majorVersions: [2, 1]
    }),
    /unique and sorted/
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
  assert.equal(handle.rawValue, "4haxFhtS3427bxV0686oib/3PkGuyEYB8n+LQCzIpAE=");
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

test("unknown application types survive while control conversation events remain audit-only", async () => {
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
  assert.equal(control.kind, "control");
  assert.equal(control.content.disposition, "silent");
  assert.equal(Object.isFrozen(control), true);
});

test("relationship delivery state is monotonic and relationship scoped", async () => {
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
  assert.equal(advanceDeliveryState(accepted, "peerStored", {
    updatedAt: "2026-07-16T12:34:59Z"
  }), null);
  assert.equal(local.state, "locallyPersisted");
});
