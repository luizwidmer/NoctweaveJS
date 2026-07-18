import assert from "node:assert/strict";
import test from "node:test";

import {
  createRelationshipLocalPolicyV2,
  relationshipAcceptsInboundEventsV2,
  relationshipAllowsUserSendingV2,
  relationshipIsMutedV2,
  validateRelationshipLocalPolicyV2
} from "../src/relationship-local-policy-v2.js";

test("relationship consent, mute, receipts, and block remain exact local state", () => {
  const policy = createRelationshipLocalPolicyV2({
    consent: "pendingRequest",
    mutedUntil: "2033-05-18T03:33:20Z",
    deliveryReceiptsEnabled: false,
    readReceiptsEnabled: false
  });

  assert.equal(relationshipAllowsUserSendingV2(policy), false);
  assert.equal(relationshipAcceptsInboundEventsV2(policy), true);
  assert.equal(relationshipIsMutedV2(policy, Date.parse("2033-05-18T03:33:19Z")), true);
  assert.deepEqual(Object.keys(policy).sort(), [
    "consent",
    "deliveryReceiptsEnabled",
    "mutedUntil",
    "readReceiptsEnabled",
    "version"
  ]);

  const blocked = createRelationshipLocalPolicyV2({ consent: "blocked" });
  assert.equal(relationshipAllowsUserSendingV2(blocked), false);
  assert.equal(relationshipAcceptsInboundEventsV2(blocked), false);
  assert.equal(relationshipIsMutedV2(blocked), false);

  assert.throws(
    () => validateRelationshipLocalPolicyV2({ ...policy, accountID: "forbidden" }),
    /fields do not match/
  );
  assert.throws(
    () => validateRelationshipLocalPolicyV2({ ...policy, consent: "authorizedDevice" }),
    /invalid/
  );
  assert.throws(
    () => validateRelationshipLocalPolicyV2({ ...policy, mutedUntil: "2033-05-18T03:33:20.000Z" }),
    /canonical/
  );
});
