import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { canonicalJson } from "../src/crypto/swift-canonical.js";
import { parseExactJSON } from "../src/strict-json.js";

const vectors = JSON.parse(await readFile(
  new URL("../../NoctweaveDocumentation/test_vectors/canonical_json_v1.json", import.meta.url),
  "utf8"
));

test("NCJ-1 matches every shared Swift/JavaScript canonical vector", () => {
  assert.equal(vectors.profile, "ncj-1");
  for (const vector of vectors.canonicalCases) {
    assert.equal(
      canonicalJson(parseExactJSON(vector.input, { canonicalNumbers: true })),
      vector.canonical,
      vector.name
    );
  }
});

test("NCJ-1 rejects every shared invalid vector", () => {
  for (const vector of vectors.rejectedCases) {
    assert.throws(
      () => canonicalJson(parseExactJSON(vector.input, { canonicalNumbers: true })),
      undefined,
      vector.name
    );
  }
});

test("NCJ-1 rejects non-protocol JavaScript values", () => {
  assert.throws(() => canonicalJson(undefined), /outside the NCJ-1/);
  assert.throws(() => canonicalJson(1.5), /canonical integers/);
  assert.throws(() => canonicalJson(Number.MAX_SAFE_INTEGER + 1), /canonical integers/);
  assert.throws(() => canonicalJson(-0), /canonical integers/);
  assert.throws(() => canonicalJson("\uD800"), /valid Unicode scalars/);
  assert.throws(() => canonicalJson(new Date()), /plain records/);

  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /cyclic/);
});
