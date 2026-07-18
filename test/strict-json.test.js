import assert from "node:assert/strict";
import test from "node:test";
import { parseExactJSON, strictJSONMaximumDepth } from "../src/index.js";

test("exact JSON accepts valid nested values", () => {
  assert.deepEqual(
    parseExactJSON('{"object":{"array":[true,false,null,1.25e2],"text":"ok"}}'),
    { object: { array: [true, false, null, 125], text: "ok" } }
  );
});

test("exact JSON rejects duplicate semantic object fields", () => {
  assert.throws(() => parseExactJSON('{"value":1,"value":2}'), /Duplicate JSON field/);
  assert.throws(() => parseExactJSON('{"value":1,"\\u0076alue":2}'), /Duplicate JSON field/);
  assert.throws(() => parseExactJSON('{"é":1,"e\\u0301":2}'), /Duplicate JSON field/);
  assert.throws(() => parseExactJSON('{"outer":{"field":1,"field":2}}'), /Duplicate JSON field/);
});

test("exact JSON accepts scalar pairs and rejects unpaired Unicode surrogates", () => {
  assert.deepEqual(parseExactJSON('{"value":"\\uD83D\\uDE00"}'), { value: "😀" });
  assert.throws(() => parseExactJSON('{"value":"\\uD800"}'), /Unpaired JSON Unicode surrogate/);
  assert.throws(() => parseExactJSON('{"value":"\\uDC00"}'), /Unpaired JSON Unicode surrogate/);
});

test("exact JSON rejects excessive nesting before native decoding", () => {
  const excessive = `${"[".repeat(strictJSONMaximumDepth + 1)}0${"]".repeat(strictJSONMaximumDepth + 1)}`;
  assert.throws(() => parseExactJSON(excessive), /nesting exceeds maximum depth/);
  assert.deepEqual(parseExactJSON('{"nested":{"ok":true}}', { maximumDepth: 2 }), {
    nested: { ok: true }
  });
  assert.throws(
    () => parseExactJSON('{"nested":{"tooDeep":true}}', { maximumDepth: 1 }),
    /nesting exceeds maximum depth/
  );
});

test("exact JSON retains native syntax rejection", () => {
  assert.throws(() => parseExactJSON('{"missing":}'), SyntaxError);
  assert.throws(() => parseExactJSON('{"trailing":true} garbage'), SyntaxError);
  assert.throws(() => parseExactJSON('{"leadingZero":01}'), SyntaxError);
  assert.throws(() => parseExactJSON('{"overflow":1e400}'), /number exceeds finite range/);
  assert.throws(() => parseExactJSON('{"overflow":-1e400}'), /number exceeds finite range/);
  assert.throws(() => parseExactJSON('\uFEFF{"bom":true}'), SyntaxError);
});
