import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("group client uses bounded exact files for large one-use admission artifacts", async () => {
  const [html, script, styles] = await Promise.all([
    readFile(new URL("../client/groups.html", import.meta.url), "utf8"),
    readFile(new URL("../client/groups.js", import.meta.url), "utf8"),
    readFile(new URL("../client/groups.css", import.meta.url), "utf8")
  ]);

  for (const id of [
    "openAdmissionRequest",
    "admissionRequestFile",
    "admissionRequestSummary",
    "shareAdmissionResponse",
    "admissionResponseActions"
  ]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(html, /\.noctgroup/);
  assert.match(script, /GROUP_ARTIFACT_MAX_BYTES = 24 \* 1_024 \* 1_024/);
  assert.match(script, /new TextDecoder\("utf-8", \{ fatal: true \}\)/);
  assert.match(script, /normalizedGroupArtifact/);
  assert.match(script, /resetAdmissionExchange/);
  assert.match(script, /admissionRequestIsReady/);
  assert.match(script, /navigator\.canShare\(\{ files: \[file\] \}\)/);
  assert.match(script, /URL\.revokeObjectURL/);
  assert.match(styles, /max-height: 180px/);
  assert.doesNotMatch(html, /<textarea[^>]+rows="(?:[7-9]|[1-9][0-9]+)"/);
});
