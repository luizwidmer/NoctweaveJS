import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("desktop release workflow is native, bounded, pinned, and draft-only", async () => {
  const workflow = await readFile(
    new URL("../../.github/workflows/noctweavejs-desktop-release.yml", import.meta.url),
    "utf8"
  );

  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /tags:\s*\n\s*- "v\*"/);
  assert.doesNotMatch(workflow, /^\s*pull_request:/m);
  assert.match(workflow, /runner: macos-15/);
  assert.match(workflow, /runner: windows-2025/);
  assert.match(workflow, /runner: ubuntu-24\.04/);
  assert.match(workflow, /gh release create .* --draft /);
  assert.doesNotMatch(workflow, /--draft=false|--latest/);

  const actionReferences = [...workflow.matchAll(/^\s*uses:\s*(\S+)(?:\s+#.*)?$/gm)].map((match) => match[1]);
  assert.ok(actionReferences.length >= 5);
  for (const reference of actionReferences) {
    assert.match(reference, /@[a-f0-9]{40}$/);
  }
});
