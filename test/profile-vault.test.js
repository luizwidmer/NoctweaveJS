import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import * as noctweave from "../src/index.js";

test("public JS surfaces cannot clone a live protocol endpoint", async () => {
  assert.equal("encryptPortableProfile" in noctweave, false);
  assert.equal("decryptPortableProfile" in noctweave, false);

  const [html, script] = await Promise.all([
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../client/app.js", import.meta.url), "utf8")
  ]);
  assert.doesNotMatch(html, /id="(?:export|import)Profile"/);
  assert.doesNotMatch(script, /(?:encrypt|decrypt)PortableProfile/);
  assert.match(
    html,
    /Live identity keys, ratchets, routes, and cursors are never exported or cloned/
  );
});
