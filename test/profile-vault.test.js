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
  assert.match(html, /This label has no protocol key or routable identifier/);
  assert.match(html, /Every peer relationship receives fresh post-quantum keys/);
  assert.match(script, /EncryptedNoctweaveStore/);
});
