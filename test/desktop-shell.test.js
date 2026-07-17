import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

test("Electrobun desktop shell packages the existing client and PQ WASM", async () => {
  const [config, main, view, html] = await Promise.all([
    readFile(new URL("../electrobun.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../desktop/bun/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../desktop/view/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../client/index.html", import.meta.url), "utf8")
  ]);

  assert.match(config, /identifier:\s*"org\.noctweave\.js-client"/);
  assert.match(config, /icon:\s*"desktop\/assets\/app-icon\.png"/);
  assert.match(config, /icon:\s*"desktop\/assets\/app-icon\.ico"/);
  assert.equal((config.match(/desktop\/scripts\/install-mac-icon\.ts/g) ?? []).length, 2);
  assert.match(config, /"wasm\/dist\/noctweave_oqs\.wasm":\s*"views\/mainview\/noctweave_oqs\.wasm"/);
  assert.equal((config.match(/bundleCEF:\s*false/g) ?? []).length, 3);
  assert.match(main, /proxyRelayRequest/);
  assert.match(main, /loadPostQuantumWasm/);
  assert.match(view, /__noctweaveDesktopRelayFetch/);
  assert.match(view, /__noctweaveDesktopWasmBinary/);
  assert.match(view, /dataset\.runtime\s*=\s*"desktop"/);
  assert.match(view, /await import\("\.\.\/\.\.\/client\/app\.js"\)/);
  assert.match(html, /src="\.\/index\.js"/);
  assert.match(html, /Pairwise Messenger/);
  assert.match(html, /One-use pairing/);

  const [macIcon, linuxIcon, windowsIcon] = await Promise.all([
    stat(new URL("../desktop/assets/app-icon.icns", import.meta.url)),
    stat(new URL("../desktop/assets/app-icon.png", import.meta.url)),
    stat(new URL("../desktop/assets/app-icon.ico", import.meta.url))
  ]);
  assert.ok(macIcon.size > 1_000);
  assert.ok(linuxIcon.size > 1_000);
  assert.ok(windowsIcon.size > 1_000);
});
