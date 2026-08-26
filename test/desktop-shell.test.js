import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

test("Electrobun desktop shell packages the existing client, PQ WASM, and secure state bridge", async () => {
  const [config, main, application, view, html, hostState, viewAnchor, rpc] = await Promise.all([
    readFile(new URL("../electrobun.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../desktop/bun/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../desktop/bun/application.ts", import.meta.url), "utf8"),
    readFile(new URL("../desktop/view/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../desktop/bun/relationship-state-store.js", import.meta.url), "utf8"),
    readFile(new URL("../desktop/view/relationship-state-anchor.ts", import.meta.url), "utf8"),
    readFile(new URL("../desktop/rpc.ts", import.meta.url), "utf8")
  ]);

  assert.match(config, /:\s*"org\.noctweave\.js-client"/);
  assert.match(config, /`org\.noctweave\.js-client\.ui-test\.\$\{uiTestProfile\}`/);
  assert.match(config, /desktop\/ui-test-bun\/index\.ts/);
  assert.match(config, /icon:\s*"desktop\/assets\/app-icon\.png"/);
  assert.match(config, /icon:\s*"desktop\/assets\/app-icon\.ico"/);
  assert.equal((config.match(/desktop\/scripts\/install-mac-icon\.ts/g) ?? []).length, 2);
  assert.match(config, /"wasm\/dist\/noctweave_oqs\.wasm":\s*"views\/mainview\/noctweave_oqs\.wasm"/);
  assert.equal((config.match(/bundleCEF:\s*false/g) ?? []).length, 3);
  assert.match(main, /DesktopRelationshipStateStore/);
  assert.match(main, /startDesktopApplication/);
  assert.match(application, /proxyRelayRequest/);
  assert.match(application, /loadPostQuantumWasm/);
  assert.match(application, /DesktopAttachmentExporter/);
  assert.match(application, /authorizeAttachmentExport/);
  assert.match(application, /writeAttachmentExport/);
  assert.match(application, /relationshipStateErasureStatus/);
  assert.match(application, /commitRelationshipState/);
  assert.match(application, /destroyRelationshipState/);
  assert.match(view, /__noctweaveDesktopRelayFetch/);
  assert.match(view, /__noctweaveDesktopWasmBinary/);
  assert.match(view, /__noctweaveDesktopExportAttachment/);
  assert.match(view, /dataset\.runtime\s*=\s*"desktop"/);
  assert.match(view, /installDesktopRelationshipStateAnchorFactory/);
  assert.match(view, /await import\("\.\.\/\.\.\/client\/app\.js"\)/);
  assert.match(html, /src="\.\/index\.js"/);
  assert.match(html, /class="shell nativeShell"/);
  assert.match(html, />People</);
  assert.match(html, />You</);
  assert.match(html, />Identity Management</);
  assert.match(html, /data-client-view="chats"/);
  assert.match(html, /data-client-view="people"/);
  assert.match(hostState, /MacOSKeychainVault/);
  assert.match(hostState, /afterSecureCommit/);
  assert.match(hostState, /afterSecureDestroy/);
  assert.match(hostState, /digestEncryptedRecord/);
  assert.match(hostState, /acquireScopeLock/);
  assert.match(hostState, /erasedRelationshipError/);
  assert.match(hostState, /Desktop host accepts only encrypted Noctweave records/);
  assert.match(viewAnchor, /encryptedStateStoreBackend/);
  assert.match(viewAnchor, /persistEncryptedState/);
  assert.match(viewAnchor, /destroyEncryptedState/);
  assert.match(viewAnchor, /erasureStatus/);
  assert.match(rpc, /relationshipStateCapability/);
  assert.match(rpc, /authorizeAttachmentExport/);
  assert.match(rpc, /writeAttachmentExport/);

  const [macIcon, linuxIcon, windowsIcon] = await Promise.all([
    stat(new URL("../desktop/assets/app-icon.icns", import.meta.url)),
    stat(new URL("../desktop/assets/app-icon.png", import.meta.url)),
    stat(new URL("../desktop/assets/app-icon.ico", import.meta.url))
  ]);
  assert.ok(macIcon.size > 1_000);
  assert.ok(linuxIcon.size > 1_000);
  assert.ok(windowsIcon.size > 1_000);
});
