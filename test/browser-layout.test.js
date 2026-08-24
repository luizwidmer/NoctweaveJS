import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("production client root redirects to its directory so relative assets resolve", async () => {
  const port = 24_000 + (process.pid % 10_000);
  const serverPath = fileURLToPath(new URL("../examples/browser-client/server.js", import.meta.url));
  const child = spawn(process.execPath, [serverPath], {
    env: {
      ...process.env,
      NODE_ENV: "test",
      NOCTWEAVE_CLIENT: "production",
      PORT: String(port)
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  try {
    await waitForServer(port, child);
    const root = await fetch(`http://127.0.0.1:${port}/`, { redirect: "manual" });
    assert.equal(root.status, 302);
    assert.equal(root.headers.get("location"), "/client/");

    const page = await fetch(`http://127.0.0.1:${port}/client/`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /\.\/styles\.css/);
    assert.equal((await fetch(`http://127.0.0.1:${port}/client/styles.css`)).status, 200);
  } finally {
    child.kill("SIGTERM");
  }
});

test("short desktop vaults use safe vertical centering", async () => {
  const css = await readFile(new URL("../client/styles.css", import.meta.url), "utf8");
  const compactDesktopRule = css.match(
    /@media \(min-width: 761px\) and \(max-height: 860px\) \{([\s\S]*?)\n\}/u
  )?.[1] ?? "";
  assert.match(compactDesktopRule, /\.vaultGate \{[^}]*align-items: safe center;/u);
  assert.match(compactDesktopRule, /\.vaultGate \{[^}]*justify-items: center;/u);
  assert.doesNotMatch(compactDesktopRule, /place-items: start center/u);
});

test("production messaging uses the native sidebar and one-surface-at-a-time layout", async () => {
  const [html, css, app] = await Promise.all([
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../client/styles.css", import.meta.url), "utf8"),
    readFile(new URL("../client/app.js", import.meta.url), "utf8")
  ]);

  for (const label of [
    "Chats",
    "Contact Book",
    "My Code",
    "Groups",
    "Relays",
    "Identity Management",
    "Settings"
  ]) {
    assert.match(html, new RegExp(`>${label}<`, "u"));
  }
  assert.match(html, /class="shell nativeShell"/u);
  assert.match(html, /data-client-view="chats"/u);
  assert.match(html, /data-client-view="pairing"[^>]*hidden/u);
  assert.match(html, /data-client-view="relays"[^>]*hidden/u);
  assert.match(css, /\.nativeShell\s*\{/u);
  assert.match(css, /grid-template:\s*minmax\(0, 1fr\)\s*\/\s*minmax\(248px, 286px\)/u);
  assert.match(app, /function activateClientView\(view, selectedControl = null\)/u);
});

async function waitForServer(port, child) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.exitCode !== null) {
      throw new Error(`Development server exited before startup with ${child.exitCode}.`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`, { redirect: "manual" });
      if (response.status === 302) return;
    } catch {
      // The loopback listener may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("Development server did not start in time.");
}
