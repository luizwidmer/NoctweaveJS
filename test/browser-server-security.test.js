import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { copyFile, mkdir, mkdtemp, open, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

// Run the actual development server against synthetic private data only.
test("development server publishes browser assets without exposing private files or symlink targets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-static-boundary-"));
  const root = join(directory, "checkout");
  const port = 35_000 + (process.pid % 10_000);
  let child;
  try {
    for (const path of ["examples/browser-client", "src", "client", "wasm/dist", ".local/group-companion", ".git"]) {
      await mkdir(join(root, path), { recursive: true, mode: 0o700 });
    }
    for (const path of ["examples/browser-client/server.js", "examples/browser-client/group-companion.js", "src/strict-json.js", "src/endpoint.js"]) {
      await copyFile(new URL(`../${path}`, import.meta.url), join(root, path));
    }
    await writeFile(join(root, "package.json"), '{"type":"module"}');
    await writeFile(join(root, "client/index.html"), "<!doctype html><title>Client</title>");
    await writeFile(join(root, "client/app.js"), "export const client = true;");
    await writeFile(join(root, "wasm/dist/noctweave_oqs.wasm"), new Uint8Array([0, 97, 115, 109]));
    await writeFile(join(root, ".local/group-companion/client-state.json"), "PRIVATE_STATE_SENTINEL", { mode: 0o600 });
    await writeFile(join(root, ".git/config"), "PRIVATE_GIT_SENTINEL", { mode: 0o600 });
    await writeFile(join(root, ".env"), "PRIVATE_ENV_SENTINEL", { mode: 0o600 });
    await writeFile(join(directory, "outside.js"), "PRIVATE_OUTSIDE_SENTINEL", { mode: 0o600 });
    await symlink(join(directory, "outside.js"), join(root, "client/external.js"));
    await symlink(join(directory), join(root, "client/linked-directory"));
    await mkdir(join(root, "client/not-a-file.js"));
    const oversized = await open(join(root, "client/oversized.js"), "wx");
    await oversized.truncate(8 * 1024 * 1024 + 1);
    await oversized.close();
    child = spawn(process.execPath, [join(root, "examples/browser-client/server.js")], {
      env: { ...process.env, PORT: String(port), NOCTWEAVE_CLIENT: "production" },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let error = "";
    child.stderr.on("data", (chunk) => { error += chunk; });
    const baseURL = `http://127.0.0.1:${port}`;
    for (let attempt = 0; ; attempt += 1) {
      if (child.exitCode !== null || attempt >= 100) throw new Error(`Development server failed to start: ${error}`);
      try {
        if ((await fetch(baseURL, { redirect: "manual" })).status === 302) break;
      } catch { /* Wait for the child listener. */ }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    for (const path of ["/client/", "/client/app.js", "/src/strict-json.js", "/wasm/dist/noctweave_oqs.wasm"]) {
      assert.equal((await fetch(baseURL + path)).status, 200, path);
    }
    for (const path of [
      "/.local/group-companion/client-state.json", "/.git/config", "/.env",
      "/%2elocal/group-companion/client-state.json", "/client/external.js",
      "/client/linked-directory/outside.js", "/client/not-a-file.js", "/client/oversized.js",
      "/examples/browser-client/server.js",
      "/examples/browser-client/group-companion.js", "/package.json"
    ]) {
      const response = await fetch(baseURL + path);
      assert.ok(response.status === 403 || response.status === 404, `${path}: ${response.status}`);
      assert.doesNotMatch(await response.text(), /PRIVATE_.*_SENTINEL/u);
    }
  } finally {
    if (child && child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited;
    }
    await rm(directory, { recursive: true, force: true });
  }
});
