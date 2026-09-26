import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, copyFile, mkdir, mkdtemp, open, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCompanionAccessToken } from "../examples/browser-client/companion-access.js";

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
    for (const path of ["examples/browser-client/server.js", "examples/browser-client/companion-access.js", "examples/browser-client/group-companion.js", "src/strict-json.js", "src/endpoint.js"]) {
      await copyFile(new URL(`../${path}`, import.meta.url), join(root, path));
    }
    await writeFile(join(root, "package.json"), '{"type":"module"}');
    await writeFile(join(root, "client/index.html"), "<!doctype html><title>Client</title>");
    await writeFile(join(root, "client/app.js"), "export const client = true;");
    await writeFile(join(root, "wasm/dist/noctweave_oqs.wasm"), new Uint8Array([0, 97, 115, 109]));
    await writeFile(join(root, ".local/group-companion/client-state.json"), "PRIVATE_STATE_SENTINEL", { mode: 0o600 });
    await writeFile(join(root, ".git/config"), "PRIVATE_GIT_SENTINEL", { mode: 0o600 });
    await writeFile(join(root, ".env"), "PRIVATE_ENV_SENTINEL", { mode: 0o600 });
    const cliPath = join(root, ".local", "dummy-cli");
    await writeFile(cliPath, [
      `#!${process.execPath}`,
      'const command = process.argv[2];',
      'console.log(JSON.stringify(command === "group-events" ?',
      '  [{ kind: "message", text: "PRIVATE_EVENT_SENTINEL" }] :',
      '  command === "groups" ? [] : { ok: true }));'
    ].join("\n"), { mode: 0o700 });
    await chmod(cliPath, 0o700);
    await writeFile(join(directory, "outside.js"), "PRIVATE_OUTSIDE_SENTINEL", { mode: 0o600 });
    await symlink(join(directory, "outside.js"), join(root, "client/external.js"));
    await symlink(join(directory), join(root, "client/linked-directory"));
    await mkdir(join(root, "client/not-a-file.js"));
    const oversized = await open(join(root, "client/oversized.js"), "wx");
    await oversized.truncate(8 * 1024 * 1024 + 1);
    await oversized.close();
    const token = "a".repeat(64);
    child = spawn(process.execPath, [join(root, "examples/browser-client/server.js")], {
      env: {
        ...process.env,
        PORT: String(port),
        NOCTWEAVE_CLIENT: "production",
        NOCTWEAVE_CLI_PATH: cliPath,
        NOCTWEAVE_GROUP_COMPANION_TOKEN: token
      },
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
      "/.local/group-companion/client-state.json", "/.local/group-companion/access-token",
      "/.git/config", "/.env",
      "/%2elocal/group-companion/client-state.json", "/client/external.js",
      "/client/linked-directory/outside.js", "/client/not-a-file.js", "/client/oversized.js",
      "/examples/browser-client/server.js",
      "/examples/browser-client/group-companion.js", "/package.json"
    ]) {
      const response = await fetch(baseURL + path);
      assert.ok(response.status === 403 || response.status === 404, `${path}: ${response.status}`);
      assert.doesNotMatch(await response.text(), /PRIVATE_.*_SENTINEL/u);
    }
    const tokenPath = join(root, ".local/group-companion/access-token");
    await assert.rejects(stat(tokenPath), { code: "ENOENT" });
    if (process.platform !== "win32") {
      assert.equal((await stat(join(root, ".local/group-companion"))).mode & 0o777, 0o700);
    }
    const eventsPath = "/api/group-companion/groups/3f770ad9-4cea-41f0-a626-6d9e04796484/events?sync=false";
    for (const headers of [
      { origin: baseURL },
      { "sec-fetch-site": "same-origin" },
      { origin: baseURL, "sec-fetch-site": "same-origin", authorization: "Bearer " + "0".repeat(64) }
    ]) {
      const denied = await fetch(baseURL + eventsPath, { headers });
      assert.equal(denied.status, 401);
      assert.doesNotMatch(await denied.text(), /PRIVATE_EVENT_SENTINEL/u);
    }
    const authorized = await fetch(baseURL + eventsPath, {
      headers: { origin: baseURL, "sec-fetch-site": "same-origin", authorization: `Bearer ${token}` }
    });
    assert.equal(authorized.status, 200);
    assert.match(await authorized.text(), /PRIVATE_EVENT_SENTINEL/u);
    const crossOrigin = await fetch(baseURL + eventsPath, {
      headers: { origin: "http://example.invalid", authorization: `Bearer ${token}` }
    });
    assert.equal(crossOrigin.status, 403);

    const exited = once(child, "exit");
    child.kill("SIGTERM");
    await exited;
    child = undefined;
    await writeFile(tokenPath, "LEGACY_PLAINTEXT_TOKEN", { mode: 0o600 });
    const blocked = spawn(process.execPath, [join(root, "examples/browser-client/server.js")], {
      env: { ...process.env, PORT: String(port), NOCTWEAVE_GROUP_COMPANION_TOKEN: token },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let blockedError = "";
    blocked.stderr.on("data", (chunk) => { blockedError += chunk; });
    const blockedTimeout = setTimeout(() => blocked.kill("SIGKILL"), 5_000);
    const [blockedStatus] = await once(blocked, "exit");
    clearTimeout(blockedTimeout);
    assert.notEqual(blockedStatus, 0);
    assert.match(blockedError, /Legacy plaintext group companion token exists/u);
    assert.equal((await stat(tokenPath)).size, "LEGACY_PLAINTEXT_TOKEN".length);
  } finally {
    if (child && child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited;
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test("companion access uses process-only credentials and rejects unattended startup without one", () => {
  const first = createCompanionAccessToken({ interactive: true });
  const second = createCompanionAccessToken({ interactive: true });
  assert.match(first.token, /^[0-9a-f]{64}$/u);
  assert.notEqual(first.token, second.token, "a restart rotates an interactive token");
  assert.equal(first.reveal, true);
  assert.deepEqual(createCompanionAccessToken({ suppliedToken: "a".repeat(64), interactive: false }),
    { token: "a".repeat(64), reveal: false });
  assert.throws(() => createCompanionAccessToken({ suppliedToken: undefined, interactive: false }),
    /requires NOCTWEAVE_GROUP_COMPANION_TOKEN/u);
  assert.throws(() => createCompanionAccessToken({ suppliedToken: "short", interactive: false }),
    /64 lowercase hex/u);
});
