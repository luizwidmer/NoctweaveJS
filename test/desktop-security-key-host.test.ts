import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { DesktopSecurityKeyHost } from "../desktop/bun/security-key-host.ts";

// Exercise the real pipe/process boundary with a test-only helper, never an authenticator.
async function fixture(run: (host: DesktopSecurityKeyHost, mode: string) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-key-host-test-"));
  const mode = join(directory, "mode");
  const executable = join(directory, "helper");
  await writeFile(mode, "present");
  await writeFile(executable, `#!${process.execPath}
const fs = require("node:fs");
let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  const request = JSON.parse(input);
  if (request.operation === "watch-presence") {
    const emit = () => {
      const mode = fs.readFileSync(${JSON.stringify(mode)}, "utf8");
      if (mode === "silent") return;
      process.stdout.write(JSON.stringify({ present: mode === "present" }) + "\\n");
    };
    emit(); setInterval(emit, 100); return;
  }
  if (request.options.scenario === "wait") { setInterval(() => {}, 100); return; }
  if (request.options.scenario === "oversized") { process.stdout.write("x".repeat(140000)); return; }
  if (request.options.scenario === "malformed") { process.stdout.write("not JSON"); return; }
  if (process.argv.length !== 2 || request.pin !== "test PIN") process.exit(2);
  process.stdout.write(JSON.stringify({ credential: { id: "fixture-credential" }, presenceToken: "1234" }));
});
`, { mode: 0o700 });
  const host = new DesktopSecurityKeyHost(executable);
  try { await run(host, mode); }
  finally { host.cancel(); host.releasePresence(); await rm(directory, { recursive: true, force: true }); }
}
const request = (scenario = "valid") => ({ operation: "get" as const, options: { scenario }, pin: "test PIN" });
const macOS = { skip: process.platform !== "darwin" };
async function until(predicate: () => boolean) {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) assert.fail("Presence did not change within the bounded wait.");
    await delay(25);
  }
}

test("desktop key host keeps the presence token private and cannot resume after removal", macOS, async () => {
  await fixture(async (host, mode) => {
    assert.deepEqual(await host.request(request()), { credential: { id: "fixture-credential" } });
    assert.deepEqual(host.presenceStatus(), { present: true, credentialID: "fixture-credential" });
    await writeFile(mode, "absent");
    await until(() => !host.presenceStatus().present);
    await writeFile(mode, "present");
    await delay(150);
    assert.equal(host.presenceStatus().present, false);
    await host.request(request());
    assert.equal(host.presenceStatus().present, true);
    host.releasePresence();
    assert.equal(host.presenceStatus().present, false);
  });
});

test("desktop key host fails closed when presence heartbeats stop", macOS, async () => {
  await fixture(async (host, mode) => {
    await host.request(request());
    await writeFile(mode, "silent");
    await until(() => !host.presenceStatus().present);
    await writeFile(mode, "present");
    await delay(150);
    assert.equal(host.presenceStatus().present, false);
  });
});

test("desktop key host rejects unbounded, malformed, concurrent and cancelled operations", macOS, async () => {
  await fixture(async (host) => {
    await assert.rejects(host.request({ ...request(), operation: "reset" } as never), /Invalid/);
    await assert.rejects(host.request({ ...request(), pin: "x".repeat(64) }), /Invalid/);
    await assert.rejects(host.request({ ...request(), options: { large: "x".repeat(65_536) } }), /too large/);
    await assert.rejects(host.request(request("malformed")), /Invalid/);
    await assert.rejects(host.request(request("oversized")), /Invalid/);
    const pending = host.request(request("wait"));
    const rejected = assert.rejects(pending, /cancelled|closed/);
    await assert.rejects(host.request(request()), /already running/);
    host.cancel();
    await rejected;
    assert.equal(host.presenceStatus().present, false);
  });
});
