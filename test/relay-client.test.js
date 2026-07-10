import assert from "node:assert/strict";
import test from "node:test";
import {
  NoctweaveRelayClient,
  normalizeRelayClientPolicy,
  relayClientPolicyLimits,
  relayRequests
} from "../src/index.js";

test("relay client posts JSON request and decodes response", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ type: "info", relayInfo: { relayName: "Test" } }), { status: 200 });
  };
  const client = new NoctweaveRelayClient("https://relay.example", { fetch, authToken: "secret" });

  const response = await client.info();

  assert.equal(response.type, "info");
  assert.equal(calls[0].url, "https://relay.example/relay");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.referrerPolicy, "no-referrer");
  assert.equal(calls[0].init.cache, "no-store");
  assert.deepEqual(JSON.parse(calls[0].init.body), { type: "info", authToken: "secret" });
});

test("relay health fallback preserves redirect and credential isolation", async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (calls.length === 1) {
      throw new TypeError("POST health unavailable");
    }
    return new Response("ok", { status: 200 });
  };
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  assert.deepEqual(await client.health(), { type: "ok" });
  assert.equal(calls[1].url, "https://relay.example/health");
  assert.equal(calls[1].init.redirect, "error");
  assert.equal(calls[1].init.credentials, "omit");
  assert.equal(calls[1].init.referrerPolicy, "no-referrer");
  assert.equal(calls[1].init.cache, "no-store");
});

test("relay client supports raw request helpers", async () => {
  const fetch = async () => new Response(JSON.stringify({ type: "messages", messages: [] }), { status: 200 });
  const client = new NoctweaveRelayClient("http://127.0.0.1:9340", { fetch });

  const response = await client.send(relayRequests.fetch({ inboxId: "inbox", maxCount: 1 }));

  assert.equal(response.type, "messages");
  assert.deepEqual(response.messages, []);
});

test("tcp endpoint fails explicitly in web client", async () => {
  const client = new NoctweaveRelayClient("127.0.0.1:9339", {
    fetch: async () => new Response("{}")
  });

  await assert.rejects(() => client.health(), /not raw TCP/);
});

test("relay client redacts HTTP error bodies", async () => {
  const fetch = async () => new Response("relay-secret-token", { status: 500 });
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  await assert.rejects(
    () => client.info(),
    (error) => {
      assert.match(error.message, /Relay returned HTTP 500/);
      assert.doesNotMatch(error.message, /relay-secret-token/);
      assert.match(error.message, /non-json response/);
      return true;
    }
  );
});

test("relay client redacts invalid JSON bodies", async () => {
  const fetch = async () => new Response("not-json-secret", { status: 200 });
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  await assert.rejects(
    () => client.info(),
    (error) => {
      assert.match(error.message, /Relay returned invalid JSON/);
      assert.doesNotMatch(error.message, /not-json-secret/);
      assert.match(error.message, /non-json response/);
      return true;
    }
  );
});

test("relay client rejects invalid timeout configuration", () => {
  assert.throws(
    () => new NoctweaveRelayClient("https://relay.example", { timeoutMs: 0, fetch: async () => new Response("{}") }),
    /Relay timeout must be between/
  );
  assert.throws(
    () => new NoctweaveRelayClient("https://relay.example", { timeoutMs: Number.NaN, fetch: async () => new Response("{}") }),
    /Relay timeout must be between/
  );
});

test("relay client rejects oversized authentication and malformed endpoint objects", () => {
  assert.throws(
    () => new NoctweaveRelayClient("https://relay.example", {
      authToken: "x".repeat(4097),
      fetch: async () => new Response("{}")
    }),
    /authentication token/
  );
  assert.throws(
    () => new NoctweaveRelayClient(
      { host: "relay.example/path", port: 443, useTLS: true, transport: "http" },
      { fetch: async () => new Response("{}") }
    )
  );
});

test("relay client stops reading oversized chunked responses", async () => {
  const oversized = new Uint8Array(1_000_001).fill(0x61);
  const fetch = async () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(oversized);
      controller.close();
    }
  }), { status: 200 });
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  await assert.rejects(() => client.info(), /response exceeds client size limit/);
});

test("relay client rejects fetch implementations without bounded streaming reads", async () => {
  const fetch = async () => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    text: async () => JSON.stringify({ type: "info" })
  });
  const client = new NoctweaveRelayClient("https://relay.example", { fetch });

  await assert.rejects(() => client.info(), /must expose a streaming response body/);
});

test("relay client rejects oversized requests before transport", async () => {
  let fetchCalled = false;
  const client = new NoctweaveRelayClient("https://relay.example", {
    fetch: async () => {
      fetchCalled = true;
      return new Response("{}");
    }
  });

  await assert.rejects(
    () => client.send({ type: "raw-test", payload: "x".repeat(600_000) }),
    /request exceeds client size limit/
  );
  assert.equal(fetchCalled, false);
});

test("relay client accepts bounded deployment policy", async () => {
  let fetchCalled = false;
  const client = new NoctweaveRelayClient("https://relay.example", {
    policy: {
      timeoutMs: 2_500,
      defaultTCPPort: 7443,
      maxRequestBytes: 2_048,
      maxResponseBytes: 4_096
    },
    fetch: async () => {
      fetchCalled = true;
      return new Response(JSON.stringify({ type: "ok", padding: "x".repeat(5_000) }));
    }
  });

  assert.equal(client.policy.timeoutMs, 2_500);
  assert.equal(client.policy.maxRequestBytes, 2_048);
  await assert.rejects(() => client.health(), /response exceeds client size limit/);
  assert.equal(fetchCalled, true);
  await assert.rejects(
    () => client.send({ type: "custom", payload: "x".repeat(3_000) }),
    /request exceeds client size limit/
  );
});

test("relay policy cannot exceed absolute allocation ceilings", () => {
  assert.throws(
    () => normalizeRelayClientPolicy({
      maxResponseBytes: relayClientPolicyLimits.maximumResponseBytes + 1
    }),
    /response budget/
  );
  assert.throws(
    () => normalizeRelayClientPolicy({
      maxRequestBytes: relayClientPolicyLimits.maximumRequestBytes + 1
    }),
    /request budget/
  );
  assert.throws(() => normalizeRelayClientPolicy({ defaultTCPPort: 0 }), /default TCP port/);
});
