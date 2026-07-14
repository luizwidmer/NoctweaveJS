import assert from "node:assert/strict";
import test from "node:test";
import { proxyRelayRequest } from "../desktop/bun/relay-proxy.js";

test("desktop relay proxy forwards bounded HTTPS relay requests", async () => {
  let observed;
  const response = await proxyRelayRequest(
    { endpoint: "https://relay.example", route: "relay", body: '{"type":"health"}' },
    {
      fetch: async (url, init) => {
        observed = { url, init };
        return new Response('{"type":"ok"}', {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
    }
  );

  assert.equal(observed.url, "https://relay.example/relay");
  assert.equal(observed.init.method, "POST");
  assert.equal(observed.init.redirect, "error");
  assert.equal(observed.init.body, '{"type":"health"}');
  assert.deepEqual(response, {
    status: 200,
    contentType: "application/json",
    body: '{"type":"ok"}'
  });
});

test("desktop relay proxy uses a GET-only health route", async () => {
  let observed;
  await proxyRelayRequest(
    { endpoint: "http://127.0.0.1:9340", route: "health" },
    {
      fetch: async (url, init) => {
        observed = { url, init };
        return new Response("ok", { status: 200 });
      }
    }
  );
  assert.equal(observed.url, "http://127.0.0.1:9340/health");
  assert.equal(observed.init.method, "GET");
  assert.equal(observed.init.body, undefined);
});

test("desktop relay proxy rejects raw TCP and oversized data", async () => {
  await assert.rejects(
    proxyRelayRequest({ endpoint: "127.0.0.1:9339", route: "health" }),
    /only HTTP or HTTPS/
  );
  await assert.rejects(
    proxyRelayRequest({ endpoint: "https://relay.example", route: "relay", body: "x".repeat(512 * 1024 + 1) }),
    /request exceeds the size limit/
  );
});

test("desktop relay proxy rejects oversized responses before reading", async () => {
  await assert.rejects(
    proxyRelayRequest(
      { endpoint: "https://relay.example", route: "health" },
      {
        fetch: async () => new Response("small", {
          status: 200,
          headers: { "content-length": "1000001" }
        })
      }
    ),
    /response exceeds the size limit/
  );
});
