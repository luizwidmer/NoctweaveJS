import assert from "node:assert/strict";
import test from "node:test";
import { proxyRelayRequest } from "../desktop/bun/relay-proxy.js";

test("desktop relay proxy forwards bounded HTTPS relay requests", async () => {
  let observed;
  const body = JSON.stringify({
    requestID: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
    module: "nw.core",
    version: 2,
    method: "health",
    body: {},
    authToken: null
  });
  const response = await proxyRelayRequest(
    { endpoint: "https://relay.example", body },
    {
      fetch: async (url, init) => {
        observed = { url, init };
        return new Response('{"status":"success"}', {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
    }
  );

  assert.equal(observed.url, "https://relay.example/relay");
  assert.equal(observed.init.method, "POST");
  assert.equal(observed.init.redirect, "error");
  assert.equal(observed.init.body, body);
  assert.deepEqual(response, {
    status: 200,
    contentType: "application/json",
    body: '{"status":"success"}'
  });
});

test("desktop relay proxy rejects alternate route selectors", async () => {
  await assert.rejects(
    proxyRelayRequest({ endpoint: "http://127.0.0.1:9340", route: "health", body: "{}" }),
    /only endpoint and body/
  );
});

test("desktop relay proxy rejects raw TCP and oversized data", async () => {
  await assert.rejects(
    proxyRelayRequest({ endpoint: "127.0.0.1:9339", body: "{}" }),
    /only HTTP or HTTPS/
  );
  await assert.rejects(
    proxyRelayRequest({ endpoint: "https://relay.example", body: "x".repeat(512 * 1024 + 1) }),
    /request exceeds the size limit/
  );
});

test("desktop relay proxy rejects oversized responses before reading", async () => {
  await assert.rejects(
    proxyRelayRequest(
      { endpoint: "https://relay.example", body: "{}" },
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
