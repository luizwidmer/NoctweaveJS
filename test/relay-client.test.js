import assert from "node:assert/strict";
import test from "node:test";
import { NoctweaveRelayClient, relayRequests } from "../src/index.js";

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
  assert.deepEqual(JSON.parse(calls[0].init.body), { type: "info", authToken: "secret" });
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
