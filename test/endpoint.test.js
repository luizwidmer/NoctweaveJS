import assert from "node:assert/strict";
import test from "node:test";
import { parseRelayEndpoint, relayEndpointURL } from "../src/index.js";

test("parses https relay endpoint", () => {
  const endpoint = parseRelayEndpoint("https://relay.example");
  assert.deepEqual(endpoint, {
    host: "relay.example",
    port: 443,
    useTLS: true,
    transport: "http"
  });
  assert.equal(relayEndpointURL(endpoint), "https://relay.example/relay");
});

test("parses websocket relay endpoint with explicit port", () => {
  const endpoint = parseRelayEndpoint("wss://relay.example:9443");
  assert.deepEqual(endpoint, {
    host: "relay.example",
    port: 9443,
    useTLS: true,
    transport: "websocket"
  });
  assert.equal(relayEndpointURL(endpoint), "wss://relay.example:9443/relay");
});

test("parses bare host port as tcp", () => {
  const endpoint = parseRelayEndpoint("127.0.0.1:9339");
  assert.deepEqual(endpoint, {
    host: "127.0.0.1",
    port: 9339,
    useTLS: false,
    transport: "tcp"
  });
});
