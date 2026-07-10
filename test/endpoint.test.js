import assert from "node:assert/strict";
import test from "node:test";
import { normalizeRelayEndpoint, parseRelayEndpoint, relayEndpointURL } from "../src/index.js";

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

test("rejects URL components that would otherwise be silently discarded", () => {
  for (const value of [
    "https://user:pass@relay.example",
    "https://relay.example/custom/path",
    "https://relay.example?token=secret",
    "https://relay.example#secret"
  ]) {
    assert.throws(() => parseRelayEndpoint(value), /cannot include/);
  }
});

test("rejects malformed bare endpoints and port zero", () => {
  for (const value of ["relay host", "relay.example/path", ":9339", "relay.example:0", "::1"]) {
    assert.throws(() => parseRelayEndpoint(value));
  }
});

test("validates endpoint objects instead of trusting caller-supplied fields", () => {
  assert.deepEqual(
    normalizeRelayEndpoint({ host: "relay.example", port: 443, useTLS: true, transport: "http" }),
    { host: "relay.example", port: 443, useTLS: true, transport: "http" }
  );
  assert.throws(() => normalizeRelayEndpoint({ host: "relay.example/path", port: 443, useTLS: true, transport: "http" }));
  assert.throws(() => normalizeRelayEndpoint({ host: "relay.example", port: 0, useTLS: true, transport: "http" }));
  assert.throws(() => relayEndpointURL({ host: "relay.example", port: 9339, useTLS: false, transport: "tcp" }));
});
