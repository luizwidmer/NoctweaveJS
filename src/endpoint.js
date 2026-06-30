const DEFAULT_TCP_PORT = 9339;

export function parseRelayEndpoint(input, options = {}) {
  if (typeof input !== "string" || input.trim() === "") {
    throw new TypeError("Relay endpoint must be a non-empty string.");
  }

  const trimmed = input.trim();
  const defaultPort = Number(options.defaultPort ?? DEFAULT_TCP_PORT);

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    return parseURLRelayEndpoint(trimmed);
  }

  const parsed = parseHostPort(trimmed, defaultPort);
  return {
    host: parsed.host,
    port: parsed.port,
    useTLS: false,
    transport: "tcp"
  };
}

export function relayEndpointURL(endpoint, path = "/relay") {
  const transport = endpoint.transport ?? "http";
  const scheme = transport === "websocket"
    ? (endpoint.useTLS ? "wss" : "ws")
    : (endpoint.useTLS ? "https" : "http");
  const defaultPort = endpoint.useTLS ? 443 : 80;
  const host = endpoint.host.includes(":") && !endpoint.host.startsWith("[")
    ? `[${endpoint.host}]`
    : endpoint.host;
  const port = Number(endpoint.port);
  const portPart = port && port !== defaultPort ? `:${port}` : "";
  return `${scheme}://${host}${portPart}${path}`;
}

function parseURLRelayEndpoint(value) {
  const url = new URL(value);
  let transport;
  let useTLS;
  let defaultPort;

  switch (url.protocol) {
  case "http:":
    transport = "http";
    useTLS = false;
    defaultPort = 80;
    break;
  case "https:":
    transport = "http";
    useTLS = true;
    defaultPort = 443;
    break;
  case "ws:":
    transport = "websocket";
    useTLS = false;
    defaultPort = 80;
    break;
  case "wss:":
    transport = "websocket";
    useTLS = true;
    defaultPort = 443;
    break;
  case "tcp:":
    transport = "tcp";
    useTLS = false;
    defaultPort = DEFAULT_TCP_PORT;
    break;
  case "tls:":
    transport = "tcp";
    useTLS = true;
    defaultPort = DEFAULT_TCP_PORT;
    break;
  default:
    throw new TypeError(`Unsupported relay endpoint protocol: ${url.protocol}`);
  }

  if (!url.hostname) {
    throw new TypeError("Relay endpoint URL must include a host.");
  }

  return {
    host: url.hostname,
    port: url.port ? parsePort(url.port) : defaultPort,
    useTLS,
    transport
  };
}

function parseHostPort(value, defaultPort) {
  if (value.startsWith("[")) {
    const close = value.indexOf("]");
    if (close < 0) {
      throw new TypeError("Invalid bracketed IPv6 relay endpoint.");
    }
    const host = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (rest === "") {
      return { host, port: defaultPort };
    }
    if (!rest.startsWith(":")) {
      throw new TypeError("Invalid relay endpoint after IPv6 host.");
    }
    return { host, port: parsePort(rest.slice(1)) };
  }

  const lastColon = value.lastIndexOf(":");
  if (lastColon > -1 && value.indexOf(":") === lastColon) {
    return {
      host: value.slice(0, lastColon),
      port: parsePort(value.slice(lastColon + 1))
    };
  }

  return { host: value, port: defaultPort };
}

function parsePort(raw) {
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError(`Invalid relay port: ${raw}`);
  }
  return port;
}
