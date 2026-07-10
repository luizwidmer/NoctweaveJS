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

export function normalizeRelayEndpoint(input, options = {}) {
  if (typeof input === "string") {
    return parseRelayEndpoint(input, options);
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Relay endpoint must be a string or endpoint object.");
  }
  validateHost(input.host);
  const port = parsePort(input.port);
  if (typeof input.useTLS !== "boolean" || !["tcp", "http", "websocket"].includes(input.transport)) {
    throw new TypeError("Relay endpoint object has an invalid transport profile.");
  }
  return {
    host: input.host,
    port,
    useTLS: input.useTLS,
    transport: input.transport
  };
}

export function relayEndpointURL(endpoint, path = "/relay") {
  const normalized = normalizeRelayEndpoint(endpoint);
  if (typeof path !== "string" || !/^\/[A-Za-z0-9/_-]*$/.test(path)) {
    throw new TypeError("Relay endpoint path is invalid.");
  }
  const transport = normalized.transport;
  if (transport === "tcp") {
    throw new TypeError("Raw TCP relay endpoints do not have an HTTP/WebSocket URL.");
  }
  const scheme = transport === "websocket"
    ? (normalized.useTLS ? "wss" : "ws")
    : (normalized.useTLS ? "https" : "http");
  const defaultPort = normalized.useTLS ? 443 : 80;
  const host = normalized.host.includes(":") && !normalized.host.startsWith("[")
    ? `[${normalized.host}]`
    : normalized.host;
  const port = normalized.port;
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
  if (url.username || url.password) {
    throw new TypeError("Relay endpoint URL cannot include user info.");
  }
  if (url.search) {
    throw new TypeError("Relay endpoint URL cannot include query parameters.");
  }
  if (url.hash) {
    throw new TypeError("Relay endpoint URL cannot include a fragment.");
  }
  if (url.pathname && url.pathname !== "/") {
    throw new TypeError("Relay endpoint URL cannot include a path.");
  }
  validateHost(url.hostname);

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
    validateHost(host);
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
    const host = value.slice(0, lastColon);
    validateHost(host);
    return {
      host,
      port: parsePort(value.slice(lastColon + 1))
    };
  }
  if (lastColon > -1) {
    throw new TypeError("IPv6 relay endpoints must use brackets.");
  }

  validateHost(value);
  return { host: value, port: defaultPort };
}

function parsePort(raw) {
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError(`Invalid relay port: ${raw}`);
  }
  return port;
}

function validateHost(host) {
  if (typeof host !== "string" || host.length === 0 || host.trim() !== host) {
    throw new TypeError("Relay endpoint must include a valid host.");
  }
  if (/\s|[/?#@]/u.test(host)) {
    throw new TypeError("Relay endpoint must include a valid host.");
  }
}
