import { base64URL, decodeBase64URL } from "../../client/security-keys.js";
const encode = (value) => new TextEncoder().encode(JSON.stringify(value));
const concat = (...values) => new Uint8Array(values.flatMap((v) => [...v]));
const hash = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

export function cbor(value) {
  const header = (major, size) => size < 24 ? [major * 32 + size]
    : size < 256 ? [major * 32 + 24, size] : [major * 32 + 25, size >> 8, size & 255];
  if (value instanceof Uint8Array) return concat(header(2, value.length), value);
  if (typeof value === "string") { const bytes = new TextEncoder().encode(value); return concat(header(3, bytes.length), bytes); }
  if (Number.isInteger(value)) return new Uint8Array(value >= 0 ? header(0, value) : header(1, -1 - value));
  if (value instanceof Map) return concat(header(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)]));
  throw new Error("Unsupported fixture CBOR");
}

function der(raw) {
  const integer = (value) => {
    while (value.length > 1 && value[0] === 0) value = value.slice(1);
    if (value[0] & 0x80) value = concat([0], value);
    return concat([2, value.length], value);
  };
  const body = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
  return concat([0x30, body.length], body);
}

/** Test-only signing authenticator. Never imported by a product entry point. */
export class SecurityKeyFixture {
  rpID = "localhost";
  origin = "http://localhost:8080";
  counter = 0;
  flags = 5;
  calls = 0;
  prf = true;
  transform = (response) => response;
  beforeGet = null;
  key = null;
  id = base64URL(crypto.getRandomValues(new Uint8Array(32)));
  seed = crypto.getRandomValues(new Uint8Array(32));

  async create(options) {
    this.calls++;
    this.key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", this.key.publicKey));
    const id = decodeBase64URL(this.id);
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, publicKey.slice(1, 33)], [-3, publicKey.slice(33)]]));
    const authData = concat(await this.header(options.rp.id, this.flags | 0x40), new Uint8Array(16), [0, id.length], id, cose);
    const response = this.envelope(options, "webauthn.create", {
      attestationObject: base64URL(cbor(new Map([["fmt", "none"], ["authData", authData], ["attStmt", new Map()]])))
    });
    return this.transform(response);
  }

  async get(options) {
    this.calls++;
    if (this.beforeGet) await this.beforeGet();
    if (!options.allowCredentials.some(({ id }) => id === this.id)) throw new Error("Wrong test key");
    this.counter++;
    const authData = await this.header(options.rpId, this.flags);
    const response = this.envelope(options, "webauthn.get", { authenticatorData: base64URL(authData) });
    const signed = concat(authData, await hash(decodeBase64URL(response.response.clientDataJSON)));
    response.response.signature = base64URL(der(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.key.privateKey, signed))));
    if (this.prf) {
      const salt = decodeBase64URL(options.extensions.prf.evalByCredential[this.id].first);
      response.clientExtensionResults = { prf: { results: { first: base64URL(await hash(concat(this.seed, salt))) } } };
    }
    return this.transform(response);
  }

  async header(rp, flags) {
    const counter = new Uint8Array(4); new DataView(counter.buffer).setUint32(0, this.counter);
    return concat(await hash(new TextEncoder().encode(rp)), [flags], counter);
  }

  envelope(options, type, response) {
    return { type: "public-key", id: this.id, rawId: this.id, authenticatorAttachment: "cross-platform",
      response: { clientDataJSON: base64URL(encode({ type, challenge: options.challenge, origin: this.origin, crossOrigin: false })), ...response } };
  }
}
