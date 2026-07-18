export const strictJSONMaximumDepth = 128;

/**
 * Parses JSON only after verifying its raw object structure. Native JSON.parse
 * silently keeps one value when an object repeats a field, which is unsafe for
 * authenticated protocol objects because different implementations may select
 * different values. This preflight rejects repeated semantic keys, including
 * escaped spellings such as `"value"` and `"\u0076alue"`.
 */
export function parseExactJSON(
  text,
  { maximumDepth = strictJSONMaximumDepth, canonicalNumbers = false } = {}
) {
  if (typeof text !== "string") {
    throw new TypeError("Exact JSON input must be a string.");
  }
  if (!Number.isSafeInteger(maximumDepth) || maximumDepth < 1 || maximumDepth > 512) {
    throw new TypeError("Exact JSON maximum depth must be between 1 and 512.");
  }
  if (typeof canonicalNumbers !== "boolean") {
    throw new TypeError("Exact JSON canonicalNumbers must be a boolean.");
  }

  new ExactJSONScanner(text, maximumDepth, canonicalNumbers).scan();
  return JSON.parse(text);
}

class ExactJSONScanner {
  constructor(text, maximumDepth, canonicalNumbers) {
    this.text = text;
    this.maximumDepth = maximumDepth;
    this.canonicalNumbers = canonicalNumbers;
    this.offset = 0;
  }

  scan() {
    this.skipWhitespace();
    this.scanValue(0);
    this.skipWhitespace();
    if (this.offset !== this.text.length) {
      this.fail("Unexpected trailing JSON data");
    }
  }

  scanValue(depth) {
    switch (this.text[this.offset]) {
    case "{":
      this.scanObject(depth + 1);
      return;
    case "[":
      this.scanArray(depth + 1);
      return;
    case "\"":
      this.scanString();
      return;
    case "t":
      this.scanLiteral("true");
      return;
    case "f":
      this.scanLiteral("false");
      return;
    case "n":
      this.scanLiteral("null");
      return;
    default:
      this.scanNumber();
    }
  }

  scanObject(depth) {
    this.requireDepth(depth);
    this.offset += 1;
    this.skipWhitespace();
    if (this.consume("}")) return;

    const keys = new Set();
    while (true) {
      if (this.text[this.offset] !== "\"") {
        this.fail("Object field must be a JSON string");
      }
      const key = this.scanString().normalize("NFC");
      if (keys.has(key)) {
        this.fail(`Duplicate JSON field ${JSON.stringify(key)}`);
      }
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) this.fail("Object field is missing ':'");
      this.skipWhitespace();
      this.scanValue(depth);
      this.skipWhitespace();
      if (this.consume("}")) return;
      if (!this.consume(",")) this.fail("Object fields must be separated by ','");
      this.skipWhitespace();
    }
  }

  scanArray(depth) {
    this.requireDepth(depth);
    this.offset += 1;
    this.skipWhitespace();
    if (this.consume("]")) return;

    while (true) {
      this.scanValue(depth);
      this.skipWhitespace();
      if (this.consume("]")) return;
      if (!this.consume(",")) this.fail("Array values must be separated by ','");
      this.skipWhitespace();
    }
  }

  scanString() {
    const start = this.offset;
    this.offset += 1;
    while (this.offset < this.text.length) {
      const code = this.text.charCodeAt(this.offset);
      if (code === 0x22) {
        this.offset += 1;
        return JSON.parse(this.text.slice(start, this.offset));
      }
      if (code < 0x20) this.fail("JSON strings cannot contain control characters");
      if (code === 0x5c) {
        this.offset += 1;
        const escape = this.text[this.offset];
        if (escape === "u") {
          const first = this.hexCodeUnit(this.offset + 1);
          if (isHighSurrogate(first)) {
            if (this.text[this.offset + 5] !== "\\" || this.text[this.offset + 6] !== "u") {
              this.fail("Unpaired JSON Unicode surrogate");
            }
            const second = this.hexCodeUnit(this.offset + 7);
            if (!isLowSurrogate(second)) this.fail("Unpaired JSON Unicode surrogate");
            this.offset += 11;
            continue;
          }
          if (isLowSurrogate(first)) this.fail("Unpaired JSON Unicode surrogate");
          this.offset += 5;
          continue;
        }
        if (!"\"\\/bfnrt".includes(escape ?? "")) this.fail("Invalid JSON string escape");
      }
      if (isHighSurrogate(code)) {
        if (!isLowSurrogate(this.text.charCodeAt(this.offset + 1))) {
          this.fail("Unpaired JSON Unicode surrogate");
        }
        this.offset += 2;
        continue;
      }
      if (isLowSurrogate(code)) this.fail("Unpaired JSON Unicode surrogate");
      this.offset += 1;
    }
    this.fail("Unterminated JSON string");
  }

  scanLiteral(literal) {
    if (this.text.slice(this.offset, this.offset + literal.length) !== literal) {
      this.fail("Invalid JSON value");
    }
    this.offset += literal.length;
  }

  hexCodeUnit(start) {
    let value = 0;
    for (let index = 0; index < 4; index += 1) {
      const nibble = hexNibble(this.text.charCodeAt(start + index));
      if (nibble < 0) this.fail("Invalid JSON Unicode escape");
      value = (value << 4) | nibble;
    }
    return value;
  }

  scanNumber() {
    const remaining = this.text.slice(this.offset);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(remaining);
    if (!match) this.fail("Invalid JSON value");
    if (!Number.isFinite(Number(match[0]))) this.fail("JSON number exceeds finite range");
    if (this.canonicalNumbers && (
      match[0].includes(".") ||
      match[0].includes("e") ||
      match[0].includes("E") ||
      match[0] === "-0" ||
      !Number.isSafeInteger(Number(match[0]))
    )) {
      this.fail("JSON number is outside the NCJ-1 safe-integer profile");
    }
    this.offset += match[0].length;
  }

  skipWhitespace() {
    while (this.offset < this.text.length && /[\u0009\u000A\u000D\u0020]/u.test(this.text[this.offset])) {
      this.offset += 1;
    }
  }

  consume(character) {
    if (this.text[this.offset] !== character) return false;
    this.offset += 1;
    return true;
  }

  requireDepth(depth) {
    if (depth > this.maximumDepth) {
      this.fail(`JSON nesting exceeds maximum depth ${this.maximumDepth}`);
    }
  }

  fail(message) {
    throw new SyntaxError(`${message} at offset ${this.offset}.`);
  }
}

function hexNibble(code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

function isHighSurrogate(code) {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code) {
  return code >= 0xdc00 && code <= 0xdfff;
}
