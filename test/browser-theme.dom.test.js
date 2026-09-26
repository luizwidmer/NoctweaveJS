import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("production exposes the appearance control and the browser example redirects to it", async () => {
  const [productionHTML, exampleHTML, css] = await Promise.all([
    readFile(new URL("../client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../examples/browser-client/index.html", import.meta.url), "utf8"),
    readFile(new URL("../client/styles.css", import.meta.url), "utf8")
  ]);

  assert.match(productionHTML, /data-appearance-control/);
  assert.match(productionHTML, /data-appearance-select/);
  assert.match(productionHTML, /value="system"[^>]*>System/);
  assert.match(productionHTML, /value="light"[^>]*>Light/);
  assert.match(productionHTML, /value="dark"[^>]*>Dark/);
  assert.match(exampleHTML, /url=\.\.\/\.\.\/client\//u);
  assert.match(exampleHTML, /location\.replace\("\.\.\/\.\.\/client\/"\)/u);
  for (const token of ["canvas", "surface", "raised", "field", "text", "muted", "border", "accent", "status", "shadow"]) {
    assert.match(css, new RegExp(`--${token}:`), `missing semantic token --${token}`);
  }
  assert.match(css, /:root\[data-theme="light"\]/);
  assert.match(css, /:root\[data-theme="dark"\]/);
  assert.doesNotMatch(css, /#151924|101,84,207|123,97,255/);
});

test("appearance stays in memory and rejects the old plaintext browser preference", async () => {
  const controls = [new TestControl(), new TestControl()];
  const document = {
    documentElement: { dataset: {} },
    querySelectorAll(selector) {
      assert.equal(selector, "[data-appearance-select]");
      return controls;
    }
  };
  const values = new Map([["noctweavejs-appearance", "dark"]]);
  const mediaQuery = {
    matches: false,
    listeners: [],
    addEventListener(type, listener) {
      if (type === "change") this.listeners.push(listener);
    }
  };
  const previous = {
    document: globalThis.document,
    localStorage: globalThis.localStorage,
    matchMedia: globalThis.matchMedia
  };
  globalThis.document = document;
  globalThis.localStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: () => { throw new Error("appearance must not write plaintext storage"); },
    removeItem: () => { throw new Error("appearance must not delete developer data"); }
  };
  globalThis.matchMedia = () => mediaQuery;

  try {
    const { initializeAppearanceControl } = await import(`../client/theme.js?theme-dom=${Date.now()}`);
    assert.throws(() => initializeAppearanceControl(), /Legacy plaintext browser preferences/u);
    assert.equal(values.get("noctweavejs-appearance"), "dark");
    values.delete("noctweavejs-appearance"); // Explicit owner cleanup.
    initializeAppearanceControl();
    assert.equal(controls[0].value, "system");
    assert.equal(controls[1].value, "system");
    assert.equal(document.documentElement.dataset.theme, "light");

    controls[0].value = "light";
    controls[0].dispatch("change");
    assert.equal(values.size, 0);
    assert.equal(document.documentElement.dataset.theme, "light");
    assert.equal(controls[1].value, "light");

    controls[1].value = "system";
    controls[1].dispatch("change");
    mediaQuery.matches = true;
    for (const listener of mediaQuery.listeners) listener();
    assert.equal(document.documentElement.dataset.appearance, "system");
    assert.equal(document.documentElement.dataset.theme, "dark");
  } finally {
    globalThis.document = previous.document;
    globalThis.localStorage = previous.localStorage;
    globalThis.matchMedia = previous.matchMedia;
  }
});

class TestControl {
  constructor() {
    this.value = "system";
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  dispatch(type) {
    this.listeners.get(type)?.({ target: this });
  }
}
