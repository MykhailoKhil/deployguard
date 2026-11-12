const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const script = fs.readFileSync(path.join(__dirname, "theme.js"), "utf8");

function renderTheme(initialValue, storageAvailable = true) {
  const root = { dataset: {} };
  const button = {
    hidden: true,
    setAttribute(name, value) { this[name] = value; },
    addEventListener(name, callback) { this[name] = callback; },
  };
  let value = initialValue;
  const document = {
    documentElement: root,
    querySelector() { return button; },
    addEventListener(name, callback) { this[name] = callback; },
  };
  const localStorage = {
    getItem() {
      if (!storageAvailable) throw new Error("storage unavailable");
      return value;
    },
    setItem(key, nextValue) {
      assert.equal(key, "deployguard-theme");
      if (!storageAvailable) throw new Error("storage unavailable");
      value = nextValue;
    },
  };
  vm.runInNewContext(script, { document, localStorage });
  document.DOMContentLoaded();
  return { root, button, stored: () => value };
}

test("defaults to dark and persists both toggle choices", () => {
  const page = renderTheme(null);
  assert.notEqual(page.root.dataset.theme, "light");
  assert.equal(page.button.hidden, false);
  assert.equal(page.button["aria-label"], "Switch to light theme");
  page.button.click();
  assert.equal(page.root.dataset.theme, "light");
  assert.equal(page.stored(), "light");
  assert.equal(page.button["aria-label"], "Switch to dark theme");
  page.button.click();
  assert.equal(page.root.dataset.theme, "dark");
  assert.equal(page.stored(), "dark");
});

test("restores light mode and rejects unknown stored values", () => {
  assert.equal(renderTheme("light").root.dataset.theme, "light");
  assert.notEqual(renderTheme("invalid").root.dataset.theme, "light");
});

test("allows switching when browser storage is unavailable", () => {
  const page = renderTheme(null, false);
  page.button.click();
  assert.equal(page.root.dataset.theme, "light");
  assert.equal(page.button["aria-label"], "Switch to dark theme");
});
