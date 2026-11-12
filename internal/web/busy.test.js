const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const script = fs.readFileSync(path.join(__dirname, "theme.js"), "utf8");

function setup() {
  const listeners = {};
  const label = { textContent: "Analyze plan", dataset: {} };
  const button = { disabled: false, querySelector: () => label };
  const attributes = {};
  const form = {
    dataset: { busyLabel: "Analyzing…" },
    querySelectorAll: () => [button],
    setAttribute(name, value) { attributes[name] = value; },
  };
  const document = {
    documentElement: { dataset: {} },
    querySelector: () => null,
    addEventListener(name, callback) { listeners[name] = callback; },
  };
  let timer;
  vm.runInNewContext(script, { document, localStorage: { getItem: () => null, setItem() {} }, setTimeout: (callback) => { timer = callback; } });
  return { listeners, form, button, label, attributes, flush: () => timer() };
}

test("submitting shows a busy label and disables the button", () => {
  const page = setup();
  let prevented = false;
  page.listeners.submit({ target: page.form, preventDefault() { prevented = true; } });
  assert.equal(prevented, false);
  assert.equal(page.attributes["aria-busy"], "true");
  assert.equal(page.button.disabled, false, "disabling must wait until the submission has started");
  page.flush();
  assert.equal(page.button.disabled, true);
  assert.equal(page.label.textContent, "Analyzing…");
});

test("a second submit while busy is ignored", () => {
  const page = setup();
  page.listeners.submit({ target: page.form, preventDefault() {} });
  let prevented = false;
  page.listeners.submit({ target: page.form, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
});
