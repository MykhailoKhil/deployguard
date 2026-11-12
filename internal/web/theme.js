(() => {
  const root = document.documentElement;
  const storageKey = "deployguard-theme";
  try {
    if (localStorage.getItem(storageKey) === "light") root.dataset.theme = "light";
  } catch (_) {
  }

  document.addEventListener("DOMContentLoaded", () => {
    const button = document.querySelector(".theme-toggle");
    if (!button) return;
    const updateButton = () => {
      const light = root.dataset.theme === "light";
      button.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
      button.textContent = light ? "☾ Dark" : "☀ Light";
    };
    updateButton();
    button.hidden = false;
    button.addEventListener("click", () => {
      const theme = root.dataset.theme === "light" ? "dark" : "light";
      root.dataset.theme = theme;
      try {
        localStorage.setItem(storageKey, theme);
      } catch (_) {
      }
      updateButton();
    });
  });

  // Give feedback while a plan uploads and analyzes, and block double submits.
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!form || !form.querySelectorAll || !form.dataset) return;
    if (form.dataset.busy === "1") {
      event.preventDefault();
      return;
    }
    form.dataset.busy = "1";
    form.setAttribute("aria-busy", "true");
    // Disable after the submission has started: disabling synchronously can
    // cancel it in some browsers.
    setTimeout(() => {
      for (const button of form.querySelectorAll("button")) {
        const label = button.querySelector ? button.querySelector(".button-label") : null;
        if (label && form.dataset.busyLabel) {
          label.dataset.original = label.textContent;
          label.textContent = form.dataset.busyLabel;
        }
        button.disabled = true;
      }
    }, 0);
  });

  // Restore forms when the page is shown again from the back/forward cache.
  if (typeof window !== "undefined") window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    for (const form of document.querySelectorAll("form[data-busy]")) {
      delete form.dataset.busy;
      form.removeAttribute("aria-busy");
      for (const button of form.querySelectorAll("button")) {
        button.disabled = false;
        const label = button.querySelector(".button-label");
        if (label && label.dataset.original) label.textContent = label.dataset.original;
      }
    }
  });
})();
