const APPEARANCE_STORAGE_KEY = "noctweavejs-appearance";
const APPEARANCES = new Set(["system", "light", "dark"]);

export function initializeAppearanceControl() {
  const control = document.querySelector("#appearancePreference");
  if (!control) return;

  const preference = readAppearancePreference();
  applyAppearance(preference);
  control.value = preference;
  control.addEventListener("change", () => {
    const nextPreference = APPEARANCES.has(control.value) ? control.value : "system";
    persistAppearancePreference(nextPreference);
    applyAppearance(nextPreference);
    control.value = nextPreference;
  });

  const mediaQuery = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  mediaQuery?.addEventListener?.("change", () => {
    if (control.value === "system") applyAppearance("system");
  });
}

function readAppearancePreference() {
  try {
    const saved = globalThis.localStorage?.getItem(APPEARANCE_STORAGE_KEY);
    return APPEARANCES.has(saved) ? saved : "system";
  } catch {
    return "system";
  }
}

function persistAppearancePreference(preference) {
  try {
    globalThis.localStorage?.setItem(APPEARANCE_STORAGE_KEY, preference);
  } catch {
    // Appearance is a convenience preference; an unavailable storage adapter
    // must never prevent the encrypted client from opening.
  }
}

function applyAppearance(preference) {
  const resolved = preference === "system" && globalThis.matchMedia?.("(prefers-color-scheme: dark)").matches
    ? "dark"
    : preference === "dark"
      ? "dark"
      : "light";
  document.documentElement.dataset.appearance = preference;
  document.documentElement.dataset.theme = resolved;
}
