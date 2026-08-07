const APPEARANCE_STORAGE_KEY = "noctweavejs-appearance";
const APPEARANCES = new Set(["system", "light", "dark"]);

export function initializeAppearanceControl() {
  const controls = [...document.querySelectorAll("[data-appearance-select]")];
  if (controls.length === 0) return;

  const preference = readAppearancePreference();
  applyAppearance(preference);
  synchronizeControls(preference);
  for (const control of controls) {
    control.addEventListener("change", () => {
      const nextPreference = APPEARANCES.has(control.value) ? control.value : "system";
      persistAppearancePreference(nextPreference);
      applyAppearance(nextPreference);
      synchronizeControls(nextPreference);
    });
  }

  const mediaQuery = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  mediaQuery?.addEventListener?.("change", () => {
    if (controls[0]?.value === "system") applyAppearance("system");
  });

  function synchronizeControls(nextPreference) {
    for (const control of controls) control.value = nextPreference;
  }
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
