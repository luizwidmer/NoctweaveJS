const APPEARANCE_STORAGE_KEY = "noctweavejs-appearance";
const APPEARANCES = new Set(["system", "light", "dark"]);

export function initializeAppearanceControl() {
  rejectLegacyPlaintextPreference(APPEARANCE_STORAGE_KEY);
  const controls = [...document.querySelectorAll("[data-appearance-select]")];
  if (controls.length === 0) return;

  // The theme is deliberately session-only: even a public preference must not
  // create a plaintext browser-storage record outside the encrypted profile.
  const preference = "system";
  applyAppearance(preference);
  synchronizeControls(preference);
  for (const control of controls) {
    control.addEventListener("change", () => {
      const nextPreference = APPEARANCES.has(control.value) ? control.value : "system";
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

export function rejectLegacyPlaintextPreference(key) {
  let exists = false;
  try { exists = globalThis.localStorage?.getItem(key) != null; } catch { return; }
  if (!exists) return;
  const message = "Legacy plaintext browser preferences were found. Clear this site's local storage in browser settings before continuing.";
  document.body?.replaceChildren?.(document.createTextNode(message));
  throw new Error(message);
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
