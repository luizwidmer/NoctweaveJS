export const unlockMethods = Object.freeze(["passphrase", "securityKey"]);

export function validateHiddenUnlockMethods(value) {
  if (!Array.isArray(value) || value.length > unlockMethods.length
    || new Set(value).size !== value.length || value.some((method) => !unlockMethods.includes(method))) {
    throw new Error("Invalid unlock-method visibility.");
  }
  return [...value].sort();
}

export function unlockFailureMessage(error, hiddenMethods) {
  // The failure surface must not reveal whether any additional factor exists.
  return "Unable to unlock. Try again.";
}
