// The host that starts desktop commands also handles package and build inputs.
// `engines.bun` is advisory, so reject older hosts before Electrobun runs.
export function requirePatchedBun(version = process.versions.bun): void {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version ?? "");
  const parts = match?.slice(1).map(Number);
  const patched = parts !== undefined
    && (parts[0]! > 1 || (parts[0] === 1
      && (parts[1]! > 4 || (parts[1] === 4 && parts[2]! >= 4))));
  if (!patched) {
    throw new Error(`Noctweave desktop commands require Bun 1.4.4 or newer; found ${version ?? "none"}.`);
  }
}
