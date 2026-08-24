import { tmpdir } from "node:os";
import { isAbsolute, join, normalize, resolve, sep } from "node:path";
import { startDesktopApplication } from "./application.js";
import { DesktopRelationshipStateStore } from "./relationship-state-store.js";
import { UITestFileVault } from "./ui-test-file-vault.js";

const stateRoot = validatedStateRoot(process.env.NOCTWEAVE_UI_TEST_STATE_ROOT);

await startDesktopApplication({
  relationshipStateStore: new DesktopRelationshipStateStore({
    rootDirectory: join(stateRoot, "encrypted-state"),
    secureVault: new UITestFileVault(join(stateRoot, "insecure-test-anchors")),
    capability: {
      available: true,
      kind: "insecure-ui-test-file-anchor",
      reason: null
    }
  }),
  title: "NoctweaveJS UI Test"
});

function validatedStateRoot(value: string | undefined) {
  if (!value || !isAbsolute(value)) {
    throw new Error("NOCTWEAVE_UI_TEST_STATE_ROOT must be an absolute temporary path.");
  }
  const root = normalize(resolve(value));
  const allowedPrefixes = [
    join(resolve("/private/tmp"), "noctweavejs-ui-test-"),
    join(resolve(tmpdir()), "noctweavejs-ui-test-")
  ];
  if (!allowedPrefixes.some((prefix) => root.startsWith(prefix) && root.length > prefix.length)) {
    throw new Error("NoctweaveJS UI-test state must stay in a dedicated temporary directory.");
  }
  if (root.includes(`${sep}..${sep}`)) {
    throw new Error("NoctweaveJS UI-test state path is invalid.");
  }
  return root;
}
