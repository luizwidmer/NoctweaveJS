import { startDesktopApplication } from "./application.js";
import { DesktopRelationshipStateStore } from "./relationship-state-store.js";

await startDesktopApplication({
  relationshipStateStore: new DesktopRelationshipStateStore(),
  title: "NoctweaveJS"
});
