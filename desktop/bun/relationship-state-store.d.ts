import type {
  DesktopRelationshipStateAnchor,
  DesktopRelationshipStateCapability,
  DesktopRelationshipStateScope
} from "../rpc.js";

export const desktopRelationshipStateCapability: Readonly<DesktopRelationshipStateCapability>;

export class MacOSKeychainVault {
  constructor(options?: { securityPath?: string });
  get(scope: { service: string; account: string }): Promise<string | null>;
  set(scope: { service: string; account: string; value: string }): Promise<void>;
  delete(scope: { service: string; account: string }): Promise<void>;
}

export class DesktopRelationshipStateStore {
  constructor(options?: {
    rootDirectory?: string;
    secureVault?: MacOSKeychainVault;
    capability?: DesktopRelationshipStateCapability;
    faultInjector?: ((stage: string, scope: unknown) => Promise<void> | void) | null;
  });
  capabilityReport(): Readonly<DesktopRelationshipStateCapability>;
  erasureStatus(scope: DesktopRelationshipStateScope): Promise<{ erased: boolean }>;
  load(scope: DesktopRelationshipStateScope): Promise<{
    anchor: DesktopRelationshipStateAnchor | null;
    encryptedRecord: unknown | null;
  }>;
  commit(scope: DesktopRelationshipStateScope & {
    expectedAnchor: DesktopRelationshipStateAnchor | null;
    nextGeneration: number;
    nextStateDigest: string;
    encryptedRecord: unknown;
  }): Promise<DesktopRelationshipStateAnchor>;
  destroy(scope: DesktopRelationshipStateScope & {
    expectedAnchor: DesktopRelationshipStateAnchor | null;
  }): Promise<{ destroyed: true }>;
}

export function relationshipStateScope(
  scope: DesktopRelationshipStateScope,
  options?: { rootDirectory?: string }
): unknown;
