import type { RPCSchema } from "electrobun/bun";

export type DesktopRelayRequest = {
  endpoint: string;
  body: string;
};

export type DesktopRelayResponse = {
  status: number;
  contentType: string;
  body: string;
};

export type DesktopRelationshipStateCapability = {
  available: boolean;
  kind: string;
  reason: string | null;
};

export type DesktopRelationshipStateAnchor = {
  version: 2;
  relationshipID: string;
  generation: number;
  stateDigest: string;
  authenticationTag: string;
};

export type DesktopRelationshipStateScope = {
  relationshipID: string;
};

export type NoctweaveDesktopRPC = {
  bun: RPCSchema<{
    requests: {
      loadPostQuantumWasm: {
        params: Record<never, never>;
        response: string;
      };
      relayFetch: {
        params: DesktopRelayRequest;
        response: DesktopRelayResponse;
      };
      relationshipStateCapability: {
        params: Record<never, never>;
        response: DesktopRelationshipStateCapability;
      };
      relationshipStateErasureStatus: {
        params: DesktopRelationshipStateScope;
        response: { erased: boolean };
      };
      loadRelationshipState: {
        params: DesktopRelationshipStateScope;
        response: {
          anchor: DesktopRelationshipStateAnchor | null;
          encryptedRecord: unknown | null;
        };
      };
      commitRelationshipState: {
        params: DesktopRelationshipStateScope & {
          expectedAnchor: DesktopRelationshipStateAnchor | null;
          nextGeneration: number;
          nextStateDigest: string;
          encryptedRecord: unknown;
        };
        response: DesktopRelationshipStateAnchor;
      };
      destroyRelationshipState: {
        params: DesktopRelationshipStateScope & {
          expectedAnchor: DesktopRelationshipStateAnchor | null;
        };
        response: { destroyed: true };
      };
    };
    messages: Record<never, never>;
  }>;
  webview: RPCSchema<{
    requests: Record<never, never>;
    messages: Record<never, never>;
  }>;
};
