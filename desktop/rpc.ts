import type { SecurityKeyRequest, SecurityKeyResult } from "./bun/security-key-host.js";
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

export type DesktopAttachmentExportAuthorization = {
  mimeType: string;
  byteCount: number;
  sha256: string;
};

export type DesktopAttachmentExportWrite = {
  token: string;
  bytesBase64: string;
};

export type NoctweaveDesktopRPC = {
  bun: RPCSchema<{
    requests: {
      securityKeyCapability: {
        params: Record<never, never>;
        response: { available: boolean; rpID: string; origin: string; continuousPresence: boolean };
      };
      securityKeyPresence: { params: Record<never, never>; response: { present: boolean; credentialID: string | null } };
      securityKeyAttachments: { params: Record<never, never>; response: { known: boolean; devices: string[] } };
      stopSecurityKeyAttachments: { params: Record<never, never>; response: { stopped: boolean } };
      releaseSecurityKeyPresence: { params: Record<never, never>; response: { released: boolean } };
      securityKeyRequest: { params: SecurityKeyRequest; response: SecurityKeyResult };
      cancelSecurityKeyRequest: { params: Record<never, never>; response: { cancelled: boolean } };
      loadPostQuantumWasm: {
        params: Record<never, never>;
        response: string;
      };
      relayFetch: {
        params: DesktopRelayRequest;
        response: DesktopRelayResponse;
      };
      authorizeAttachmentExport: {
        params: DesktopAttachmentExportAuthorization;
        response: { token: string | null };
      };
      writeAttachmentExport: {
        params: DesktopAttachmentExportWrite;
        response: { saved: true; fileName: string; byteCount: number };
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
