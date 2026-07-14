import type { RPCSchema } from "electrobun/bun";

export type DesktopRelayRoute = "health" | "relay";

export type DesktopRelayRequest = {
  endpoint: string;
  route: DesktopRelayRoute;
  body?: string;
};

export type DesktopRelayResponse = {
  status: number;
  contentType: string;
  body: string;
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
    };
    messages: Record<never, never>;
  }>;
  webview: RPCSchema<{
    requests: Record<never, never>;
    messages: Record<never, never>;
  }>;
};
