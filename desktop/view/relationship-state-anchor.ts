import type {
  DesktopRelationshipStateAnchor,
  DesktopRelationshipStateCapability,
  DesktopRelationshipStateScope,
  NoctweaveDesktopRPC
} from "../rpc.js";

type DesktopRequests = {
  relationshipStateCapability(params: Record<never, never>): Promise<DesktopRelationshipStateCapability>;
  relationshipStateErasureStatus(params: DesktopRelationshipStateScope): Promise<{ erased: boolean }>;
  loadRelationshipState(params: DesktopRelationshipStateScope): Promise<{
    anchor: DesktopRelationshipStateAnchor | null;
    encryptedRecord: unknown | null;
  }>;
  commitRelationshipState(params: DesktopRelationshipStateScope & {
    expectedAnchor: DesktopRelationshipStateAnchor | null;
    nextGeneration: number;
    nextStateDigest: string;
    encryptedRecord: unknown;
  }): Promise<DesktopRelationshipStateAnchor>;
  destroyRelationshipState(params: DesktopRelationshipStateScope & {
    expectedAnchor: DesktopRelationshipStateAnchor | null;
  }): Promise<{ destroyed: true }>;
};

type AnchorRuntimeLoad = {
  anchorKey: string;
  relationshipID: string;
  loadEncryptedState(): Promise<unknown | null>;
};

type AnchorRuntimeCommit = {
  anchorKey: string;
  relationshipID: string;
  expectedAnchor: DesktopRelationshipStateAnchor | null;
  nextGeneration: number;
  nextStateDigest: string;
  persistEncryptedState(): Promise<unknown>;
};

type AnchorRuntimeDestroy = {
  anchorKey: string;
  relationshipID: string;
  expectedAnchor: DesktopRelationshipStateAnchor | null;
  destroyEncryptedState(): Promise<unknown>;
};

const unset = Symbol("unset desktop encrypted record");

/**
 * Bridges the WebView encryption boundary to one host-side crash journal.
 * The Bun host sees only the relationship ID needed to bind the fixed-app
 * erasure scope plus EncryptedNoctweaveStore envelopes. URL profiles, browser
 * storage keys, message content, the passphrase, the derived AES key, and
 * decrypted protocol state never cross RPC. This is a local encryption
 * boundary, not anonymity from the desktop host.
 */
export class DesktopRelationshipStateAnchorStore {
  readonly encryptedStateStoreBackend: {
    get(key: string): Promise<unknown | null>;
    set(key: string, value: unknown): Promise<void>;
    delete(key: string): Promise<void>;
  };

  private readonly requests: DesktopRequests;
  private readonly scope: DesktopRelationshipStateScope;
  private readonly anchorKey: string;
  private readonly stateKey: string;
  private readRecord: unknown | null | typeof unset = unset;
  private stagedRecord: unknown | typeof unset = unset;
  private stage: "commit" | "destroy" | null = null;

  constructor({
    requests,
    relationshipID,
    anchorKey,
    stateKey
  }: {
    requests: DesktopRequests;
    relationshipID: string;
    anchorKey: string;
    stateKey: string;
  }) {
    this.requests = requests;
    this.scope = Object.freeze({ relationshipID });
    this.anchorKey = anchorKey;
    this.stateKey = stateKey;
    this.encryptedStateStoreBackend = Object.freeze({
      get: (key: string) => this.getEncryptedRecord(key),
      set: (key: string, value: unknown) => this.stageEncryptedRecord(key, value),
      delete: (key: string) => this.stageEncryptedDeletion(key)
    });
  }

  async load({ anchorKey, relationshipID, loadEncryptedState }: AnchorRuntimeLoad) {
    this.requireScope(anchorKey, relationshipID);
    if (typeof loadEncryptedState !== "function" || this.stage !== null) {
      throw new Error("Desktop relationship-state load is not serializable.");
    }
    const snapshot = await this.requests.loadRelationshipState(this.scope);
    this.readRecord = snapshot.encryptedRecord === null
      ? null
      : structuredClone(snapshot.encryptedRecord);
    try {
      const state = await loadEncryptedState();
      return Object.freeze({ anchor: snapshot.anchor, state });
    } finally {
      this.readRecord = unset;
    }
  }

  async erasureStatus({ anchorKey, relationshipID }: {
    anchorKey: string;
    relationshipID: string;
  }) {
    this.requireScope(anchorKey, relationshipID);
    const status = await this.requests.relationshipStateErasureStatus(this.scope);
    if (!status || typeof status.erased !== "boolean" || Object.keys(status).length !== 1) {
      throw new Error("Desktop relationship erasure status is malformed.");
    }
    return Object.freeze({ erased: status.erased });
  }

  async commit({
    anchorKey,
    relationshipID,
    expectedAnchor,
    nextGeneration,
    nextStateDigest,
    persistEncryptedState
  }: AnchorRuntimeCommit) {
    this.requireScope(anchorKey, relationshipID);
    if (typeof persistEncryptedState !== "function" || this.stage !== null) {
      throw new Error("Desktop relationship-state commit is not serializable.");
    }
    this.stage = "commit";
    this.stagedRecord = unset;
    try {
      await persistEncryptedState();
      if (this.stagedRecord === unset) {
        throw new Error("Encrypted relationship state was not staged for atomic commit.");
      }
      return await this.requests.commitRelationshipState({
        ...this.scope,
        expectedAnchor,
        nextGeneration,
        nextStateDigest,
        encryptedRecord: structuredClone(this.stagedRecord)
      });
    } finally {
      this.stagedRecord = unset;
      this.stage = null;
    }
  }

  async destroy({
    anchorKey,
    relationshipID,
    expectedAnchor,
    destroyEncryptedState
  }: AnchorRuntimeDestroy) {
    this.requireScope(anchorKey, relationshipID);
    if (typeof destroyEncryptedState !== "function" || this.stage !== null) {
      throw new Error("Desktop relationship-state destruction is not serializable.");
    }
    this.stage = "destroy";
    this.stagedRecord = unset;
    try {
      await destroyEncryptedState();
      if (this.stagedRecord !== null) {
        throw new Error("Encrypted relationship state was not staged for atomic destruction.");
      }
      return await this.requests.destroyRelationshipState({
        ...this.scope,
        expectedAnchor
      });
    } finally {
      this.stagedRecord = unset;
      this.stage = null;
    }
  }

  private async getEncryptedRecord(key: string) {
    this.requireStateKey(key);
    if (this.readRecord === unset || this.stage !== null) {
      throw new Error("Desktop encrypted relationship state may only load inside anchor.load(...).");
    }
    return this.readRecord === null ? null : structuredClone(this.readRecord);
  }

  private async stageEncryptedRecord(key: string, value: unknown) {
    this.requireStateKey(key);
    if (this.stage !== "commit" || this.stagedRecord !== unset) {
      throw new Error("Desktop encrypted relationship state write escaped atomic anchor commit.");
    }
    this.stagedRecord = structuredClone(value);
  }

  private async stageEncryptedDeletion(key: string) {
    this.requireStateKey(key);
    if (this.stage !== "destroy" || this.stagedRecord !== unset) {
      throw new Error("Desktop encrypted relationship state deletion escaped atomic anchor destruction.");
    }
    this.stagedRecord = null;
  }

  private requireScope(anchorKey: string, relationshipID: string) {
    if (anchorKey !== this.anchorKey || relationshipID !== this.scope.relationshipID) {
      throw new Error("Desktop relationship anchor scope changed after construction.");
    }
  }

  private requireStateKey(key: string) {
    if (key !== this.stateKey) {
      throw new Error("Desktop encrypted relationship state key is outside its anchor scope.");
    }
  }
}

export async function installDesktopRelationshipStateAnchorFactory({
  requests
}: {
  requests: DesktopRequests;
}) {
  const capability = await requests.relationshipStateCapability({});
  if (capability.available !== true) return capability;
  globalThis.noctweaveRelationshipStateAnchorStoreFactory = async ({
    relationshipID,
    anchorKey,
    stateKey
  }) => new DesktopRelationshipStateAnchorStore({
    requests,
    relationshipID,
    anchorKey,
    stateKey
  });
  return capability;
}

declare global {
  var noctweaveRelationshipStateAnchorStoreFactory: ((scope: {
    relationshipID: string;
    anchorKey: string;
    stateKey: string;
  }) => Promise<DesktopRelationshipStateAnchorStore>) | undefined;
}

// Retain the imported schema in generated declaration output.
export type DesktopNoctweaveRPC = NoctweaveDesktopRPC;
