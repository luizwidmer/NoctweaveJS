import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";

export type SecurityKeyRequest = { operation: "create" | "get"; options: Record<string, unknown>; pin: string };
export type SecurityKeyResult = { credential?: unknown; error?: string; message?: string; presenceToken?: string };

/** A single bounded child over inherited pipes. No shell, persistent secrets, or remote origins. */
export class DesktopSecurityKeyHost {
  private active: ChildProcessWithoutNullStreams | null = null;
  private presenceProcess: ChildProcessWithoutNullStreams | null = null;
  private presentCredential: string | null = null;
  private presenceGeneration = 0;
  private presenceConfirmedAt = 0;
  private attachmentProcess: ChildProcessWithoutNullStreams | null = null;
  private attachedDevices: string[] = [];
  private attachmentConfirmedAt = 0;
  private attachmentIdleTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly executable: string;
  constructor(executable: string) { this.executable = executable; }

  capability() {
    return { available: process.platform === "darwin" && existsSync(this.executable),
      continuousPresence: process.platform === "darwin",
      rpID: "noctweavejs-app-lock.invalid", origin: "https://noctweavejs-app-lock.invalid" };
  }

  cancel() {
    this.active?.kill("SIGTERM");
    return { cancelled: true };
  }

  attachmentStatus() {
    if (!this.capability().available) return { known: false, devices: [] };
    if (!this.attachmentProcess) this.watchAttached();
    if (this.attachmentIdleTimer) clearTimeout(this.attachmentIdleTimer);
    this.attachmentIdleTimer = setTimeout(() => this.stopWatchingAttached(), 3_000);
    const age = Date.now() - this.attachmentConfirmedAt;
    const known = this.attachmentConfirmedAt > 0 && age >= 0 && age < 1_500;
    return { known, devices: known ? [...this.attachedDevices] : [] };
  }

  stopWatchingAttached() {
    const child = this.attachmentProcess;
    this.attachmentProcess = null;
    this.attachedDevices = [];
    this.attachmentConfirmedAt = 0;
    if (this.attachmentIdleTimer) clearTimeout(this.attachmentIdleTimer);
    this.attachmentIdleTimer = null;
    child?.kill("SIGTERM");
    return { stopped: true };
  }

  private watchAttached() {
    const child = spawn(this.executable, [], { stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/bin:/bin", LANG: "en_US.UTF-8" } });
    this.attachmentProcess = child;
    let buffer = "";
    const stopped = () => { if (this.attachmentProcess === child) this.stopWatchingAttached(); };
    child.stdout.on("data", (data: Buffer) => {
      if (this.attachmentProcess !== child) return;
      buffer += data.toString("utf8");
      if (buffer.length > 4_096) { stopped(); return; }
      while (buffer.includes("\n")) {
        const index = buffer.indexOf("\n");
        const line = buffer.slice(0, index); buffer = buffer.slice(index + 1);
        try {
          const value = JSON.parse(line);
          if (Object.keys(value).join(",") !== "devices" || !Array.isArray(value.devices)
            || value.devices.length > 32 || new Set(value.devices).size !== value.devices.length
            || value.devices.some((token: unknown) => typeof token !== "string" || !/^[1-9][0-9]{0,19}$/.test(token))) throw new Error();
          this.attachedDevices = value.devices;
          this.attachmentConfirmedAt = Date.now();
        } catch { stopped(); return; }
      }
    });
    child.stderr.on("data", (data: Buffer) => data.fill(0));
    child.on("close", stopped); child.on("error", stopped); child.stdin.on("error", stopped);
    child.stdin.end(JSON.stringify({ operation: "watch-attached", options: {} }));
  }

  presenceStatus() {
    const age = Date.now() - this.presenceConfirmedAt;
    // A silent, suspended, or wedged helper cannot keep a session authorized.
    if (this.presentCredential !== null && (age < 0 || age > 1_000)) this.releasePresence();
    return { present: this.presentCredential !== null, credentialID: this.presentCredential };
  }

  releasePresence() {
    this.presenceGeneration++;
    this.presentCredential = null;
    this.presenceConfirmedAt = 0;
    this.presenceProcess?.kill("SIGTERM");
    this.presenceProcess = null;
    return { released: true };
  }

  private async watchPresence(token: string, credentialID: string) {
    this.releasePresence();
    if (!/^[1-9][0-9]{0,19}$/.test(token) || credentialID.length > 1_366) return;
    const generation = this.presenceGeneration;
    const child = spawn(this.executable, [], { stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/bin:/bin", LANG: "en_US.UTF-8" } });
    this.presenceProcess = child;
    await new Promise<void>((resolve) => {
      let buffer = "";
      let ended = false;
      const readyTimeout = setTimeout(() => { child.kill("SIGTERM"); resolve(); }, 3_000);
      const stopped = () => {
        ended = true;
        clearTimeout(readyTimeout);
        if (this.presenceGeneration === generation) this.presentCredential = null;
        resolve();
      };
      child.stdout.on("data", (data: Buffer) => {
        if (ended) return;
        buffer += data.toString("utf8");
        if (buffer.length > 256) { child.kill("SIGTERM"); stopped(); return; }
        while (buffer.includes("\n")) {
          const index = buffer.indexOf("\n");
          const line = buffer.slice(0, index); buffer = buffer.slice(index + 1);
          try {
            const value = JSON.parse(line);
            if (Object.keys(value).join(",") !== "present" || typeof value.present !== "boolean") throw new Error();
            if (generation === this.presenceGeneration) {
              this.presentCredential = value.present ? credentialID : null;
              this.presenceConfirmedAt = value.present ? Date.now() : 0;
            }
            clearTimeout(readyTimeout); resolve();
            if (!value.present) { child.kill("SIGTERM"); stopped(); return; }
          } catch { child.kill("SIGTERM"); stopped(); }
        }
      });
      child.stderr.on("data", (data: Buffer) => data.fill(0));
      child.on("close", stopped); child.on("error", stopped); child.stdin.on("error", stopped);
      child.stdin.end(JSON.stringify({ operation: "watch-presence", options: { registryEntryID: token } }));
    });
  }

  async request(request: SecurityKeyRequest): Promise<SecurityKeyResult> {
    if (!this.capability().available) throw new Error("Hardware keys are unavailable in this desktop build.");
    if (this.active) throw new Error("A security key request is already running.");
    if (!request || Object.keys(request).sort().join(",") !== "operation,options,pin"
      || !["create", "get"].includes(request.operation) || typeof request.pin !== "string"
      || Buffer.byteLength(request.pin) > 63 || !request.options || Array.isArray(request.options)) {
      throw new Error("Invalid security key request.");
    }
    let input = JSON.stringify(request);
    if (Buffer.byteLength(input) > 65_536) throw new Error("Security key request is too large.");
    const child = spawn(this.executable, [], { stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/bin:/bin", LANG: "en_US.UTF-8" } });
    this.active = child;
    try {
      const result = await new Promise<SecurityKeyResult>((resolve, reject) => {
        const output = new Uint8Array(131_072);
        let outputLength = 0;
        let settled = false;
        const finish = (error?: Error, result?: SecurityKeyResult) => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          output.fill(0);
          if (error) reject(error); else resolve(result!);
        };
        const timeout = setTimeout(() => {
          child.kill("SIGTERM");
          finish(new Error("Security key request timed out."));
        }, 60_000);
        child.stdout.on("data", (data: Buffer) => {
          if (settled) return;
          if (outputLength + data.length > output.length) {
            child.kill("SIGTERM"); finish(new Error("Invalid security key response.")); return;
          }
          output.set(Uint8Array.from(data), outputLength);
          outputLength += data.length;
        });
        // SDK diagnostics must never be forwarded to logs or the page.
        child.stderr.on("data", (data: Buffer) => { data.fill(0); });
        child.stdin.on("error", () => finish(new Error("The security key connection closed.")));
        child.on("error", () => finish(new Error("The security key helper could not start.")));
        child.on("close", (code) => {
          if (settled) return;
          if (code !== 0) { finish(new Error("Security key request was cancelled.")); return; }
          try {
            const result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(output.subarray(0, outputLength)));
            if (!result || typeof result !== "object" || (!result.credential && typeof result.error !== "string")) {
              throw new Error();
            }
            finish(undefined, result);
          } catch { finish(new Error("Invalid security key response.")); }
        });
        child.stdin.end(input);
        input = "";
      });
      const credential = result.credential as { id?: unknown } | undefined;
      if (request.operation === "get" && typeof result.presenceToken === "string" && typeof credential?.id === "string") {
        await this.watchPresence(result.presenceToken, credential.id);
      }
      delete result.presenceToken;
      return result;
    } finally {
      input = "";
      child.kill("SIGTERM");
      this.active = null;
    }
  }
}
