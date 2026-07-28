import { randomUUID } from "node:crypto";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

const executeFile = promisify(execFile);
const maximumOutputBytes = 4 * 1024 * 1024;
const commandTimeoutMs = 300_000;

export class NoctweaveGroupCompanion {
  constructor({
    cliPath,
    statePath,
    plaintextForTesting = false,
    executeCLI = executeFile
  }) {
    this.cliPath = cliPath;
    this.statePath = statePath;
    this.plaintextForTesting = plaintextForTesting;
    this.executeCLI = executeCLI;
  }

  async capability() {
    try {
      await access(this.cliPath, fsConstants.X_OK);
      return {
        available: true,
        encryptedState: !this.plaintextForTesting,
        statePath: this.statePath
      };
    } catch {
      return {
        available: false,
        encryptedState: !this.plaintextForTesting,
        reason: "Build NoctweaveCLI or set NOCTWEAVE_CLI_PATH before using groups."
      };
    }
  }

  async status() {
    const capability = await this.capability();
    if (!capability.available) {
      return { ...capability, initialized: false, groups: [] };
    }
    try {
      const persona = await this.runJSON(["status"]);
      const groups = await this.runJSON(["groups"]);
      return { ...capability, initialized: true, persona, groups };
    } catch (error) {
      if (String(error?.message ?? error).includes("No state exists")) {
        return { ...capability, initialized: false, groups: [] };
      }
      throw error;
    }
  }

  async setup({ displayName, relay }) {
    const normalizedName = boundedText(displayName, "Display name", 1, 128);
    const normalizedRelay = boundedText(relay, "Relay", 1, 2_048);
    await this.runJSON([
      "init",
      "--display-name", normalizedName,
      "--relay", normalizedRelay,
      "--relay-name", "NoctweaveJS group companion",
      "--accept-privacy-policy", "true",
      "--accept-terms-of-use", "true"
    ]);
    return this.status();
  }

  async createGroup({ relay }) {
    const groupID = randomUUID();
    const normalizedRelay = boundedText(relay, "Relay", 1, 2_048);
    const result = await this.runJSON([
      "group-create",
      "--group", groupID,
      "--relay", normalizedRelay
    ]);
    return { ...result, groups: await this.runJSON(["groups"]) };
  }

  async groups() {
    return this.runJSON(["groups"]);
  }

  async syncAndReadEvents(groupID) {
    requireUUID(groupID);
    await this.runJSON([
      "group-maintain",
      "--group", groupID
    ], { acceptDurableStructuredFailure: true });
    await this.runJSON([
      "group-sync",
      "--group", groupID,
      "--max", "128",
      "--pages", "8"
    ]);
    return this.runJSON(["group-events", "--group", groupID]);
  }

  async readEvents(groupID) {
    requireUUID(groupID);
    return this.runJSON(["group-events", "--group", groupID]);
  }

  async sendMessage(groupID, text) {
    requireUUID(groupID);
    const value = boundedText(text, "Message", 1, 16_384);
    return this.withPrivateDirectory(async (directory) => {
      const messagePath = join(directory, "message.txt");
      await writeFile(messagePath, value, { encoding: "utf8", mode: 0o600, flag: "wx" });
      const result = await this.runJSON([
        "group-send",
        "--group", groupID,
        "--text-file", messagePath
      ]);
      return { ...result, events: await this.readEvents(groupID) };
    });
  }

  async acceptAdmissionRequest(groupID, requestLink) {
    requireUUID(groupID);
    const value = boundedText(requestLink, "Admission request", 1, 2 * 1024 * 1024);
    return this.withPrivateDirectory(async (directory) => {
      const requestPath = join(directory, "request.txt");
      const responsePath = join(directory, "response.txt");
      await writeFile(requestPath, value, { encoding: "utf8", mode: 0o600, flag: "wx" });
      let result;
      try {
        result = await this.runJSON([
          "group-link-add-member",
          "--request-file", requestPath,
          "--response-out", responsePath
        ], { acceptDurableStructuredFailure: true });
      } catch (error) {
        const durableResponse = await readFile(responsePath, "utf8").catch(() => "");
        if (!durableResponse.startsWith("noctweave-group-welcome-v1:")) {
          throw error;
        }
        return {
          groupID,
          responseLink: durableResponse,
          maintenanceComplete: false,
          maintenanceWarning: String(error?.message ?? error).slice(0, 2_048)
        };
      }
      if (String(result.groupID).toLowerCase() !== groupID.toLowerCase()) {
        throw new Error("The admission request targets a different group.");
      }
      const responseLink = await readFile(responsePath, "utf8");
      return { ...result, responseLink };
    });
  }

  async runJSON(argumentsList, { acceptDurableStructuredFailure = false } = {}) {
    const stateDirectory = dirname(this.statePath);
    await mkdir(stateDirectory, {
      recursive: true,
      mode: 0o700
    });
    await chmod(stateDirectory, 0o700);
    const stateArguments = ["--state", this.statePath];
    if (this.plaintextForTesting) {
      stateArguments.push("--plaintext", "true");
    }
    let stdout;
    try {
      ({ stdout } = await this.executeCLI(
        this.cliPath,
        [...argumentsList, ...stateArguments],
        {
          encoding: "utf8",
          timeout: commandTimeoutMs,
          maxBuffer: maximumOutputBytes,
          windowsHide: true
        }
      ));
    } catch (error) {
      const detail = String(
        String(error?.stderr ?? "").trim()
          || error?.message
          || "Group companion command failed"
      )
        .trim()
        .slice(0, 2_048);
      if (acceptDurableStructuredFailure && typeof error?.stdout === "string") {
        try {
          const durableResult = JSON.parse(error.stdout);
          return {
            ...durableResult,
            maintenanceComplete: false,
            maintenanceWarning: detail || "The durable result still needs relay maintenance."
          };
        } catch {
          // The command failed before writing a complete durable result.
        }
      }
      throw new Error(detail || "Group companion command failed");
    }
    try {
      return JSON.parse(stdout);
    } catch {
      throw new Error("NoctweaveCLI returned an invalid structured response.");
    }
  }

  async withPrivateDirectory(operation) {
    const directory = await mkdtemp(join(tmpdir(), "noctweave-group-"));
    await chmod(directory, 0o700);
    try {
      return await operation(directory);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
}

function boundedText(value, label, minimum, maximum) {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be text.`);
  }
  const normalized = value.trim();
  const length = Buffer.byteLength(normalized, "utf8");
  if (length < minimum || length > maximum) {
    throw new RangeError(`${label} must contain between ${minimum} and ${maximum} UTF-8 bytes.`);
  }
  return normalized;
}

function requireUUID(value) {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) {
    throw new TypeError("Group ID must be a UUID.");
  }
}
