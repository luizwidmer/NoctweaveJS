import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { NoctweaveGroupCompanion } from "../examples/browser-client/group-companion.js";

const groupID = "3f770ad9-4cea-41f0-a626-6d9e04796484";

test("admission returns a durably written Welcome when relay maintenance fails", async () => {
  await withCompanion(async ({ companion }) => {
    companion.executeCLI = async (_cliPath, argumentsList) => {
      const responseIndex = argumentsList.indexOf("--response-out");
      assert.notEqual(responseIndex, -1);
      await writeFile(
        argumentsList[responseIndex + 1],
        "noctweave-group-welcome-v1:durable",
        "utf8"
      );
      const error = new Error("relay maintenance timed out");
      error.stderr = "";
      throw error;
    };

    const result = await companion.acceptAdmissionRequest(
      groupID,
      "noctweave-group-admission-v1:request"
    );

    assert.equal(result.groupID, groupID);
    assert.equal(result.responseLink, "noctweave-group-welcome-v1:durable");
    assert.equal(result.maintenanceComplete, false);
    assert.match(result.maintenanceWarning, /relay maintenance timed out/u);
  });
});

test("empty stderr does not hide the companion command error", async () => {
  await withCompanion(async ({ companion }) => {
    companion.executeCLI = async () => {
      const error = new Error("command exceeded its deadline");
      error.stderr = "";
      throw error;
    };

    await assert.rejects(
      companion.runJSON(["status"]),
      /command exceeded its deadline/u
    );
  });
});

test("group synchronization maintains routes before fetching messages", async () => {
  await withCompanion(async ({ companion }) => {
    const commands = [];
    companion.executeCLI = async (_cliPath, argumentsList) => {
      commands.push(argumentsList[0]);
      if (argumentsList[0] === "group-events") {
        return { stdout: JSON.stringify([{ kind: "message", text: "hello" }]) };
      }
      return { stdout: JSON.stringify({ ok: true }) };
    };

    const events = await companion.syncAndReadEvents(groupID);

    assert.deepEqual(commands, ["group-maintain", "group-sync", "group-events"]);
    assert.deepEqual(events, [{ kind: "message", text: "hello" }]);
  });
});

async function withCompanion(operation) {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-group-test-"));
  try {
    const companion = new NoctweaveGroupCompanion({
      cliPath: join(directory, "NoctweaveCLI"),
      statePath: join(directory, "state", "client.json"),
      plaintextForTesting: true
    });
    await operation({ companion, directory });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
