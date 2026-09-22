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
      admissionLink(groupID)
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

const otherGroupID = "57364e86-d934-4f1e-9816-e18d76658bdb";

function admissionLink(targetGroupID) {
  return "noctweave-group-admission-v1:" + Buffer.from(JSON.stringify({
    version: 1,
    groupID: targetGroupID
  })).toString("base64");
}

test("admission rejects a different group before the CLI can commit membership", async () => {
  await withCompanion(async ({ companion }) => {
    let commands = 0;
    companion.executeCLI = async () => {
      commands += 1;
      return { stdout: JSON.stringify({ groupID: otherGroupID }) };
    };
    await assert.rejects(
      companion.acceptAdmissionRequest(groupID, admissionLink(otherGroupID)),
      /different group/u
    );
    assert.equal(commands, 0, "Group authorization must happen before any CLI side effect");
  });
});

test("wrong-group admission cannot be mislabeled as a durable maintenance recovery", async () => {
  await withCompanion(async ({ companion }) => {
    let commands = 0;
    companion.executeCLI = async (_cliPath, args) => {
      commands += 1;
      await writeFile(args[args.indexOf("--response-out") + 1], "noctweave-group-welcome-v1:other-group");
      throw new Error("relay maintenance failed after membership was committed");
    };
    await assert.rejects(
      companion.acceptAdmissionRequest(groupID, admissionLink(otherGroupID)),
      /different group/u
    );
    assert.equal(commands, 0);
  });
});

test("admission rejects ambiguous and malformed group links before launching the CLI", async () => {
  await withCompanion(async ({ companion }) => {
    let commands = 0;
    companion.executeCLI = async () => {
      commands += 1;
      return { stdout: JSON.stringify({ groupID }) };
    };
    const prefix = "noctweave-group-admission-v1:";
    const encode = (text) => prefix + Buffer.from(text).toString("base64");
    for (const link of [
      "invalid",
      prefix + "!!!!",
      encode(`{"version":1,"groupID":"${otherGroupID}","groupID":"${groupID}"}`),
      encode(`{"version":1,"groupID":"${otherGroupID}","group\\u0049D":"${groupID}"}`),
      encode(`{"version":2,"groupID":"${groupID}"}`),
      encode('{"version":1,"groupID":null}'),
      prefix + Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]).toString("base64")
    ]) {
      await assert.rejects(companion.acceptAdmissionRequest(groupID, link));
    }
    assert.equal(commands, 0);
  });
});

test("admission group comparison accepts uppercase protocol UUIDs", async () => {
  await withCompanion(async ({ companion }) => {
    companion.executeCLI = async (_cliPath, args) => {
      await writeFile(args[args.indexOf("--response-out") + 1], "noctweave-group-welcome-v1:durable");
      return { stdout: JSON.stringify({ groupID: groupID.toUpperCase() }) };
    };
    const result = await companion.acceptAdmissionRequest(groupID, admissionLink(groupID.toUpperCase()));
    assert.equal(result.groupID, groupID.toUpperCase());
  });
});
