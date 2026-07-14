import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";

const artifactDirectory = new URL("../../artifacts/", import.meta.url);
const target = process.env.NOCTWEAVE_DESKTOP_TARGET?.trim();

if (!target || !/^[a-z0-9-]{1,64}$/.test(target)) {
  throw new Error("NOCTWEAVE_DESKTOP_TARGET must be a bounded lowercase target name.");
}

const names = (await readdir(artifactDirectory))
  .filter((name) => !name.startsWith("SHA256SUMS-"))
  .sort();

if (names.length === 0) {
  throw new Error("No desktop artifacts were produced.");
}

const lines: string[] = [];
for (const name of names) {
  const bytes = await readFile(new URL(name, artifactDirectory));
  lines.push(`${createHash("sha256").update(Uint8Array.from(bytes)).digest("hex")}  ${name}`);
}

await writeFile(
  new URL(`SHA256SUMS-${target}.txt`, artifactDirectory),
  `${lines.join("\n")}\n`,
  { encoding: "utf8", mode: 0o644 }
);
