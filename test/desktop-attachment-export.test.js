import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  DesktopAttachmentExporter,
  maximumDesktopAttachmentExportBytes
} from "../desktop/bun/attachment-export.ts";

test("desktop attachment export requires approval, revalidates bytes, and refuses overwrite", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-attachment-export-"));
  try {
    const bytes = Buffer.from("verified Noctweave attachment\n", "utf8");
    const sha256 = createHash("sha256").update(bytes).digest("base64");
    const exporter = new DesktopAttachmentExporter({
      selectDirectory: async () => directory
    });
    const authorization = await exporter.authorize({
      mimeType: "text/plain",
      byteCount: bytes.byteLength,
      sha256
    });
    assert.equal(typeof authorization.token, "string");

    const first = await exporter.write({
      token: authorization.token,
      bytesBase64: bytes.toString("base64")
    });
    assert.deepEqual(first, {
      saved: true,
      fileName: "noctweave-attachment.txt",
      byteCount: bytes.byteLength
    });
    assert.deepEqual(await readFile(join(directory, first.fileName)), bytes);
    assert.equal((await lstat(join(directory, first.fileName))).mode & 0o777, 0o600);
    await assert.rejects(
      () => exporter.write({
        token: authorization.token,
        bytesBase64: bytes.toString("base64")
      }),
      /missing or expired/
    );

    const secondAuthorization = await exporter.authorize({
      mimeType: "text/plain",
      byteCount: bytes.byteLength,
      sha256
    });
    const second = await exporter.write({
      token: secondAuthorization.token,
      bytesBase64: bytes.toString("base64")
    });
    assert.equal(second.fileName, "noctweave-attachment (1).txt");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("desktop attachment export cancellation and digest mismatch write no file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-attachment-export-"));
  try {
    const bytes = Buffer.from("expected", "utf8");
    const sha256 = createHash("sha256").update(bytes).digest("base64");
    const canceled = new DesktopAttachmentExporter({ selectDirectory: async () => null });
    assert.deepEqual(await canceled.authorize({
      mimeType: "application/octet-stream",
      byteCount: bytes.byteLength,
      sha256
    }), { token: null });

    const exporter = new DesktopAttachmentExporter({ selectDirectory: async () => directory });
    const authorization = await exporter.authorize({
      mimeType: "application/octet-stream",
      byteCount: bytes.byteLength,
      sha256
    });
    await assert.rejects(
      () => exporter.write({
        token: authorization.token,
        bytesBase64: Buffer.from("tampered", "utf8").toString("base64")
      }),
      /digest does not match/
    );
    await assert.rejects(() => readFile(join(directory, "noctweave-attachment.bin")), /ENOENT/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("desktop attachment export rejects oversized metadata and a symlink destination", async () => {
  const directory = await mkdtemp(join(tmpdir(), "noctweave-attachment-export-"));
  const link = `${directory}-link`;
  try {
    const digest = createHash("sha256").update("x").digest("base64");
    const oversized = new DesktopAttachmentExporter({ selectDirectory: async () => directory });
    await assert.rejects(
      () => oversized.authorize({
        mimeType: "text/plain",
        byteCount: maximumDesktopAttachmentExportBytes + 1,
        sha256: digest
      }),
      /invalid byte count/
    );

    await symlink(directory, link);
    const linked = new DesktopAttachmentExporter({ selectDirectory: async () => link });
    await assert.rejects(
      () => linked.authorize({
        mimeType: "text/plain",
        byteCount: 1,
        sha256: digest
      }),
      /symbolic link/
    );
  } finally {
    await rm(link, { force: true });
    await rm(directory, { recursive: true, force: true });
  }
});
