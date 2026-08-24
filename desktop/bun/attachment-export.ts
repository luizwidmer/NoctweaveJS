import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import { basename, join } from "node:path";

export const maximumDesktopAttachmentExportBytes = 3 * 1024 * 1024;

type AttachmentExportAuthorizationRequest = {
  mimeType: string;
  byteCount: number;
  sha256: string;
};

type AttachmentExportWriteRequest = {
  token: string;
  bytesBase64: string;
};

type AttachmentExportGrant = AttachmentExportAuthorizationRequest & {
  directory: string;
  expiresAt: number;
};

type DesktopAttachmentExporterOptions = {
  selectDirectory: () => Promise<string | null>;
  now?: () => number;
  tokenFactory?: () => string;
};

const maximumOutstandingGrants = 4;
const grantLifetimeMilliseconds = 2 * 60 * 1_000;

/**
 * Implements a deliberately narrow plaintext boundary for user-approved file
 * export. No attachment bytes cross RPC until the native folder chooser has
 * returned a directory, and every grant is short-lived, one-use, digest-bound,
 * byte-count-bound, and filename-neutral.
 */
export class DesktopAttachmentExporter {
  private readonly selectDirectory: () => Promise<string | null>;
  private readonly now: () => number;
  private readonly tokenFactory: () => string;
  private readonly grants = new Map<string, AttachmentExportGrant>();

  constructor({
    selectDirectory,
    now = Date.now,
    tokenFactory = randomUUID
  }: DesktopAttachmentExporterOptions) {
    if (typeof selectDirectory !== "function") {
      throw new TypeError("Attachment export requires a directory selector.");
    }
    this.selectDirectory = selectDirectory;
    this.now = now;
    this.tokenFactory = tokenFactory;
  }

  async authorize(request: AttachmentExportAuthorizationRequest) {
    const metadata = validateAuthorizationRequest(request);
    this.discardExpiredGrants();
    if (this.grants.size >= maximumOutstandingGrants) {
      throw new Error("Too many attachment exports are awaiting completion.");
    }

    const selected = await this.selectDirectory();
    if (selected === null || selected.trim().length === 0) {
      return Object.freeze({ token: null });
    }
    const selectedInfo = await lstat(selected);
    if (selectedInfo.isSymbolicLink()) {
      throw new Error("The selected attachment export destination cannot be a symbolic link.");
    }
    const directory = await realpath(selected);
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
      throw new Error("The selected attachment export destination is not a directory.");
    }

    const token = canonicalToken(this.tokenFactory());
    if (this.grants.has(token)) {
      throw new Error("Attachment export capability collision.");
    }
    this.grants.set(token, {
      ...metadata,
      directory,
      expiresAt: this.now() + grantLifetimeMilliseconds
    });
    return Object.freeze({ token });
  }

  async write(request: AttachmentExportWriteRequest) {
    if (!request || typeof request !== "object" ||
        !hasExactKeys(request, ["bytesBase64", "token"])) {
      throw new TypeError("Attachment export request is invalid.");
    }
    const token = canonicalToken(request.token);
    const grant = this.grants.get(token);
    this.grants.delete(token);
    if (!grant || grant.expiresAt < this.now()) {
      throw new Error("Attachment export capability is missing or expired.");
    }

    const bytes = decodeCanonicalBase64(
      request.bytesBase64,
      maximumDesktopAttachmentExportBytes,
      "Attachment export bytes"
    );
    try {
      if (bytes.byteLength !== grant.byteCount) {
        throw new Error("Attachment export byte count does not match its authorization.");
      }
      const digest = createHash("sha256").update(bytes).digest("base64");
      if (digest !== grant.sha256) {
        throw new Error("Attachment export digest does not match its authorization.");
      }

      const currentDirectory = await realpath(grant.directory);
      const directoryInfo = await lstat(currentDirectory);
      if (currentDirectory !== grant.directory || !directoryInfo.isDirectory() ||
          directoryInfo.isSymbolicLink()) {
        throw new Error("Attachment export destination changed after authorization.");
      }

      const destination = await writeWithoutOverwrite({
        directory: currentDirectory,
        fileName: attachmentExportName(grant.mimeType),
        bytes
      });
      return Object.freeze({
        saved: true as const,
        fileName: basename(destination),
        byteCount: bytes.byteLength
      });
    } finally {
      bytes.fill(0);
    }
  }

  private discardExpiredGrants() {
    const now = this.now();
    for (const [token, grant] of this.grants) {
      if (grant.expiresAt < now) this.grants.delete(token);
    }
  }
}

function validateAuthorizationRequest(value: AttachmentExportAuthorizationRequest) {
  if (!value || typeof value !== "object" ||
      !hasExactKeys(value, ["byteCount", "mimeType", "sha256"]) ||
      !Number.isSafeInteger(value.byteCount) || value.byteCount < 1 ||
      value.byteCount > maximumDesktopAttachmentExportBytes) {
    throw new TypeError("Attachment export metadata has an invalid byte count.");
  }
  const mimeType = canonicalMIME(value.mimeType);
  const digest = decodeCanonicalBase64(value.sha256, 32, "Attachment export digest");
  digest.fill(0);
  return Object.freeze({
    mimeType,
    byteCount: value.byteCount,
    sha256: value.sha256
  });
}

function hasExactKeys(value: object, expected: string[]) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length &&
    keys.every((key, index) => key === expected[index]);
}

function canonicalMIME(value: string) {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 ||
      value !== value.toLowerCase() || !/^[\x20-\x3a\x3c-\x7e]+$/u.test(value)) {
    throw new TypeError("Attachment export MIME type is invalid.");
  }
  return value;
}

function canonicalToken(value: string) {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) {
    throw new TypeError("Attachment export capability is invalid.");
  }
  return value.toLowerCase();
}

function decodeCanonicalBase64(
  value: string,
  maximumBytes: number,
  label: string
): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > Math.ceil(maximumBytes / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength === 0 || decoded.byteLength > maximumBytes ||
      decoded.toString("base64") !== value) {
    decoded.fill(0);
    throw new TypeError(`${label} is invalid.`);
  }
  const bytes = new Uint8Array(decoded);
  decoded.fill(0);
  return bytes;
}

function attachmentExportName(mimeType: string) {
  const suffix = ({
    "text/plain": "txt",
    "application/pdf": "pdf",
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "audio/mpeg": "mp3",
    "audio/mp4": "m4a"
  } as Record<string, string>)[mimeType] ?? "bin";
  return `noctweave-attachment.${suffix}`;
}

async function writeWithoutOverwrite({
  directory,
  fileName,
  bytes
}: {
  directory: string;
  fileName: string;
  bytes: Uint8Array;
}) {
  const extensionIndex = fileName.lastIndexOf(".");
  const stem = extensionIndex > 0 ? fileName.slice(0, extensionIndex) : fileName;
  const extension = extensionIndex > 0 ? fileName.slice(extensionIndex) : "";
  for (let attempt = 0; attempt < 1_000; attempt += 1) {
    const candidateName = attempt === 0
      ? fileName
      : `${stem} (${attempt})${extension}`;
    const destination = join(directory, candidateName);
    let handle;
    try {
      handle = await open(
        destination,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === "EEXIST") continue;
      throw error;
    }
    try {
      await handle.writeFile(bytes);
      await handle.sync();
      return destination;
    } catch (error) {
      await handle.close().catch(() => {});
      handle = undefined;
      await unlink(destination).catch(() => {});
      throw error;
    } finally {
      await handle?.close();
    }
  }
  throw new Error("Attachment export destination has too many filename collisions.");
}
