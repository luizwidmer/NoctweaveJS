import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Insecure test-only replacement for the OS rollback anchor. This module is
 * reachable only from the separately named UI-test entrypoint and is never
 * bundled into the production application.
 */
export class UITestFileVault {
  private readonly directory: string;

  constructor(directory: string) {
    this.directory = directory;
  }

  async get({ service, account }: { service: string; account: string }) {
    try {
      return await readFile(this.path(service, account), "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return null;
      throw error;
    }
  }

  async set({
    service,
    account,
    value
  }: {
    service: string;
    account: string;
    value: string;
  }) {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const destination = this.path(service, account);
    const temporary = join(this.directory, `.${randomUUID()}.tmp`);
    await writeFile(temporary, value, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await rename(temporary, destination);
  }

  async delete({ service, account }: { service: string; account: string }) {
    await rm(this.path(service, account), { force: true });
  }

  private path(service: string, account: string) {
    if (!service || !account || service.length > 512 || account.length > 512) {
      throw new Error("UI-test anchor scope is invalid.");
    }
    const digest = createHash("sha256")
      .update(service, "utf8")
      .update("\0", "utf8")
      .update(account, "utf8")
      .digest("hex");
    return join(this.directory, `${digest}.anchor`);
  }
}
