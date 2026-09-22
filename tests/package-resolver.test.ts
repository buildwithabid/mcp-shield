import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { resolveTarget } from "../src/utils/package-resolver.js";

describe("local path resolution", () => {
  it("keeps an absolute path as given instead of prefixing the cwd", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-abs-"));
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "abs-server", version: "2.0.0" }), "utf-8");

    const resolved = await resolveTarget(dir);
    expect(resolved.path).toBe(dir);
    expect(resolved.path.startsWith(process.cwd())).toBe(false);
    expect(resolved.name).toBe("abs-server");
    expect(resolved.version).toBe("2.0.0");
    expect(resolved.isTemp).toBe(false);
  });

  it("resolves a relative path against the cwd", async () => {
    const resolved = await resolveTarget("./tests/fixtures/safe-server");
    expect(resolved.path).toBe(resolve(process.cwd(), "tests/fixtures/safe-server"));
  });

  it("expands a leading ~ to the home directory", async () => {
    const resolved = await resolveTarget("~");
    expect(resolved.path).toBe(homedir());
  });

  it("reports the real path when a local target does not exist", async () => {
    const missing = join(tmpdir(), "shield-does-not-exist-" + Date.now());
    await expect(resolveTarget(missing)).rejects.toThrow(`Local path not found: ${missing}`);
  });
});
