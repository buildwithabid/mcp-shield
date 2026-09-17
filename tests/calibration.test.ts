import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ScanConfig, FileCache } from "../src/types.js";
import { permissionCheckScanner } from "../src/scanner/permission-check.js";
import { collectSourceFiles } from "../src/utils/ast-helpers.js";

function cfg(targetPath: string): ScanConfig {
  return { targetPath, targetIdentifier: targetPath, quick: false, format: "terminal" };
}

async function cacheOf(dir: string, files: Record<string, string>): Promise<FileCache> {
  const contents = new Map<string, string>();
  for (const [name, body] of Object.entries(files)) {
    const p = join(dir, name);
    await writeFile(p, body, "utf-8");
    contents.set(p, body);
  }
  return { files: [...contents.keys()], contents };
}

describe("false-positive calibration", () => {
  it("does not report regex .exec() as shell execution", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-fp-"));
    const cache = await cacheOf(dir, {
      "regex.js": [
        "const re = /foo(\\d+)/g;",
        "let m;",
        "while ((m = re.exec(line)) !== null) { out.push(m[1]); }",
        "const hit = pattern.exec(content);",
      ].join("\n"),
    });
    const findings = await permissionCheckScanner.run(cfg(dir), cache);
    const shell = findings.filter((f) => f.title.toLowerCase().includes("shell execution"));
    expect(shell).toHaveLength(0);
  });

  it("still reports a real child_process call", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-tp-"));
    const cache = await cacheOf(dir, {
      "danger.js": 'const { execSync } = require("child_process");\nexecSync("rm -rf " + userInput);',
    });
    const findings = await permissionCheckScanner.run(cfg(dir), cache);
    const shell = findings.filter((f) => f.title.toLowerCase().includes("shell execution"));
    expect(shell.length).toBeGreaterThan(0);
  });

  it("skips emitted .js when the .ts it came from sits beside it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-dup-"));
    await writeFile(join(dir, "server.ts"), "export const a = 1;", "utf-8");
    await writeFile(join(dir, "server.js"), "export const a = 1;", "utf-8");
    await writeFile(join(dir, "standalone.js"), "export const b = 2;", "utf-8");

    const files = (await collectSourceFiles(dir)).map((f) => f.split("/").pop());
    expect(files).toContain("server.ts");
    expect(files).not.toContain("server.js");
    expect(files).toContain("standalone.js");
  });

  it("skips build tooling that never ships to a client", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-build-"));
    await writeFile(join(dir, "build.js"), 'require("child_process").execSync("tsc");', "utf-8");
    await writeFile(join(dir, "vite.config.ts"), "export default {};", "utf-8");
    await writeFile(join(dir, "index.ts"), "export const x = 1;", "utf-8");

    const files = (await collectSourceFiles(dir)).map((f) => f.split("/").pop());
    expect(files).toContain("index.ts");
    expect(files).not.toContain("build.js");
    expect(files).not.toContain("vite.config.ts");
  });
});
