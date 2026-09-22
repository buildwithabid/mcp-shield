import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import type { ScanConfig, FileCache, Finding } from "../src/types.js";
import { permissionCheckScanner } from "../src/scanner/permission-check.js";
import { transportSecurityScanner } from "../src/scanner/transport-security.js";
import { collectSourceFiles } from "../src/utils/ast-helpers.js";
import { runScan } from "../src/scanner/index.js";

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

  it("does not report words ending in -eval as eval()", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-eval-"));
    const cache = await cacheOf(dir, {
      "tool.js": [
        'const description = `Do NOT use this tool for immediate data retrieval (time words like "today")`;',
        "const retrieval = (x) => x; retrieval (1);",
      ].join("\n"),
      "danger.js": "module.exports = (input) => eval(input);\nwindow.eval (code);",
    });
    const findings = await permissionCheckScanner.run(cfg(dir), cache);
    const evals = findings.filter((f) => f.title === "eval() usage");
    expect(evals.map((f) => f.file)).toEqual(["danger.js", "danger.js"]);
  });

  it("does not flag plain HTTP to loopback, still flags every other host", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-http-"));
    const loopback = [
      '"http://localhost"',
      '"http://localhost:3000/mcp"',
      "'http://127.0.0.1:8080'",
      "`http://0.0.0.0/health`",
      '"http://[::1]:3000/sse"',
      '"http://localhost?debug=1"',
    ];
    const remote = [
      '"http://example.com"',
      '"http://localhost.evil.com/x"',
      '"http://127.0.0.1.nip.io"',
      '"http://10.0.0.5:8080/api"',
      "`http://${host}/mcp`",
    ];
    const cache = await cacheOf(dir, {
      "urls.js": [...loopback, ...remote].map((u) => `fetch(${u});`).join("\n"),
    });
    const findings = await transportSecurityScanner.run(cfg(dir), cache);
    const flagged = findings.filter((f) => f.title === "Insecure HTTP endpoint").map((f) => f.line);
    const remoteLines = remote.map((_, i) => loopback.length + i + 1);
    expect(flagged).toEqual(remoteLines);
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

  it("skips a .d.ts beside the .js it was emitted with, keeps a standalone one", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-dts-"));
    await writeFile(join(dir, "const.js"), 'export const apiKey = "e97714a64e2b4b8b8fe0b01cd8592870";', "utf-8");
    await writeFile(join(dir, "const.d.ts"), 'export declare const apiKey: "e97714a64e2b4b8b8fe0b01cd8592870";', "utf-8");
    await writeFile(join(dir, "types.d.ts"), "export type Id = string;", "utf-8");

    const files = (await collectSourceFiles(dir, "package")).map((f) => f.split("/").pop());
    expect(files).toContain("const.js");
    expect(files).not.toContain("const.d.ts");
    expect(files).toContain("types.d.ts");
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

  it("local scans skip build output and vendored directories", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-out-"));
    const skipped = [".next", "dist", "build", "out", "node_modules", "coverage", ".git"];
    for (const d of skipped) await plant(dir, d);
    await writeFile(join(dir, "index.ts"), "export const x = 1;", "utf-8");

    const files = await collectSourceFiles(dir, "local");
    expect(files).toEqual([join(dir, "index.ts")]);

    const result = await runScan({ ...cfg(dir), mode: "local", quick: true });
    expect(findingsUnder(result.findings, skipped)).toHaveLength(0);
    expect(result.summary.critical).toBe(0);
  });

  it("package scans read build output, since it is often all a package ships", async () => {
    const dir = await mkdtemp(join(tmpdir(), "shield-pkg-"));
    const shipped = ["dist", "build", "out", "lib"];
    const skipped = ["node_modules", "coverage", ".git"];
    for (const d of [...shipped, ...skipped]) await plant(dir, d);

    const files = (await collectSourceFiles(dir, "package")).map((f) => relative(dir, f).split(sep)[0]);
    expect(files.sort()).toEqual([...shipped].sort());

    const result = await runScan({ ...cfg(dir), mode: "package", quick: true });
    expect(result.summary.critical).toBeGreaterThan(0);
    const inDist = findingsUnder(result.findings, ["dist"]);
    expect(inDist.some((f) => f.severity === "critical")).toBe(true);
    expect(inDist.some((f) => f.title.toLowerCase().includes("shell execution"))).toBe(true);
    expect(findingsUnder(result.findings, skipped)).toHaveLength(0);
  });
});

/** Write a file with eval() and a child_process call into <dir>/<sub>/server/chunk.js */
async function plant(dir: string, sub: string): Promise<void> {
  await mkdir(join(dir, sub, "server"), { recursive: true });
  await writeFile(
    join(dir, sub, "server", "chunk.js"),
    'eval(userInput);\nrequire("child_process").execSync("rm -rf " + userInput);',
    "utf-8"
  );
}

function findingsUnder(findings: Finding[], dirs: string[]): Finding[] {
  return findings.filter((f) => f.file?.split(/[\\/]/).some((seg) => dirs.includes(seg)));
}
