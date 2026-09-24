import { describe, it, expect, vi, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SAFE_PATH = join(__dirname, "fixtures/safe-server");
const PKG_VERSION = (JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8")) as { version: string }).version;

const argv = process.argv;

afterEach(() => {
  process.argv = argv;
  vi.restoreAllMocks();
});

describe("CLI terminal output", () => {
  it("prints the banner once, with the version", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.join(" "));
    });
    const exited = new Promise<number | undefined>((resolve) => {
      vi.spyOn(process, "exit").mockImplementation(((code?: number) => resolve(code)) as typeof process.exit);
    });

    process.argv = ["node", "mcp-shield", "scan", SAFE_PATH, "--quick"];
    await import("../src/index.js");
    expect(await exited).toBe(0);

    const output = logs.join("\n");
    expect(output.match(/MCP Security Scanner/g)).toHaveLength(1);
    expect(output).toContain(`mcp-shield v${PKG_VERSION} — MCP Security Scanner`);
  });
});
