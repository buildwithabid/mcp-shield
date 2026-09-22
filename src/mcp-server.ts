import { readFileSync } from "node:fs";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolveTarget, cleanupResolved } from "./utils/package-resolver.js";
import { runScan } from "./scanner/index.js";
import { report } from "./reporter/index.js";
import type { ScanConfig, ScanResult, ReportFormat } from "./types.js";

const PKG_VERSION: string = (JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8")) as { version: string }).version;

let lastResult: ScanResult | null = null;

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: "mcp-shield",
    version: PKG_VERSION,
  });

  server.tool(
    "scan_package",
    "Scan an npm MCP server package for security vulnerabilities",
    {
      package_name: z.string().describe("npm package name to scan (e.g. @modelcontextprotocol/server-filesystem)"),
      quick: z.boolean().optional().default(false).describe("Skip slow checks like rug-pull detection"),
    },
    async ({ package_name, quick }) => {
      const resolved = await resolveTarget(package_name);
      try {
        const config: ScanConfig = {
          targetPath: resolved.path,
          targetIdentifier: package_name,
          packageName: resolved.name,
          packageVersion: resolved.version,
          mode: resolved.isTemp ? "package" : "local",
          quick,
          format: "json",
        };

        lastResult = await runScan(config);
        const output = await report(lastResult, "json");

        return {
          content: [{ type: "text" as const, text: output }],
        };
      } finally {
        await cleanupResolved(resolved);
      }
    }
  );

  server.tool(
    "scan_local",
    "Scan a local MCP server directory for security vulnerabilities",
    {
      path: z.string().describe("Local directory path to scan"),
      quick: z.boolean().optional().default(false).describe("Skip slow checks like rug-pull detection"),
    },
    async ({ path, quick }) => {
      const resolved = await resolveTarget(path);
      try {
        const config: ScanConfig = {
          targetPath: resolved.path,
          targetIdentifier: path,
          packageVersion: resolved.version,
          mode: resolved.isTemp ? "package" : "local",
          quick,
          format: "json",
        };

        lastResult = await runScan(config);
        const output = await report(lastResult, "json");

        return {
          content: [{ type: "text" as const, text: output }],
        };
      } finally {
        await cleanupResolved(resolved);
      }
    }
  );

  server.tool(
    "get_report",
    "Retrieve the last scan report in a specified format",
    {
      format: z.enum(["json", "markdown", "terminal"]).optional().default("markdown").describe("Output format"),
    },
    async ({ format }) => {
      if (!lastResult) {
        return {
          content: [{ type: "text" as const, text: "No scan has been run yet. Use scan_package or scan_local first." }],
        };
      }

      const output = await report(lastResult, format as ReportFormat);
      return {
        content: [{ type: "text" as const, text: output }],
      };
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
