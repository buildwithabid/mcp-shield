#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";
import { resolveTarget, cleanupResolved } from "./utils/package-resolver.js";
import { runScan } from "./scanner/index.js";
import { report } from "./reporter/index.js";
import type { ReportFormat, ScanConfig } from "./types.js";

const PKG_VERSION: string = (JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8")) as { version: string }).version;

const program = new Command();

program
  .name("mcp-shield")
  .description("Security scanner for MCP servers. Find vulnerabilities before your AI agent does.")
  .version(PKG_VERSION);

program
  .command("scan")
  .description("Scan an MCP server package or local directory for security vulnerabilities")
  .argument("<target>", "npm package name or local path to scan")
  .option("-f, --format <format>", "Output format: terminal, json, markdown", "terminal")
  .option("-o, --output <file>", "Write report to file")
  .option("-q, --quick", "Skip slow checks (rug-pull detection)", false)
  .action(async (target: string, options: { format: string; output?: string; quick: boolean }) => {
    const format = options.format as ReportFormat;
    if (!["terminal", "json", "markdown"].includes(format)) {
      console.error(`Invalid format: ${format}. Use terminal, json, or markdown.`);
      process.exit(1);
    }

    if (format === "terminal") {
      console.log("");
      console.log(`\x1b[1m\u{1F6E1}\u{FE0F}  mcp-shield v${PKG_VERSION} \u2014 MCP Security Scanner\x1b[0m`);
      console.log("");
      console.log(`Resolving target: ${target}...`);
    }

    let resolved;
    try {
      resolved = await resolveTarget(target);
    } catch (error) {
      console.error(`Failed to resolve target: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }

    if (format === "terminal") {
      console.log(`Scanning: ${resolved.name}${resolved.version !== "local" ? ` v${resolved.version}` : ""}`);
      console.log("");
    }

    const config: ScanConfig = {
      targetPath: resolved.path,
      targetIdentifier: target,
      packageName: resolved.isTemp ? resolved.name : undefined,
      packageVersion: resolved.version,
      mode: resolved.isTemp ? "package" : "local",
      quick: options.quick,
      format,
      outputFile: options.output,
    };

    try {
      const result = await runScan(config);
      const output = await report(result, format, options.output);

      console.log(output);

      if (options.output && format === "terminal") {
        console.log(`\x1b[2mReport written to ${options.output}\x1b[0m`);
      }

      // Exit with non-zero if scan failed
      process.exit(result.passed ? 0 : 1);
    } catch (error) {
      console.error(`Scan failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(2);
    } finally {
      await cleanupResolved(resolved);
    }
  });

program
  .command("serve")
  .description("Run mcp-shield as an MCP server")
  .action(async () => {
    const { startMcpServer } = await import("./mcp-server.js");
    await startMcpServer();
  });

program.parse();
