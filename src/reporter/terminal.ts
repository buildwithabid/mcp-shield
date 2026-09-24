import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ScanResult, Finding, Severity, ScannerName } from "../types.js";
import { SCANNER_DISPLAY_NAMES } from "../types.js";

const PKG_VERSION: string = (JSON.parse(readFileSync(join(__dirname, "..", "..", "package.json"), "utf-8")) as { version: string }).version;

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "\x1b[31m\u{1F534} CRITICAL\x1b[0m",
  high: "\x1b[33m\u{1F7E0} HIGH    \x1b[0m",
  medium: "\x1b[33m\u{1F7E1} MEDIUM  \x1b[0m",
  low: "\x1b[32m\u{1F7E2} LOW     \x1b[0m",
  info: "\x1b[34m\u{2139}\u{FE0F}  INFO    \x1b[0m",
  pass: "\x1b[32m\u2705 PASS    \x1b[0m",
};

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";

export function formatTerminal(result: ScanResult): string {
  const lines: string[] = [];

  // Header
  lines.push("");
  lines.push(`${BOLD}\u{1F6E1}\u{FE0F}  mcp-shield v${PKG_VERSION} \u2014 MCP Security Scanner${RESET}`);
  lines.push("");
  lines.push(`${BOLD}Scanning:${RESET} ${result.target}${result.version ? ` v${result.version}` : ""}`);
  lines.push("\u2501".repeat(50));
  lines.push("");

  // Findings
  const nonPassFindings = result.findings.filter((f) => f.severity !== "pass");
  const passFindings = result.findings.filter((f) => f.severity === "pass");

  for (const finding of nonPassFindings) {
    lines.push(formatFinding(finding));
  }

  for (const finding of passFindings) {
    lines.push(formatFinding(finding));
  }

  // Errors
  if (result.errors.length > 0) {
    lines.push("");
    for (const error of result.errors) {
      lines.push(`${DIM}\u26A0\u{FE0F}  ${error.scanner}: ${error.message}${RESET}`);
    }
  }

  // Summary
  lines.push("");
  lines.push("\u2501".repeat(50));

  const scoreColor = result.score >= 70 ? GREEN : result.score >= 40 ? YELLOW : RED;
  const passLabel = result.passed ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;

  lines.push(`${BOLD}Score: ${scoreColor}${result.score}/100${RESET} (${passLabel})`);

  const parts: string[] = [];
  if (result.summary.critical > 0) parts.push(`${RED}${result.summary.critical} critical${RESET}`);
  if (result.summary.high > 0) parts.push(`${YELLOW}${result.summary.high} high${RESET}`);
  if (result.summary.medium > 0) parts.push(`${YELLOW}${result.summary.medium} medium${RESET}`);
  if (result.summary.low > 0) parts.push(`${GREEN}${result.summary.low} low${RESET}`);
  if (result.summary.pass > 0) parts.push(`${GREEN}${result.summary.pass} pass${RESET}`);

  lines.push(parts.join(" \u00B7 "));
  lines.push("");

  return lines.join("\n");
}

function formatFinding(finding: Finding): string {
  const icon = SEVERITY_ICONS[finding.severity];
  const scanner = `${DIM}${formatScannerName(finding.scanner)}:${RESET}`;
  const title = finding.title;
  let line = `${icon}  ${scanner} ${title}`;

  if (finding.file) {
    line += ` ${DIM}(${finding.file}${finding.line ? `:${finding.line}` : ""})${RESET}`;
  }

  return line;
}

function formatScannerName(name: string): string {
  return SCANNER_DISPLAY_NAMES[name as ScannerName]?.short ?? name;
}
