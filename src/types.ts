export type Severity = "critical" | "high" | "medium" | "low" | "info" | "pass";

export interface Finding {
  /** Which scanner produced this finding */
  scanner: ScannerName;
  /** Severity level */
  severity: Severity;
  /** Short title for the finding */
  title: string;
  /** Detailed description */
  description: string;
  /** File path where the issue was found, if applicable */
  file?: string;
  /** Line number, if applicable */
  line?: number;
  /** CVE ID, if applicable */
  cveId?: string;
  /** Remediation advice */
  remediation?: string;
}

export type ScannerName =
  | "dependency-audit"
  | "permission-check"
  | "tool-description"
  | "rug-pull-detect"
  | "secrets-leak"
  | "transport-security"
  | "supply-chain";

export interface ScanConfig {
  /** Path to the target MCP server (local dir or resolved package) */
  targetPath: string;
  /** Original target identifier (package name or path as provided by user) */
  targetIdentifier: string;
  /** Package name if scanning an npm package */
  packageName?: string;
  /** Package version if scanning an npm package */
  packageVersion?: string;
  /** "package" for a downloaded npm package, "local" (default) for a project directory */
  mode?: ScanMode;
  /** Whether to skip slow checks (rug-pull, etc.) */
  quick: boolean;
  /** Output format */
  format: ReportFormat;
  /** Output file path, if writing to file */
  outputFile?: string;
  /** MCP server command to connect to (for live checks) */
  serverCommand?: string;
  /** MCP server args */
  serverArgs?: string[];
}

export type ReportFormat = "terminal" | "json" | "markdown";

export type ScanMode = "local" | "package";

export interface ScanResult {
  /** Target that was scanned */
  target: string;
  /** Package version if applicable */
  version?: string;
  /** When the scan was run */
  timestamp: string;
  /** All findings from all scanners */
  findings: Finding[];
  /** Overall score 0-100 */
  score: number;
  /** Whether the scan passed */
  passed: boolean;
  /** Summary counts by severity */
  summary: SeverityCounts;
  /** Scanners that errored out */
  errors: ScannerError[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  pass: number;
}

export interface ScannerError {
  scanner: string;
  message: string;
}

/** Pre-collected file paths and cached file contents, shared across scanners */
export interface FileCache {
  /** All scannable file paths in the target */
  files: string[];
  /** Map from absolute file path to file content */
  contents: Map<string, string>;
}

export interface Scanner {
  name: ScannerName;
  run(config: ScanConfig, cache: FileCache): Promise<Finding[]>;
}

/** Display names for scanners, keyed by format context */
export const SCANNER_DISPLAY_NAMES: Record<ScannerName, { short: string; long: string }> = {
  "dependency-audit": { short: "Dependencies", long: "Dependency Audit" },
  "permission-check": { short: "Permissions", long: "Permission & Scope Check" },
  "tool-description": { short: "Tool Injection", long: "Tool Description Injection" },
  "rug-pull-detect": { short: "Rug-Pull", long: "Rug-Pull Detection" },
  "secrets-leak": { short: "Secrets", long: "Secrets Detection" },
  "transport-security": { short: "Transport", long: "Transport Security" },
  "supply-chain": { short: "Supply Chain", long: "Supply Chain Analysis" },
};

export function createPassFinding(scanner: ScannerName, title: string, description: string): Finding {
  return { scanner, severity: "pass", title, description };
}
