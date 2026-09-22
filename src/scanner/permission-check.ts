import { relative } from "node:path";
import type { Finding, ScanConfig, Scanner, FileCache } from "../types.js";
import { createPassFinding } from "../types.js";
import { DANGEROUS_SCHEMA_PATTERNS } from "../utils/patterns.js";

export const permissionCheckScanner: Scanner = {
  name: "permission-check",

  async run(config: ScanConfig, cache: FileCache): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const [filePath, content] of cache.contents) {
      const relPath = relative(config.targetPath, filePath);

      const schemaFindings = analyzeToolSchemas(content, relPath);
      findings.push(...schemaFindings);

      const capFindings = analyzeCapabilities(content, relPath);
      findings.push(...capFindings);
    }

    if (findings.length === 0) {
      findings.push(createPassFinding("permission-check", "No overly broad permissions detected", "Tool input schemas and capabilities appear appropriately scoped"));
    }

    return findings;
  },
};

function analyzeToolSchemas(content: string, relPath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  const propertyBlocks = extractSchemaProperties(lines);

  for (const prop of propertyBlocks) {
    for (const pattern of DANGEROUS_SCHEMA_PATTERNS) {
      if (pattern.check(prop.name, prop.schema)) {
        findings.push({
          scanner: "permission-check",
          severity: pattern.severity,
          title: `${pattern.name}: "${prop.name}"`,
          description: `${pattern.description} (property "${prop.name}" in ${relPath}:${prop.line})`,
          file: relPath,
          line: prop.line,
          remediation: getRemediation(pattern.name),
        });
      }
    }
  }

  const execPatterns = [
    // The leading (?<![.\w]) is load-bearing: without it this also matched
    // `regex.exec(line)` and `pattern.exec(content)` — ordinary regex use,
    // present in almost every codebase — and reported each one as
    // high-severity shell execution. Only a bare `exec(` / `spawn(` etc.
    // is a real child_process call.
    { pattern: /(?<![.\w])(?:child_process|exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/, name: "child_process usage" },
    { pattern: /(?:require|import).*child_process/, name: "child_process import" },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const ep of execPatterns) {
      if (ep.pattern.test(line)) {
        findings.push({
          scanner: "permission-check",
          severity: "high",
          title: `Shell execution: ${ep.name}`,
          description: `${ep.name} found at ${relPath}:${i + 1}. MCP servers with shell access can execute arbitrary commands.`,
          file: relPath,
          line: i + 1,
          remediation: "Ensure shell commands are strictly validated and scoped. Prefer specific operations over generic shell access.",
        });
        break;
      }
    }
  }

  return findings;
}

interface SchemaProperty {
  name: string;
  schema: Record<string, unknown>;
  line: number;
}

function extractSchemaProperties(lines: string[]): SchemaProperty[] {
  const properties: SchemaProperty[] = [];

  let inProperties = false;
  let braceDepth = 0;
  let currentProp = "";
  let currentPropLine = 0;
  let currentPropContent = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (/properties\s*:\s*\{/.test(line) || /["']properties["']\s*:\s*\{/.test(line)) {
      inProperties = true;
      braceDepth = 1;
      continue;
    }

    if (inProperties) {
      for (const ch of line) {
        if (ch === "{") braceDepth++;
        if (ch === "}") braceDepth--;
      }

      const propMatch = line.match(/["']?(\w+)["']?\s*:\s*\{/);
      if (propMatch && braceDepth >= 2) {
        if (currentProp && currentPropContent) {
          tryParseProperty(currentProp, currentPropContent, currentPropLine, properties);
        }
        currentProp = propMatch[1]!;
        currentPropLine = i + 1;
        currentPropContent = line;
      } else if (currentProp) {
        currentPropContent += "\n" + line;
      }

      if (braceDepth <= 0) {
        if (currentProp && currentPropContent) {
          tryParseProperty(currentProp, currentPropContent, currentPropLine, properties);
        }
        inProperties = false;
        currentProp = "";
        currentPropContent = "";
      }
    }
  }

  const inlinePattern = /(\w+)\s*:\s*\{\s*type\s*:\s*["'](\w+)["']/g;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    inlinePattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = inlinePattern.exec(line)) !== null) {
      const descMatch = line.match(/description\s*:\s*["']([^"']+)["']/);
      properties.push({
        name: match[1]!,
        schema: {
          type: match[2]!,
          description: descMatch?.[1] ?? "",
        },
        line: i + 1,
      });
    }
  }

  return properties;
}

function tryParseProperty(name: string, content: string, line: number, properties: SchemaProperty[]): void {
  const typeMatch = content.match(/type\s*:\s*["'](\w+)["']/);
  const descMatch = content.match(/description\s*:\s*["']([^"']+)["']/);
  const enumMatch = content.match(/enum\s*:/);
  const patternMatch = content.match(/pattern\s*:/);

  if (typeMatch) {
    properties.push({
      name,
      schema: {
        type: typeMatch[1]!,
        description: descMatch?.[1] ?? "",
        ...(enumMatch ? { enum: true } : {}),
        ...(patternMatch ? { pattern: true } : {}),
      },
      line,
    });
  }
}

/**
 * Capability findings are still all reported — the severity decides how loudly.
 *
 * These are graded by how *unusual* a capability is for an MCP server, not by
 * how alarming the API name sounds. Reading files and serving HTTP is what most
 * of these servers are for, so rating them high/medium meant the genuinely
 * interesting findings — eval, a shell call, a hardcoded key — arrived in the
 * same colour as `fs.readFile`. High should mean "look at this now".
 *
 * Deliberately unchanged: eval() and the Function constructor stay critical.
 */
const CAPABILITY_PATTERNS = [
  // Writing/deleting files is worth surfacing, but it is ordinary for a server
  // that caches tokens or manages a workspace.
  { pattern: /fs\.(writeFile|unlink|rmdir|rm|rename|chmod|chown)/, name: "Filesystem write operation", severity: "medium" as const },
  // Reading files is near-universal and on its own tells you nothing.
  { pattern: /fs\.(readFile|readdir|stat|access)/, name: "Filesystem read operation", severity: "low" as const },
  { pattern: /net\.(createServer|connect|Socket)/, name: "Network server/socket", severity: "medium" as const },
  // A Streamable HTTP MCP server does this by definition.
  { pattern: /http\.createServer|https\.createServer/, name: "HTTP server creation", severity: "low" as const },
  // \b so prose such as "data retrieval (e.g. ...)" in a tool description is not eval.
  { pattern: /\beval\s*\(/, name: "eval() usage", severity: "critical" as const },
  { pattern: /new\s+Function\s*\(/, name: "Function constructor", severity: "critical" as const },
  { pattern: /process\.env/, name: "Environment variable access", severity: "low" as const },
];

function analyzeCapabilities(content: string, relPath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const dp of CAPABILITY_PATTERNS) {
      if (dp.pattern.test(line)) {
        findings.push({
          scanner: "permission-check",
          severity: dp.severity,
          title: dp.name,
          description: `${dp.name} detected at ${relPath}:${i + 1}`,
          file: relPath,
          line: i + 1,
        });
      }
    }
  }

  return findings;
}

function getRemediation(patternName: string): string {
  const remediations: Record<string, string> = {
    "Unrestricted shell command": "Use an enum or allowlist to restrict which commands can be executed. Never pass user input directly to shell.",
    "Unrestricted file path": "Add a pattern constraint or validate paths against an allowlist. Prevent path traversal with normalization.",
    "Raw SQL input": "Use parameterized queries instead of accepting raw SQL. If raw SQL is needed, implement a query allowlist.",
    "Unrestricted URL": "Add URL validation with a format constraint or restrict to specific domains.",
    "Glob wildcard accepted": "Restrict glob patterns to specific directories and prevent access to sensitive paths.",
  };
  return remediations[patternName] ?? "Review and restrict the input scope.";
}
