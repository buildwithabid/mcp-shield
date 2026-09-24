import { relative } from "node:path";
import type { Finding, ScanConfig, Scanner, FileCache } from "../types.js";
import { createPassFinding } from "../types.js";
import { INJECTION_PATTERNS } from "../utils/patterns.js";
import { extractToolDefinitionsFromSource } from "../utils/ast-helpers.js";

export const toolDescriptionScanner: Scanner = {
  name: "tool-description",

  async run(config: ScanConfig, cache: FileCache): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const [filePath, content] of cache.contents) {
      const relPath = relative(config.targetPath, filePath);

      const toolDefs = extractToolDefinitionsFromSource(content);

      for (const tool of toolDefs) {
        const descFindings = scanDescription(tool.descriptionText, tool.name, relPath, tool.line);
        findings.push(...descFindings);
      }

      const allDescFindings = scanAllDescriptionFields(content, relPath, toolDefs);
      findings.push(...allDescFindings);
    }

    const deduped = deduplicateFindings(findings);

    if (deduped.length === 0) {
      deduped.push(createPassFinding("tool-description", "No prompt injection patterns detected", "Tool descriptions appear clean of known injection techniques"));
    }

    return deduped;
  },
};

function scanDescription(description: string, toolName: string, file: string, line: number): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of INJECTION_PATTERNS) {
    pattern.pattern.lastIndex = 0;
    if (pattern.pattern.test(description)) {
      findings.push({
        scanner: "tool-description",
        severity: pattern.severity,
        title: `Tool Injection: ${pattern.name}`,
        description: `Tool "${toolName}" description contains ${pattern.name} pattern`,
        file,
        line,
        remediation: "Review and sanitize the tool description. Tool descriptions should be clear, factual, and contain no hidden instructions.",
      });
    }
  }

  if (description.length > 2000) {
    findings.push({
      scanner: "tool-description",
      severity: "medium",
      title: "Suspiciously long tool description",
      description: `Tool "${toolName}" has an unusually long description (${description.length} chars). Long descriptions can hide injected content.`,
      file,
      line,
      remediation: "Review the full description carefully. Tool descriptions should be concise.",
    });
  }

  const base64Blocks = description.match(/[A-Za-z0-9+/=]{40,}/g);
  if (base64Blocks) {
    findings.push({
      scanner: "tool-description",
      severity: "high",
      title: "Encoded content in tool description",
      description: `Tool "${toolName}" description contains what appears to be base64-encoded content`,
      file,
      line,
      remediation: "Decode and review the encoded content. Legitimate tool descriptions do not need encoded blocks.",
    });
  }

  return findings;
}

function scanAllDescriptionFields(
  content: string,
  relPath: string,
  toolDefs: ReadonlyArray<{ descriptionText: string; line: number }>
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");
  const descPattern = /description\s*[:=]\s*["'`]([\s\S]*?)["'`]/g;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    descPattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = descPattern.exec(line)) !== null) {
      const descValue = match[1]!;

      // Tool descriptions were already scanned by scanDescription, which names
      // the tool. Scanning them again here reported every injection twice.
      if (toolDefs.some((t) => t.line === i + 1 && t.descriptionText === descValue)) continue;

      for (const pattern of INJECTION_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        if (pattern.pattern.test(descValue)) {
          findings.push({
            scanner: "tool-description",
            severity: pattern.severity,
            title: `Description injection: ${pattern.name}`,
            description: `Found ${pattern.name} pattern in a description field at ${relPath}:${i + 1}`,
            file: relPath,
            line: i + 1,
            remediation: "Review and sanitize the description. Remove any hidden instructions or encoded content.",
          });
        }
      }
    }
  }

  return findings;
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.file ?? ""}:${f.line ?? ""}:${f.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
