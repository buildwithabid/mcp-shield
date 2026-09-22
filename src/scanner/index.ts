import type { Finding, ScanConfig, ScannerError, ScanResult, Scanner, SeverityCounts, Severity, FileCache } from "../types.js";
import { collectSourceFiles, safeReadFile } from "../utils/ast-helpers.js";
import { secretsLeakScanner } from "./secrets-leak.js";
import { dependencyAuditScanner } from "./dependency-audit.js";
import { toolDescriptionScanner } from "./tool-description.js";
import { permissionCheckScanner } from "./permission-check.js";
import { supplyChainScanner } from "./supply-chain.js";
import { rugPullDetectScanner } from "./rug-pull-detect.js";
import { transportSecurityScanner } from "./transport-security.js";

const ALL_SCANNERS: Scanner[] = [
  secretsLeakScanner,
  dependencyAuditScanner,
  toolDescriptionScanner,
  permissionCheckScanner,
  supplyChainScanner,
  rugPullDetectScanner,
  transportSecurityScanner,
];

const QUICK_SKIP = new Set(["rug-pull-detect"]);

/**
 * Run all security scanners against the target and produce a ScanResult.
 */
export async function runScan(config: ScanConfig): Promise<ScanResult> {
  const scanners = config.quick
    ? ALL_SCANNERS.filter((s) => !QUICK_SKIP.has(s.name))
    : ALL_SCANNERS;

  // Collect files and read contents once, shared across all scanners
  const files = await collectSourceFiles(config.targetPath, config.mode);
  const contents = new Map<string, string>();
  await Promise.all(
    files.map(async (filePath) => {
      const content = await safeReadFile(filePath);
      if (content !== null) {
        contents.set(filePath, content);
      }
    })
  );
  const cache: FileCache = { files, contents };

  const allFindings: Finding[] = [];
  const errors: ScannerError[] = [];

  // Run scanners concurrently
  const results = await Promise.allSettled(
    scanners.map(async (scanner) => {
      try {
        return { name: scanner.name, findings: await scanner.run(config, cache) };
      } catch (error) {
        return { name: scanner.name, findings: null as null, error: error instanceof Error ? error.message : String(error) };
      }
    })
  );

  for (const result of results) {
    if (result.status === "fulfilled") {
      if (result.value.findings) {
        allFindings.push(...result.value.findings);
      } else {
        errors.push({ scanner: result.value.name, message: result.value.error! });
      }
    } else {
      errors.push({ scanner: "unknown", message: String(result.reason) });
    }
  }

  const summary = countSeverities(allFindings);
  const score = calculateScore(allFindings);

  return {
    target: config.targetIdentifier,
    version: config.packageVersion,
    timestamp: new Date().toISOString(),
    findings: sortFindings(allFindings),
    score,
    passed: score >= 70,
    summary,
    errors,
  };
}

function countSeverities(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, pass: 0 };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}

/**
 * Score a package from 0-100.
 *
 * Each finding is still reported at its own severity; this only decides how the
 * headline number is produced. Penalties grow with the square root of the count
 * and are capped per severity, for two reasons:
 *
 *  - A flat per-finding penalty saturated immediately. Seven high findings put
 *    any package at zero, so a 400-tool server with three shell calls scored the
 *    same as genuinely malicious code. Above the threshold the number carried no
 *    information at all.
 *  - The tenth instance of a pattern tells you much less than the first. Ten
 *    filesystem writes in one package is usually one design decision, not ten
 *    independent problems.
 *
 * Small counts are unchanged: a single high finding still costs 15, so packages
 * that scored well before score exactly the same now.
 */
function calculateScore(findings: Finding[]): number {
  const unit: Record<Severity, number> = {
    critical: 25,
    high: 15,
    medium: 5,
    low: 2,
    info: 0,
    pass: 0,
  };

  // Ceiling on how much any one severity can remove, so a long tail of
  // low-severity noise can never sink a package on its own.
  const cap: Record<Severity, number> = {
    critical: 60,
    high: 40,
    medium: 20,
    low: 8,
    info: 0,
    pass: 0,
  };

  const counts = new Map<Severity, number>();
  for (const f of findings) {
    counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  }

  let score = 100;
  for (const [severity, count] of counts) {
    if (!unit[severity]) continue;
    score -= Math.min(cap[severity], unit[severity] * Math.sqrt(count));
  }

  return Math.round(Math.max(0, Math.min(100, score)));
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  pass: 5,
};

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
