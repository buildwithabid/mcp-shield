import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Finding, ScanConfig, Scanner, FileCache } from "../types.js";
import { createPassFinding } from "../types.js";
import { KNOWN_MCP_PACKAGES } from "../utils/patterns.js";

const execFileAsync = promisify(execFile);

export const supplyChainScanner: Scanner = {
  name: "supply-chain",

  async run(config: ScanConfig, _cache: FileCache): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (config.packageName) {
      // npm package — check registry metadata
      const registryFindings = await checkNpmRegistry(config.packageName);
      findings.push(...registryFindings);

      // Check for typosquatting
      const typoFindings = checkTyposquatting(config.packageName);
      findings.push(...typoFindings);
    }

    // Check package.json scripts. npm runs install hooks on install, so a
    // package scan (the pre-install check) needs this as much as a local one.
    const scriptFindings = await checkPackageScripts(config.targetPath);
    findings.push(...scriptFindings);

    // Check source repo matches declared repo
    const repoFindings = await checkRepoIntegrity(config.targetPath);
    findings.push(...repoFindings);

    if (findings.length === 0) {
      findings.push(createPassFinding("supply-chain", "Supply chain checks passed", "No supply chain anomalies detected"));
    }

    return findings;
  },
};

async function checkNpmRegistry(packageName: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const { stdout } = await execFileAsync("npm", ["view", packageName, "--json"], {
      timeout: 30_000,
    });

    const metadata = JSON.parse(stdout) as NpmMetadata;

    // Check publish date
    const publishDate = metadata.time?.modified ?? metadata.time?.created;
    if (publishDate) {
      const daysSincePublish = Math.floor(
        (Date.now() - new Date(publishDate).getTime()) / (1000 * 60 * 60 * 24)
      );
      // Informational only: actively maintained packages, official ones
      // included, publish every few days, so a recent date says nothing about
      // intent. Still reported, but it costs no score.
      if (daysSincePublish < 30) {
        findings.push({
          scanner: "supply-chain",
          severity: "info",
          title: "Recently published package",
          description: `Package was published/updated ${daysSincePublish} days ago. New packages have limited community vetting.`,
          remediation: "Verify the package author and source code manually before trusting new packages.",
        });
      }
    }

    // Check maintainer count
    const maintainers = metadata.maintainers ?? [];
    if (maintainers.length === 1) {
      findings.push({
        scanner: "supply-chain",
        severity: "low",
        title: "Single maintainer",
        description: `Package has only 1 maintainer. Single-maintainer packages are at higher risk of account takeover.`,
        remediation: "Consider the bus-factor risk. Verify the maintainer's identity and activity.",
      });
    }

    // Check if the name resembles an official package
    if (looksOfficial(packageName) && !isKnownPackage(packageName)) {
      findings.push({
        scanner: "supply-chain",
        severity: "high",
        title: "Package mimics official naming",
        description: `Package name "${packageName}" resembles official MCP packages but is not in the known-safe list.`,
        remediation: "Verify this is the intended package and not a typosquatting attempt.",
      });
    }

    // Check description for suspicious content
    const description = metadata.description ?? "";
    if (!description || description.length < 10) {
      findings.push({
        scanner: "supply-chain",
        severity: "medium",
        title: "Missing or minimal description",
        description: "Package has no meaningful description, which is common in malicious or placeholder packages.",
      });
    }
  } catch {
    findings.push({
      scanner: "supply-chain",
      severity: "info",
      title: "Could not fetch npm registry data",
      description: `Failed to query npm registry for "${packageName}". Supply chain checks are limited.`,
    });
  }

  return findings;
}

function checkTyposquatting(packageName: string): Finding[] {
  const findings: Finding[] = [];

  const pkgLower = packageName.toLowerCase();
  for (const known of KNOWN_MCP_PACKAGES) {
    if (packageName === known) continue;

    const knownLower = known.toLowerCase();
    const distance = levenshteinDistance(pkgLower, knownLower);
    const maxLen = Math.max(packageName.length, known.length);
    const similarity = 1 - distance / maxLen;

    if (similarity > 0.8 && distance <= 3) {
      findings.push({
        scanner: "supply-chain",
        severity: "critical",
        title: "Potential typosquatting",
        description: `Package name "${packageName}" is very similar to known package "${known}" (${Math.round(similarity * 100)}% similar, edit distance: ${distance})`,
        remediation: `Verify you intended to install "${packageName}" and not "${known}".`,
      });
    }
  }

  return findings;
}

async function checkPackageScripts(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const pkgJson = JSON.parse(
      await readFile(join(targetPath, "package.json"), "utf-8")
    ) as Record<string, unknown>;

    // Check for suspicious scripts
    const scripts = pkgJson["scripts"] as Record<string, string> | undefined;
    if (scripts) {
      const dangerousHooks = ["preinstall", "postinstall", "preuninstall", "postuninstall"];
      for (const hook of dangerousHooks) {
        const script = scripts[hook];
        if (script) {
          const severity = /curl|wget|eval|bash|sh\s+-c|node\s+-e|python/.test(script) ? "critical" as const : "high" as const;
          findings.push({
            scanner: "supply-chain",
            severity,
            title: `Suspicious ${hook} script`,
            description: `Package has a ${hook} lifecycle script: "${script}"`,
            remediation: "Review lifecycle scripts carefully. Malicious packages often use install hooks to execute code.",
          });
        }
      }
    }

    // Check for install scripts downloading remote code
    if (scripts) {
      for (const [name, cmd] of Object.entries(scripts)) {
        if (/https?:\/\//.test(cmd) && /curl|wget|fetch/.test(cmd)) {
          findings.push({
            scanner: "supply-chain",
            severity: "critical",
            title: `Script "${name}" downloads remote code`,
            description: `Script "${name}" fetches code from a remote URL: ${cmd}`,
            remediation: "Scripts should not download and execute remote code. Bundle all needed code with the package.",
          });
        }
      }
    }
  } catch {
    // No package.json
  }

  return findings;
}

async function checkRepoIntegrity(targetPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const pkgJson = JSON.parse(
      await readFile(join(targetPath, "package.json"), "utf-8")
    ) as Record<string, unknown>;

    const repo = pkgJson["repository"];
    if (!repo) {
      findings.push({
        scanner: "supply-chain",
        severity: "medium",
        title: "No repository declared",
        description: "Package does not declare a repository in package.json. Source code provenance cannot be verified.",
        remediation: "Add a repository field to package.json pointing to the source code repository.",
      });
    }
  } catch {
    // Ignore
  }

  return findings;
}

function looksOfficial(name: string): boolean {
  return name.includes("modelcontextprotocol") || name.includes("mcp-server") || name.includes("mcp-official");
}

function isKnownPackage(name: string): boolean {
  return KNOWN_MCP_PACKAGES.includes(name);
}

/**
 * Compute Levenshtein edit distance between two strings.
 */
function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  // Use two rows instead of full matrix for space efficiency
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);

  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1]! + 1,
        prev[j]! + 1,
        prev[j - 1]! + cost
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n]!;
}

interface NpmMetadata {
  name?: string;
  version?: string;
  description?: string;
  maintainers?: Array<{ name: string; email?: string }>;
  time?: {
    created?: string;
    modified?: string;
    [version: string]: string | undefined;
  };
  repository?: { type?: string; url?: string } | string;
  homepage?: string;
}
