import { relative } from "node:path";
import type { Finding, ScanConfig, Scanner, FileCache } from "../types.js";
import { createPassFinding } from "../types.js";

interface LineContext {
  line: string;
  file: string;
  lineNum: number;
  findings: Finding[];
}

export const transportSecurityScanner: Scanner = {
  name: "transport-security",

  async run(config: ScanConfig, cache: FileCache): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const [filePath, content] of cache.contents) {
      const relPath = relative(config.targetPath, filePath);
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const ctx: LineContext = { line: lines[i]!, file: relPath, lineNum: i + 1, findings };
        checkInsecureHttp(ctx);
        checkCorsMisconfig(ctx);
        checkTokenInQueryString(ctx);
        checkTlsDisabled(ctx);
        checkAuthPatterns(ctx);
      }
    }

    if (findings.length === 0) {
      findings.push(createPassFinding("transport-security", "No transport security issues detected", "Transport configuration appears secure"));
    }

    return findings;
  },
};

function checkInsecureHttp({ line, file, lineNum, findings }: LineContext): void {
  // Loopback never leaves the machine, so plain HTTP to it is not a transport
  // risk. The host must end there (port, path, query, fragment or closing quote):
  // "localhost.evil.com" is a remote host and is still flagged.
  const httpPattern = /["'`]http:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[:/?#"'`])[^"'`\s]+["'`]/g;
  if (httpPattern.test(line)) {
    findings.push({
      scanner: "transport-security",
      severity: "high",
      title: "Insecure HTTP endpoint",
      description: `Non-localhost HTTP URL found at ${file}:${lineNum}. Use HTTPS for remote connections.`,
      file,
      line: lineNum,
      remediation: "Replace http:// with https:// for all non-localhost endpoints.",
    });
  }
}

function checkCorsMisconfig({ line, file, lineNum, findings }: LineContext): void {
  if (/Access-Control-Allow-Origin['"]*\s*[,:=]\s*['"`]\*['"`]/.test(line) || /cors\(\s*\)/.test(line) || /origin\s*:\s*(?:true|\*|['"`]\*['"`])/.test(line)) {
    findings.push({
      scanner: "transport-security",
      severity: "medium",
      title: "Permissive CORS configuration",
      description: `CORS allows all origins at ${file}:${lineNum}. This may be acceptable for local stdio servers but is risky for HTTP-based servers.`,
      file,
      line: lineNum,
      remediation: "Restrict CORS to specific trusted origins instead of using wildcard (*) for HTTP-based servers.",
    });
  }

  if (/credentials\s*:\s*true/.test(line) && /origin\s*:\s*(?:true|\*)/.test(line)) {
    findings.push({
      scanner: "transport-security",
      severity: "high",
      title: "CORS credentials with wildcard origin",
      description: `CORS allows credentials with permissive origin at ${file}:${lineNum}`,
      file,
      line: lineNum,
      remediation: "Never use credentials: true with origin: * or origin: true. Specify explicit allowed origins.",
    });
  }
}

function checkTokenInQueryString({ line, file, lineNum, findings }: LineContext): void {
  if (/[?&](?:token|key|api[_-]?key|auth|access[_-]?token|secret)=/i.test(line)) {
    findings.push({
      scanner: "transport-security",
      severity: "high",
      title: "Auth token in query string",
      description: `Authentication credential passed in URL query string at ${file}:${lineNum}. Tokens in URLs are logged and cached.`,
      file,
      line: lineNum,
      remediation: "Pass authentication tokens in Authorization headers, not in URL query parameters.",
    });
  }
}

function checkTlsDisabled({ line, file, lineNum, findings }: LineContext): void {
  if (
    /rejectUnauthorized\s*:\s*false/.test(line) ||
    /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0/.test(line) ||
    /verify\s*=\s*False/.test(line) ||
    /InsecureRequestWarning/.test(line)
  ) {
    findings.push({
      scanner: "transport-security",
      severity: "critical",
      title: "TLS verification disabled",
      description: `TLS certificate verification is disabled at ${file}:${lineNum}. This allows man-in-the-middle attacks.`,
      file,
      line: lineNum,
      remediation: "Enable TLS certificate verification. If using self-signed certs in development, use a proper CA chain.",
    });
  }
}

function checkAuthPatterns({ line, file, lineNum, findings }: LineContext): void {
  if (/\.(get|post|put|delete|patch)\s*\(\s*['"`]\//.test(line) && !/auth|verify|protect|middleware|guard/i.test(line)) {
    if (/admin|user|account|payment|secret|internal|api\/v/i.test(line)) {
      findings.push({
        scanner: "transport-security",
        severity: "medium",
        title: "Potentially unprotected route",
        description: `Sensitive-looking route handler without visible auth middleware at ${file}:${lineNum}`,
        file,
        line: lineNum,
        remediation: "Ensure authentication middleware is applied to sensitive routes.",
      });
    }
  }
}
