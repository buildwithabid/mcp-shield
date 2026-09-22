/** Patterns for detecting hardcoded secrets in source code */
export const SECRET_PATTERNS: ReadonlyArray<{
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
}> = [
  // AWS
  { name: "AWS Access Key ID", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
  { name: "AWS Secret Access Key", pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/g, severity: "critical" },

  // OpenAI / Anthropic / AI API keys
  { name: "OpenAI API Key", pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, severity: "critical" },
  { name: "Anthropic API Key", pattern: /sk-ant-[A-Za-z0-9\-_]{80,}/g, severity: "critical" },
  { name: "Generic Secret Key (sk-)", pattern: /(?:api[_-]?key|secret[_-]?key|token)\s*[=:]\s*["']sk-[A-Za-z0-9]{20,}["']/gi, severity: "critical" },

  // GitHub
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: "critical" },
  { name: "GitHub Personal Access Token (classic)", pattern: /ghp_[A-Za-z0-9]{36}/g, severity: "critical" },

  // Generic tokens and passwords
  { name: "Generic API Key Assignment", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["'][A-Za-z0-9\-_]{16,}["']/gi, severity: "high" },
  { name: "Generic Password Assignment", pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}["']/gi, severity: "high" },
  { name: "Generic Token Assignment", pattern: /(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[=:]\s*["'][A-Za-z0-9\-_.]{16,}["']/gi, severity: "high" },
  { name: "Generic Secret Assignment", pattern: /(?:client[_-]?secret|app[_-]?secret)\s*[=:]\s*["'][A-Za-z0-9\-_.]{16,}["']/gi, severity: "high" },

  // Private keys
  { name: "RSA Private Key", pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: "critical" },
  { name: "SSH Private Key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: "critical" },

  // Database connection strings
  { name: "Database Connection String", pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+:[^\s"']+@[^\s"']+/gi, severity: "critical" },

  // Stripe
  { name: "Stripe Secret Key", pattern: /sk_live_[A-Za-z0-9]{24,}/g, severity: "critical" },
  { name: "Stripe Publishable Key", pattern: /pk_live_[A-Za-z0-9]{24,}/g, severity: "medium" },

  // Slack
  { name: "Slack Token", pattern: /xox[bprs]-[A-Za-z0-9\-]{10,}/g, severity: "critical" },

  // Google
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: "high" },

  // JWT
  { name: "JSON Web Token", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: "high" },

  // Twilio
  { name: "Twilio API Key", pattern: /SK[0-9a-fA-F]{32}/g, severity: "high" },

  // SendGrid
  { name: "SendGrid API Key", pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, severity: "critical" },

  // Hex-encoded secrets
  { name: "Hex-encoded Secret", pattern: /(?:secret|private[_-]?key|signing[_-]?key)\s*[=:]\s*["'][0-9a-fA-F]{32,}["']/gi, severity: "high" },
];

/** Patterns for detecting prompt injection in tool descriptions */
export const INJECTION_PATTERNS: ReadonlyArray<{
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
}> = [
  // Direct instruction injection
  { name: "Ignore previous instructions", pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|context|rules|prompts)/gi, severity: "critical" },
  { name: "System prompt override", pattern: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|your\s+new\s+(?:role|instructions|prompt))/gi, severity: "critical" },
  { name: "Do not tell the user", pattern: /(?:do\s+not|don't|never)\s+(?:tell|inform|reveal|show|disclose)\s+(?:the\s+)?user/gi, severity: "critical" },

  // Hidden text techniques
  { name: "Zero-width characters", pattern: /[\u200B\u200C\u200D\uFEFF\u00AD]/g, severity: "high" },
  { name: "Unicode tag characters", pattern: /[\u{E0001}-\u{E007F}]/gu, severity: "high" },
  { name: "Right-to-left override", pattern: /[\u202A-\u202E\u2066-\u2069]/g, severity: "high" },

  // Markdown injection
  { name: "Markdown image exfiltration", pattern: /!\[.*?\]\(https?:\/\/[^\s)]*\{/gi, severity: "critical" },
  { name: "Markdown link with data exfiltration", pattern: /\[.*?\]\(https?:\/\/.*?(?:callback|exfil|steal|leak|webhook)/gi, severity: "high" },

  // Encoded payloads
  { name: "Base64 encoded block", pattern: /(?:atob|decode|base64)\s*\(\s*["'][A-Za-z0-9+/=]{20,}["']\s*\)/gi, severity: "high" },
  { name: "Hex escape sequences", pattern: /(?:\\x[0-9a-fA-F]{2}){8,}/g, severity: "medium" },

  // Behavioral manipulation
  { name: "Always/must execute pattern", pattern: /(?:always|must|required\s+to)\s+(?:execute|run|call|invoke)\s+(?:this|the)\s+(?:tool|function|command)/gi, severity: "high" },
  { name: "Before responding pattern", pattern: /before\s+(?:responding|answering|replying)\s*,?\s*(?:always|first|must)/gi, severity: "high" },
  { name: "Without user consent", pattern: /without\s+(?:asking|confirming|user\s+(?:consent|approval|permission))/gi, severity: "critical" },

  // Data exfiltration instructions
  { name: "Send data to URL", pattern: /(?:send|post|forward|transmit|exfiltrate)\s+(?:the\s+)?(?:data|information|contents?|results?|response)\s+(?:to|at)\s+(?:https?:\/\/|the\s+(?:url|endpoint))/gi, severity: "critical" },
  { name: "Include in URL", pattern: /include\s+(?:the\s+)?(?:data|information|key|token|secret|password)\s+(?:in|as)\s+(?:the\s+)?(?:url|query|parameter)/gi, severity: "critical" },

  // Hidden instructions in description
  { name: "HTML comment injection", pattern: /<!--[\s\S]*?(?:instruction|ignore|override|system)[\s\S]*?-->/gi, severity: "high" },
  { name: "Invisible instruction separator", pattern: /\n{5,}/g, severity: "medium" },
];

/** Well-known legitimate MCP server packages for typosquatting detection */
export const KNOWN_MCP_PACKAGES: ReadonlyArray<string> = [
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-gitlab",
  "@modelcontextprotocol/server-google-maps",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-slack",
  "@modelcontextprotocol/server-sqlite",
  "@modelcontextprotocol/server-brave-search",
  "@modelcontextprotocol/server-fetch",
  "@modelcontextprotocol/server-everything",
  "@modelcontextprotocol/server-sequential-thinking",
];

/** Dangerous input patterns in tool schemas */
export const DANGEROUS_SCHEMA_PATTERNS: ReadonlyArray<{
  name: string;
  check: (propertyName: string, schema: Record<string, unknown>) => boolean;
  severity: "critical" | "high" | "medium";
  description: string;
}> = [
  {
    name: "Unrestricted shell command",
    check: (propertyName, schema) => {
      const desc = String(schema["description"] ?? "").toLowerCase();
      const propLower = propertyName.toLowerCase();
      return (
        (desc.includes("command") || desc.includes("shell") || desc.includes("exec") || propLower.includes("command") || propLower.includes("cmd")) &&
        schema["type"] === "string" &&
        !schema["enum"] &&
        !schema["pattern"]
      );
    },
    severity: "critical",
    description: "Tool accepts arbitrary shell commands without restriction",
  },
  {
    name: "Unrestricted file path",
    check: (propertyName, schema) => {
      const desc = String(schema["description"] ?? "").toLowerCase();
      const propLower = propertyName.toLowerCase();
      return (
        (desc.includes("path") || desc.includes("file") || propLower.includes("path") || propLower.includes("file")) &&
        schema["type"] === "string" &&
        !schema["pattern"] &&
        !schema["enum"]
      );
    },
    severity: "high",
    description: "Tool accepts unrestricted file paths (path traversal risk)",
  },
  {
    name: "Raw SQL input",
    check: (propertyName, schema) => {
      const desc = String(schema["description"] ?? "").toLowerCase();
      const propLower = propertyName.toLowerCase();
      return (
        (desc.includes("sql") || desc.includes("query") || propLower.includes("sql") || propLower.includes("query")) &&
        schema["type"] === "string" &&
        !schema["enum"]
      );
    },
    severity: "high",
    description: "Tool accepts raw SQL queries (SQL injection risk)",
  },
  {
    name: "Unrestricted URL",
    check: (propertyName, schema) => {
      const desc = String(schema["description"] ?? "").toLowerCase();
      const propLower = propertyName.toLowerCase();
      return (
        (desc.includes("url") || propLower.includes("url") || propLower.includes("endpoint")) &&
        schema["type"] === "string" &&
        !schema["pattern"] &&
        !schema["enum"] &&
        !schema["format"]
      );
    },
    severity: "medium",
    description: "Tool accepts unrestricted URLs (SSRF risk)",
  },
  {
    name: "Glob wildcard accepted",
    check: (_propertyName, schema) => {
      const desc = String(schema["description"] ?? "").toLowerCase();
      return desc.includes("glob") || desc.includes("wildcard") || desc.includes("*");
    },
    severity: "medium",
    description: "Tool accepts glob/wildcard patterns that could match broadly",
  },
];

/** File extensions to scan for secrets */
export const SCANNABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".pyw",
  ".json", ".jsonc",
  ".yaml", ".yml",
  ".toml",
  ".env", ".env.example", ".env.local", ".env.development", ".env.production",
  ".cfg", ".ini", ".conf",
  ".xml",
  ".sh", ".bash", ".zsh",
  ".rb",
  ".go",
  ".rs",
  ".java", ".kt",
  ".cs",
  ".php",
  ".tf", ".tfvars",
]);

/** Files/dirs to skip during scanning */
export const SKIP_DIRS: ReadonlySet<string> = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  ".tox",
  ".mypy_cache",
  ".pytest_cache",
]);

/**
 * Build and tooling scripts to skip.
 *
 * These run on the maintainer's machine at build time. They are not loaded when
 * an MCP client connects, so they are not part of the server's attack surface —
 * but they are exactly the files that legitimately shell out and write to disk,
 * so scanning them produced high-severity findings for behaviour that can never
 * reach a user.
 */
export const SKIP_FILES: ReadonlySet<string> = new Set([
  "build.js",
  "build.mjs",
  "build.ts",
  "gulpfile.js",
  "Gruntfile.js",
  "esbuild.config.js",
  "esbuild.config.mjs",
]);

/** Matches config/tooling files such as vite.config.ts or webpack.config.js */
export const SKIP_FILE_RE =
  /^(?:rollup|webpack|vite|jest|vitest|babel|eslint|prettier|tsup|tailwind|postcss|commitlint)\.config\.[cm]?[jt]s$/;
