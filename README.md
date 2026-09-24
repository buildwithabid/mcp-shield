<div align="center">

```
                          _____ __    _      __    __
   ____ ___  _________   / ___// /_  (_)__  / /___/ /
  / __ `__ \/ ___/ __ \  \__ \/ __ \/ / _ \/ / __  /
 / / / / / / /__/ /_/ / ___/ / / / / /  __/ / /_/ /
/_/ /_/ /_/\___/ .___/ /____/_/ /_/_/\___/_/\__,_/
              /_/
```

# mcp-shield

**Security scanner for Model Context Protocol (MCP) servers**

Find vulnerabilities, prompt injection, secrets leaks, and supply chain attacks in MCP servers — before your AI agent does.

[![CI](https://github.com/BuildWithAbid/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/BuildWithAbid/mcp-shield/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-18%20%7C%2020%20%7C%20≥22-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://www.typescriptlang.org/)
[![npm](https://img.shields.io/npm/v/@buildwithabid/mcp-shield.svg)](https://www.npmjs.com/package/@buildwithabid/mcp-shield)

[Quick Start](#quick-start) &bull; [Security Checks](#7-security-checks) &bull; [MCP Server Mode](#mcp-server-mode) &bull; [Documentation](#documentation) &bull; [Contributing](#contributing)

</div>

---

## Why mcp-shield?

MCP servers are the new attack surface for AI applications. Recent research has found:

- **66% of MCP servers** have at least one security vulnerability
- **Tool description injection** is the #1 attack vector — malicious servers embed hidden instructions that manipulate the AI agent
- **Rug-pull attacks** change tool behavior after a user approves them
- **Supply chain attacks** through typosquatting and malicious npm packages are increasing

**mcp-shield** is a dedicated security scanner for the MCP ecosystem. It runs 7 security checks against any MCP server package, produces a scored report, and works as both a CLI tool and an MCP server itself.

---

## Quick Start

### Install and Run

```bash
# Run directly with npx (no install needed)
npx @buildwithabid/mcp-shield scan <target>

# Or install globally
npm install -g @buildwithabid/mcp-shield
```

### Scan an MCP Server

```bash
# Scan an npm package
npx @buildwithabid/mcp-shield scan @modelcontextprotocol/server-filesystem

# Scan a local project
npx @buildwithabid/mcp-shield scan ./my-mcp-server

# JSON output for CI/CD
npx @buildwithabid/mcp-shield scan @some/mcp-server --format json

# Markdown report saved to file
npx @buildwithabid/mcp-shield scan @some/mcp-server --format markdown --output report.md

# Quick scan (skip slow checks like rug-pull detection)
npx @buildwithabid/mcp-shield scan @some/mcp-server --quick
```

### Example Output

```
Resolving target: @example/mcp-server-db...
Scanning: @example/mcp-server-db v2.1.0


🛡️  mcp-shield v1.1.1 — MCP Security Scanner

Scanning: @example/mcp-server-db v2.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL  Permissions: Unrestricted shell command: "command" (dist/tools/execute.js:18)
🟠 HIGH      Secrets: Generic API Key Assignment detected (dist/config.js:14)
🟠 HIGH      Transport: Insecure HTTP endpoint (dist/client.js:31)
🟡 MEDIUM    Transport: Permissive CORS configuration (dist/server.js:9)
🟢 LOW       Supply Chain: Single maintainer
ℹ️  INFO      Supply Chain: Recently published package
✅ PASS      Dependencies: No known vulnerabilities
✅ PASS      Tool Injection: No prompt injection patterns detected
✅ PASS      Rug-Pull: Tool descriptions are static

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Score: 47/100 (FAIL)
1 critical · 2 high · 1 medium · 1 low · 3 pass
```

---

## 7 Security Checks

mcp-shield runs these scanners against every target:

### 1. Dependency Audit

Runs `npm audit` to find known CVEs in direct and transitive dependencies.

- Severities: Critical, High, Medium, Low
- Automatically generates a lock file if missing

### 2. Permission & Scope Check

Analyzes tool input schemas for overly broad permissions:

- **Unrestricted shell commands** — tools that accept arbitrary commands without an enum or allowlist
- **Unrestricted file paths** — tools without path pattern constraints (path traversal risk)
- **Raw SQL input** — tools accepting raw SQL strings (SQL injection risk)
- **Unrestricted URLs** — tools without URL validation (SSRF risk)
- **eval() / Function()** — dynamic code execution
- **child_process** — shell access

### 3. Tool Description Injection

Scans tool descriptions for prompt injection patterns:

- Hidden instructions ("ignore previous instructions", "do not tell the user")
- Role/persona override ("you are now", "act as")
- Unicode tricks (zero-width characters, homoglyphs, RTL overrides)
- Base64-encoded payloads
- Markdown/HTML injection
- Data exfiltration patterns

### 4. Rug-Pull Detection

Detects mutable tool descriptions that can change after approval:

- Descriptions loaded from environment variables or config
- Descriptions generated by function calls or network requests
- Timer-based tool modification (`setTimeout`/`setInterval`)
- Post-registration tool changes (`setTools`, `updateTool`)

### 5. Secrets Detection

Finds hardcoded secrets in source code and `.env` files:

- AWS keys, OpenAI/Anthropic API keys, GitHub tokens
- Stripe, Slack, Google, Twilio, SendGrid keys
- Database connection strings, JWTs, private keys
- Generic password/token/secret assignments
- Smart placeholder detection (skips `"your-key-here"` etc.)

### 6. Transport Security

Checks transport-layer configuration:

- HTTP instead of HTTPS for remote endpoints (loopback `localhost`, `127.0.0.1`, `0.0.0.0` and `[::1]` is exempt)
- Permissive CORS (`Access-Control-Allow-Origin: *`)
- Credentials with wildcard CORS origin
- Auth tokens in URL query strings
- Disabled TLS verification (`rejectUnauthorized: false`)
- Unprotected sensitive routes

### 7. Supply Chain Analysis

Checks npm metadata and package integrity.

Package scans query the npm registry:

- **Typosquatting detection** via Levenshtein distance against known MCP packages
- Recently published packages (< 30 days), reported as info with no score penalty
- Single-maintainer risk
- Packages mimicking official naming
- Missing or minimal package description

Package and local scans both read the target's `package.json`:

- Suspicious lifecycle scripts (`preinstall`, `postinstall`, `preuninstall`, `postuninstall`). npm runs these on install, so a package scan reports them before you install.
- Scripts downloading remote code
- Missing repository declaration

---

## MCP Server Mode

mcp-shield also runs as an MCP server, so AI assistants can scan other MCP servers directly:

```bash
# Start the MCP server
npx @buildwithabid/mcp-shield serve

# Add to Claude Code
claude mcp add mcp-shield -- npx @buildwithabid/mcp-shield serve
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `scan_package` | Scan an npm MCP server package by name (package scan) |
| `scan_local` | Scan a local directory for security issues (local scan) |
| `get_report` | Get the last scan report (JSON, Markdown, or terminal format) |

---

## Documentation

### CLI Reference

```
Usage: mcp-shield scan [options] <target>

Scan an MCP server package or local directory for security vulnerabilities

Arguments:
  target                 npm package name or local path to scan

Options:
  -f, --format <format>  Output format: terminal, json, markdown (default: "terminal")
  -o, --output <file>    Write report to file
  -q, --quick            Skip slow checks (rug-pull detection) (default: false)
  -h, --help             display help for command
```

```
Usage: mcp-shield serve [options]

Run mcp-shield as an MCP server

Options:
  -h, --help  display help for command
```

`mcp-shield --version` prints the installed version. With `--output`, the report is written to the file and also printed. The MCP server uses the stdio transport.

A target that starts with `.`, `/` or `~`, or is any absolute path, is a local path; anything else is looked up on npm. Relative paths resolve against the current directory, absolute paths are used as given, and a leading `~` expands to your home directory.

### What Gets Scanned

mcp-shield reads source and config files under the target: JavaScript and TypeScript, Python, JSON, YAML, TOML, INI and XML config, `.env` files, shell scripts, and Ruby, Go, Rust, Java, Kotlin, C#, PHP and Terraform files. Which directories it skips depends on the kind of scan:

| Directories | Local scan (a path on disk) | Package scan (downloaded from npm) |
|-------------|-----------------------------|------------------------------------|
| `node_modules/`, `.git/`, `coverage/`, `__pycache__/`, `.venv/`, `venv/`, `.tox/`, `.mypy_cache/`, `.pytest_cache/` | Skipped | Skipped |
| `dist/`, `build/`, `out/`, `.next/` | Skipped: this is your own build output, and bundled chunks produce false findings for code you never wrote | Scanned: it is often the only code a published package ships |

In both kinds of scan mcp-shield also skips:

- Build tooling that never reaches a client: `build.js`/`.mjs`/`.ts`, `gulpfile.js`, `Gruntfile.js`, `esbuild.config.js`/`.mjs`, and `rollup`, `webpack`, `vite`, `jest`, `vitest`, `babel`, `eslint`, `prettier`, `tsup`, `tailwind`, `postcss` and `commitlint` config files
- Compiled `.js` when the `.ts` it came from sits beside it, and a `.d.ts` when its `.js` sits beside it, so each finding is reported once
- Files larger than 1 MB

### Output Formats

| Format | Flag | Best For |
|--------|------|----------|
| Terminal | `--format terminal` (default) | Human-readable with colors and severity icons |
| JSON | `--format json` | CI/CD pipelines, programmatic access |
| Markdown | `--format markdown` | GitHub issues, pull requests, wikis |

### Scoring System

Every scan starts at 100. Findings are counted per severity, and each severity deducts `unit × √count`, up to a cap:

| Severity | Unit | Cap | 1 finding | 4 findings | Cap reached at | Examples |
|----------|------|-----|-----------|------------|----------------|----------|
| Critical | 25 | 60 | -25 | -50 | 6 findings | eval(), unrestricted shell command, TLS verification disabled, AWS key, typosquatting |
| High | 15 | 40 | -15 | -30 | 8 findings | child_process call, insecure HTTP endpoint, generic API key, unrestricted file path |
| Medium | 5 | 20 | -5 | -10 | 16 findings | Filesystem write, permissive CORS, no repository declared |
| Low | 2 | 8 | -2 | -4 | 16 findings | Filesystem read, environment variable access, single maintainer |
| Info | 0 | 0 | 0 | 0 | never | Recently published package, audit could not run |
| Pass | 0 | 0 | 0 | 0 | never | Check passed cleanly |

The result is rounded and never goes below 0. The square root means the tenth instance of a pattern costs less than the first. The cap means no single severity can sink a package on its own: a long tail of low findings costs at most 8 points. The example above scores 100 − 25 − 15×√2 − 5 − 2 = 46.8, shown as 47.

**Score ≥ 70** = PASS. **Score < 70** = FAIL. The CLI exits with code 0 on PASS and 1 on FAIL (also 1 if the target cannot be resolved), and 2 if the scan itself errors, so CI can gate on it.

### Architecture

```
                  ┌─────────────┐
                  │   CLI / MCP  │  (index.ts / mcp-server.ts)
                  │   Server     │
                  └──────┬───────┘
                         │
                  ┌──────▼───────┐
                  │ Orchestrator │  (scanner/index.ts)
                  │  File Cache  │  Collects files once, shares across scanners
                  └──────┬───────┘
                         │
        ┌────────┬───────┼───────┬────────┬────────┬────────┐
        ▼        ▼       ▼       ▼        ▼        ▼        ▼
   ┌────────┐┌───────┐┌──────┐┌───────┐┌───────┐┌───────┐┌───────┐
   │Secrets ││ Deps  ││ Tool ││ Perms ││Rug-Pull││ Trans ││Supply │
   │  Leak  ││ Audit ││ Desc ││ Check ││Detect  ││  Sec  ││ Chain │
   └────────┘└───────┘└──────┘└───────┘└───────┘└───────┘└───────┘
        │        │       │       │        │        │        │
        └────────┴───────┴───────┴────────┴────────┴────────┘
                         │
                  ┌──────▼───────┐
                  │   Reporter   │  Terminal / JSON / Markdown
                  └──────────────┘
```

All 7 scanners run concurrently using `Promise.allSettled`, sharing a single file cache for maximum performance.

---

## Use Cases

### CI/CD Pipeline

```bash
# Fail the build if the MCP server has security issues
npx @buildwithabid/mcp-shield scan ./my-mcp-server --format json
# Exit code 1 if score < 70
```

### Pre-Install Check

```bash
# Check an MCP server package before installing it
npx @buildwithabid/mcp-shield scan @unknown/mcp-server-database
```

### Security Audit

```bash
# Generate a markdown report for a security review
npx @buildwithabid/mcp-shield scan @company/internal-mcp-server --format markdown --output audit-report.md
```

### AI-Assisted Scanning

```bash
# Let Claude scan MCP servers from within a conversation
claude mcp add mcp-shield -- npx @buildwithabid/mcp-shield serve
# Then ask: "Scan @modelcontextprotocol/server-filesystem for security issues"
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and guidelines.

### Areas Where Help Is Needed

- **New detection patterns** — prompt injection techniques, secret formats, dangerous APIs
- **Live server scanning** — connecting to running MCP servers to test tool responses
- **PyPI / pip support** — extending to Python MCP servers
- **CI/CD integrations** — GitHub Actions workflow, pre-commit hooks
- **Documentation** — guides, tutorials, real-world examples

---

## Related Projects

- [Model Context Protocol](https://modelcontextprotocol.io) — the protocol specification
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) — official TypeScript SDK
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) — AI coding assistant with MCP support

---

## License

[MIT](LICENSE) — free for personal and commercial use.


---

**Available for MCP work** — tool surface reviews, production builds, and keeping them running afterwards. Scope and fixed prices: **[The Write Path](https://claude.ai/artifact/F1w4szMDEa6e4NonRyFqp6)**

Built by [Abid Ali](https://github.com/buildwithabid), who runs a guarded MCP server over live invoices and statutory filing deadlines every working day. 📬 support@bizfilo.com
