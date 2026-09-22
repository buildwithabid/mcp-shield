import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import type { ScanMode } from "../types.js";
import { BUILD_OUTPUT_DIRS, SCANNABLE_EXTENSIONS, SKIP_DIRS, SKIP_FILES, SKIP_FILE_RE } from "./patterns.js";

const LOCAL_SKIP_DIRS: ReadonlySet<string> = new Set([...SKIP_DIRS, ...BUILD_OUTPUT_DIRS]);

/**
 * Recursively collect all scannable source files in a directory.
 *
 * Local scans skip build output; package scans read it, because a published
 * package often ships nothing else (see BUILD_OUTPUT_DIRS).
 */
export async function collectSourceFiles(dir: string, mode: ScanMode = "local"): Promise<string[]> {
  const files: string[] = [];
  await walkDir(dir, files, mode === "package" ? SKIP_DIRS : LOCAL_SKIP_DIRS);
  return dropCompiledDuplicates(files);
}

/**
 * Drop emitted JavaScript when the TypeScript it was compiled from sits beside it.
 *
 * Packages that ship both `src/foo.ts` and `src/foo.js` are publishing one
 * implementation in two forms. Scanning both reports every finding twice, which
 * silently doubles the severity counts for any package that ships its sources —
 * good practice being punished. The `.ts` is kept because its line numbers are
 * the ones a maintainer can act on.
 *
 * Likewise a `foo.d.ts` beside `foo.js` is dropped: it is emitted from the same
 * code and repeats its constants as literal types, so every key or URL in
 * dist/ was reported twice. A declaration file with no JS beside it is kept.
 */
function dropCompiledDuplicates(files: string[]): string[] {
  const COMPILED = new Set([".js", ".mjs", ".cjs"]);
  const SOURCE = [".ts", ".tsx", ".mts", ".cts"];
  const DECLARATION = /\.d\.[cm]?ts$/i;

  const present = new Set(files);
  return files.filter((f) => {
    const decl = DECLARATION.exec(f);
    if (decl) {
      const stem = f.slice(0, decl.index);
      return ![...COMPILED].some((c) => present.has(stem + c));
    }
    const ext = extname(f).toLowerCase();
    if (!COMPILED.has(ext)) return true;
    const stem = f.slice(0, -ext.length);
    return !SOURCE.some((s) => present.has(stem + s));
  });
}

async function walkDir(dir: string, files: string[], skipDirs: ReadonlySet<string>): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (skipDirs.has(entry.name)) continue;

    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkDir(fullPath, files, skipDirs);
    } else if (entry.isFile()) {
      if (SKIP_FILES.has(entry.name) || SKIP_FILE_RE.test(entry.name)) continue;
      const ext = extname(entry.name).toLowerCase();
      // Also include extensionless dotfiles like .env
      if (SCANNABLE_EXTENSIONS.has(ext) || entry.name.startsWith(".env")) {
        files.push(fullPath);
      }
    }
  }
}

/**
 * Read a file safely, returning null if it can't be read.
 */
export async function safeReadFile(filePath: string): Promise<string | null> {
  try {
    const stats = await stat(filePath);
    // Skip files larger than 1MB
    if (stats.size > 1_048_576) return null;
    return await readFile(filePath, "utf-8");
  } catch {
    return null;
  }
}

/**
 * Find lines matching a pattern in file content, returning line numbers and matched text.
 */
export function findPatternMatches(
  content: string,
  pattern: RegExp
): Array<{ line: number; match: string; lineContent: string }> {
  const lines = content.split("\n");
  const results: Array<{ line: number; match: string; lineContent: string }> = [];

  // Reset regex state
  const regex = new RegExp(pattern.source, pattern.flags);

  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i]!;
    regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = regex.exec(lineContent)) !== null) {
      results.push({
        line: i + 1,
        match: match[0],
        lineContent: lineContent.trim(),
      });
      // Prevent infinite loops on zero-length matches
      if (match.index === regex.lastIndex) {
        regex.lastIndex++;
      }
    }
  }

  return results;
}

/**
 * Check if a file path looks like a test or fixture file.
 */
export function isTestFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.includes("test") ||
    lower.includes("spec") ||
    lower.includes("__tests__") ||
    lower.includes("fixture") ||
    lower.includes("mock") ||
    lower.includes("example")
  );
}

/**
 * Extract tool definitions from source code by looking for common MCP server patterns.
 * This is a heuristic-based approach, not full AST parsing.
 */
export function extractToolDefinitionsFromSource(content: string): Array<{
  name: string;
  descriptionText: string;
  line: number;
}> {
  const tools: Array<{ name: string; descriptionText: string; line: number }> = [];
  const lines = content.split("\n");

  // Pattern: server.tool("name", "description", ...)
  // or tool definitions in object form
  const toolDefPattern = /\.tool\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*["'`]([\s\S]*?)["'`]/g;

  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i]!;
    toolDefPattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = toolDefPattern.exec(lineContent)) !== null) {
      tools.push({
        name: match[1]!,
        descriptionText: match[2]!,
        line: i + 1,
      });
    }
  }

  // Also look for description fields in object literals
  const descFieldPattern = /description\s*:\s*["'`]([\s\S]*?)["'`]/g;
  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i]!;
    descFieldPattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = descFieldPattern.exec(lineContent)) !== null) {
      // Check if this is near a tool name definition
      const contextStart = Math.max(0, i - 5);
      const contextLines = lines.slice(contextStart, i + 1).join("\n");
      const nameMatch = /name\s*:\s*["'`]([^"'`]+)["'`]/.exec(contextLines);
      if (nameMatch) {
        tools.push({
          name: nameMatch[1]!,
          descriptionText: match[1]!,
          line: i + 1,
        });
      }
    }
  }

  return tools;
}

/**
 * Detect if tool descriptions are dynamically generated
 * (potential rug-pull vector).
 */
export function detectDynamicDescriptions(content: string): Array<{
  line: number;
  reason: string;
}> {
  const findings: Array<{ line: number; reason: string }> = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Template literals with expressions in description fields
    if (/description\s*:\s*`[^`]*\$\{/.test(line)) {
      findings.push({ line: i + 1, reason: "Description uses template literal with dynamic expression" });
    }

    // Descriptions built from variables
    if (/description\s*:\s*[a-zA-Z_]\w*\s*(?:[,\n}]|$)/.test(line) && !/description\s*:\s*["'`]/.test(line)) {
      findings.push({ line: i + 1, reason: "Description assigned from variable (may be mutable)" });
    }

    // Descriptions from function calls
    if (/description\s*:\s*\w+\s*\(/.test(line)) {
      findings.push({ line: i + 1, reason: "Description generated by function call" });
    }

    // Descriptions from env vars
    if (/description\s*:.*process\.env/.test(line)) {
      findings.push({ line: i + 1, reason: "Description includes environment variable" });
    }

    // Descriptions from fetch/axios/http calls nearby
    if (/(?:fetch|axios|http|request)\s*\(/.test(line)) {
      // Check if within 10 lines of a description assignment
      const nearby = lines.slice(Math.max(0, i - 10), i + 10).join("\n");
      if (/description/.test(nearby)) {
        findings.push({ line: i + 1, reason: "Network call near tool description definition" });
      }
    }
  }

  return findings;
}
