import { execFile } from "node:child_process";
import { mkdtemp, rm, access, readFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface ResolvedPackage {
  path: string;
  name: string;
  version: string;
  isTemp: boolean;
}

/**
 * Determines if the target is a local path or an npm package name,
 * then resolves it to a local directory that can be scanned.
 */
export async function resolveTarget(target: string): Promise<ResolvedPackage> {
  if (isLocalPath(target)) {
    return resolveLocalPath(target);
  }
  return resolveNpmPackage(target);
}

function isLocalPath(target: string): boolean {
  return target.startsWith(".") || isAbsolute(target) || target.startsWith("~");
}

/** Expand a leading "~" — the shell leaves it alone when quoted, and MCP tool calls never see a shell. */
function expandHome(target: string): string {
  if (target === "~" || target.startsWith("~/")) return join(homedir(), target.slice(1));
  return target;
}

async function resolveLocalPath(target: string): Promise<ResolvedPackage> {
  // resolve() keeps absolute paths as given; join(process.cwd(), target) turned
  // "/srv/server" into "<cwd>/srv/server" and the scan failed with "not found".
  const resolvedPath = resolve(expandHome(target));
  try {
    await access(resolvedPath);
  } catch {
    throw new Error(`Local path not found: ${resolvedPath}`);
  }

  let name = target;
  let version = "local";

  try {
    const pkgJsonPath = join(resolvedPath, "package.json");
    const pkgJson = JSON.parse(await readFile(pkgJsonPath, "utf-8")) as Record<string, unknown>;
    name = String(pkgJson["name"] ?? target);
    version = String(pkgJson["version"] ?? "local");
  } catch {
    // No package.json — that's fine for local scans
  }

  return { path: resolvedPath, name, version, isTemp: false };
}

async function resolveNpmPackage(packageName: string): Promise<ResolvedPackage> {
  const tempDir = await mkdtemp(join(tmpdir(), "mcp-shield-"));

  try {
    // Use npm pack to download the package tarball
    await execFileAsync("npm", ["pack", packageName, "--pack-destination", tempDir], {
      cwd: tempDir,
      timeout: 60_000,
    });

    // Find the tarball
    const { stdout: lsOutput } = await execFileAsync("ls", [tempDir]);
    const tarball = lsOutput.trim().split("\n").find((f) => f.endsWith(".tgz"));
    if (!tarball) {
      throw new Error(`Failed to download package: ${packageName}`);
    }

    // Extract the tarball
    await execFileAsync("tar", ["xzf", join(tempDir, tarball), "-C", tempDir]);

    const extractedPath = join(tempDir, "package");

    // Install dependencies for audit
    try {
      await execFileAsync("npm", ["install", "--ignore-scripts", "--no-audit"], {
        cwd: extractedPath,
        timeout: 120_000,
      });
    } catch {
      // Installation might fail but we can still scan source
    }

    let version = "unknown";
    try {
      const pkgJson = JSON.parse(await readFile(join(extractedPath, "package.json"), "utf-8")) as Record<string, unknown>;
      version = String(pkgJson["version"] ?? "unknown");
    } catch {
      // Ignore
    }

    return { path: extractedPath, name: packageName, version, isTemp: true };
  } catch (error) {
    // Cleanup on failure
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    throw new Error(`Failed to resolve npm package "${packageName}": ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Clean up a temporary directory created by resolveTarget */
export async function cleanupResolved(resolved: ResolvedPackage): Promise<void> {
  if (resolved.isTemp) {
    // The temp dir is the parent of the "package" dir
    const tempDir = join(resolved.path, "..");
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}
