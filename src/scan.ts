import { readdir, readFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import {
  parseCargoLock,
  parseComposerLock,
  parseGemfileLock,
  parseGoMod,
  parseGradleLock,
  parseNugetLock,
  parsePackageLock,
  parsePnpmLock,
  parsePoetryLock,
  parseRequirements,
  parseUvLock,
  parseYarnLock,
} from "./parsers.ts";
import type { Ecosystem, Parsed, Scan } from "./types.ts";

const SKIP_DIRS = new Set(["node_modules", "vendor", ".git", ".venv", "venv", "dist", "build", "target", ".gradle", "__pycache__"]);
const MAX_DEPTH = 5;

const LOCKFILES: Record<string, { ecosystem: Ecosystem; parse: (lock: string, manifest?: string) => Parsed; manifest?: string }> = {
  "composer.lock": { ecosystem: "Packagist", parse: parseComposerLock, manifest: "composer.json" },
  "package-lock.json": { ecosystem: "npm", parse: parsePackageLock },
  "pnpm-lock.yaml": { ecosystem: "npm", parse: parsePnpmLock },
  "yarn.lock": { ecosystem: "npm", parse: parseYarnLock, manifest: "package.json" },
  "poetry.lock": { ecosystem: "PyPI", parse: parsePoetryLock, manifest: "pyproject.toml" },
  "uv.lock": { ecosystem: "PyPI", parse: parseUvLock, manifest: "pyproject.toml" },
  "go.mod": { ecosystem: "Go", parse: parseGoMod },
  "Cargo.lock": { ecosystem: "crates.io", parse: parseCargoLock, manifest: "Cargo.toml" },
  "Gemfile.lock": { ecosystem: "RubyGems", parse: parseGemfileLock },
  "gradle.lockfile": { ecosystem: "Maven", parse: parseGradleLock, manifest: "build.gradle" },
  "packages.lock.json": { ecosystem: "NuGet", parse: parseNugetLock },
};

const MANIFESTS: Record<string, Ecosystem> = {
  "composer.json": "Packagist",
  "package.json": "npm",
  "pyproject.toml": "PyPI",
  "Cargo.toml": "crates.io",
  Gemfile: "RubyGems",
  "pom.xml": "Maven",
  "build.gradle": "Maven",
  "build.gradle.kts": "Maven",
};

const UNSUPPORTED = new Set(["mix.lock", "pubspec.lock", "Package.resolved"]);

/** Names end up in shell commands the agent may run, so a crafted lockfile must not get through. */
export const isSafe = (s: string) => /^[@a-zA-Z0-9][a-zA-Z0-9@._/+:-]*$/.test(s);

const isRequirements = (file: string) => /^requirements.*\.txt$/.test(file);

async function walk(root: string, depth = 0): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files = entries.filter((e) => e.isFile()).map((e) => join(root, e.name));
  if (depth === MAX_DEPTH) return files;
  const dirs = entries.filter((e) => e.isDirectory() && !SKIP_DIRS.has(e.name));
  const nested = await Promise.all(dirs.map((d) => walk(join(root, d.name), depth + 1)));
  return [...files, ...nested.flat()];
}

const covers = (lockDir: string, dir: string) => dir === lockDir || dir.startsWith(lockDir + "/");

export async function scanProject(root: string, only?: Ecosystem): Promise<Scan> {
  const scan: Scan = { deps: [], private: [], unchecked: [] };
  const files = await walk(root);
  const names = new Set(files);
  const locked: { dir: string; ecosystem: Ecosystem }[] = [];

  for (const file of files) {
    const base = file.slice(file.lastIndexOf("/") + 1);
    const rel = relative(root, file);
    const spec = isRequirements(base)
      ? { ecosystem: "PyPI" as const, parse: parseRequirements, manifest: undefined }
      : LOCKFILES[base];
    if (UNSUPPORTED.has(base) && !only) scan.unchecked.push({ item: rel, reason: "ecosystem not supported yet" });
    if (!spec) continue;
    locked.push({ dir: dirname(file), ecosystem: spec.ecosystem });
    if (only && spec.ecosystem !== only) continue;
    try {
      const base = spec.manifest && join(dirname(file), spec.manifest);
      const manifestPath = base && [base, `${base}.kts`].find((p) => names.has(p));
      const manifest = manifestPath ? await readFile(manifestPath, "utf8") : undefined;
      const parsed = spec.parse(await readFile(file, "utf8"), manifest);
      for (const d of parsed.deps) {
        if (isSafe(d.name) && isSafe(d.version)) scan.deps.push({ ...d, ecosystem: spec.ecosystem, lockfile: rel });
        else scan.unchecked.push({ item: rel, reason: "entry with invalid package name or version" });
      }
      scan.private.push(...parsed.private);
      scan.unchecked.push(...parsed.unchecked);
    } catch (e) {
      scan.unchecked.push({ item: rel, reason: `could not parse: ${(e as Error).message}` });
    }
  }

  for (const file of files) {
    const base = file.slice(file.lastIndexOf("/") + 1);
    const ecosystem = base.endsWith(".csproj") ? "NuGet" : MANIFESTS[base];
    if (!ecosystem || (only && ecosystem !== only)) continue;
    const dir = dirname(file);
    if (!locked.some((l) => l.ecosystem === ecosystem && covers(l.dir, dir)))
      scan.unchecked.push({ item: relative(root, file), reason: "no lockfile, installed versions unknown" });
  }

  scan.private = [...new Set(scan.private)];
  return scan;
}
