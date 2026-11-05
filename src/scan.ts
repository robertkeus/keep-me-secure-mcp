import { readdir, readFile, stat } from "node:fs/promises";
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
import { PLATFORM_FILES, PLATFORM_PACKAGES } from "./platforms.ts";
import type { Ecosystem, Parsed, Scan } from "./types.ts";

const SKIP_DIRS = new Set(["node_modules", "vendor", ".git", ".venv", "venv", "dist", "build", "target", ".gradle", "__pycache__"]);
const MAX_DEPTH = 5;
const MAX_IGNORED_LISTED = 20;
const MAX_LISTED = 100;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
/** Lockfiles here are usually samples that never ship. Name one with `path` to check it anyway. */
const TEST_DIRS = new Set(["test", "tests", "__tests__", "spec", "fixtures", "__fixtures__", "testdata", "example", "examples", "samples"]);

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
export const isSafe = (s: unknown): s is string => typeof s === "string" && /^[@a-zA-Z0-9][a-zA-Z0-9@._/+-]{0,213}$/.test(s);
export const isSafeVersion = (s: unknown): s is string => typeof s === "string" && /^\d[A-Za-z0-9.+_-]{0,63}$/.test(s);
export const isSafeName = (name: unknown, ecosystem: Ecosystem) =>
  ecosystem === "Maven" ? typeof name === "string" && /^[\w.-]{1,120}:[\w.-]{1,120}$/.test(name) : isSafe(name);

/**
 * Lockfile contents and file paths are written by whoever made the repo, and they reach the agent. Keeping only
 * the characters of a package name or path means they can't carry an instruction, or even a space.
 */
export const safeLabel = (value: unknown) => String(value).replace(/[^A-Za-z0-9@._/+:=-]/g, "_").slice(-120);

const isRequirements = (file: string) => /^requirements.*\.txt$/.test(file);

async function walk(root: string, depth = 0): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files = entries.filter((e) => e.isFile()).map((e) => join(root, e.name));
  if (depth === MAX_DEPTH) return files;
  const dirs = entries.filter((e) => e.isDirectory() && !SKIP_DIRS.has(e.name));
  const nested = await Promise.all(dirs.map((d) => walk(join(root, d.name), depth + 1)));
  return [...files, ...nested.flat()];
}

const inTestDir = (rel: string) => rel.split("/").slice(0, -1).some((dir) => TEST_DIRS.has(dir));
const baseName = (file: string) => file.slice(file.lastIndexOf("/") + 1);

async function readLimited(file: string): Promise<string> {
  if ((await stat(file)).size > MAX_FILE_BYTES) throw new Error("too large");
  return readFile(file, "utf8");
}

const covers = (lockDir: string, dir: string) => dir === lockDir || dir.startsWith(lockDir + "/");

export async function scanProject(root: string, only?: Ecosystem): Promise<Scan> {
  const scan: Scan = { deps: [], private: [], unchecked: [] };
  const all = await walk(root);
  const files = all.filter((f) => !inTestDir(relative(root, f)));
  scan.ignored = all
    .filter((f) => inTestDir(relative(root, f)) && (Object.hasOwn(LOCKFILES, baseName(f)) || isRequirements(baseName(f))))
    .map((f) => safeLabel(relative(root, f)))
    .slice(0, MAX_IGNORED_LISTED);
  const names = new Set(files);
  const locked: { dir: string; ecosystem: Ecosystem }[] = [];

  for (const file of files) {
    const base = baseName(file);
    const rel = safeLabel(relative(root, file));
    const spec = isRequirements(base)
      ? { ecosystem: "PyPI" as const, parse: parseRequirements, manifest: undefined }
      : Object.hasOwn(LOCKFILES, base)
        ? LOCKFILES[base]
        : undefined;
    if (UNSUPPORTED.has(base) && !only) scan.unchecked.push({ item: rel, reason: "ecosystem not supported yet" });
    if (!spec) continue;
    locked.push({ dir: dirname(file), ecosystem: spec.ecosystem });
    if (only && spec.ecosystem !== only) continue;
    try {
      const base = spec.manifest && join(dirname(file), spec.manifest);
      const manifestPath = base && [base, `${base}.kts`].find((p) => names.has(p));
      const manifest = manifestPath ? await readLimited(manifestPath) : undefined;
      const parsed = spec.parse(await readLimited(file), manifest);
      for (const d of parsed.deps) {
        if (isSafeName(d.name, spec.ecosystem) && isSafeVersion(d.version))
          scan.deps.push({ ...d, ecosystem: spec.ecosystem, lockfile: rel });
        else scan.unchecked.push({ item: rel, reason: "entry with invalid package name or version" });
      }
      scan.private.push(...parsed.private.map(safeLabel));
      scan.unchecked.push(...parsed.unchecked.map((u) => ({ item: safeLabel(u.item), reason: u.reason })));
    } catch {
      // Parser errors quote the file, so the reason stays fixed text.
      scan.unchecked.push({ item: rel, reason: "could not read this file, or its format isn't supported" });
    }
  }

  for (const file of files) {
    const base = baseName(file);
    const ecosystem = base.endsWith(".csproj") ? "NuGet" : Object.hasOwn(MANIFESTS, base) ? MANIFESTS[base] : undefined;
    if (!ecosystem || (only && ecosystem !== only)) continue;
    const dir = dirname(file);
    if (!locked.some((l) => l.ecosystem === ecosystem && covers(l.dir, dir)))
      scan.unchecked.push({ item: safeLabel(relative(root, file)), reason: "no lockfile, installed versions unknown" });
  }

  const platforms = [
    ...files.filter((f) => Object.hasOwn(PLATFORM_FILES, baseName(f))).map((f) => PLATFORM_FILES[baseName(f)]!),
    ...files.filter((f) => relative(root, f).split("/").includes(".vercel")).map(() => "vercel"),
    ...scan.deps.filter((d) => Object.hasOwn(PLATFORM_PACKAGES, d.name)).map((d) => PLATFORM_PACKAGES[d.name]!),
  ];
  scan.platforms = [...new Set(platforms)].sort();
  scan.private = [...new Set(scan.private)].slice(0, MAX_LISTED);
  scan.unchecked = scan.unchecked.slice(0, MAX_LISTED);
  return scan;
}
