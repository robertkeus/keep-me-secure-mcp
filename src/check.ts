import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { relative, resolve } from "node:path";
import { readCache, today, writeCache } from "./cache.ts";
import { normalizePy } from "./parsers.ts";
import { allIncidents, forPlatforms, INCIDENTS, isRecent, loadIncidents, type PlatformReport } from "./platforms.ts";
import { buildReport, NO_LOCKFILE, type Report } from "./report.ts";
import {
  checkRuntimes,
  loadRuntimeAdvisories,
  parseDeclared,
  RUNTIME_ADVISORIES,
  runtimeName,
  type Runtime,
  type RuntimeReport,
} from "./runtimes.ts";
import { isSafeName, isSafeVersion, safeLabel, scanProject } from "./scan.ts";
import type { Dep, Ecosystem, Scan } from "./types.ts";
import { findOldPackages, installProtection } from "./upkeep.ts";

/** A message written here, safe to show. Anything else may quote file paths, so it's never passed on. */
export class InputError extends Error {}

const ECOSYSTEMS: Record<string, Ecosystem> = {
  php: "Packagist",
  composer: "Packagist",
  packagist: "Packagist",
  js: "npm",
  javascript: "npm",
  typescript: "npm",
  node: "npm",
  npm: "npm",
  python: "PyPI",
  pip: "PyPI",
  pypi: "PyPI",
  go: "Go",
  golang: "Go",
  rust: "crates.io",
  cargo: "crates.io",
  "crates.io": "crates.io",
  ruby: "RubyGems",
  gem: "RubyGems",
  rubygems: "RubyGems",
  java: "Maven",
  kotlin: "Maven",
  maven: "Maven",
  gradle: "Maven",
  dotnet: "NuGet",
  ".net": "NuGet",
  csharp: "NuGet",
  nuget: "NuGet",
};

export function toEcosystem(input: string): Ecosystem {
  const ecosystem = Object.hasOwn(ECOSYSTEMS, input.toLowerCase()) ? ECOSYSTEMS[input.toLowerCase()] : undefined;
  if (!ecosystem) throw new InputError("Unsupported ecosystem. Use php, npm, python, go, rust, ruby, java or dotnet.");
  return ecosystem;
}

function projectRoot(path = "."): string {
  const refuse = () => new InputError("path must be a subfolder of the project, relative to its root. Omit it to scan the whole project.");
  const cwd = realpathSync(process.cwd());
  let root: string;
  try {
    root = realpathSync(resolve(cwd, path));
  } catch {
    throw refuse();
  }
  const rel = relative(cwd, root);
  if (rel.startsWith("..") || resolve(cwd, rel) !== root) throw refuse();
  return root;
}

export async function checkProject(
  opts: { path?: string; ecosystem?: string; refresh?: boolean; packageAges?: boolean } = {},
): Promise<Report> {
  const scan = await scanProject(projectRoot(opts.path), opts.ecosystem ? toEcosystem(opts.ecosystem) : undefined);
  const key = `report-${createHash("sha256").update(JSON.stringify(scan)).digest("hex").slice(0, 32)}`;
  const cached = await readCache<{ date: string; report: Report }>(key);
  // Platforms and runtimes are looked up fresh, so they're never served from a saved report.
  const withPlatforms = async (report: Report): Promise<Report> => ({
    ...report,
    platforms: { detected: scan.platforms ?? [], ...forPlatforms(await loadIncidents(), scan.platforms ?? []) },
    runtimes: await checkRuntimes(scan.runtimes ?? [], await loadRuntimeAdvisories()),
    install_protection: installProtection(scan.protection ?? []),
    old_packages: opts.packageAges === false ? undefined : await findOldPackages(scan.deps),
  });
  if (!opts.refresh && cached?.date === today()) return withPlatforms(cached.report);
  const report = await buildReport(scan);
  const lookupFailed = report.coverage.unchecked.some((u) => u.item === "OSV");
  if (!lookupFailed) await writeCache(key, { date: today(), report });
  return withPlatforms(report);
}

type PackageInput = { ecosystem: string; name: string; version: string };

function toDep(opts: PackageInput): Dep {
  const ecosystem = toEcosystem(opts.ecosystem);
  const version = opts.version.replace(/^v/, "");
  const name = ecosystem === "PyPI" ? normalizePy(opts.name) : opts.name;
  if (!isSafeName(name, ecosystem) || !isSafeVersion(version))
    throw new InputError("name must be a package name and version an exact version such as 1.2.3, not a range.");
  return { ecosystem, name, version, direct: true, lockfile: "" };
}

export async function checkPackage(opts: PackageInput): Promise<Report> {
  return buildReport({ deps: [toDep(opts)], private: [], unchecked: [] });
}

/** For the hosted server, which can't read lockfiles: it only knows what the agent sends. */
export async function checkPackages(packages: PackageInput[]): Promise<Report> {
  const scan: Scan = { deps: [], private: [], unchecked: [] };
  for (const p of packages) {
    try {
      scan.deps.push(toDep(p));
    } catch (e) {
      scan.unchecked.push({ item: safeLabel(`${p.name}@${p.version}`), reason: (e as Error).message });
    }
  }
  const report = await buildReport(scan);
  return { ...report, note: `Only the ${packages.length} packages sent were checked. ${report.note}` };
}

/** The hosted server answers from the list it was deployed with, so it never calls itself. */
export async function checkPlatform(name: string | undefined, { hosted = false } = {}): Promise<PlatformReport> {
  const incidents = hosted ? INCIDENTS : await loadIncidents();
  return name ? forPlatforms(incidents, [name.toLowerCase().trim()]) : allIncidents(incidents);
}

export async function checkRuntime(runtime: string, version: string, { hosted = false } = {}): Promise<RuntimeReport> {
  const names = new Map<string, Runtime>([["node", "node"], ["nodejs", "node"], ["node.js", "node"], ["php", "php"]]);
  const name = names.get(runtime.toLowerCase());
  if (!name) throw new InputError("Unsupported runtime. Use node or php.");
  if (!/^v?\d+(\.\d+){0,2}$/.test(version)) throw new InputError("version must look like 8.4.26.");
  return checkRuntimes([parseDeclared(name, version, "")], hosted ? RUNTIME_ADVISORIES : await loadRuntimeAdvisories());
}

export function summarize(r: Report): string {
  const packages = summarizePackages(r);
  const runtimes = (r.runtimes?.findings ?? [])
    .filter((f) => f.status === "affected" && /^[\d.]+$/.test(f.declared))
    .map((f) => {
      const fix = f.fixed_in ? `Upgrade to ${f.fixed_in} or later.` : "That release line has no official release with the fix.";
      const known = f.exploited ? " It's being exploited." : "";
      return `keep-me-secure: ${runtimeName(f.runtime)} ${f.declared} has a ${f.severity} security flaw.${known} ${fix}`;
    });
  const noFix = new Set(
    (r.runtimes?.findings ?? []).filter((f) => f.status === "affected" && !f.fixed_in).map((f) => f.declared),
  );
  const support = (r.runtimes?.declared ?? []).flatMap((d) => {
    if (!d.support || d.support.status === "on_track" || noFix.has(d.declared)) return [];
    const name = `${runtimeName(d.runtime)} ${d.support.line}`;
    return d.support.status === "end_of_life"
      ? `keep-me-secure: ${name} reached end of life on ${d.support.security_until}. Move to a supported version.`
      : `keep-me-secure: ${name} stops getting security fixes on ${d.support.security_until}.`;
  });
  const recent = (r.platforms?.incidents ?? []).filter((i) => isRecent(i));
  const platforms = recent.map(
    (i) => `keep-me-secure: ${i.platform} reported a security incident on ${i.date}. Call the check_platform tool for what to do.`,
  );
  return [packages, ...new Set(runtimes), ...new Set(support), ...platforms].filter(Boolean).join("\n");
}

function summarizePackages(r: Report): string {
  const noProject = r.verdict === "unknown" && r.coverage.unchecked.length === 1 && r.coverage.unchecked[0]!.reason === NO_LOCKFILE;
  if (noProject) return "";
  const counts = Object.entries(r.coverage.by_ecosystem).map(([e, n]) => `${e} ${n}`).join(", ");
  if (r.verdict === "no") return `keep-me-secure: no known issues in ${r.coverage.scanned} packages (${counts}).`;
  if (r.verdict === "unknown")
    return `keep-me-secure: no issues found, but ${r.coverage.unchecked.length} item(s) couldn't be checked. Call the check_project tool for details.`;
  const lines = r.findings.slice(0, 10).map((f) => {
    const fix = /^[\d.]+$/.test(f.fixed_in ?? "") ? ` -> ${f.fixed_in}` : "";
    return `- [${f.urgency}] ${f.package}${fix} (${f.malicious ? "MALICIOUS" : f.severity}, ${f.ecosystem})`;
  });
  const more = r.findings.length > 10 ? [`- and ${r.findings.length - 10} more`] : [];
  return [
    `keep-me-secure: ${r.findings.length} of ${r.coverage.scanned} package(s) need patching (${counts}), most urgent: ${r.urgency}.`,
    ...lines,
    ...more,
    "Tell the user, and call the check_project tool for advice and commands.",
  ].join("\n");
}
