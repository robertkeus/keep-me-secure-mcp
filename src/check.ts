import { createHash } from "node:crypto";
import { relative, resolve } from "node:path";
import { readCache, today, writeCache } from "./cache.ts";
import { normalizePy } from "./parsers.ts";
import { buildReport, type Report } from "./report.ts";
import { isSafe, scanProject } from "./scan.ts";
import type { Ecosystem } from "./types.ts";

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
  const ecosystem = ECOSYSTEMS[input.toLowerCase()];
  if (!ecosystem) throw new Error(`Unsupported ecosystem "${input}". Use php, npm, python, go, rust, ruby, java or dotnet.`);
  return ecosystem;
}

function projectRoot(path = "."): string {
  const root = resolve(process.cwd(), path);
  const rel = relative(process.cwd(), root);
  if (rel.startsWith("..") || resolve(rel) !== root)
    throw new Error("path must be a subfolder of the project, relative to its root. Omit it to scan the whole project.");
  return root;
}

export async function checkProject(opts: { path?: string; ecosystem?: string; refresh?: boolean } = {}): Promise<Report> {
  const scan = await scanProject(projectRoot(opts.path), opts.ecosystem ? toEcosystem(opts.ecosystem) : undefined);
  const key = `report-${createHash("sha256").update(JSON.stringify(scan)).digest("hex").slice(0, 32)}`;
  const cached = await readCache<{ date: string; report: Report }>(key);
  if (!opts.refresh && cached?.date === today()) return cached.report;
  const report = await buildReport(scan);
  const lookupFailed = report.coverage.unchecked.some((u) => u.item === "OSV");
  if (!lookupFailed) await writeCache(key, { date: today(), report });
  return report;
}

export async function checkPackage(opts: { ecosystem: string; name: string; version: string }): Promise<Report> {
  const ecosystem = toEcosystem(opts.ecosystem);
  const version = opts.version.replace(/^v/, "");
  const name = ecosystem === "PyPI" ? normalizePy(opts.name) : opts.name;
  if (!isSafe(name) || !isSafe(version) || !/^\d/.test(version))
    throw new Error("name must be a package name and version an exact version such as 1.2.3, not a range.");
  return buildReport({ deps: [{ ecosystem, name, version, direct: true, lockfile: "" }], private: [], unchecked: [] });
}

export function summarize(r: Report): string {
  const counts = Object.entries(r.coverage.by_ecosystem).map(([e, n]) => `${e} ${n}`).join(", ");
  if (r.verdict === "no") return `keep-me-secure: no known issues in ${r.coverage.scanned} packages (${counts}).`;
  if (r.verdict === "unknown") {
    const why = r.coverage.unchecked.slice(0, 5).map((u) => `- ${u.item}: ${u.reason}`);
    return ["keep-me-secure: no issues found, but the check is incomplete.", ...why].join("\n");
  }
  const lines = r.findings.slice(0, 10).map((f) => {
    const fix = f.fixed_in ? ` -> ${f.fixed_in}` : "";
    return `- [${f.urgency}] ${f.package} ${f.installed}${fix} (${f.severity}, ${f.lockfile || "direct check"})`;
  });
  const more = r.findings.length > 10 ? [`- and ${r.findings.length - 10} more`] : [];
  return [
    `keep-me-secure: ${r.findings.length} of ${r.coverage.scanned} package(s) need patching (${counts}), most urgent: ${r.urgency}.`,
    ...lines,
    ...more,
    "Tell the user, and call the check_project tool for advice and commands.",
  ].join("\n");
}
