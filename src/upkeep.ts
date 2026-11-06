import { readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { readCache, today, writeCache } from "./cache.ts";
import type { Dep, Ecosystem } from "./types.ts";

type Manager = "npm" | "pnpm" | "yarn" | "composer";

export interface ManagerProtection {
  manager: Manager;
  /** on: new releases wait. off: they install at once. unknown: it depends on a version we can't see. */
  status: "on" | "off" | "unknown";
  setting: string;
  /** How to let one urgent security fix through. */
  urgent_fix: string;
}

export interface InstallProtection {
  managers: ManagerProtection[];
  note: string;
}

export interface OldPackage {
  package: string;
  ecosystem: Ecosystem;
  installed: string;
  latest_release: string | null;
  reason: "deprecated" | "abandoned" | "no_recent_release";
}

export interface OldPackages {
  packages: OldPackage[];
  checked: number;
  not_checked: number;
  note: string;
}

const MAX_CONFIG_BYTES = 1024 * 1024;
const PROTECTION_NOTE =
  "Most malicious releases are found within days, so waiting about 2 days before installing new versions blocks many supply chain attacks. " +
  "The catch is that it also delays security fixes. If a finding has urgency now, don't wait: use urgent_fix for that package, and confirm the version matches fixed_in.";

const MANAGERS: Record<string, Manager> = {
  "package-lock.json": "npm",
  "pnpm-lock.yaml": "pnpm",
  "yarn.lock": "yarn",
  "composer.lock": "composer",
};

const SETTINGS: Record<Manager, { setting: string; urgent_fix: string }> = {
  npm: {
    setting: "Add min-release-age=2 to .npmrc. The value is in days, and it needs npm 11.10 or newer.",
    urgent_fix: "Add the package to min-release-age-exclude in .npmrc, which needs npm 11.17 or newer, then remove it after installing.",
  },
  pnpm: {
    setting: "Add minimumReleaseAge: 2880 to pnpm-workspace.yaml. The value is in minutes. pnpm 11 and newer default to one day.",
    urgent_fix: "Add the package to minimumReleaseAgeExclude in pnpm-workspace.yaml, then remove it after installing.",
  },
  yarn: {
    setting: "Add npmMinimalAgeGate: 2d to .yarnrc.yml. This needs a recent Yarn 4.",
    urgent_fix: "Add the package to npmPreapprovedPackages in .yarnrc.yml, then remove it after installing.",
  },
  composer: {
    setting: 'Set config.policy.cooldown.period to "2 days" in composer.json. This needs Composer 2.11 or newer.',
    urgent_fix: "Run the update with --no-cooldown, or add the package to config.policy.cooldown.ignore.",
  },
};

async function read(file: string): Promise<string> {
  try {
    return (await stat(file)).size > MAX_CONFIG_BYTES ? "" : await readFile(file, "utf8");
  } catch {
    return "";
  }
}

const MINUTES: Record<string, number> = { m: 1, minute: 1, h: 60, hour: 60, d: 1440, day: 1440, w: 10080, week: 10080 };
const MIN_WAIT_MINUTES = 1440;

/** Reads "2d", "2 days" or "90 minutes". A wait under a day doesn't count as protection. */
function waitsLongEnough(value: unknown, unit: "minute" | "day" | "second"): boolean {
  if (typeof value === "number") return (unit === "second" ? value / 60 : value) >= MIN_WAIT_MINUTES;
  const match = String(value).trim().match(/^(\d+)\s*([a-z]*?)s?$/i);
  if (!match) return false;
  const named = match[2] ? MINUTES[match[2].toLowerCase()] : undefined;
  if (match[2] && !named) return false;
  return Number(match[1]) * (named ?? (unit === "day" ? 1440 : unit === "second" ? 1 / 60 : 1)) >= MIN_WAIT_MINUTES;
}

async function statusFor(manager: Manager, dir: string): Promise<ManagerProtection["status"]> {
  if (manager === "npm") {
    const value = (await read(join(dir, ".npmrc"))).match(/^\s*min-release-age\s*=\s*(\d+)/m)?.[1];
    return value !== undefined && waitsLongEnough(value, "day") ? "on" : "off";
  }
  if (manager === "yarn") {
    const value = (await read(join(dir, ".yarnrc.yml"))).match(/^npmMinimalAgeGate:\s*["']?([^\s"'#]+)/m)?.[1];
    return value !== undefined && waitsLongEnough(value, "minute") ? "on" : "off";
  }
  if (manager === "composer") {
    try {
      const cooldown = JSON.parse(await read(join(dir, "composer.json")))?.config?.policy?.cooldown;
      return cooldown?.block !== false && cooldown?.period != null && waitsLongEnough(cooldown.period, "second") ? "on" : "off";
    } catch {
      return "off";
    }
  }
  const value = (await read(join(dir, "pnpm-workspace.yaml"))).match(/^minimumReleaseAge:\s*(\d+)/m)?.[1];
  let major: number | undefined;
  try {
    const declared = JSON.parse(await read(join(dir, "package.json")))?.packageManager;
    const found = typeof declared === "string" ? declared.match(/^pnpm@(\d+)\./)?.[1] : undefined;
    if (found) major = Number(found);
  } catch {}
  if (major !== undefined && major < 10) return "off";
  if (value !== undefined) return waitsLongEnough(value, "minute") ? "on" : "off";
  if (major !== undefined) return major >= 11 ? "on" : "off";
  return "unknown";
}

const RANK = { off: 0, unknown: 1, on: 2 };

/** A manager counts as protected only if every project using it is. */
export async function findProtection(files: string[]): Promise<ManagerProtection[]> {
  const found = new Map<Manager, ManagerProtection["status"]>();
  for (const file of files) {
    const base = file.slice(file.lastIndexOf("/") + 1);
    if (!Object.hasOwn(MANAGERS, base)) continue;
    const manager = MANAGERS[base]!;
    const status = await statusFor(manager, dirname(file));
    const known = found.get(manager);
    if (!known || RANK[status] < RANK[known]) found.set(manager, status);
  }
  return [...found].map(([manager, status]) => ({ manager, status, ...SETTINGS[manager] }));
}

export const installProtection = (managers: ManagerProtection[]): InstallProtection => ({ managers, note: PROTECTION_NOTE });

const MAX_LOOKUPS = 150;
const CONCURRENCY = 8;
/** Comfortably inside an MCP client's timeout, so a slow registry can't lose the rest of the report. */
const LOOKUP_BUDGET_MS = 15_000;
const STALE_DAYS = 730;
const CACHE_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;
const OLD_NOTE =
  "Old doesn't mean unsafe: a finished package may rarely change. It's a prompt to check that someone would fix a flaw if one appeared. " +
  "Only direct dependencies are checked, and this doesn't change the verdict.";

const DEPS_DEV: Partial<Record<Ecosystem, string>> = {
  npm: "NPM",
  PyPI: "PYPI",
  Go: "GO",
  "crates.io": "CARGO",
  RubyGems: "RUBYGEMS",
  Maven: "MAVEN",
  NuGet: "NUGET",
};

interface PackageState {
  checked: string;
  release: string | null;
  retired: "deprecated" | "abandoned" | null;
}

const validDate = (value: unknown) =>
  typeof value === "string" && /^\d{4}-\d{2}-\d{2}/.test(value) && !Number.isNaN(Date.parse(value)) ? value.slice(0, 10) : null;

async function getJson(url: string): Promise<any> {
  const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

async function lookup(dep: Dep): Promise<Omit<PackageState, "checked">> {
  if (dep.ecosystem === "Packagist") {
    const data = await getJson(`https://repo.packagist.org/p2/${dep.name}.json`);
    const latest = data?.packages?.[dep.name]?.[0];
    if (!latest) throw new Error("no data");
    return { release: validDate(latest.time), retired: latest.abandoned ? "abandoned" : null };
  }
  const data = await getJson(`https://api.deps.dev/v3/systems/${DEPS_DEV[dep.ecosystem]}/packages/${encodeURIComponent(dep.name)}`);
  const latest = Array.isArray(data?.versions) ? data.versions.find((v: any) => v?.isDefault) : undefined;
  if (!latest) throw new Error("no data");
  return { release: validDate(latest.publishedAt), retired: latest.isDeprecated === true ? "deprecated" : null };
}

async function stateOf(dep: Dep): Promise<PackageState> {
  const key = `age-${dep.ecosystem}-${dep.name}`;
  const cached = await readCache<PackageState>(key);
  if (cached?.checked && Date.now() - Date.parse(cached.checked) < CACHE_DAYS * DAY_MS) return cached;
  const state = { checked: today(), ...(await lookup(dep)) };
  await writeCache(key, state);
  return state;
}

/** Direct dependencies only: they're the ones you chose, and it keeps the number of lookups down. */
export async function findOldPackages(deps: Dep[]): Promise<OldPackages> {
  const direct = [...new Map(deps.filter((d) => d.direct).map((d) => [`${d.ecosystem}:${d.name}`, d])).values()];
  const supported = direct.filter((d) => d.ecosystem === "Packagist" || DEPS_DEV[d.ecosystem]);
  const queue = supported.slice(0, MAX_LOOKUPS);
  const packages: OldPackage[] = [];
  let checked = 0;
  const deadline = Date.now() + LOOKUP_BUDGET_MS;

  const worker = async () => {
    for (let dep = queue.pop(); dep && Date.now() < deadline; dep = queue.pop()) {
      try {
        const state = await stateOf(dep);
        checked++;
        const old = state.release !== null && Date.now() - Date.parse(state.release) > STALE_DAYS * DAY_MS;
        const reason = state.retired ?? (old ? "no_recent_release" : null);
        if (reason)
          packages.push({
            package: dep.name,
            ecosystem: dep.ecosystem,
            installed: dep.version,
            latest_release: state.release,
            reason,
          });
      } catch {}
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  const order = { deprecated: 0, abandoned: 0, no_recent_release: 1 };
  packages.sort((a, b) => order[a.reason] - order[b.reason] || a.package.localeCompare(b.package));
  return { packages, checked, not_checked: direct.length - checked, note: OLD_NOTE };
}
