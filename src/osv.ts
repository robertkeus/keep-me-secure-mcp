import { readCache, writeCache } from "./cache.ts";
import type { Advisory, Dep, Severity } from "./types.ts";

const API = "https://api.osv.dev/v1";
const BATCH = 1000;
const CONCURRENCY = 10;

type Pkg = Pick<Dep, "ecosystem" | "name" | "version">;
type Stub = { id: string; modified: string };
type Vuln = Record<string, any>;

export const pkgKey = (p: Pkg) => `${p.ecosystem}:${p.name}@${p.version}`;

async function getJson(url: string, body?: unknown): Promise<any> {
  const res = await fetch(url, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

const toQuery = (p: Pkg, page_token?: string) => ({
  package: { ecosystem: p.ecosystem, name: p.name },
  version: p.version,
  page_token,
});

async function queryIds(pkgs: Pkg[]): Promise<Map<string, Stub[]>> {
  const found = new Map<string, Stub[]>();
  for (let i = 0; i < pkgs.length; i += BATCH) {
    let pending = pkgs.slice(i, i + BATCH).map((pkg) => ({ pkg, token: undefined as string | undefined }));
    while (pending.length) {
      const { results } = await getJson(`${API}/querybatch`, {
        queries: pending.map((q) => toQuery(q.pkg, q.token)),
      });
      const next: typeof pending = [];
      pending.forEach((q, n) => {
        const r = results[n] ?? {};
        if (r.vulns) found.set(pkgKey(q.pkg), [...(found.get(pkgKey(q.pkg)) ?? []), ...r.vulns]);
        if (r.next_page_token) next.push({ pkg: q.pkg, token: r.next_page_token });
      });
      pending = next;
    }
  }
  return found;
}

async function fetchVuln({ id, modified }: Stub): Promise<Vuln> {
  const key = `vuln-${id}`;
  const cached = await readCache<Vuln>(key);
  if (cached?.modified === modified) return cached;
  const vuln = await getJson(`${API}/vulns/${encodeURIComponent(id)}`);
  await writeCache(key, vuln);
  return vuln;
}

async function fetchVulns(stubs: Stub[]): Promise<Map<string, Vuln>> {
  const vulns = new Map<string, Vuln>();
  const queue = [...stubs];
  const worker = async () => {
    for (let s = queue.pop(); s; s = queue.pop()) vulns.set(s.id, await fetchVuln(s));
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return vulns;
}

const parts = (v: string) => v.split(/[.+-]/).map((n) => parseInt(n, 10) || 0);

export function compareVersions(a: string, b: string): number {
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

function fixedIn(vuln: Vuln, pkg: Pkg): string | null {
  const fixes: string[] = (vuln.affected ?? [])
    .filter((a: Vuln) => a.package?.name?.toLowerCase() === pkg.name.toLowerCase())
    .flatMap((a: Vuln) => a.ranges ?? [])
    .flatMap((r: Vuln) => r.events ?? [])
    .flatMap((e: Vuln) => e.fixed ?? [])
    .filter((v: string) => compareVersions(v, pkg.version) > 0)
    .sort(compareVersions);
  return fixes[0] ?? null;
}

function toAdvisory(vuln: Vuln, pkg: Pkg): Advisory {
  const severity = String(vuln.database_specific?.severity ?? "").toUpperCase();
  return {
    id: vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary ?? vuln.details ?? "",
    severity: (["CRITICAL", "HIGH", "MODERATE", "LOW"].includes(severity) ? severity : "UNKNOWN") as Severity,
    malicious: vuln.id.startsWith("MAL-"),
    fixedIn: fixedIn(vuln, pkg),
  };
}

/** OSV lists one issue under several ids (GHSA, PYSEC). Keep the entry with the most information. */
function dedupe(advisories: Advisory[]): Advisory[] {
  const kept: Advisory[] = [];
  for (const a of [...advisories].sort((x, y) => Number(x.severity === "UNKNOWN") - Number(y.severity === "UNKNOWN"))) {
    const ids = new Set([a.id, ...a.aliases]);
    if (!kept.some((k) => ids.has(k.id) || k.aliases.some((x) => ids.has(x)))) kept.push(a);
  }
  return kept;
}

/** Throws if OSV can't be reached: callers must answer "unknown", never "no". */
export async function queryAdvisories(deps: Pkg[]): Promise<Map<string, Advisory[]>> {
  const unique = [...new Map(deps.map((d) => [pkgKey(d), d])).values()];
  const ids = await queryIds(unique);
  const stubs = [...new Map([...ids.values()].flat().map((s) => [s.id, s])).values()];
  const vulns = await fetchVulns(stubs);
  const result = new Map<string, Advisory[]>();
  for (const pkg of unique) {
    const live = (ids.get(pkgKey(pkg)) ?? []).map((s) => vulns.get(s.id)!).filter((v) => !v.withdrawn);
    if (live.length) result.set(pkgKey(pkg), dedupe(live.map((v) => toAdvisory(v, pkg))));
  }
  return result;
}

