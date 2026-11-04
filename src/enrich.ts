import { readCache, today, writeCache } from "./cache.ts";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const EPSS_CHUNK = 50;

/** Returns null when the feed is unavailable, so a failure never reads as "not exploited". */
export async function knownExploited(): Promise<Set<string> | null> {
  const cached = await readCache<{ date: string; cves: string[] }>("kev");
  if (cached?.date === today()) return new Set(cached.cves);
  try {
    const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(20_000) });
    if (!res.ok) throw new Error(String(res.status));
    const { vulnerabilities } = (await res.json()) as { vulnerabilities: { cveID: string }[] };
    const cves = vulnerabilities.map((v) => v.cveID);
    await writeCache("kev", { date: today(), cves });
    return new Set(cves);
  } catch {
    return cached ? new Set(cached.cves) : null;
  }
}

export async function epssScores(cves: string[]): Promise<Map<string, number>> {
  const scores = new Map<string, number>();
  for (let i = 0; i < cves.length; i += EPSS_CHUNK) {
    try {
      const chunk = cves.slice(i, i + EPSS_CHUNK).join(",");
      const res = await fetch(`${EPSS_URL}?cve=${chunk}`, { signal: AbortSignal.timeout(20_000) });
      const { data } = (await res.json()) as { data: { cve: string; epss: string }[] };
      for (const d of data) scores.set(d.cve, Number(d.epss));
    } catch {}
  }
  return scores;
}
