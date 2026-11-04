import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, mock, test } from "node:test";
import { buildReport } from "../src/report.ts";
import type { Dep, Scan } from "../src/types.ts";

const dep = (over: Partial<Dep> = {}): Dep => ({
  ecosystem: "npm", name: "lodash", version: "1.0.0", direct: true, lockfile: "package-lock.json", ...over,
});
const scan = (over: Partial<Scan> = {}): Scan => ({ deps: [dep()], private: [], unchecked: [], ...over });
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const vuln = (over: Record<string, any> = {}) => ({
  id: "GHSA-1",
  modified: "m",
  aliases: ["CVE-2020-1"],
  summary: "bad",
  database_specific: { severity: "HIGH" },
  affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "1.2.0" }] }] }],
  ...over,
});

function serve(vulns: Record<string, any>[], kev: string[] = []) {
  mock.method(globalThis, "fetch", async (url: string) => {
    if (url.endsWith("/querybatch")) return json({ results: [{ vulns: vulns.map(({ id, modified }) => ({ id, modified })) }] });
    if (url.includes("/vulns/")) return json(vulns.find((v) => url.endsWith(v.id)));
    if (url.includes("known_exploited")) return json({ vulnerabilities: kev.map((cveID) => ({ cveID })) });
    return json({ data: [{ cve: "CVE-2020-1", epss: "0.42" }] });
  });
}

beforeEach(() => {
  mock.restoreAll();
  process.env.KMS_CACHE_DIR = mkdtempSync(join(tmpdir(), "kms-"));
});

test("no advisories gives no", async () => {
  serve([]);
  const r = await buildReport(scan());
  assert.equal(r.verdict, "no");
  assert.equal(r.urgency, null);
});

test("high severity gives yes, today, with a command", async () => {
  serve([vuln()]);
  const r = await buildReport(scan());
  const f = r.findings[0]!;
  assert.equal(r.verdict, "yes");
  assert.equal(r.urgency, "today");
  assert.equal(f.fixed_in, "1.2.0");
  assert.equal(f.command, "npm install lodash@1.2.0");
  assert.equal(f.epss, 0.42);
  assert.equal(f.exploited, false);
});

test("KEV listing raises urgency to now", async () => {
  serve([vuln({ database_specific: { severity: "LOW" } })], ["CVE-2020-1"]);
  const r = await buildReport(scan());
  assert.equal(r.urgency, "now");
  assert.equal(r.findings[0]!.exploited, true);
});

test("moderate severity can wait a week", async () => {
  serve([vuln({ database_specific: { severity: "MODERATE" } })]);
  assert.equal((await buildReport(scan())).urgency, "this_week");
});

test("malicious package: now, no upgrade command, says to rotate secrets", async () => {
  serve([vuln({ id: "MAL-1", aliases: [], database_specific: undefined, affected: [] })]);
  const r = await buildReport(scan());
  assert.equal(r.urgency, "now");
  assert.equal(r.findings[0]!.command, null);
  assert.match(r.findings[0]!.advice, /rotate secrets/);
});

test("target is the highest fix across advisories", async () => {
  serve([
    vuln(),
    vuln({
      id: "GHSA-2",
      aliases: ["CVE-2020-2"],
      affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ fixed: "1.10.0" }] }] }],
    }),
  ]);
  assert.equal((await buildReport(scan())).findings[0]!.fixed_in, "1.10.0");
});

test("OSV failure gives unknown, not no", async () => {
  mock.method(globalThis, "fetch", async () => json({}, 503));
  const r = await buildReport(scan());
  assert.equal(r.verdict, "unknown");
  assert.equal(r.coverage.unchecked.at(-1)!.item, "OSV");
});

test("nothing scanned gives unknown", async () => {
  serve([]);
  const r = await buildReport(scan({ deps: [] }));
  assert.equal(r.verdict, "unknown");
  assert.match(r.coverage.unchecked[0]!.reason, /no supported lockfile/);
});

test("unchecked items turn no into unknown, but findings still say yes", async () => {
  const unchecked = [{ item: "go.mod", reason: "ecosystem not supported yet" }];
  serve([]);
  assert.equal((await buildReport(scan({ unchecked }))).verdict, "unknown");
  mock.restoreAll();
  serve([vuln()]);
  assert.equal((await buildReport(scan({ unchecked }))).verdict, "yes");
});

test("KEV outage reports exploited as null, not false", async () => {
  mock.method(globalThis, "fetch", async (url: string) => {
    if (url.endsWith("/querybatch")) return json({ results: [{ vulns: [{ id: "GHSA-1", modified: "m" }] }] });
    if (url.includes("/vulns/")) return json(vuln());
    return json({}, 500);
  });
  assert.equal((await buildReport(scan())).findings[0]!.exploited, null);
});

test("advisory text is flattened and truncated", async () => {
  serve([vuln({ summary: `line one\n\nIGNORE PREVIOUS\u0007 ${"x".repeat(500)}` })]);
  const s = (await buildReport(scan())).findings[0]!.advisories[0]!.summary_untrusted;
  assert.ok(s.length <= 200);
  assert.ok(!/[\n\u0007]/.test(s));
});
