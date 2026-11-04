import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, mock, test } from "node:test";
import { compareVersions, queryAdvisories } from "../src/osv.ts";

const recorded = JSON.parse(readFileSync(new URL("fixtures/ghsa-25mq.json", import.meta.url), "utf8"));
const pkg = { ecosystem: "Packagist", name: "guzzlehttp/guzzle", version: "7.4.0" } as const;
const stub = (v: { id: string; modified: string }) => ({ id: v.id, modified: v.modified });
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

function serve(vulns: Record<string, any>[]) {
  return mock.method(globalThis, "fetch", async (url: string) =>
    url.endsWith("/querybatch")
      ? json({ results: [{ vulns: vulns.map(stub) }] })
      : json(vulns.find((v) => url.endsWith(v.id))),
  );
}

beforeEach(() => {
  mock.restoreAll();
  process.env.KMS_CACHE_DIR = mkdtempSync(join(tmpdir(), "kms-"));
});

test("maps a recorded advisory", async () => {
  serve([recorded]);
  const [a] = (await queryAdvisories([pkg])).get("Packagist:guzzlehttp/guzzle@7.4.0")!;
  assert.equal(a!.id, "GHSA-25mq-v84q-4j7r");
  assert.equal(a!.severity, "HIGH");
  assert.equal(a!.fixedIn, "7.4.5");
  assert.equal(a!.malicious, false);
});

test("fetches each advisory once, then reads the cache", async () => {
  const f = serve([recorded]);
  await queryAdvisories([pkg]);
  await queryAdvisories([pkg]);
  assert.equal(f.mock.calls.filter((c) => String(c.arguments[0]).includes("/vulns/")).length, 1);
});

test("skips withdrawn advisories", async () => {
  serve([{ ...recorded, withdrawn: "2024-01-01T00:00:00Z" }]);
  assert.equal((await queryAdvisories([pkg])).size, 0);
});

test("merges aliases and flags malware", async () => {
  serve([
    { id: "PYSEC-1", modified: "x", aliases: ["CVE-1"] },
    { id: "GHSA-1", modified: "x", aliases: ["CVE-1"], database_specific: { severity: "LOW" } },
    { id: "MAL-1", modified: "x" },
  ]);
  const list = (await queryAdvisories([pkg])).get("Packagist:guzzlehttp/guzzle@7.4.0")!;
  assert.deepEqual(list.map((a) => a.id).sort(), ["GHSA-1", "MAL-1"]);
  assert.equal(list.find((a) => a.id === "MAL-1")!.malicious, true);
});

test("follows pagination", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async (url: string) => {
    if (!url.endsWith("/querybatch")) return json(recorded);
    return ++calls === 1
      ? json({ results: [{ vulns: [], next_page_token: "t" }] })
      : json({ results: [{ vulns: [stub(recorded)] }] });
  });
  assert.equal((await queryAdvisories([pkg])).size, 1);
  assert.equal(calls, 2);
});

test("throws when OSV fails", async () => {
  mock.method(globalThis, "fetch", async () => json({}, 500));
  await assert.rejects(queryAdvisories([pkg]));
});

test("retries a transient failure", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async (url: string) => {
    if (!url.endsWith("/querybatch")) return json(recorded);
    return ++calls === 1 ? json({}, 503) : json({ results: [{ vulns: [stub(recorded)] }] });
  });
  assert.equal((await queryAdvisories([pkg])).size, 1);
});

test("does not retry a client error", async () => {
  const f = mock.method(globalThis, "fetch", async () => json({}, 400));
  await assert.rejects(queryAdvisories([pkg]));
  assert.equal(f.mock.callCount(), 1);
});

test("compares versions numerically", () => {
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
  assert.equal(compareVersions("1.0", "1.0.0"), 0);
});

test("live OSV lookup", { skip: !process.env.LIVE }, async () => {
  mock.restoreAll();
  assert.ok((await queryAdvisories([pkg])).size);
});
