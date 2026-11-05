import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, mock, test } from "node:test";
import { checkPlatform, checkProject, summarize } from "../src/check.ts";
import { INCIDENTS, isRecent, loadIncidents } from "../src/platforms.ts";
import { scanProject } from "../src/scan.ts";

const json = (body: unknown) => new Response(JSON.stringify(body));
const dir = () => mkdtempSync(join(tmpdir(), "kms-pl-"));
const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" } } });

beforeEach(() => {
  mock.restoreAll();
  process.env.KMS_CACHE_DIR = dir();
  mock.method(globalThis, "fetch", async (url: string) =>
    String(url).endsWith("incidents.json") ? json(INCIDENTS) : json({ results: [{}] }),
  );
});

test("detects platforms from files and packages", async () => {
  const root = dir();
  writeFileSync(join(root, "railway.toml"), "");
  mkdirSync(join(root, ".vercel"));
  writeFileSync(join(root, ".vercel", "project.json"), "{}");
  writeFileSync(join(root, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/@trigger.dev/sdk": { version: "3.0.0" } } }));
  assert.deepEqual((await scanProject(root)).platforms, ["railway", "trigger.dev", "vercel"]);
});

test("a file in a test folder doesn't count as using a platform", async () => {
  const root = dir();
  mkdirSync(join(root, "test"));
  writeFileSync(join(root, "test", "railway.toml"), "");
  assert.deepEqual((await scanProject(root)).platforms, []);
});

test("a project on a breached platform hears about it, separately from the package verdict", async () => {
  const start = process.cwd();
  const root = dir();
  writeFileSync(join(root, "railway.toml"), "");
  writeFileSync(join(root, "package-lock.json"), lock);
  process.chdir(root);
  const report = await checkProject();
  process.chdir(start);
  assert.equal(report.verdict, "no");
  assert.deepEqual(report.platforms!.detected, ["railway"]);
  assert.equal(report.platforms!.incidents[0]!.id, "railway-2026-10");
});

test("a project on a platform with no incident hears nothing", async () => {
  const start = process.cwd();
  const root = dir();
  writeFileSync(join(root, "package-lock.json"), lock);
  process.chdir(root);
  const line = summarize(await checkProject());
  process.chdir(start);
  assert.doesNotMatch(line, /incident/);
});

test("the hook mentions a recent incident even with no lockfile", async () => {
  const start = process.cwd();
  const root = dir();
  writeFileSync(join(root, "railway.toml"), "");
  process.chdir(root);
  const report = await checkProject();
  process.chdir(start);
  report.platforms!.incidents = report.platforms!.incidents.map((i) => ({ ...i, date: new Date().toISOString().slice(0, 10) }));
  assert.match(summarize(report), /Railway reported a security incident/);
  assert.doesNotMatch(summarize(report), /couldn't be checked/);
});

test("the hook stops repeating an old incident, while the tool still shows it", async () => {
  const vercel = INCIDENTS.find((i) => i.id === "vercel-2026-04")!;
  assert.equal(isRecent(vercel, Date.parse("2026-11-05")), false);
  assert.equal(isRecent(vercel, Date.parse("2026-05-01")), true);
  assert.equal((await checkPlatform("vercel")).incidents.length, 1);
});

test("check_platform matches names and says when it knows nothing", async () => {
  assert.equal((await checkPlatform("Railway")).incidents[0]!.platform, "Railway");
  const none = await checkPlatform("netlify");
  assert.deepEqual(none.incidents, []);
  assert.match(none.note, /isn't complete/);
  assert.equal((await checkPlatform(undefined)).incidents.length, INCIDENTS.length);
});

test("the hosted server never fetches its own feed", async () => {
  const f = mock.method(globalThis, "fetch", async () => json([]));
  await checkPlatform("railway", { hosted: true });
  assert.equal(f.mock.callCount(), 0);
});

test("new incidents arrive through the feed without a release", async () => {
  const fresh = { ...INCIDENTS[0]!, id: "new-2026-11", platform: "Newco", names: ["newco"] };
  mock.restoreAll();
  mock.method(globalThis, "fetch", async () => json([fresh]));
  assert.ok((await loadIncidents()).some((i) => i.platform === "Newco"));
});

test("the published feed matches the source", () => {
  const feed = JSON.parse(readFileSync(new URL("../site/incidents.json", import.meta.url), "utf8"));
  assert.equal(feed.length, INCIDENTS.length);
  assert.ok(feed.every((i: { source: string }) => i.source.startsWith("https://")));
});
