import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, mock, test } from "node:test";
import { checkPackage, checkProject, summarize, toEcosystem } from "../src/check.ts";

const json = (body: unknown) => new Response(JSON.stringify(body));
const start = process.cwd();
let root: string;

function lock(version: string) {
  writeFileSync(
    join(root, "package-lock.json"),
    JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version } } }),
  );
}

const countOsv = () => {
  const f = mock.method(globalThis, "fetch", async () => json({ results: [{}] }));
  return () => f.mock.callCount();
};

before(() => {
  root = mkdtempSync(join(tmpdir(), "kms-project-"));
  process.chdir(root);
});
after(() => process.chdir(start));
beforeEach(() => {
  mock.restoreAll();
  process.env.KMS_CACHE_DIR = mkdtempSync(join(tmpdir(), "kms-"));
});

test("second run the same day uses the cache", async () => {
  lock("1.0.0");
  const calls = countOsv();
  assert.equal((await checkProject()).verdict, "no");
  await checkProject();
  assert.equal(calls(), 1);
});

test("a lockfile change or refresh runs a new check", async () => {
  lock("1.0.0");
  const calls = countOsv();
  await checkProject();
  lock("1.0.1");
  await checkProject();
  assert.equal(calls(), 2);
  await checkProject({ refresh: true });
  assert.equal(calls(), 3);
});

test("a failed lookup is not cached", async () => {
  lock("1.0.0");
  mock.method(globalThis, "fetch", async () => new Response("", { status: 503 }));
  assert.equal((await checkProject()).verdict, "unknown");
  mock.restoreAll();
  countOsv();
  assert.equal((await checkProject()).verdict, "no");
});

test("rejects paths outside the project", async () => {
  await assert.rejects(checkProject({ path: "../etc" }), /subfolder/);
  await assert.rejects(checkProject({ path: "/etc" }), /subfolder/);
});

test("check_package refuses ranges", async () => {
  await assert.rejects(checkPackage({ ecosystem: "npm", name: "lodash", version: "^4.0.0" }), /exact version/);
});

test("ecosystem aliases", () => {
  assert.equal(toEcosystem("PHP"), "Packagist");
  assert.throws(() => toEcosystem("ruby"), /Unsupported/);
});

test("summary is one line when clean", async () => {
  lock("1.0.0");
  countOsv();
  assert.match(summarize(await checkProject()), /^keep-me-secure: no known issues in 1 packages\.$/);
});
