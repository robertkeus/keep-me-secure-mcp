import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { scanProject } from "../src/scan.ts";

const dir = (p: string) => fileURLToPath(new URL(`fixtures/${p}`, import.meta.url));

test("finds lockfiles and tags deps with ecosystem and path", async () => {
  const s = await scanProject(dir("php"));
  assert.equal(s.deps[0]?.ecosystem, "Packagist");
  assert.equal(s.deps[0]?.lockfile, "composer.lock");
});

test("a broken lockfile is unchecked, and a workspace package is covered by the root lock", async () => {
  const s = await scanProject(dir("mono"));
  assert.equal(s.deps.length, 1);
  assert.deepEqual(s.unchecked.map((u) => u.item), ["composer.lock"]);
});

test("manifest without lockfile is unchecked", async () => {
  const s = await scanProject(dir("nolock"));
  assert.match(s.unchecked[0]?.reason ?? "", /no lockfile/);
});

test("unsupported ecosystems are reported", async () => {
  const s = await scanProject(dir("dart"));
  assert.deepEqual(s.unchecked.map((u) => u.item), ["pubspec.lock"]);
});

test("Maven and .NET projects without a lockfile are unchecked", async () => {
  const s = await scanProject(dir("nolock-jvm"));
  assert.deepEqual(s.unchecked.map((u) => u.item).sort(), ["app.csproj", "pom.xml"]);
});

test("a polyglot project scans every ecosystem", async () => {
  const s = await scanProject(dir("stack"));
  assert.deepEqual([...new Set(s.deps.map((d) => d.ecosystem))].sort(), ["Go", "Maven", "NuGet", "RubyGems", "crates.io"]);
  assert.deepEqual(s.unchecked, []);
});

test("lockfiles in test folders are listed, not checked, unless they're the root", async () => {
  const root = mkdtempSync(join(tmpdir(), "kms-"));
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" } } });
  mkdirSync(join(root, "test", "app"), { recursive: true });
  writeFileSync(join(root, "package-lock.json"), lock);
  writeFileSync(join(root, "test", "app", "package-lock.json"), lock);
  writeFileSync(join(root, "test", "app", "package.json"), "{}");
  const s = await scanProject(root);
  assert.deepEqual(s.deps.map((d) => d.lockfile), ["package-lock.json"]);
  assert.deepEqual(s.ignored, ["test/app/package-lock.json"]);
  assert.deepEqual(s.unchecked, []);
  assert.equal((await scanProject(join(root, "test", "app"))).deps.length, 1);
});

test("ecosystem filter", async () => {
  const s = await scanProject(dir("mono"), "npm");
  assert.deepEqual(s.unchecked, []);
});

test("a crafted package name never reaches a report", async () => {
  const root = mkdtempSync(join(tmpdir(), "kms-"));
  writeFileSync(
    join(root, "package-lock.json"),
    JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/x;rm -rf ~": { version: "1.0.0" } } }),
  );
  const s = await scanProject(root);
  assert.deepEqual(s.deps, []);
  assert.match(s.unchecked[0]!.reason, /invalid/);
});
