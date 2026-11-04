import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  parseComposerLock,
  parsePackageLock,
  parsePnpmLock,
  parsePoetryLock,
  parseRequirements,
  parseUvLock,
  parseYarnLock,
} from "../src/parsers.ts";

const read = (p: string) => readFileSync(new URL(`fixtures/${p}`, import.meta.url), "utf8");
const dep = (name: string, version: string, direct: boolean) => ({ name, version, direct });

test("composer.lock strips v, flags private and branch versions", () => {
  const r = parseComposerLock(read("php/composer.lock"), read("php/composer.json"));
  assert.deepEqual(r.deps, [dep("guzzlehttp/guzzle", "7.4.0", true), dep("psr/log", "1.1.4", false)]);
  assert.deepEqual(r.private, ["acme/internal"]);
  assert.equal(r.unchecked[0]?.item, "acme/tool@dev-main");
});

test("package-lock.json handles nesting, links and private registries", () => {
  const r = parsePackageLock(read("npm/package-lock.json"));
  assert.deepEqual(r.deps, [
    dep("lodash", "4.17.15", true),
    dep("a", "1.0.0", false),
    dep("lodash", "3.0.0", false),
  ]);
  assert.deepEqual(r.private, ["@acme/ui"]);
});

test("package-lock.json v1 is refused", () => {
  assert.throws(() => parsePackageLock('{"lockfileVersion":1,"dependencies":{}}'));
});

test("pnpm-lock.yaml strips peer suffixes", () => {
  const r = parsePnpmLock(read("pnpm/pnpm-lock.yaml"));
  assert.deepEqual(r.deps, [dep("lodash", "4.17.15", true), dep("@babel/core", "7.1.0", false)]);
  assert.deepEqual(r.private, ["internal"]);
});

test("yarn.lock v1", () => {
  const r = parseYarnLock(read("yarn1/yarn.lock"), read("yarn1/package.json"));
  assert.deepEqual(r.deps, [dep("@babel/core", "7.1.0", false), dep("lodash", "4.17.15", true)]);
  assert.deepEqual(r.private, ["internal"]);
});

test("yarn.lock berry", () => {
  const r = parseYarnLock(read("yarn4/yarn.lock"), read("yarn4/package.json"));
  assert.deepEqual(r.deps, [dep("lodash", "4.17.15", true), dep("@babel/core", "7.1.0", false)]);
  assert.deepEqual(r.private, ["gitdep"]);
});

test("poetry.lock", () => {
  const r = parsePoetryLock(read("poetry/poetry.lock"), read("poetry/pyproject.toml"));
  assert.deepEqual(r.deps, [dep("django", "3.2.0", true), dep("sqlparse", "0.4.0", false)]);
  assert.deepEqual(r.private, ["internal"]);
});

test("uv.lock skips the root project", () => {
  const r = parseUvLock(read("uv/uv.lock"), read("uv/pyproject.toml"));
  assert.deepEqual(r.deps, [dep("django", "3.2.0", true)]);
  assert.deepEqual(r.private, ["internal"]);
});

test("requirements.txt reads pins and reports the rest", () => {
  const r = parseRequirements(read("pip/requirements.txt"));
  assert.deepEqual(r.deps, [dep("django", "3.2.0", true), dep("requests", "2.25.0", true)]);
  assert.deepEqual(r.unchecked.map((u) => u.item), ["flask>=2.0"]);
});
