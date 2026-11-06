import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { VERSION } from "../src/version.ts";

test("every release has a changelog entry", () => {
  const changelog = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");
  assert.equal(changelog.match(/^## (\S+)/m)?.[1], VERSION);
});

test("version matches package.json and server.json", () => {
  for (const file of ["package.json", "server.json", "plugin/.claude-plugin/plugin.json"])
    assert.equal(JSON.parse(readFileSync(new URL(`../${file}`, import.meta.url), "utf8")).version, VERSION);
});
