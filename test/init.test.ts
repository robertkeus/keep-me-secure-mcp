import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, beforeEach, test } from "node:test";
import { init } from "../src/init.ts";

const start = process.cwd();
const read = (f: string) => readFileSync(f, "utf8");

beforeEach(() => process.chdir(mkdtempSync(join(tmpdir(), "kms-init-"))));
after(() => process.chdir(start));

test("writes config and is idempotent", async () => {
  await init();
  await init();
  const settings = JSON.parse(read(".claude/settings.json"));
  assert.equal(settings.hooks.SessionStart.length, 1);
  assert.equal(read("AGENTS.md").match(/keep-me-secure/g)?.length, 1);
  assert.equal(JSON.parse(read(".mcp.json")).mcpServers["keep-me-secure"].command, "sh");
});

test("keeps existing config", async () => {
  mkdirSync(".claude");
  writeFileSync(".mcp.json", '{"mcpServers":{"other":{"command":"x"}}}');
  writeFileSync(".claude/settings.json", '{"model":"m","hooks":{"Stop":[]}}');
  writeFileSync("AGENTS.md", "# Rules\n");
  await init();
  const settings = JSON.parse(read(".claude/settings.json"));
  assert.ok(JSON.parse(read(".mcp.json")).mcpServers.other);
  assert.equal(settings.model, "m");
  assert.deepEqual(settings.hooks.Stop, []);
  assert.match(read("AGENTS.md"), /^# Rules\n\n## Security check/);
});

test("refuses to overwrite invalid JSON", async () => {
  writeFileSync(".mcp.json", "{oops");
  await assert.rejects(init(), /not valid JSON/);
  assert.equal(read(".mcp.json"), "{oops");
});
