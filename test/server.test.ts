import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.ts";

test("lists both tools and reports bad input as a tool error", async () => {
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "1" });
  await Promise.all([createServer().connect(a), client.connect(b)]);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name), ["check_project", "check_platform", "suggest_dependabot", "check_runtime", "check_package"]);
  const r = await client.callTool({ name: "check_project", arguments: { path: "/etc" } });
  assert.equal(r.isError, true);
  await client.close();
});
