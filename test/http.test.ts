import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, mock, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { serve } from "../src/http.ts";

const realFetch = globalThis.fetch;
const json = (body: unknown) => new Response(JSON.stringify(body));
let server: Server;
let base: string;

beforeEach(async () => {
  process.env.KMS_CACHE_DIR = mkdtempSync(join(tmpdir(), "kms-"));
  mock.method(globalThis, "fetch", async (url: any, init: any) => {
    if (String(url).startsWith("http://127.0.0.1")) return realFetch(url, init);
    return json({ results: JSON.parse(init.body).queries.map(() => ({})) });
  });
  server = serve();
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  mock.restoreAll();
  server.closeAllConnections();
  await new Promise((done) => server.close(done));
  delete process.env.KMS_TRUST_PROXY;
});

const connect = async () => {
  const client = new Client({ name: "test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)));
  return client;
};

const post = (body: string, headers: Record<string, string> = {}) =>
  realFetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body,
  });

const call = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "check_package", arguments: { ecosystem: "npm", name: "a", version: "1.0.0" } },
});

test("hosted server offers no tool that reads the disk", async () => {
  const client = await connect();
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ["check_package", "check_packages"]);
  await client.close();
});

test("check_packages checks a list and reports bad entries", async () => {
  const client = await connect();
  const r: any = await client.callTool({
    name: "check_packages",
    arguments: {
      packages: [
        { ecosystem: "npm", name: "lodash", version: "4.17.21" },
        { ecosystem: "cobol", name: "x", version: "1.0.0" },
        { ecosystem: "npm", name: "x;rm -rf ~", version: "1.0.0" },
      ],
    },
  });
  const report = JSON.parse(r.content[0].text);
  assert.equal(report.coverage.scanned, 1);
  assert.equal(report.coverage.unchecked.length, 2);
  assert.equal(report.verdict, "unknown");
  assert.match(report.note, /Only the 3 packages sent/);
  await client.close();
});

test("rejects more than 500 packages", async () => {
  const client = await connect();
  const packages = Array.from({ length: 501 }, () => ({ ecosystem: "npm", name: "a", version: "1.0.0" }));
  const r: any = await client.callTool({ name: "check_packages", arguments: { packages } }).catch((e) => ({ isError: true, e }));
  assert.equal(r.isError, true);
  await client.close();
});

test("routes", async () => {
  assert.equal((await realFetch(`${base}/health`)).status, 200);
  assert.equal((await realFetch(`${base}/`)).status, 404);
  assert.equal((await realFetch(`${base}/mcp`)).status, 405);
});

test("refuses bad bodies", async () => {
  assert.equal((await post("{oops")).status, 400);
  assert.equal((await post(`[${call}]`)).status, 400);
  assert.equal((await post("x".repeat(300 * 1024))).status, 413);
});

test("limits checks per client", async () => {
  const codes = [];
  for (let i = 0; i < 21; i++) codes.push((await post(call)).status);
  assert.equal(codes.filter((c) => c === 429).length, 1);
  assert.equal(codes.at(-1), 429);
});

test("a spoofed X-Forwarded-For entry doesn't dodge the limit", async () => {
  process.env.KMS_TRUST_PROXY = "1";
  const codes = [];
  for (let i = 0; i < 21; i++)
    codes.push((await post(call, { "x-forwarded-for": `10.0.0.${i}, 203.0.113.9` })).status);
  assert.equal(codes.at(-1), 429);
});

test("without a trusted proxy the header is ignored", async () => {
  const codes = [];
  for (let i = 0; i < 21; i++) codes.push((await post(call, { "x-forwarded-for": `10.0.0.${i}` })).status);
  assert.equal(codes.at(-1), 429);
});
