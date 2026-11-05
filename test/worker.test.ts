import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { clientKey } from "../src/handler.ts";
import worker, { RateLimiter } from "../src/worker.ts";

const allowed = async (limiter: RateLimiter, n: number) => {
  let ok = 0;
  for (let i = 0; i < n; i++) if ((await limiter.fetch()).status === 204) ok++;
  return ok;
};

test("allows 20 checks a minute, then blocks until the window ends", async () => {
  const now = mock.method(Date, "now", () => 1_000_000);
  const limiter = new RateLimiter();
  assert.equal(await allowed(limiter, 25), 20);
  now.mock.mockImplementation(() => 1_059_999);
  assert.equal(await allowed(limiter, 1), 0);
  now.mock.mockImplementation(() => 1_060_000);
  assert.equal(await allowed(limiter, 25), 20);
  mock.restoreAll();
});

test("an IPv6 network shares one limit, IPv4 addresses don't", () => {
  assert.equal(clientKey("2a06:98c1:3121:1:aaaa::1"), clientKey("2a06:98c1:3121:1:bbbb::2"));
  assert.notEqual(clientKey("2a06:98c1:3121:1::1"), clientKey("2a06:98c1:3121:2::1"));
  assert.notEqual(clientKey("203.0.113.1"), clientKey("203.0.113.2"));
});

const call = () =>
  new Request("https://mcp.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "cf-connecting-ip": "203.0.113.1" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "nope", arguments: {} } }),
  });

const env = (fetch: () => Promise<Response>) =>
  ({
    REQUEST_LIMIT: { limit: async () => ({ success: true }) },
    CHECKS: { idFromName: (n: string) => n, get: () => ({ fetch }) },
  }) as any;

test("a blocked client gets a 429", async () => {
  const r = await worker.fetch(call(), env(async () => new Response(null, { status: 429 })));
  assert.equal(r.status, 429);
  assert.equal(r.headers.get("retry-after"), "60");
});

test("a limiter outage doesn't take the service down", async () => {
  const r = await worker.fetch(call(), env(async () => { throw new Error("down"); }));
  assert.equal(r.status, 200);
});
