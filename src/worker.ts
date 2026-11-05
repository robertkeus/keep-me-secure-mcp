import { setCacheStore } from "./cache.ts";
import { clientKey, handle } from "./handler.ts";

interface Env {
  REQUEST_LIMIT: { limit(options: { key: string }): Promise<{ success: boolean }> };
  CHECKS: {
    idFromName(name: string): unknown;
    get(id: unknown): { fetch(url: string): Promise<Response> };
  };
}

const CACHE_SECONDS = 86_400;
const MAX_CHECKS_PER_WINDOW = 20;
const WINDOW_MS = 60_000;
const cacheUrl = (key: string) => `https://cache.keep-me-secure.internal/${key}`;
const edge = () => (globalThis as any).caches.default;

setCacheStore({
  async read(key) {
    return (await edge().match(cacheUrl(key)))?.json();
  },
  async write(key, value) {
    const headers = { "cache-control": `max-age=${CACHE_SECONDS}`, "content-type": "application/json" };
    await edge().put(cacheUrl(key), new Response(JSON.stringify(value), { headers }));
  },
});

/**
 * One instance per client, so the count is exact across every Cloudflare location. Cloudflare's rate
 * limit binding counts per running copy, which lets low limits through. Memory is enough: an instance
 * only goes away after sitting idle, and idle clients aren't over the limit.
 */
export class RateLimiter {
  count = 0;
  windowEnd = 0;

  async fetch(): Promise<Response> {
    const now = Date.now();
    if (now >= this.windowEnd) {
      this.count = 0;
      this.windowEnd = now + WINDOW_MS;
    }
    this.count++;
    return new Response(null, { status: this.count <= MAX_CHECKS_PER_WINDOW ? 204 : 429 });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const ip = clientKey(request.headers.get("cf-connecting-ip") ?? "unknown");
    return handle(request, ip, {
      request: async (key) => (await env.REQUEST_LIMIT.limit({ key })).success,
      async check(key) {
        // If the limiter itself is down, keep answering: an outage shouldn't take the service with it.
        try {
          return (await env.CHECKS.get(env.CHECKS.idFromName(key)).fetch("https://limit/")).status !== 429;
        } catch {
          return true;
        }
      },
    });
  },
};
