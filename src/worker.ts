import { setCacheStore } from "./cache.ts";
import { handle } from "./handler.ts";

interface Env {
  REQUEST_LIMIT: { limit(options: { key: string }): Promise<{ success: boolean }> };
  CHECK_LIMIT: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

const CACHE_SECONDS = 86_400;
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
    return handle(request, ip, {
      request: async (key) => (await env.REQUEST_LIMIT.limit({ key })).success,
      check: async (key) => (await env.CHECK_LIMIT.limit({ key })).success,
    });
  },
};
