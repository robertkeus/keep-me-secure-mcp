import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createServer } from "./server.ts";

export const MAX_BODY_BYTES = 256 * 1024;

export interface Limits {
  request(ip: string): boolean | Promise<boolean>;
  check(ip: string): boolean | Promise<boolean>;
}

export const reply = (status: number, message: string, headers: Record<string, string> = {}) =>
  new Response(`${message}\n`, { status, headers: { "content-type": "text/plain", ...headers } });

const tooMany = (message: string) => reply(429, message, { "retry-after": "60" });

/** Stateless, and deliberately logs nothing about requests: package lists show what a company runs. */
export async function handle(request: Request, ip: string, limits: Limits): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (pathname === "/health") return reply(200, "ok");
  if (pathname !== "/mcp") return reply(404, "Not found. The MCP endpoint is /mcp");
  if (request.method !== "POST") return reply(405, "Use POST", { allow: "POST" });
  if (!(await limits.request(ip))) return tooMany("Too many requests, try again in a minute");

  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY_BYTES) return reply(413, "Request too large");
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return reply(413, "Request too large");

  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    return reply(400, "Invalid JSON");
  }
  if (Array.isArray(body)) return reply(400, "Batch requests are not supported");
  if (body?.method === "tools/call" && !(await limits.check(ip))) return tooMany("Too many checks, try again in a minute");

  const server = createServer({ hosted: true });
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  try {
    await server.connect(transport);
    return await transport.handleRequest(new Request(request.url, { method: "POST", headers: request.headers, body: text }), {
      parsedBody: body,
    });
  } catch {
    return reply(500, "Internal error");
  } finally {
    await server.close();
  }
}
