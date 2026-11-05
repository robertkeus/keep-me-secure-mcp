import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { handle, MAX_BODY_BYTES } from "./handler.ts";

const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 120;
const MAX_CHECKS_PER_WINDOW = 20;
const MAX_IN_FLIGHT = 50;
const MAX_TRACKED_CLIENTS = 100_000;

function limiter(max: number) {
  let hits = new Map<string, number>();
  let windowEnd = 0;
  return (ip: string) => {
    if (Date.now() > windowEnd || hits.size > MAX_TRACKED_CLIENTS) {
      hits = new Map();
      windowEnd = Date.now() + WINDOW_MS;
    }
    const count = (hits.get(ip) ?? 0) + 1;
    hits.set(ip, count);
    return count <= max;
  };
}

/** Behind a proxy the last X-Forwarded-For entry is the one the proxy added, so clients can't spoof it. */
function clientIp(req: IncomingMessage): string {
  const forwarded = process.env.KMS_TRUST_PROXY && String(req.headers["x-forwarded-for"] ?? "").split(",").at(-1)?.trim();
  return forwarded || req.socket.remoteAddress || "unknown";
}

async function readBody(req: IncomingMessage): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function send(res: ServerResponse, response: Response) {
  res.writeHead(response.status, Object.fromEntries(response.headers)).end(await response.text());
}

/** The self-hosted server: a Node front for the handler the Cloudflare Worker uses too. */
export function serve(): Server {
  const limits = { request: limiter(MAX_REQUESTS_PER_WINDOW), check: limiter(MAX_CHECKS_PER_WINDOW) };
  let inFlight = 0;

  const server = createHttpServer(async (req, res) => {
    if (inFlight >= MAX_IN_FLIGHT)
      return res.writeHead(503, { "content-type": "text/plain", "retry-after": "5" }).end("Busy, try again shortly\n");
    inFlight++;
    res.on("close", () => inFlight--);
    try {
      const body = req.method === "POST" ? await readBody(req) : undefined;
      if (body === null) return res.writeHead(413, { connection: "close" }).end("Request too large\n");
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
      const request = new Request(`http://${req.headers.host ?? "localhost"}${req.url}`, { method: req.method, headers, body });
      await send(res, await handle(request, clientIp(req), limits));
    } catch {
      if (!res.headersSent) res.writeHead(500).end("Internal error\n");
    }
  });
  server.requestTimeout = 30_000;
  return server;
}
