import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkPackage, checkProject } from "./check.ts";
import type { Report } from "./report.ts";
import { VERSION } from "./version.ts";

const INSTRUCTIONS =
  "Call check_project once at the start of each coding session and tell the user the result. " +
  "Results are cached per day, so repeat calls are cheap. " +
  "Use check_package before adding a dependency or when asked about a specific package. " +
  "Never run an upgrade without the user's approval.";

const tool = (run: () => Promise<Report>) =>
  run().then(
    (report) => ({ content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] }),
    (e: Error) => ({ content: [{ type: "text" as const, text: e.message }], isError: true }),
  );

export function createServer(): McpServer {
  const server = new McpServer({ name: "keep-me-secure", version: VERSION }, { instructions: INSTRUCTIONS });
  const annotations = { readOnlyHint: true, openWorldHint: true };

  server.registerTool(
    "check_project",
    {
      title: "Do I need to patch anything?",
      description:
        "Checks the installed versions in this project's lockfiles against public security advisories. " +
        "verdict is yes, no or unknown; unknown means the check was incomplete, so never report it as safe. " +
        "Supports PHP (Composer), JavaScript (npm, pnpm, Yarn) and Python (pip, Poetry, uv).",
      inputSchema: {
        ecosystem: z.string().optional().describe("Limit the check: php, npm or python"),
        path: z.string().optional().describe("Subfolder relative to the project root. Omit to scan the whole project."),
        refresh: z.boolean().optional().describe("Ignore today's cached result"),
      },
      annotations,
    },
    (args) => tool(() => checkProject(args)),
  );

  server.registerTool(
    "check_package",
    {
      title: "Is this package version safe?",
      description: "Checks one exact package version against public security advisories.",
      inputSchema: {
        ecosystem: z.string().describe("php, npm or python"),
        name: z.string().describe("Package name, such as guzzlehttp/guzzle"),
        version: z.string().describe("Exact version, such as 7.4.0"),
      },
      annotations,
    },
    (args) => tool(() => checkPackage(args)),
  );

  return server;
}
