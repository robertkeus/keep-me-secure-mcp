import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkPackage, checkProject } from "./check.ts";
import type { Report } from "./report.ts";
import { VERSION } from "./version.ts";

const INSTRUCTIONS =
  "Call check_project once at the start of each coding session and tell the user the result. " +
  "Also call it, without an ecosystem, for any broad security question such as 'is my stack secure?' or 'do we have vulnerable dependencies?'. " +
  "Tell the user what was covered and what was not. " +
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
      title: "Is my stack secure?",
      description:
        "Use for questions like 'is my stack secure?', 'do I need to patch anything?' or 'do we have vulnerable packages?'. " +
        "Checks every installed package, including transitive ones, in all lockfiles in this project against public security advisories. " +
        "verdict is yes, no or unknown; unknown means the check was incomplete, so never report it as safe. " +
        "Supports PHP, JavaScript, Python, Go, Rust, Ruby, Java (Gradle lockfiles) and .NET. " +
        "Does not cover language runtimes, OS packages or Docker base images.",
      inputSchema: {
        ecosystem: z.string().optional().describe("Only to limit the check: php, npm, python, go, rust, ruby, java or dotnet. Omit for a full check."),
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
        ecosystem: z.string().describe("php, npm, python, go, rust, ruby, java or dotnet"),
        name: z.string().describe("Package name, such as guzzlehttp/guzzle"),
        version: z.string().describe("Exact version, such as 7.4.0"),
      },
      annotations,
    },
    (args) => tool(() => checkPackage(args)),
  );

  return server;
}
