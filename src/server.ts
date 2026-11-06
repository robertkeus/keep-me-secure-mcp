import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkPackage, checkPackages, checkPlatform, checkProject, checkRuntime, InputError } from "./check.ts";
import type { PlatformReport } from "./platforms.ts";
import type { Report } from "./report.ts";
import type { RuntimeReport } from "./runtimes.ts";
import { VERSION } from "./version.ts";

const INSTRUCTIONS =
  "Call check_project once at the start of each coding session and tell the user the result. " +
  "Also call it, without an ecosystem, for any broad security question such as 'is my stack secure?' or 'do we have vulnerable dependencies?'. " +
  "Tell the user what was covered and what was not. " +
  "platforms and runtimes in the result list known issues with the platforms and Node.js or PHP versions the project uses, separately from the package verdict. " +
  "A runtime with status unverified can't be confirmed from the repo, so ask the user to check the version really running. " +
  "The result also covers support dates, install_protection and old_packages: mention any that need action, and never present an old package as a vulnerability. " +
  "Call check_platform when the user asks about a hosting or AI platform, or a breach. " +
  "Results are cached per day, so repeat calls are cheap. " +
  "Use check_package before adding a dependency or when asked about a specific package. " +
  "Never run an upgrade without the user's approval.";

const HOSTED_INSTRUCTIONS =
  "This hosted server can't see the user's files. For any broad security question such as 'is my stack secure?', " +
  "read the exact installed versions from the project's lockfiles and send them to check_packages, up to 500 per call. " +
  "Never guess a version from a range. Never send private or internal package names. " +
  "Tell the user which lockfiles you read and what was left out. " +
  "Call check_platform for any hosting or AI platform the user names, or to list recent platform breaches. " +
  "Call check_runtime with the exact Node.js or PHP version from the project or the running system. Never run an upgrade without the user's approval.";

const tool = (run: () => Promise<Report | PlatformReport | RuntimeReport>) =>
  run().then(
    (report) => ({ content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] }),
    (e: Error) => ({
      content: [{ type: "text" as const, text: e instanceof InputError ? e.message : "The check failed." }],
      isError: true,
    }),
  );

export function createServer({ hosted = false } = {}): McpServer {
  const instructions = hosted ? HOSTED_INSTRUCTIONS : INSTRUCTIONS;
  const server = new McpServer({ name: "keep-me-secure", version: VERSION }, { instructions });
  const annotations = { readOnlyHint: true, openWorldHint: true };

  const packageFields = {
    ecosystem: z.string().describe("php, npm, python, go, rust, ruby, java or dotnet"),
    name: z.string().describe("Package name, such as guzzlehttp/guzzle"),
    version: z.string().describe("Exact version, such as 7.4.0"),
  };

  if (hosted)
    server.registerTool(
      "check_packages",
      {
        title: "Is my stack secure?",
        description:
          "Use for questions like 'is my stack secure?' or 'do we have vulnerable packages?'. " +
          "Checks a list of exact installed package versions against public security advisories. " +
          "Read them from the project's lockfiles, including transitive packages. Up to 500 per call; call again for more. " +
          "verdict is yes, no or unknown; unknown means the check was incomplete, so never report it as safe. " +
          "Does not cover OS packages, Docker base images or your own code. Use check_runtime for Node.js and PHP versions.",
        inputSchema: { packages: z.array(z.object(packageFields)).min(1).max(500) },
        annotations,
      },
      ({ packages }) => tool(() => checkPackages(packages)),
    );
  else
    server.registerTool(
    "check_project",
    {
      title: "Is my stack secure?",
      description:
        "Use for questions like 'is my stack secure?', 'do I need to patch anything?' or 'do we have vulnerable packages?'. " +
        "Checks every installed package, including transitive ones, in all lockfiles in this project against public security advisories. " +
        "verdict is yes, no or unknown; unknown means the check was incomplete, so never report it as safe. " +
        "Supports PHP, JavaScript, Python, Go, Rust, Ruby, Java (Gradle lockfiles) and .NET. " +
        "Also reports known issues with the platforms and the Node.js or PHP versions the project uses. Does not cover OS packages, Docker base images or your own code.",
      inputSchema: {
        ecosystem: z.string().optional().describe("Only to limit the check: php, npm, python, go, rust, ruby, java or dotnet. Omit for a full check."),
        path: z.string().optional().describe("Subfolder relative to the project root. Omit to scan the whole project. Test and example folders are skipped unless named here."),
        refresh: z.boolean().optional().describe("Ignore today's cached result"),
      },
      annotations,
    },
    (args) => tool(() => checkProject(args)),
  );

  server.registerTool(
    "check_platform",
    {
      title: "Has this platform been breached?",
      description:
        "Lists known security incidents at hosting, deployment and AI platforms, with what to do and a link to the source. " +
        "Use when the user asks about a platform or breach. Omit name to list all. " +
        "The list is curated and not complete, so no result doesn't mean a platform is safe.",
      inputSchema: { name: z.string().max(40).optional().describe("Platform name, such as railway or vercel") },
      annotations,
    },
    ({ name }) => tool(() => checkPlatform(name, { hosted })),
  );

  server.registerTool(
    "check_runtime",
    {
      title: "Is this Node.js or PHP version safe?",
      description:
        "Checks a Node.js or PHP version against known security flaws in the runtime itself. " +
        "Use with the exact version, for example from `node --version` or `php --version`. " +
        "The list is curated, so no findings doesn't prove a version is safe.",
      inputSchema: {
        runtime: z.string().describe("node or php"),
        version: z.string().max(20).describe("Version, such as 8.4.26"),
      },
      annotations,
    },
    ({ runtime, version }) => tool(() => checkRuntime(runtime, version, { hosted })),
  );

  server.registerTool(
    "check_package",
    {
      title: "Is this package version safe?",
      description: "Checks one exact package version against public security advisories.",
      inputSchema: packageFields,
      annotations,
    },
    (args) => tool(() => checkPackage(args)),
  );

  return server;
}
