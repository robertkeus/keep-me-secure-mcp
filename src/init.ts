import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { VERSION } from "./version.ts";

const IMAGE = `ghcr.io/robertkeus/keep-me-secure-mcp:v${VERSION}`;
const RUN =
  'docker run -i --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges ' +
  '-v "${CLAUDE_PROJECT_DIR:-$PWD}:/workspace:ro" -v kms-cache:/cache ' +
  IMAGE;
const HOOK = `${RUN} check 2>/dev/null || echo "keep-me-secure: security check skipped, is Docker running?"`;
const AGENTS_RULE = `## Security check

At the start of each coding session, call the \`check_project\` tool from the keep-me-secure MCP server and tell the user the result. Never run an upgrade without their approval.
`;

async function readJson(file: string): Promise<Record<string, any>> {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new Error(`${file} is not valid JSON, fix it and run init again`);
  }
}

async function writeJson(file: string, value: unknown) {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(value, null, 2) + "\n");
}

export async function init(): Promise<string[]> {
  const mcp = await readJson(".mcp.json");
  mcp.mcpServers = { ...mcp.mcpServers, "keep-me-secure": { command: "sh", args: ["-c", `exec ${RUN}`] } };

  const settings = await readJson(".claude/settings.json");
  const ours = (h: any) => h.command?.includes("keep-me-secure");
  const sessionStart: any[] = (settings.hooks?.SessionStart ?? [])
    .map((g: any) => ({ ...g, hooks: g.hooks?.filter((h: any) => !ours(h)) }))
    .filter((g: any) => g.hooks?.length);
  sessionStart.push({ hooks: [{ type: "command", command: HOOK, timeout: 120 }] });
  settings.hooks = { ...settings.hooks, SessionStart: sessionStart };

  const agents = await readFile("AGENTS.md", "utf8").catch(() => "");

  await writeJson(".mcp.json", mcp);
  await writeJson(".claude/settings.json", settings);
  if (!agents.includes("keep-me-secure")) await writeFile("AGENTS.md", agents ? `${agents.trimEnd()}\n\n${AGENTS_RULE}` : AGENTS_RULE);
  return [".mcp.json", ".claude/settings.json", "AGENTS.md"];
}
