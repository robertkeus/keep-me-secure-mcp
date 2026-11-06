import { dirname, join, relative } from "node:path";
import { isDockerfile } from "./docker.ts";
import { readSmallFile } from "./upkeep.ts";

export interface DependabotReport {
  exists: boolean;
  /** Ecosystems in this project that the current file doesn't mention. */
  missing: string[];
  file: string;
  /** A suggested file. Nothing is written: the agent shows it, and writes it with the user's OK. */
  content: string;
  note: string;
}

const COOLDOWN_DAYS = 2;
const NOTE =
  "Dependabot opens pull requests, so nothing changes without a review. The cooldown makes routine updates wait, which blocks many supply chain attacks, " +
  "and GitHub doesn't apply it to security updates, so fixes aren't delayed. Turn on Dependabot security updates in the repo settings too. " +
  "Show this to the user, and only write the file with their OK.";

const ECOSYSTEMS: Record<string, string> = {
  "package-lock.json": "npm",
  "pnpm-lock.yaml": "npm",
  "yarn.lock": "npm",
  "composer.lock": "composer",
  "poetry.lock": "pip",
  "uv.lock": "uv",
  "go.mod": "gomod",
  "Cargo.lock": "cargo",
  "Gemfile.lock": "bundler",
  "gradle.lockfile": "gradle",
  "packages.lock.json": "nuget",
};

const isSafeDirectory = (dir: string) => /^\/[A-Za-z0-9._/@+-]*$/.test(dir) && !dir.includes("..");

function ecosystemOf(file: string): string | undefined {
  const base = file.slice(file.lastIndexOf("/") + 1);
  if (/^requirements.*\.txt$/.test(base)) return "pip";
  if (isDockerfile(base)) return "docker";
  return Object.hasOwn(ECOSYSTEMS, base) ? ECOSYSTEMS[base] : undefined;
}

export async function dependabotConfig(root: string, files: string[]): Promise<DependabotReport> {
  const found = new Map<string, Set<string>>();
  const add = (ecosystem: string, dir: string) => {
    if (isSafeDirectory(dir)) found.set(ecosystem, (found.get(ecosystem) ?? new Set()).add(dir));
  };
  for (const file of files) {
    const rel = relative(root, file);
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel)) add("github-actions", "/");
    const ecosystem = ecosystemOf(file);
    if (ecosystem) add(ecosystem, `/${relative(root, dirname(file))}`.replace(/\/$/, "") || "/");
  }

  const blocks = [...found].sort(([a], [b]) => a.localeCompare(b)).map(([ecosystem, dirs]) => {
    const list = [...dirs].sort().map((d) => `      - "${d}"`).join("\n");
    const cooldown = ecosystem === "github-actions" ? "" : `\n    cooldown:\n      default-days: ${COOLDOWN_DAYS}`;
    return `  - package-ecosystem: "${ecosystem}"\n    directories:\n${list}\n    schedule:\n      interval: "weekly"${cooldown}`;
  });
  const content = `version: 2\nupdates:\n${blocks.join("\n")}\n`;

  let current: string | null = null;
  for (const name of ["dependabot.yml", "dependabot.yaml"]) {
    current ??= (await readSmallFile(join(root, ".github", name))) || null;
  }
  const missing = [...found.keys()].filter((e) => !current?.match(new RegExp(`package-ecosystem:\\s*["']?${e}["']?\\s*$`, "m"))).sort();
  return { exists: current !== null, missing, file: ".github/dependabot.yml", content: found.size ? content : "", note: NOTE };
}
