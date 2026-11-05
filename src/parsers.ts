import { parse as parseToml } from "smol-toml";
import type { Parsed } from "./types.ts";

type Json = Record<string, any>;

const BAD_VERSION = "no exact version, so it can't be checked";

const empty = (): Parsed => ({ deps: [], private: [], unchecked: [] });
const isVersion = (v: unknown): v is string => typeof v === "string" && /^\d/.test(v);
const onNpm = (url?: string) => !url || /^https:\/\/registry\.(npmjs\.org|yarnpkg\.com)\//.test(url);

function npmDirect(manifest?: string): Set<string> {
  if (!manifest) return new Set();
  const m = JSON.parse(manifest);
  return new Set(
    ["dependencies", "devDependencies", "optionalDependencies"].flatMap((k) => Object.keys(m[k] ?? {})),
  );
}

export function parseComposerLock(lock: string, manifest?: string): Parsed {
  const out = empty();
  const data = JSON.parse(lock);
  const m = manifest ? JSON.parse(manifest) : {};
  const direct = new Set([...Object.keys(m.require ?? {}), ...Object.keys(m["require-dev"] ?? {})]);
  for (const p of [...(data.packages ?? []), ...(data["packages-dev"] ?? [])]) {
    if (typeof p?.name !== "string") {
      out.unchecked.push({ item: "composer.lock", reason: "entry with an invalid package name" });
      continue;
    }
    if (!String(p["notification-url"] ?? "").includes("packagist.org")) out.private.push(p.name);
    else {
      const version = String(p.version).replace(/^v/, "");
      if (isVersion(version)) out.deps.push({ name: p.name, version, direct: direct.has(p.name) });
      else out.unchecked.push({ item: `${p.name}@${p.version}`, reason: "branch version, no release to match" });
    }
  }
  return out;
}

export function parsePackageLock(lock: string): Parsed {
  const out = empty();
  const data = JSON.parse(lock);
  if (!data.packages) throw new Error("lockfileVersion 1 is not supported, run npm install to upgrade it");
  const root: Json = data.packages[""] ?? {};
  const direct = new Set(
    ["dependencies", "devDependencies", "optionalDependencies"].flatMap((k) => Object.keys(root[k] ?? {})),
  );
  for (const [path, p] of Object.entries<Json>(data.packages)) {
    const at = path.lastIndexOf("node_modules/");
    if (at < 0 || p.link) continue;
    const installedAs = path.slice(at + "node_modules/".length);
    const name = p.name ?? installedAs;
    if (!onNpm(p.resolved)) out.private.push(name);
    else if (isVersion(p.version))
      out.deps.push({ name, version: p.version, direct: at === 0 && direct.has(installedAs) });
    else out.unchecked.push({ item: name, reason: BAD_VERSION });
  }
  return out;
}

/**
 * Reads the lockfile line by line. A full YAML parser can be pushed out of memory by a small crafted file, and
 * nothing can catch that. pnpm writes a fixed layout, so this only needs its keys.
 */
export function parsePnpmLock(lock: string): Parsed {
  const out = empty();
  const lines = lock.split(/\r\n|\r|\n/);
  const format = lines.find((l) => l.startsWith("lockfileVersion:"))?.slice("lockfileVersion:".length);
  if (!(parseFloat(format?.replace(/['"\s]/g, "") ?? "") >= 6)) throw new Error("pnpm lockfile older than v6 is not supported");

  const keyOf = (line: string) => {
    const text = line.trim();
    return (text.endsWith(":") ? text.slice(0, -1) : text.split(": ", 1)[0]!).replace(/^['"]|['"]$/g, "");
  };
  const direct = new Set<string>();
  const entries: { key: string; tarball?: string }[] = [];
  const isDepsBlock = (name: string) => ["dependencies", "devDependencies", "optionalDependencies"].includes(name);
  let section = "";
  let block = "";
  let inResolution = false;
  for (const line of lines) {
    const indent = line.length - line.trimStart().length;
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (indent === 0) {
      section = keyOf(line);
      block = "";
    } else if (section === "importers") {
      if (indent === 4) block = keyOf(line);
      else if (indent === 6 && isDepsBlock(block)) direct.add(keyOf(line));
    } else if (isDepsBlock(section)) {
      if (indent === 2) direct.add(keyOf(line));
    } else if (section === "packages") {
      if (indent === 2) entries.push({ key: keyOf(line) });
      else if (indent === 4) inResolution = line.trimStart().startsWith("resolution:");
      if (entries.length && inResolution && indent >= 4) {
        const tarball = line.match(/(?:^|[\s{,"'])tarball["']?:\s*["']?([^\s,}"']+)/)?.[1];
        if (tarball) entries.at(-1)!.tarball = tarball;
      }
    }
  }

  // No entries means a layout this reader doesn't know, and that has to be unknown, never no.
  if (!entries.length) throw new Error("no packages found");

  for (const { key, tarball } of entries) {
    const id = key.replace(/^\//, "").split("(", 1)[0]!;
    const at = id.lastIndexOf("@");
    const name = id.slice(0, at);
    const version = id.slice(at + 1);
    if (!onNpm(tarball) || version.includes(":")) out.private.push(name || id);
    else if (isVersion(version)) out.deps.push({ name, version, direct: direct.has(name) });
    else out.unchecked.push({ item: name || id, reason: BAD_VERSION });
  }
  return out;
}

export function parseYarnLock(lock: string, manifest?: string): Parsed {
  const out = empty();
  const direct = npmDirect(manifest);
  const add = (header: string, body: Json) => {
    const first = header.split(",")[0]!.trim().replace(/^"|"$/g, "");
    const id = body.resolution ?? first;
    const alias = body.resolution ? undefined : first.match(/@npm:(@?[^@]+)@/)?.[1];
    const name = alias ?? id.slice(0, id.indexOf("@", 1));
    if (id.includes("@workspace:")) return;
    const fromNpm = body.resolution ? id.includes("@npm:") : onNpm(body.resolved);
    if (!fromNpm) out.private.push(name);
    else if (isVersion(body.version)) out.deps.push({ name, version: body.version, direct: direct.has(name) });
    else out.unchecked.push({ item: name, reason: BAD_VERSION });
  };
  let header = "";
  let body: Json = {};
  for (const line of lock.split(/\r?\n/)) {
    if (/^\S.*:$/.test(line) && !line.startsWith("#") && !line.startsWith("__metadata")) {
      if (header) add(header, body);
      header = line.slice(0, -1);
      body = {};
    } else if (/^\S/.test(line)) {
      if (header) add(header, body);
      header = "";
    } else {
      const m = line.match(/^ {2}(version|resolved|resolution):? "?([^"]+)"?$/);
      if (m) body[m[1]!] = m[2];
    }
  }
  if (header) add(header, body);
  return out;
}

export const normalizePy = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");

export function parseRequirements(text: string): Parsed {
  const out = empty();
  for (const raw of text.replace(/\\\r?\n/g, " ").split(/\r\n|\r|\n/)) {
    const line = (raw.startsWith("#") ? "" : raw.split(" #", 1)[0]!).trim();
    if (/^(-r|-c|--requirement|--constraint)/.test(line)) {
      out.unchecked.push({ item: "requirements", reason: "includes another file, which wasn't read" });
      continue;
    }
    if (!line || (line.startsWith("-") && !/^-e\s|^--editable/.test(line))) continue;
    const requirement = line.split(/;|\s--hash/, 1)[0]!.trim();
    const pin = requirement.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s,*]+)$/);
    if (pin) out.deps.push({ name: normalizePy(pin[1]!), version: pin[2]!, direct: true });
    else {
      const name = line.match(/^[A-Za-z0-9._-]{1,80}/)?.[0] ?? "unreadable line";
      out.unchecked.push({ item: name, reason: "not pinned with ==, installed version unknown" });
    }
  }
  return out;
}

function pyprojectDirect(manifest?: string): Set<string> {
  if (!manifest) return new Set();
  const m = parseToml(manifest) as Json;
  const pep508 = [
    ...(m.project?.dependencies ?? []),
    ...Object.values<any[]>(m["dependency-groups"] ?? {}).flat(),
    ...Object.values<any[]>(m.project?.["optional-dependencies"] ?? {}).flat(),
  ].filter((d) => typeof d === "string");
  const poetry = [
    m.tool?.poetry?.dependencies,
    m.tool?.poetry?.["dev-dependencies"],
    ...Object.values<Json>(m.tool?.poetry?.group ?? {}).map((g) => g.dependencies),
  ].flatMap((deps) => Object.keys(deps ?? {}));
  return new Set(
    [...pep508.map((d: string) => d.match(/^[A-Za-z0-9._-]+/)?.[0] ?? d), ...poetry].map(normalizePy),
  );
}

export function parsePoetryLock(lock: string, manifest?: string): Parsed {
  const out = empty();
  const direct = pyprojectDirect(manifest);
  for (const p of ((parseToml(lock) as Json).package ?? []) as Json[]) {
    const name = normalizePy(p.name);
    if (p.source) out.private.push(name);
    else out.deps.push({ name, version: p.version, direct: direct.has(name) });
  }
  return out;
}

export function parseUvLock(lock: string, manifest?: string): Parsed {
  const out = empty();
  const direct = pyprojectDirect(manifest);
  for (const p of ((parseToml(lock) as Json).package ?? []) as Json[]) {
    const name = normalizePy(p.name);
    if (p.source?.virtual || p.source?.editable) continue;
    if (!String(p.source?.registry ?? "").startsWith("https://pypi.org/")) out.private.push(name);
    else out.deps.push({ name, version: p.version, direct: direct.has(name) });
  }
  return out;
}

export function parseGoMod(text: string): Parsed {
  const out = empty();
  const required: { name: string; version: string; direct: boolean }[] = [];
  const replaced = new Map<string, { path: string; version?: string; only?: string }>();
  let block = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const open = line.match(/^(require|replace)\s*\($/);
    if (open) block = open[1]!;
    else if (line === ")") block = "";
    else {
      const body = block ? line : line.replace(/^(require|replace)\s+/, "");
      const kind = block || line.match(/^(require|replace)\s/)?.[1];
      const swap = body.match(/^(\S+)(?:\s+v(\S+))?\s+=>\s+(\S+)(?:\s+v(\S+))?/);
      const req = body.match(/^(\S+)\s+v(\S+)(\s*\/\/\s*indirect)?/);
      if (kind === "replace" && swap) replaced.set(swap[1]!, { only: swap[2], path: swap[3]!, version: swap[4] });
      else if (kind === "require" && req) required.push({ name: req[1]!, version: req[2]!, direct: !req[3] });
      else if (kind === "require" && body && !body.startsWith("//"))
        out.unchecked.push({ item: body.split(/\s/, 1)[0]!, reason: BAD_VERSION });
    }
  }
  for (const r of required) {
    const found = replaced.get(r.name);
    const swap = !found?.only || found.only === r.version ? found : undefined;
    if (swap && !swap.version) out.private.push(r.name);
    else
      out.deps.push({
        name: swap?.path ?? r.name,
        version: (swap?.version ?? r.version).replace(/\+incompatible$/, ""),
        direct: r.direct,
      });
  }
  return out;
}

export function parseCargoLock(lock: string, manifest?: string): Parsed {
  const out = empty();
  const m = manifest ? (parseToml(manifest) as Json) : {};
  const direct = new Set(
    [m.dependencies, m["dev-dependencies"], m["build-dependencies"], m.workspace?.dependencies].flatMap((d) =>
      Object.keys(d ?? {}),
    ),
  );
  for (const p of ((parseToml(lock) as Json).package ?? []) as Json[]) {
    if (!p.source) continue;
    if (/crates\.io-index|index\.crates\.io/.test(p.source))
      out.deps.push({ name: p.name, version: p.version, direct: direct.has(p.name) });
    else out.private.push(p.name);
  }
  return out;
}

export function parseGemfileLock(lock: string): Parsed {
  const out = empty();
  const direct = new Set<string>();
  const gems: { name: string; version: string; isPublic: boolean }[] = [];
  let section = "";
  let remote = "";
  for (const line of lock.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      section = line.trim();
      remote = "";
      continue;
    }
    remote = line.match(/^ {2}remote: (\S+)/)?.[1] ?? remote;
    const spec = line.match(/^ {4}(\S+)(?: \(([^)]+)\))?!?$/);
    if (spec && spec[1] !== "specs:" && ["GEM", "GIT", "PATH", "PLUGIN SOURCE"].includes(section)) {
      if (spec[2])
        gems.push({
          name: spec[1]!,
          version: spec[2].split(/-[a-z]/, 1)[0]!,
          isPublic: section === "GEM" && remote.startsWith("https://rubygems.org"),
        });
      else out.unchecked.push({ item: spec[1]!, reason: BAD_VERSION });
    }
    const dep = section === "DEPENDENCIES" && line.match(/^ {2}([^\s!]+)/);
    if (dep) direct.add(dep[1]!);
  }
  for (const { name, version, isPublic } of gems) {
    if (isPublic) out.deps.push({ name, version, direct: direct.has(name) });
    else out.private.push(name);
  }
  return out;
}

export function parseGradleLock(lock: string, manifest = ""): Parsed {
  const out = empty();
  const declared = new Set(manifest.split(/[^\w.:-]+/).map((token) => token.split(":", 2).join(":")));
  for (const line of lock.split(/\r?\n/)) {
    const m = line.match(/^([^#:=\s]+:[^:=\s]+):([^:=\s]+)=/);
    if (m) out.deps.push({ name: m[1]!, version: m[2]!, direct: declared.has(m[1]!) });
    else if (line.trim() && !line.startsWith("#") && !line.startsWith("empty="))
      out.unchecked.push({ item: "gradle.lockfile", reason: BAD_VERSION });
  }
  return out;
}

export function parseNugetLock(lock: string): Parsed {
  const out = empty();
  for (const framework of Object.values<Json>(JSON.parse(lock).dependencies ?? {}))
    for (const [name, p] of Object.entries<Json>(framework))
      if (p?.type === "Project") continue;
      else if (isVersion(p?.resolved)) out.deps.push({ name, version: p.resolved, direct: p.type === "Direct" });
      else out.unchecked.push({ item: name, reason: BAD_VERSION });
  return out;
}
