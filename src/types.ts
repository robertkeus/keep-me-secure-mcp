import type { ImageInfo } from "./docker.ts";
import type { DeclaredRuntime } from "./runtimes.ts";
import type { ManagerProtection } from "./upkeep.ts";

export type Ecosystem = "Packagist" | "npm" | "PyPI" | "Go" | "crates.io" | "RubyGems" | "Maven" | "NuGet";

export interface Dep {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  lockfile: string;
  /** True when the lockfile marks this as a development-only package. */
  dev?: boolean;
}

export interface Unchecked {
  item: string;
  reason: string;
}

export interface Parsed {
  deps: Omit<Dep, "ecosystem" | "lockfile">[];
  /** Packages from private registries, git or local paths. Never sent to OSV. */
  private: string[];
  unchecked: Unchecked[];
}

export interface Scan {
  deps: Dep[];
  private: string[];
  unchecked: Unchecked[];
  /** Lockfiles left out because they sit in test or example folders. */
  ignored?: string[];
  /** Lower-case names of platforms this project appears to use. */
  platforms?: string[];
  /** Runtime versions the project declares. */
  runtimes?: DeclaredRuntime[];
  /** Whether each package manager in use waits before installing new releases. */
  protection?: ManagerProtection[];
  images?: ImageInfo[];
  dependabot?: { exists: boolean; missing: string[] };
}

export type Severity = "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "UNKNOWN";

export interface Advisory {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  malicious: boolean;
  /** Lowest fixed release above the installed version, if any. */
  fixedIn: string | null;
}
