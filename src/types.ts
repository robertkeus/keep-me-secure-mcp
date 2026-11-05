export type Ecosystem = "Packagist" | "npm" | "PyPI" | "Go" | "crates.io" | "RubyGems" | "Maven" | "NuGet";

export interface Dep {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  lockfile: string;
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
