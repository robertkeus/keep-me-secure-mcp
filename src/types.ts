export type Ecosystem = "Packagist" | "npm" | "PyPI";

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
}
