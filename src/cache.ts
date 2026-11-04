import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const dir = () => process.env.KMS_CACHE_DIR ?? join(homedir(), ".cache", "keep-me-secure");

export async function readCache<T>(key: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(join(dir(), `${key}.json`), "utf8"));
  } catch {
    return undefined;
  }
}

/** Best effort: a read-only filesystem only costs us the speed-up. */
export async function writeCache(key: string, value: unknown): Promise<void> {
  const file = join(dir(), `${key}.json`);
  try {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify(value));
  } catch {}
}

export const today = () => new Date().toISOString().slice(0, 10);
