import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

interface Store {
  read(key: string): Promise<unknown>;
  write(key: string, value: unknown): Promise<void>;
}

/** Keys can hold advisory ids from a third party, so they must never choose a path. */
const safeKey = (key: string) => key.replace(/[^A-Za-z0-9._-]/g, "_");

const file = (key: string) =>
  join(process.env.KMS_CACHE_DIR ?? join(homedir(), ".cache", "keep-me-secure"), `${safeKey(key)}.json`);

let store: Store = {
  read: async (key) => JSON.parse(await readFile(file(key), "utf8")),
  async write(key, value) {
    await mkdir(dirname(file(key)), { recursive: true });
    await writeFile(file(key), JSON.stringify(value));
  },
};

export const setCacheStore = (s: Store) => {
  store = s;
};

export async function readCache<T>(key: string): Promise<T | undefined> {
  try {
    return (await store.read(key)) as T | undefined;
  } catch {
    return undefined;
  }
}

/** Best effort: a read-only filesystem only costs us the speed-up. */
export async function writeCache(key: string, value: unknown): Promise<void> {
  try {
    await store.write(key, value);
  } catch {}
}

export const today = () => new Date().toISOString().slice(0, 10);
