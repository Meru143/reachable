// File-based advisory cache (.reachable-cache/).
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import type { Advisory } from "./types.js";

type CacheRecord = {
  fetchedAt: string;
  advisories: Advisory[];
};

export function createCacheKey(packageName: string, packageVersion: string): string {
  return createHash("sha256").update(`${packageName}@${packageVersion}`).digest("hex");
}

export function getCached(key: string, cacheDir: string, ttlHours: number): Advisory[] | null {
  const cacheFile = path.join(cacheDir, `${key}.json`);
  if (!existsSync(cacheFile)) {
    return null;
  }

  const payload = JSON.parse(readFileSync(cacheFile, "utf8")) as CacheRecord;
  const fetchedAt = new Date(payload.fetchedAt).getTime();
  const ttlMs = ttlHours * 60 * 60 * 1000;

  if (Number.isNaN(fetchedAt) || Date.now() - fetchedAt > ttlMs) {
    return null;
  }

  return payload.advisories;
}

export function setCache(key: string, data: Advisory[], cacheDir: string): void {
  mkdirSync(cacheDir, { recursive: true });
  const cacheFile = path.join(cacheDir, `${key}.json`);
  const payload: CacheRecord = {
    fetchedAt: new Date().toISOString(),
    advisories: data,
  };
  writeFileSync(cacheFile, JSON.stringify(payload, null, 2), "utf8");
}

export function clearCache(cacheDir: string): void {
  if (!existsSync(cacheDir)) {
    return;
  }

  for (const entry of readdirSync(cacheDir)) {
    rmSync(path.join(cacheDir, entry), { force: true, recursive: true });
  }
}
