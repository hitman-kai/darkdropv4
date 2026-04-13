/**
 * Persistent deposit TX tracker — survives relayer restarts.
 * Stores processed deposit TX signatures with timestamps.
 * Prunes entries older than 24 hours on each load/save cycle.
 */

import fs from "fs";
import path from "path";

const STORE_PATH = path.join(__dirname, "..", "data", "processed-deposits.json");
const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface Entry {
  ts: number; // unix ms
}

let cache: Record<string, Entry> = {};

function ensureDir() {
  const dir = path.dirname(STORE_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function load() {
  try {
    if (fs.existsSync(STORE_PATH)) {
      cache = JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
    }
  } catch {
    cache = {};
  }
  prune();
}

function prune() {
  const cutoff = Date.now() - TTL_MS;
  for (const sig of Object.keys(cache)) {
    if (cache[sig].ts < cutoff) {
      delete cache[sig];
    }
  }
}

function save() {
  ensureDir();
  fs.writeFileSync(STORE_PATH, JSON.stringify(cache), "utf8");
}

// Load on startup
load();

export function hasProcessedTx(sig: string): boolean {
  return sig in cache;
}

export function markProcessed(sig: string) {
  cache[sig] = { ts: Date.now() };
  save();
}

export function unmarkProcessed(sig: string) {
  delete cache[sig];
  save();
}
