/**
 * DarkDrop V4 — DepositReceipt client helpers.
 *
 * A DepositReceipt is a PDA created at deposit time (via the 7-account
 * create_drop path) that lets the depositor revoke an unclaimed drop
 * after a 30-day time-lock.
 *
 * To revoke, the depositor must supply the full leaf preimage
 * (secret, nullifier, blinding). We store it locally, keyed by leaf,
 * so the depositor can recover without a separate recovery file.
 *
 * localStorage-only by design: if the user changes browsers/devices
 * the preimage is lost. This is an opt-in fallback mechanism; users
 * who want recoverability accept this constraint.
 */

import { Connection, PublicKey } from "@solana/web3.js";
import { PROGRAM_ID } from "./vault";

// Matches programs/darkdrop/src/state.rs REVOKE_TIMEOUT (production).
export const REVOKE_TIMEOUT_SECONDS = 30 * 24 * 60 * 60;

// DepositReceipt on-chain layout (89 bytes):
//   discriminator(8) + bump(1) + depositor(32) + amount(8 LE)
//   + created_at(8 LE i64) + leaf(32)
const RECEIPT_ACCOUNT_SIZE = 89;

export function getReceiptPDA(leafBytes: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("receipt"), leafBytes],
    PROGRAM_ID
  );
}

export interface DepositReceiptData {
  bump: number;
  depositor: PublicKey;
  amount: bigint;
  createdAt: number; // unix seconds
  leaf: Uint8Array;
}

export function parseDepositReceipt(data: Uint8Array): DepositReceiptData {
  if (data.length !== RECEIPT_ACCOUNT_SIZE) {
    throw new Error(
      `Unexpected DepositReceipt size: ${data.length} (expected ${RECEIPT_ACCOUNT_SIZE})`
    );
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const bump = data[8];
  const depositor = new PublicKey(data.slice(9, 41));
  const amount = view.getBigUint64(41, true);
  const createdAt = Number(view.getBigInt64(49, true));
  const leaf = data.slice(57, 89);
  return { bump, depositor, amount, createdAt, leaf };
}

export async function fetchReceipt(
  connection: Connection,
  leafBytes: Uint8Array
): Promise<DepositReceiptData | null> {
  const [pda] = getReceiptPDA(leafBytes);
  const account = await connection.getAccountInfo(pda);
  if (!account) return null;
  return parseDepositReceipt(account.data);
}

// ────────────────────────────────────────────────────────────
// Preimage storage (localStorage)
// ────────────────────────────────────────────────────────────

export interface StoredReceipt {
  leafHex: string;
  leafIndex: number;
  amountLamports: string;
  depositor: string;
  createdAt: number; // unix seconds
  cluster: string;
  vaultAddress: string;
  // Preimage (base-16 of 32-byte BE field elements) — required for revoke.
  secretHex: string;
  nullifierHex: string;
  blindingHex: string;
  txSig: string;
}

function indexKey(depositor: string): string {
  return `darkdrop:receipts:${depositor}`;
}

function entryKey(leafHex: string): string {
  return `darkdrop:receipt:${leafHex}`;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Bad hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function bigintToHex32(v: bigint): string {
  return v.toString(16).padStart(64, "0");
}

export function hex32ToBigint(hex: string): bigint {
  return BigInt("0x" + hex);
}

export function saveReceipt(entry: StoredReceipt): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(entryKey(entry.leafHex), JSON.stringify(entry));
  const ix = indexKey(entry.depositor);
  const existing: string[] = JSON.parse(
    window.localStorage.getItem(ix) || "[]"
  );
  if (!existing.includes(entry.leafHex)) {
    existing.push(entry.leafHex);
    window.localStorage.setItem(ix, JSON.stringify(existing));
  }
}

export function listLocalReceipts(depositor: string): StoredReceipt[] {
  if (typeof window === "undefined") return [];
  const leaves: string[] = JSON.parse(
    window.localStorage.getItem(indexKey(depositor)) || "[]"
  );
  const out: StoredReceipt[] = [];
  for (const leafHex of leaves) {
    const raw = window.localStorage.getItem(entryKey(leafHex));
    if (!raw) continue;
    try {
      out.push(JSON.parse(raw));
    } catch {
      // skip corrupt entries
    }
  }
  return out.sort((a, b) => b.createdAt - a.createdAt);
}

export function removeLocalReceipt(depositor: string, leafHex: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(entryKey(leafHex));
  const ix = indexKey(depositor);
  const existing: string[] = JSON.parse(
    window.localStorage.getItem(ix) || "[]"
  );
  const next = existing.filter((l) => l !== leafHex);
  window.localStorage.setItem(ix, JSON.stringify(next));
}
