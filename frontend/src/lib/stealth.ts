/**
 * DarkDrop V4 — Stealth Recipient Helpers
 *
 * A stealth address is a fresh ed25519 keypair generated client-side and used
 * as the on-chain recipient of a claim. The user's main wallet pays gas and
 * submits the TX, but the SOL lands at the stealth address. The user later
 * sweeps the stealth balance to their main wallet (or spends from it directly).
 *
 * Privacy property: the claim TX names the stealth pubkey as the recipient,
 * not the main wallet. An outside observer monitoring the main wallet does
 * not see the claim arrive there. The sweep TX does eventually reveal the
 * stealth → main link, but it is timing-decoupled from the claim and can
 * mix with other wallet activity.
 *
 * Caveats (honest scope):
 *   - This is recipient-side identity unlinkability. It does NOT hide the
 *     amount at withdraw — that remains visible in TX metadata.
 *   - Stealth privkeys are stored in localStorage (plain). Same trust model
 *     as the existing receipt store. Device compromise = stealth funds at risk.
 *   - The stealth keypair is fully owned by the user and can be imported into
 *     any Solana wallet via the secret key.
 */

import {
  Keypair,
  PublicKey,
  Connection,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import bs58 from "bs58";

const STEALTH_STORAGE_KEY = "darkdrop-stealth-v1";

// Approximate fee for a single SystemProgram.transfer signed by the stealth
// keypair. The stealth account is not rent-bearing (it holds SOL only), so we
// can sweep balance - fee. Solana base fee is 5000 lamports per signature.
const SWEEP_FEE_LAMPORTS = 5000;

export interface StealthRecord {
  /** Stealth address as base58. */
  pubkey: string;
  /** Full ed25519 secret key as base58 (64-byte expanded form). */
  secretKeyB58: string;
  /** Main wallet that owns this stealth (for filtering). Base58. */
  ownerWallet: string;
  /** Unix seconds. */
  createdAt: number;
  /** Free-form provenance ("claim", "claim:dropId", etc.). */
  source: string;
}

/**
 * Generate a fresh stealth keypair. The user must save it before submitting
 * any transaction that names the pubkey as recipient — otherwise the funds
 * are unrecoverable.
 */
export function generateStealthKeypair(): Keypair {
  return Keypair.generate();
}

function loadAll(): StealthRecord[] {
  if (typeof window === "undefined") return [];
  const raw = window.localStorage.getItem(STEALTH_STORAGE_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistAll(records: StealthRecord[]): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STEALTH_STORAGE_KEY, JSON.stringify(records));
}

/**
 * Save a stealth keypair to localStorage. Returns the StealthRecord.
 *
 * Call this BEFORE submitting any TX that uses the stealth pubkey as recipient.
 * Losing the secret key after the TX lands means the funds are stuck.
 */
export function saveStealth(
  keypair: Keypair,
  ownerWallet: PublicKey,
  source: string
): StealthRecord {
  const record: StealthRecord = {
    pubkey: keypair.publicKey.toBase58(),
    secretKeyB58: bs58.encode(keypair.secretKey),
    ownerWallet: ownerWallet.toBase58(),
    createdAt: Math.floor(Date.now() / 1000),
    source,
  };
  const all = loadAll();
  // Idempotent: if a record for this pubkey already exists, replace it.
  const filtered = all.filter((r) => r.pubkey !== record.pubkey);
  filtered.push(record);
  persistAll(filtered);
  return record;
}

/** All stealth records on this device, regardless of owner. */
export function listAllStealth(): StealthRecord[] {
  return loadAll();
}

/** Stealth records owned by a specific main wallet. */
export function listStealthForOwner(owner: PublicKey): StealthRecord[] {
  const ownerB58 = owner.toBase58();
  return loadAll().filter((r) => r.ownerWallet === ownerB58);
}

/** Look up a stealth record by stealth pubkey (base58 or PublicKey). */
export function findStealthByPubkey(
  pubkey: PublicKey | string
): StealthRecord | null {
  const target = pubkey instanceof PublicKey ? pubkey.toBase58() : pubkey;
  return loadAll().find((r) => r.pubkey === target) ?? null;
}

/** Reconstruct the full Keypair from a stored record. */
export function recoverKeypair(record: StealthRecord): Keypair {
  return Keypair.fromSecretKey(bs58.decode(record.secretKeyB58));
}

/** Remove a stealth record (after a successful sweep, typically). */
export function deleteStealth(pubkey: PublicKey | string): void {
  const target = pubkey instanceof PublicKey ? pubkey.toBase58() : pubkey;
  const filtered = loadAll().filter((r) => r.pubkey !== target);
  persistAll(filtered);
}

/**
 * Build a system_program::transfer that moves the entire stealth balance
 * (minus the signature fee) to `destination`. The TX is signed by the stealth
 * keypair as both fee payer and source.
 *
 * Returns the signed Transaction ready for connection.sendRawTransaction.
 */
export async function buildSweepTransaction(
  stealth: Keypair,
  destination: PublicKey,
  connection: Connection
): Promise<{ tx: Transaction; lamports: number }> {
  const balance = await connection.getBalance(stealth.publicKey);
  const lamports = balance - SWEEP_FEE_LAMPORTS;
  if (lamports <= 0) {
    throw new Error(
      `Stealth balance ${balance} insufficient to cover sweep fee ${SWEEP_FEE_LAMPORTS}`
    );
  }

  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: stealth.publicKey,
      toPubkey: destination,
      lamports,
    })
  );
  const { blockhash } = await connection.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;
  tx.feePayer = stealth.publicKey;
  tx.sign(stealth);
  return { tx, lamports };
}

/**
 * Sweep the stealth balance to `destination` and return the TX signature.
 * Caller is responsible for awaiting confirmation if desired.
 */
export async function sweepStealth(
  stealth: Keypair,
  destination: PublicKey,
  connection: Connection
): Promise<{ signature: string; lamports: number }> {
  const { tx, lamports } = await buildSweepTransaction(
    stealth,
    destination,
    connection
  );
  const signature = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
    maxRetries: 3,
  });
  return { signature, lamports };
}
