/**
 * DarkDrop V4 — Client Cryptography Library
 *
 * Core cryptographic functions that MUST match the on-chain program exactly.
 * Any mismatch between these functions and the Anchor program's implementations
 * will cause proof verification to fail.
 *
 * On-chain counterparts:
 *   pubkeyToField  <-> claim.rs::pubkey_to_field
 *   amountToFieldBE <-> claim.rs::u64_to_field_be
 *   poseidonHash   <-> poseidon.rs::poseidon_hash (via light-hasher)
 *   createLeaf     <-> circuit constraint 1
 *   nullifierHash  <-> circuit constraint 3
 *   amountCommitment <-> circuit constraint 4
 *   passwordHash   <-> circuit constraint 6
 */

import { buildPoseidon } from "circomlibjs";
import { PublicKey } from "@solana/web3.js";

// BN254 scalar field modulus
const BN254_FIELD_MODULUS = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

let poseidon: any;
let F: any;

/**
 * Initialize the Poseidon hasher. Must be called before any other function.
 */
export async function initPoseidon(): Promise<void> {
  if (!poseidon) {
    poseidon = await buildPoseidon();
    F = poseidon.F;
  }
}

function ensureInitialized(): void {
  if (!poseidon) {
    throw new Error("Poseidon not initialized. Call initPoseidon() first.");
  }
}

/**
 * Compute Poseidon hash of field element inputs. Returns a BigInt.
 */
export function poseidonHash(inputs: bigint[]): bigint {
  ensureInitialized();
  return F.toObject(poseidon(inputs));
}

/**
 * Convert a Solana PublicKey to a valid BN254 field element via Poseidon hash.
 *
 * MUST match on-chain: claim.rs::pubkey_to_field
 *
 * Algorithm:
 *   1. Get 32 raw pubkey bytes
 *   2. Split into two 16-byte (128-bit) halves — both safely < field modulus
 *   3. Pad each to 32 bytes (big-endian, value in low 16 bytes)
 *   4. Interpret as field elements and hash: Poseidon(hi, lo)
 *
 * On-chain Rust equivalent:
 *   hi[16..32] = bytes[0..16]   → hi is bytes[0..16] as BE u256
 *   lo[16..32] = bytes[16..32]  → lo is bytes[16..32] as BE u256
 *   result = poseidon_hash(&hi, &lo)
 */
export function pubkeyToField(pubkey: PublicKey): bigint {
  ensureInitialized();
  const bytes = pubkey.toBytes(); // 32 bytes

  // Split into two 128-bit halves, interpreted as big-endian integers.
  // On-chain: hi[16..32] = bytes[0..16], meaning bytes[0..16] is in the low
  // 16 bytes of a 32-byte BE number. This is equivalent to reading bytes[0..16]
  // as a big-endian u128.
  const hi = bytesToBigIntBE(bytes.slice(0, 16));
  const lo = bytesToBigIntBE(bytes.slice(16, 32));

  return poseidonHash([hi, lo]);
}

/**
 * Convert a u64 amount (in lamports) to a BN254 field element.
 *
 * MUST match on-chain: claim.rs::u64_to_field_be
 *
 * On-chain:
 *   let mut bytes = [0u8; 32];
 *   bytes[24..32].copy_from_slice(&amount.to_be_bytes());
 *
 * This is simply the amount as a big-endian 256-bit integer,
 * which is just BigInt(amount) since amount < 2^64 < field modulus.
 */
export function amountToFieldBE(amount: bigint): bigint {
  // amount is a u64, always < 2^64 < BN254 field modulus. No reduction needed.
  if (amount < 0n || amount >= 2n ** 64n) {
    throw new Error(`Amount out of u64 range: ${amount}`);
  }
  return amount;
}

/**
 * Compute the Merkle tree leaf hash.
 * leaf = Poseidon(secret, nullifier, amount, blinding_factor)
 *
 * Matches circuit constraint 1.
 */
export function createLeaf(
  secret: bigint,
  nullifier: bigint,
  amount: bigint,
  blindingFactor: bigint
): bigint {
  ensureInitialized();
  return poseidonHash([secret, nullifier, amount, blindingFactor]);
}

/**
 * Compute the nullifier hash.
 * nullifier_hash = Poseidon(nullifier)
 *
 * Matches circuit constraint 3.
 */
export function nullifierHash(nullifier: bigint): bigint {
  ensureInitialized();
  return poseidonHash([nullifier]);
}

/**
 * Compute the amount commitment.
 * commitment = Poseidon(amount, blinding_factor)
 *
 * Matches circuit constraint 4.
 */
export function amountCommitment(
  amount: bigint,
  blindingFactor: bigint
): bigint {
  ensureInitialized();
  return poseidonHash([amount, blindingFactor]);
}

/**
 * Compute the password hash. Returns 0n if no password.
 * password_hash = Poseidon(password) or 0n
 *
 * Matches circuit constraint 6.
 */
export function passwordHash(password: bigint): bigint {
  ensureInitialized();
  if (password === 0n) return 0n;
  return poseidonHash([password]);
}

/**
 * Generate a random field element (< BN254 modulus).
 * Used for secret, nullifier, blinding_factor.
 */
export function randomFieldElement(): bigint {
  // Generate 31 random bytes (248 bits) — always < 254-bit field modulus
  const bytes = new Uint8Array(31);
  globalThis.crypto.getRandomValues(bytes);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}

/**
 * Convert a BigInt to a 32-byte big-endian Uint8Array.
 * Used for serializing field elements to pass to the Solana program.
 */
export function bigintToBytes32BE(val: bigint): Uint8Array {
  const hex = val.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert a 32-byte big-endian Uint8Array to a BigInt.
 */
export function bytes32BEToBigint(bytes: Uint8Array): bigint {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}

// --- Internal helpers ---

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + (hex || "0"));
}
