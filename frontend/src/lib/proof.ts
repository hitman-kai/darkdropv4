/**
 * DarkDrop V4 — Client-side Groth16 Proof Generation
 *
 * Generates ZK proofs using snarkjs WASM in the browser or Node.js.
 * The proof proves the claimer knows a valid drop secret without revealing which drop.
 */

import * as snarkjs from "snarkjs";
import { PublicKey } from "@solana/web3.js";
import {
  pubkeyToField,
  amountToFieldBE,
  bigintToBytes32BE,
} from "./crypto";
import type { MerkleProof } from "./merkle";

// Paths to circuit artifacts served from public/circuits/
let WASM_PATH = "/circuits/darkdrop.wasm";
let ZKEY_PATH = "/circuits/darkdrop_final.zkey";

export function setArtifactPaths(wasmPath: string, zkeyPath: string): void {
  WASM_PATH = wasmPath;
  ZKEY_PATH = zkeyPath;
}

/**
 * Drop secret data needed to generate a claim proof.
 * This comes from decoding the claim code.
 */
export interface DropSecret {
  secret: bigint;
  nullifier: bigint;
  amount: bigint;
  blindingFactor: bigint;
  password: bigint; // 0n if no password
}

/**
 * Proof result ready for on-chain submission.
 */
export interface ClaimProofResult {
  // Groth16 proof points (raw bytes for on-chain)
  proofA: Uint8Array; // 64 bytes (G1)
  proofB: Uint8Array; // 128 bytes (G2)
  proofC: Uint8Array; // 64 bytes (G1)

  // Public inputs (32-byte big-endian field elements)
  merkleRoot: Uint8Array;
  nullifierHash: Uint8Array;
  recipientField: Uint8Array;
  amountCommitment: Uint8Array;
  passwordHash: Uint8Array;
  amount: bigint;
}

/**
 * Generate a Groth16 claim proof.
 *
 * Public inputs order MUST match circuit:
 *   [amount, merkle_root, nullifier_hash, recipient, amount_commitment, password_hash]
 */
export async function generateClaimProof(
  dropSecret: DropSecret,
  merkleProof: MerkleProof,
  recipient: PublicKey,
  nullifierHashVal: bigint,
  amountCommitmentVal: bigint,
  passwordHashVal: bigint
): Promise<ClaimProofResult> {
  // Compute recipient field element — MUST match on-chain pubkey_to_field
  const recipientField = pubkeyToField(recipient);

  // Build circuit input
  const circuitInput = {
    // Private inputs
    secret: dropSecret.secret.toString(),
    amount: dropSecret.amount.toString(),
    blinding_factor: dropSecret.blindingFactor.toString(),
    nullifier: dropSecret.nullifier.toString(),
    merkle_path: merkleProof.pathElements.map((e) => e.toString()),
    merkle_indices: merkleProof.pathIndices.map((i) => i.toString()),
    password: dropSecret.password.toString(),

    // Public inputs
    merkle_root: merkleProof.root.toString(),
    nullifier_hash: nullifierHashVal.toString(),
    recipient: recipientField.toString(),
    amount_commitment: amountCommitmentVal.toString(),
    password_hash: passwordHashVal.toString(),
  };

  // Generate proof via snarkjs
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH
  );

  // Convert snarkjs proof format to raw bytes for on-chain
  const proofA = g1NegToBytes(proof.pi_a);
  const proofB = g2ToBytes(proof.pi_b);
  const proofC = g1ToBytes(proof.pi_c);

  return {
    proofA,
    proofB,
    proofC,
    merkleRoot: bigintToBytes32BE(merkleProof.root),
    nullifierHash: bigintToBytes32BE(nullifierHashVal),
    recipientField: bigintToBytes32BE(recipientField),
    amountCommitment: bigintToBytes32BE(amountCommitmentVal),
    passwordHash: bigintToBytes32BE(passwordHashVal),
    amount: dropSecret.amount,
  };
}

// V2 circuit artifacts (amount is private — 5 public inputs)
let WASM_V2_PATH = "/circuits/darkdrop.wasm"; // same WASM (circuit logic unchanged)
let ZKEY_V2_PATH = "/circuits/darkdrop_v2_final.zkey";

export function setV2ArtifactPaths(wasmPath: string, zkeyPath: string): void {
  WASM_V2_PATH = wasmPath;
  ZKEY_V2_PATH = zkeyPath;
}

/**
 * Generate a Groth16 claim proof using V2 circuit (amount is PRIVATE).
 * Returns 5 public inputs (no amount).
 */
export async function generateClaimProofV2(
  dropSecret: DropSecret,
  merkleProof: MerkleProof,
  recipient: PublicKey,
  nullifierHashVal: bigint,
  amountCommitmentVal: bigint,
  passwordHashVal: bigint
): Promise<ClaimProofResult> {
  const recipientField = pubkeyToField(recipient);

  // Same circuit input structure — amount is still provided but is private
  const circuitInput = {
    secret: dropSecret.secret.toString(),
    amount: dropSecret.amount.toString(),
    blinding_factor: dropSecret.blindingFactor.toString(),
    nullifier: dropSecret.nullifier.toString(),
    merkle_path: merkleProof.pathElements.map((e) => e.toString()),
    merkle_indices: merkleProof.pathIndices.map((i) => i.toString()),
    password: dropSecret.password.toString(),
    merkle_root: merkleProof.root.toString(),
    nullifier_hash: nullifierHashVal.toString(),
    recipient: recipientField.toString(),
    amount_commitment: amountCommitmentVal.toString(),
    password_hash: passwordHashVal.toString(),
  };

  // Generate proof with V2 zkey (5 public inputs, amount private)
  const { proof } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_V2_PATH,
    ZKEY_V2_PATH
  );

  const proofA = g1NegToBytes(proof.pi_a);
  const proofB = g2ToBytes(proof.pi_b);
  const proofC = g1ToBytes(proof.pi_c);

  return {
    proofA,
    proofB,
    proofC,
    merkleRoot: bigintToBytes32BE(merkleProof.root),
    nullifierHash: bigintToBytes32BE(nullifierHashVal),
    recipientField: bigintToBytes32BE(recipientField),
    amountCommitment: bigintToBytes32BE(amountCommitmentVal),
    passwordHash: bigintToBytes32BE(passwordHashVal),
    amount: dropSecret.amount,
  };
}

// --- Proof serialization helpers ---
// snarkjs outputs proof points as decimal string arrays.
// On-chain expects raw big-endian bytes.

function bigintToBE32(val: string): Uint8Array {
  const bi = BigInt(val);
  const hex = bi.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// BN254 base field modulus (Fq) — used to negate G1 y-coordinates
const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/**
 * Convert snarkjs G1 point [x, y, z] to 64-byte big-endian format.
 * On-chain: proof_a is [x_BE_32bytes || y_BE_32bytes]
 */
function g1ToBytes(point: string[]): Uint8Array {
  const result = new Uint8Array(64);
  result.set(bigintToBE32(point[0]), 0);
  result.set(bigintToBE32(point[1]), 32);
  return result;
}

/**
 * Convert snarkjs G1 point with NEGATED y-coordinate.
 * groth16_solana expects proof_a negated for the pairing equation.
 */
function g1NegToBytes(point: string[]): Uint8Array {
  const result = new Uint8Array(64);
  result.set(bigintToBE32(point[0]), 0);
  result.set(bigintToBE32((BN254_FQ - BigInt(point[1])).toString()), 32);
  return result;
}

/**
 * Convert snarkjs G2 point [[x0, x1], [y0, y1], [z0, z1]] to 128-byte format.
 * On-chain G2 encoding: [x1_BE || x0_BE || y1_BE || y0_BE]
 * (element pairs are reversed for alt_bn128 compatibility)
 */
function g2ToBytes(point: string[][]): Uint8Array {
  const result = new Uint8Array(128);
  result.set(bigintToBE32(point[0][1]), 0);   // x1
  result.set(bigintToBE32(point[0][0]), 32);  // x0
  result.set(bigintToBE32(point[1][1]), 64);  // y1
  result.set(bigintToBE32(point[1][0]), 96);  // y0
  return result;
}
