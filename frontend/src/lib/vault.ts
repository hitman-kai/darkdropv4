/**
 * DarkDrop V4 — On-chain Vault Interaction
 *
 * Builds Solana instructions for create_drop and claim.
 * Handles PDA derivation and account resolution.
 */

import {
  Connection,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  bigintToBytes32BE,
  createLeaf,
  nullifierHash,
  amountCommitment,
  passwordHash,
  randomFieldElement,
} from "./crypto";
import type { ClaimCodePayload } from "./claim-code";
import type { ClaimProofResult } from "./proof";

// Program ID — must match declare_id! in lib.rs
export const PROGRAM_ID = new PublicKey(
  "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU"
);

// PDA seeds
export function getVaultPDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
}

export function getMerkleTreePDA(vault: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vault.toBytes()],
    PROGRAM_ID
  );
}

export function getSolVaultPDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("sol_vault")],
    PROGRAM_ID
  );
}

export function getTreasuryPDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("treasury")],
    PROGRAM_ID
  );
}

export function getNullifierPDA(
  nullifierHashBytes: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier"), nullifierHashBytes],
    PROGRAM_ID
  );
}

export function getCreditNotePDA(
  nullifierHashBytes: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("credit"), nullifierHashBytes],
    PROGRAM_ID
  );
}

/**
 * Create a new drop. Returns the claim code payload and the leaf hash.
 *
 * Steps:
 *   1. Generate random secret, nullifier, blinding_factor
 *   2. Compute leaf = Poseidon(secret, nullifier, amount, blinding)
 *   3. Compute amount_commitment = Poseidon(amount, blinding)
 *   4. Optionally compute password_hash = Poseidon(password)
 *   5. Return everything needed for the claim code and the TX
 */
export interface CreateDropResult {
  leaf: Uint8Array;
  amountCommitment: Uint8Array;
  passwordHash: Uint8Array;
  claimPayload: Omit<ClaimCodePayload, "leafIndex" | "vaultAddress">;
}

export function prepareCreateDrop(
  amount: bigint,
  password?: bigint
): CreateDropResult {
  const secret = randomFieldElement();
  const nullifier = randomFieldElement();
  const blindingFactor = randomFieldElement();

  const leaf = createLeaf(secret, nullifier, amount, blindingFactor);
  const amtCommitment = amountCommitment(amount, blindingFactor);
  const pwdHash = password ? passwordHash(password) : 0n;

  return {
    leaf: bigintToBytes32BE(leaf),
    amountCommitment: bigintToBytes32BE(amtCommitment),
    passwordHash: bigintToBytes32BE(pwdHash),
    claimPayload: {
      secret,
      nullifier,
      amount,
      blindingFactor,
    },
  };
}

/**
 * Check if a nullifier has already been spent.
 */
export async function isNullifierSpent(
  connection: Connection,
  nullifierHashBytes: Uint8Array
): Promise<boolean> {
  const [pda] = getNullifierPDA(nullifierHashBytes);
  const account = await connection.getAccountInfo(pda);
  return account !== null;
}
