/**
 * DarkDrop V4 — Note Pool client helpers.
 *
 * Two TX builders:
 *   - create_drop_to_pool  — direct SOL → pool leaf (single-TX deposit)
 *   - claim_from_note_pool — V3 Groth16 proof → fresh CreditNote
 *
 * The withdraw side reuses the existing `withdraw_credit` flow from the
 * base claim page; the CreditNote that claim_from_note_pool produces is
 * indistinguishable (by layout) from one produced by claim_credit.
 */

import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { PROGRAM_ID, getVaultPDA, getTreasuryPDA } from "./vault";
import { bigintToBytes32BE } from "./crypto";

// sha256("global:create_drop_to_pool")[0..8]
const CREATE_DROP_TO_POOL_DISCRIMINATOR = new Uint8Array([
  92, 206, 41, 22, 178, 116, 89, 63,
]);

// sha256("global:claim_from_note_pool")[0..8]
// Existing on-chain ix — cached here so the claim page doesn't need to
// import from the V1/V2 claim code, which has its own discriminator set.
const CLAIM_FROM_NOTE_POOL_DISCRIMINATOR = new Uint8Array([
  253, 6, 222, 21, 191, 226, 43, 142,
]);

export function getNotePoolPDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("note_pool")], PROGRAM_ID);
}

export function getNotePoolTreePDA(vault: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("note_pool_tree"), vault.toBytes()],
    PROGRAM_ID
  );
}

export function getPoolNullifierPDA(
  poolNullifierHashBytes: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("pool_nullifier"), poolNullifierHashBytes],
    PROGRAM_ID
  );
}

// Re-exported here so the claim page can grab the credit note PDA for
// a pool-claimed drop without importing from vault.ts separately.
export function getPoolCreditNotePDA(
  poolNullifierHashBytes: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("credit"), poolNullifierHashBytes],
    PROGRAM_ID
  );
}

export interface BuildCreateDropToPoolArgs {
  sender: PublicKey;
  amount: bigint;
  poolSecret: bigint;
  poolNullifier: bigint;
  poolBlinding: bigint;
}

export function buildCreateDropToPoolIx(
  args: BuildCreateDropToPoolArgs
): TransactionInstruction {
  const [vault] = getVaultPDA();
  const [notePool] = getNotePoolPDA();
  const [notePoolTree] = getNotePoolTreePDA(vault);
  const [treasury] = getTreasuryPDA();

  const poolParams = new Uint8Array(96);
  poolParams.set(bigintToBytes32BE(args.poolSecret), 0);
  poolParams.set(bigintToBytes32BE(args.poolNullifier), 32);
  poolParams.set(bigintToBytes32BE(args.poolBlinding), 64);

  const amountBuf = new Uint8Array(8);
  new DataView(amountBuf.buffer).setBigUint64(0, args.amount, true);

  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, poolParams.length, true);

  // Layout: disc(8) + amount(8 LE) + Vec<u8>(len 4 + 96)
  const data = new Uint8Array(8 + 8 + 4 + 96);
  let off = 0;
  data.set(CREATE_DROP_TO_POOL_DISCRIMINATOR, off); off += 8;
  data.set(amountBuf, off); off += 8;
  data.set(lenBuf, off); off += 4;
  data.set(poolParams, off);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: notePool, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: args.sender, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

export interface BuildClaimFromNotePoolArgs {
  payer: PublicKey;            // fees + rent for new CreditNote
  recipient: PublicKey;        // bound via Poseidon(recipient) in the circuit
  poolNullifierHashBytes: Uint8Array; // 32 bytes = Poseidon(pool_nullifier)
  proofA: Uint8Array; // 64
  proofB: Uint8Array; // 128
  proofC: Uint8Array; // 64
  opaqueInputs: Uint8Array; // 64 = pool_root(32) || new_stored_commitment(32)
}

export function buildClaimFromNotePoolIx(
  args: BuildClaimFromNotePoolArgs
): TransactionInstruction {
  const [vault] = getVaultPDA();
  const [notePool] = getNotePoolPDA();
  const [notePoolTree] = getNotePoolTreePDA(vault);
  const [creditNote] = getPoolCreditNotePDA(args.poolNullifierHashBytes);
  const [poolNullifierAcct] = getPoolNullifierPDA(args.poolNullifierHashBytes);

  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, args.opaqueInputs.length, true);

  // Layout: disc(8) + pool_nullifier_hash(32) + proof_a(64) + proof_b(128) + proof_c(64) + Vec<u8>(len 4 + body)
  const data = new Uint8Array(
    8 + 32 + 64 + 128 + 64 + 4 + args.opaqueInputs.length
  );
  let off = 0;
  data.set(CLAIM_FROM_NOTE_POOL_DISCRIMINATOR, off); off += 8;
  data.set(args.poolNullifierHashBytes, off); off += 32;
  data.set(args.proofA, off); off += 64;
  data.set(args.proofB, off); off += 128;
  data.set(args.proofC, off); off += 64;
  data.set(lenBuf, off); off += 4;
  data.set(args.opaqueInputs, off);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: notePool, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: false },
      { pubkey: creditNote, isSigner: false, isWritable: true },
      { pubkey: poolNullifierAcct, isSigner: false, isWritable: true },
      { pubkey: args.recipient, isSigner: false, isWritable: false },
      { pubkey: args.payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}
