/**
 * DarkDrop V4 — revoke_drop and close_receipt TX builders.
 *
 * revoke_drop: depositor submits the leaf preimage after the 30-day time-lock.
 * Program reconstructs the leaf + nullifier_hash on-chain and refunds via
 * direct lamport manipulation (no CPI transfer).
 *
 * close_receipt: depositor recovers rent from an orphaned receipt after the
 * drop was claimed normally. No time-lock.
 */

import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  PROGRAM_ID,
  getVaultPDA,
  getTreasuryPDA,
  getNullifierPDA,
} from "./vault";
import { getReceiptPDA } from "./receipt";
import { bigintToBytes32BE } from "./crypto";

// sha256("global:revoke_drop")[0..8]
const REVOKE_DROP_DISCRIMINATOR = new Uint8Array([
  191, 194, 86, 39, 243, 136, 64, 16,
]);

// sha256("global:close_receipt")[0..8]
const CLOSE_RECEIPT_DISCRIMINATOR = new Uint8Array([
  126, 254, 244, 203, 124, 164, 134, 89,
]);

export interface BuildRevokeArgs {
  depositor: PublicKey;
  leaf: Uint8Array; // 32 bytes
  nullifierHashBytes: Uint8Array; // 32 bytes = Poseidon(nullifier)
  secret: bigint;
  nullifier: bigint;
  blinding: bigint;
}

export function buildRevokeDropIx(args: BuildRevokeArgs): TransactionInstruction {
  const [vault] = getVaultPDA();
  const [treasury] = getTreasuryPDA();
  const [receipt] = getReceiptPDA(args.leaf);
  const [nullifierPda] = getNullifierPDA(args.nullifierHashBytes);

  const preimage = new Uint8Array(96);
  preimage.set(bigintToBytes32BE(args.secret), 0);
  preimage.set(bigintToBytes32BE(args.nullifier), 32);
  preimage.set(bigintToBytes32BE(args.blinding), 64);

  const preimageLenBuf = new Uint8Array(4);
  new DataView(preimageLenBuf.buffer).setUint32(0, preimage.length, true);

  // Layout: disc(8) + leaf(32) + nullifier_hash(32) + Vec<u8>(len 4 + 96)
  const data = new Uint8Array(8 + 32 + 32 + 4 + 96);
  let off = 0;
  data.set(REVOKE_DROP_DISCRIMINATOR, off); off += 8;
  data.set(args.leaf, off); off += 32;
  data.set(args.nullifierHashBytes, off); off += 32;
  data.set(preimageLenBuf, off); off += 4;
  data.set(preimage, off);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: receipt, isSigner: false, isWritable: true },
      { pubkey: nullifierPda, isSigner: false, isWritable: true },
      { pubkey: args.depositor, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

export interface BuildCloseReceiptArgs {
  depositor: PublicKey;
  leaf: Uint8Array; // 32 bytes
}

export function buildCloseReceiptIx(
  args: BuildCloseReceiptArgs
): TransactionInstruction {
  const [receipt] = getReceiptPDA(args.leaf);

  // Layout: disc(8) + leaf(32)
  const data = new Uint8Array(8 + 32);
  data.set(CLOSE_RECEIPT_DISCRIMINATOR, 0);
  data.set(args.leaf, 8);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: receipt, isSigner: false, isWritable: true },
      { pubkey: args.depositor, isSigner: true, isWritable: true },
    ],
    data: Buffer.from(data),
  });
}
