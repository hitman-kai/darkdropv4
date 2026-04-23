/**
 * DarkDrop V4 — Note Pool Claim Relay Endpoint
 *
 * POST /api/relay/pool/claim
 *
 * Relayer-mediated version of claim_from_note_pool. Recipient generates the
 * V3 Groth16 proof client-side and sends it here; relayer submits the TX
 * and pays compute budget + rent for the new CreditNote PDA. Recipient
 * subsequently calls /api/relay/credit/withdraw to extract SOL — the same
 * endpoint as base-layer claims, since the CreditNote produced here uses
 * pool_nullifier_hash as its seed (shape-identical to a standard CreditNote).
 */

import { Router, Request, Response } from "express";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  ComputeBudgetProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { config } from "../config";

const router = Router();

const PROGRAM_ID = new PublicKey(config.programId);

function pda(seeds: (Buffer | Uint8Array)[]) {
  return PublicKey.findProgramAddressSync(seeds, PROGRAM_ID)[0];
}

// sha256("global:claim_from_note_pool")[0..8]
const CLAIM_FROM_NOTE_POOL_DISCRIMINATOR = Buffer.from([
  253, 6, 222, 21, 191, 226, 43, 142,
]);

interface PoolClaimRequest {
  proof: {
    proofA: number[];   // 64
    proofB: number[];   // 128
    proofC: number[];   // 64
  };
  poolNullifierHash: number[];  // 32
  recipient: string;             // base58 pubkey
  inputs: number[];              // 64 = pool_root(32) + new_stored_commitment(32)
}

router.post("/", async (req: Request, res: Response) => {
  try {
    const body = req.body as PoolClaimRequest;

    if (!body.proof || !body.poolNullifierHash || !body.recipient || !body.inputs) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.proof.proofA.length !== 64) return res.status(400).json({ error: "proofA must be 64 bytes" });
    if (body.proof.proofB.length !== 128) return res.status(400).json({ error: "proofB must be 128 bytes" });
    if (body.proof.proofC.length !== 64) return res.status(400).json({ error: "proofC must be 64 bytes" });
    if (body.poolNullifierHash.length !== 32) return res.status(400).json({ error: "poolNullifierHash must be 32 bytes" });
    if (body.inputs.length !== 64) return res.status(400).json({ error: "inputs must be 64 bytes (pool_root + commitment)" });

    let recipientPubkey: PublicKey;
    try { recipientPubkey = new PublicKey(body.recipient); } catch {
      return res.status(400).json({ error: "Invalid recipient pubkey" });
    }

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    const vault = pda([Buffer.from("vault")]);
    const notePool = pda([Buffer.from("note_pool")]);
    const notePoolTree = pda([Buffer.from("note_pool_tree"), vault.toBytes()]);
    const poolNullHashBytes = Buffer.from(body.poolNullifierHash);
    const creditNote = pda([Buffer.from("credit"), poolNullHashBytes]);
    const poolNullifierAccount = pda([Buffer.from("pool_nullifier"), poolNullHashBytes]);

    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(body.inputs.length);

    const data = Buffer.concat([
      CLAIM_FROM_NOTE_POOL_DISCRIMINATOR,
      poolNullHashBytes,
      Buffer.from(body.proof.proofA),
      Buffer.from(body.proof.proofB),
      Buffer.from(body.proof.proofC),
      lenBuf,
      Buffer.from(body.inputs),
    ]);

    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: notePool, isSigner: false, isWritable: true },
        { pubkey: notePoolTree, isSigner: false, isWritable: false },
        { pubkey: creditNote, isSigner: false, isWritable: true },
        { pubkey: poolNullifierAccount, isSigner: false, isWritable: true },
        { pubkey: recipientPubkey, isSigner: false, isWritable: false },
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      ix,
    );
    tx.feePayer = relayer.publicKey;

    const signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
      commitment: "confirmed",
    });

    console.log(`Pool claim relayed: ${signature} | recipient=${body.recipient}`);
    res.json({ success: true, signature });
  } catch (err: any) {
    console.error("Pool claim relay error:", err.message);
    res.status(500).json({ error: "Relay failed" });
  }
});

export default router;
