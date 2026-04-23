/**
 * DarkDrop V4 — Note Pool Deposit Relay Endpoint
 *
 * POST /api/relay/create-drop-to-pool
 *
 * Mirrors /api/relay/create-drop but targets create_drop_to_pool:
 *   1. Client sends { amount, poolParams, depositTx } to relayer
 *   2. Relayer verifies depositTx transferred at least `amount` to the relayer
 *   3. Relayer calls create_drop_to_pool with itself as sender
 *
 * The user's wallet only appears as the source of a plain system transfer —
 * never in the DarkDrop TX. Combined with the V3 pool claim this gives
 * max-privacy deposit + claim, with a single TX at each end.
 */

import { Router, Request, Response } from "express";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { config } from "../config";
import { hasProcessedTx, markProcessed, unmarkProcessed } from "../processed-txs";

const router = Router();

const PROGRAM_ID = new PublicKey(config.programId);

function pda(seeds: (Buffer | Uint8Array)[]) {
  return PublicKey.findProgramAddressSync(seeds, PROGRAM_ID)[0];
}

// sha256("global:create_drop_to_pool")[0..8]
const CREATE_DROP_TO_POOL_DISCRIMINATOR = Buffer.from([
  92, 206, 41, 22, 178, 116, 89, 63,
]);

interface PoolDepositRelayRequest {
  amount: string;          // lamports
  poolParams: number[];    // 96 bytes = secret(32) || nullifier(32) || blinding(32)
  depositTx: string;       // signature of user -> relayer SOL transfer
}

router.post("/", async (req: Request, res: Response) => {
  try {
    const body = req.body as PoolDepositRelayRequest;

    if (!body.amount || !body.poolParams || !body.depositTx) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.poolParams.length !== 96) {
      return res.status(400).json({ error: "poolParams must be 96 bytes" });
    }

    let amount: bigint;
    try { amount = BigInt(body.amount); } catch {
      return res.status(400).json({ error: "Invalid amount" });
    }
    if (amount <= 0n) return res.status(400).json({ error: "Amount must be > 0" });
    if (amount > config.maxClaimAmount) return res.status(400).json({ error: "Amount exceeds relay limit" });

    if (hasProcessedTx(body.depositTx)) {
      return res.status(409).json({ error: "Deposit TX already processed" });
    }

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    // Verify the deposit TX transferred the correct amount to the relayer wallet.
    const txInfo = await connection.getTransaction(body.depositTx, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    if (!txInfo) {
      return res.status(400).json({ error: "Deposit TX not found or not confirmed" });
    }
    const accountKeys = txInfo.transaction.message.getAccountKeys().staticAccountKeys;
    const relayerIndex = accountKeys.findIndex(
      (k) => k.toString() === relayer.publicKey.toString()
    );
    if (relayerIndex === -1) {
      return res.status(400).json({ error: "Relayer not in deposit TX accounts" });
    }
    const received = BigInt(
      (txInfo.meta?.postBalances[relayerIndex] ?? 0) - (txInfo.meta?.preBalances[relayerIndex] ?? 0)
    );
    if (received < amount) {
      return res.status(400).json({
        error: `Deposit TX transferred ${received} lamports, expected at least ${amount}`,
      });
    }

    markProcessed(body.depositTx);

    // Build create_drop_to_pool ix.
    const vault = pda([Buffer.from("vault")]);
    const notePool = pda([Buffer.from("note_pool")]);
    const notePoolTree = pda([Buffer.from("note_pool_tree"), vault.toBytes()]);
    const treasury = pda([Buffer.from("treasury")]);

    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(amount);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(96);

    const data = Buffer.concat([
      CREATE_DROP_TO_POOL_DISCRIMINATOR,
      amountBuf,
      lenBuf,
      Buffer.from(body.poolParams),
    ]);

    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: notePool, isSigner: false, isWritable: true },
        { pubkey: notePoolTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });

    const tx = new Transaction().add(ix);
    tx.feePayer = relayer.publicKey;

    let signature: string;
    try {
      signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
        commitment: "confirmed",
      });
    } catch (err) {
      unmarkProcessed(body.depositTx);
      throw err;
    }

    console.log(`Pool deposit relayed: ${signature} | amount=${amount} | depositTx=${body.depositTx}`);
    res.json({ success: true, signature, depositTx: body.depositTx });
  } catch (err: any) {
    console.error("Pool deposit relay error:", err.message);
    res.status(500).json({ error: "Relay failed" });
  }
});

export default router;
