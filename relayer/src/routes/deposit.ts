/**
 * DarkDrop V4 — Deposit Relay Endpoint
 *
 * POST /api/relay/create-drop
 *
 * User sends SOL to the relayer wallet via a normal system transfer (separate TX).
 * The relayer then calls create_drop with itself as the sender.
 * The user's wallet never appears in any DarkDrop transaction.
 *
 * Flow:
 *   1. Client sends { leaf, commitment, seed, depositTx } to relayer
 *   2. Relayer verifies the depositTx transferred SOL to the relayer wallet
 *   3. Relayer calls create_drop with the relayer as sender
 *   4. User's wallet is NOT in the DarkDrop TX — only the relayer
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

function getVaultPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID)[0];
}

function getMerkleTreePDA(vault: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vault.toBytes()],
    PROGRAM_ID
  )[0];
}

function getTreasuryPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID)[0];
}

const CREATE_DROP_DISCRIMINATOR = Buffer.from([157, 142, 145, 247, 92, 73, 59, 48]);

interface DepositRelayRequest {
  leaf: number[];           // 32 bytes
  amount: string;           // lamports as string
  commitment: number[];     // 32 bytes (amount_commitment)
  seed: number[];           // 32 bytes (password_hash)
  depositTx: string;        // signature of the SOL transfer TX from user to relayer
}

router.post("/", async (req: Request, res: Response) => {
  try {
    const body = req.body as DepositRelayRequest;

    // Validate required fields
    if (!body.leaf || !body.amount || !body.commitment || !body.seed || !body.depositTx) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (body.leaf.length !== 32) return res.status(400).json({ error: "leaf must be 32 bytes" });
    if (body.commitment.length !== 32) return res.status(400).json({ error: "commitment must be 32 bytes" });
    if (body.seed.length !== 32) return res.status(400).json({ error: "seed must be 32 bytes" });

    let amount: bigint;
    try {
      amount = BigInt(body.amount);
    } catch {
      return res.status(400).json({ error: "Invalid amount" });
    }
    if (amount <= 0n) return res.status(400).json({ error: "Amount must be > 0" });
    if (amount > config.maxClaimAmount) return res.status(400).json({ error: "Amount exceeds relay limit" });

    // C-01 FIX: Reject replayed deposit TX signatures (persistent across restarts)
    if (hasProcessedTx(body.depositTx)) {
      return res.status(409).json({ error: "Deposit TX already processed" });
    }

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    // Verify the deposit TX transferred the correct amount to the relayer
    const txInfo = await connection.getTransaction(body.depositTx, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });

    if (!txInfo) {
      return res.status(400).json({ error: "Deposit TX not found or not confirmed" });
    }

    // Check that the relayer received at least `amount` lamports
    const accountKeys = txInfo.transaction.message.getAccountKeys().staticAccountKeys;
    const relayerIndex = accountKeys.findIndex(
      (key) => key.toString() === relayer.publicKey.toString()
    );

    if (relayerIndex === -1) {
      return res.status(400).json({ error: "Relayer not in deposit TX accounts" });
    }

    const preBalance = txInfo.meta?.preBalances[relayerIndex] ?? 0;
    const postBalance = txInfo.meta?.postBalances[relayerIndex] ?? 0;
    const received = BigInt(postBalance - preBalance);

    if (received < amount) {
      return res.status(400).json({
        error: `Deposit TX transferred ${received} lamports, expected at least ${amount}`,
      });
    }

    // Mark TX as processed BEFORE submitting on-chain (prevent concurrent replays)
    markProcessed(body.depositTx);

    // Build create_drop instruction with relayer as sender
    const vault = getVaultPDA();
    const merkleTree = getMerkleTreePDA(vault);
    const treasury = getTreasuryPDA();

    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(amount);

    const instructionData = Buffer.concat([
      CREATE_DROP_DISCRIMINATOR,
      new Uint8Array(body.leaf),        // 32
      amountBuf,                        // 8
      new Uint8Array(body.commitment),  // 32
      new Uint8Array(body.seed),        // 32
    ]);

    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },  // relayer is sender
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: instructionData,
    });

    const tx = new Transaction().add(ix);
    tx.feePayer = relayer.publicKey;

    let signature: string;
    try {
      signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
        commitment: "confirmed",
      });
    } catch (err) {
      // On-chain TX failed — remove from processed set so user can retry
      unmarkProcessed(body.depositTx);
      throw err;
    }

    console.log(
      `Deposit relayed: ${signature} | amount=${amount} | depositTx=${body.depositTx}`
    );

    res.json({
      success: true,
      signature,
      depositTx: body.depositTx,
    });
  } catch (err: any) {
    console.error("Relay deposit error:", err.message);
    res.status(500).json({ error: "Relay failed" });
  }
});

export default router;
