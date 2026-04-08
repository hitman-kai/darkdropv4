/**
 * DarkDrop V4 — Credit Note Relay Endpoints
 *
 * POST /api/relay/credit/claim
 *   Relays claim_credit TX (no SOL moves, amount hidden)
 *
 * POST /api/relay/credit/withdraw
 *   Relays withdraw_credit TX (SOL moves via direct lamport manipulation)
 *
 * Both endpoints: relayer is sole signer, recipient never signs.
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
import fs from "fs";
import os from "os";

const router = Router();

function loadRelayerKeypair(): Keypair {
  const keypairPath = config.keypairPath.replace("~", os.homedir());
  const secretKey = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
  return Keypair.fromSecretKey(new Uint8Array(secretKey));
}

const PROGRAM_ID = new PublicKey(config.programId);

function getVaultPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID)[0];
}
function getMerkleTreePDA(vault: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID
  )[0];
}
function getTreasuryPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID)[0];
}
function getCreditNotePDA(nullifierHash: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("credit"), nullifierHash], PROGRAM_ID
  )[0];
}
function getNullifierPDA(nullifierHash: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier"), nullifierHash], PROGRAM_ID
  )[0];
}

const CLAIM_CREDIT_DISC = Buffer.from([190, 242, 172, 79, 29, 82, 22, 163]);
const WITHDRAW_CREDIT_DISC = Buffer.from([8, 173, 134, 129, 40, 255, 134, 30]);

// ─── POST /claim ─────────────────────────────────────────────
interface CreditClaimRequest {
  proof: {
    proofA: number[];
    proofB: number[];
    proofC: number[];
  };
  nullifierHash: number[];    // 32 bytes
  recipient: string;          // base58 pubkey
  inputs: number[];           // 96 bytes: merkle_root(32) + commitment(32) + seed(32)
}

router.post("/claim", async (req: Request, res: Response) => {
  try {
    const body = req.body as CreditClaimRequest;

    if (!body.proof?.proofA || !body.nullifierHash || !body.recipient || !body.inputs) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.inputs.length !== 96) return res.status(400).json({ error: "inputs must be 96 bytes" });

    const relayer = loadRelayerKeypair();
    const connection = new Connection(config.rpcUrl, "confirmed");

    const nullifierHashBytes = new Uint8Array(body.nullifierHash);
    const vault = getVaultPDA();
    const merkleTree = getMerkleTreePDA(vault);
    const creditNotePDA = getCreditNotePDA(nullifierHashBytes);
    const nullifierPDA = getNullifierPDA(nullifierHashBytes);
    const recipient = new PublicKey(body.recipient);

    // Check nullifier not spent
    const existingNullifier = await connection.getAccountInfo(nullifierPDA);
    if (existingNullifier) {
      return res.status(409).json({ error: "Nullifier already spent" });
    }

    // Borsh-encode Vec<u8> inputs
    const inputsBuf = Buffer.from(body.inputs);
    const inputsLenBuf = Buffer.alloc(4);
    inputsLenBuf.writeUInt32LE(inputsBuf.length);

    const instructionData = Buffer.concat([
      CLAIM_CREDIT_DISC,
      Buffer.from(body.nullifierHash),
      Buffer.from(body.proof.proofA),
      Buffer.from(body.proof.proofB),
      Buffer.from(body.proof.proofC),
      inputsLenBuf,
      inputsBuf,
    ]);

    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: false },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: nullifierPDA, isSigner: false, isWritable: true },
        { pubkey: recipient, isSigner: false, isWritable: false },
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: instructionData,
    });

    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      ix,
    );
    tx.feePayer = relayer.publicKey;

    const signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
      commitment: "confirmed",
    });

    console.log(`Credit claim relayed: ${signature} | recipient=${body.recipient}`);

    res.json({
      success: true,
      signature,
      recipient: body.recipient,
      creditNote: creditNotePDA.toString(),
    });
  } catch (err: any) {
    console.error("Relay credit claim error:", err.message);
    if (err.message?.includes("already in use")) {
      return res.status(409).json({ error: "Nullifier already spent" });
    }
    res.status(500).json({ error: "Relay failed: " + err.message });
  }
});

// ─── POST /withdraw ──────────────────────────────────────────
interface CreditWithdrawRequest {
  nullifierHash: number[];    // 32 bytes
  opening: number[];          // 40 bytes: amount(8 LE) + blinding(32)
  recipient: string;          // base58 pubkey
}

router.post("/withdraw", async (req: Request, res: Response) => {
  try {
    const body = req.body as CreditWithdrawRequest;

    if (!body.nullifierHash || !body.opening || !body.recipient) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.opening.length !== 40) return res.status(400).json({ error: "opening must be 40 bytes" });

    const relayer = loadRelayerKeypair();
    const connection = new Connection(config.rpcUrl, "confirmed");

    const nullifierHashBytes = new Uint8Array(body.nullifierHash);
    const vault = getVaultPDA();
    const treasury = getTreasuryPDA();
    const creditNotePDA = getCreditNotePDA(nullifierHashBytes);
    const recipient = new PublicKey(body.recipient);

    // Verify credit note exists
    const creditNoteInfo = await connection.getAccountInfo(creditNotePDA);
    if (!creditNoteInfo) {
      return res.status(404).json({ error: "Credit note not found" });
    }

    // Rate in basis points (relayer fee)
    const rate = config.feeRateBps;
    const rateBuf = Buffer.alloc(2);
    rateBuf.writeUInt16LE(rate);

    // Borsh-encode Vec<u8> opening
    const openingBuf = Buffer.from(body.opening);
    const openingLenBuf = Buffer.alloc(4);
    openingLenBuf.writeUInt32LE(openingBuf.length);

    const instructionData = Buffer.concat([
      WITHDRAW_CREDIT_DISC,
      Buffer.from(body.nullifierHash),
      openingLenBuf,
      openingBuf,
      rateBuf,
    ]);

    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: recipient, isSigner: false, isWritable: true },
        { pubkey: relayer.publicKey, isSigner: false, isWritable: true },   // fee_recipient
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },    // payer
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: instructionData,
    });

    const tx = new Transaction().add(ix);
    tx.feePayer = relayer.publicKey;

    const signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
      commitment: "confirmed",
    });

    // Extract amount from opening for logging
    const amountFromOpening = Buffer.from(body.opening.slice(0, 8)).readBigUInt64LE(0);
    const fee = (amountFromOpening * BigInt(rate)) / 10000n;
    const net = amountFromOpening - fee;

    console.log(
      `Credit withdraw relayed: ${signature} | net=${net} | fee=${fee} | recipient=${body.recipient}`
    );

    res.json({
      success: true,
      signature,
      recipient: body.recipient,
    });
  } catch (err: any) {
    console.error("Relay credit withdraw error:", err.message);
    res.status(500).json({ error: "Relay failed: " + err.message });
  }
});

export default router;
