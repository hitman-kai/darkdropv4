/**
 * DarkDrop V4 — Relay Claim Endpoint
 *
 * POST /api/relay/claim
 *
 * Receives a ZK proof and claim parameters, builds the claim TX,
 * signs it with the relayer keypair (fee payer), and submits to Solana.
 *
 * The relayer CANNOT steal funds — the ZK proof binds the claim to a
 * specific recipient pubkey. The relayer can only take its pre-agreed fee.
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
import { verifyClaimProofV1, pubkeyToField, bytes32ToBigInt } from "../verify";

const router = Router();

// PDA derivation helpers
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

function getSolVaultPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("sol_vault")], PROGRAM_ID)[0];
}

function getNullifierPDA(nullifierHash: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier"), nullifierHash],
    PROGRAM_ID
  )[0];
}

interface RelayClaimRequest {
  proof: {
    proofA: number[]; // 64 bytes
    proofB: number[]; // 128 bytes
    proofC: number[]; // 64 bytes
  };
  merkleRoot: number[];       // 32 bytes
  nullifierHash: number[];    // 32 bytes
  recipient: string;          // base58 pubkey
  amount: string;             // lamports as string
  amountCommitment: number[]; // 32 bytes
  passwordHash: number[];     // 32 bytes
}

// Precomputed: sha256("global:claim")[0..8]
const CLAIM_DISCRIMINATOR = Buffer.from([62, 198, 214, 193, 213, 159, 108, 210]);

router.post("/", async (req: Request, res: Response) => {
  try {
    const body = req.body as RelayClaimRequest;

    // Validate required fields
    if (
      !body.proof?.proofA ||
      !body.proof?.proofB ||
      !body.proof?.proofC ||
      !body.merkleRoot ||
      !body.nullifierHash ||
      !body.recipient ||
      !body.amount ||
      !body.amountCommitment ||
      !body.passwordHash
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Validate proof sizes
    if (body.proof.proofA.length !== 64) return res.status(400).json({ error: "proofA must be 64 bytes" });
    if (body.proof.proofB.length !== 128) return res.status(400).json({ error: "proofB must be 128 bytes" });
    if (body.proof.proofC.length !== 64) return res.status(400).json({ error: "proofC must be 64 bytes" });

    let amount: bigint;
    try {
      amount = BigInt(body.amount);
    } catch {
      return res.status(400).json({ error: "Invalid amount" });
    }
    if (amount <= 0n) return res.status(400).json({ error: "Amount must be > 0" });
    if (amount > config.maxClaimAmount) return res.status(400).json({ error: "Amount exceeds relay limit" });

    // Pre-validate ZK proof off-chain before spending gas
    const recipientPubkey = new PublicKey(body.recipient);
    const recipientField = await pubkeyToField(recipientPubkey.toBytes());
    const merkleRootBigint = bytes32ToBigInt(Buffer.from(body.merkleRoot));
    const nullifierHashBigint = bytes32ToBigInt(Buffer.from(body.nullifierHash));
    const amountCommitBigint = bytes32ToBigInt(Buffer.from(body.amountCommitment));
    const passwordHashBigint = bytes32ToBigInt(Buffer.from(body.passwordHash));

    // V1 public inputs order: [amount, merkle_root, nullifier_hash, recipient_hash, amount_commitment, password_hash]
    const amountField = amount; // amount as lamports, zero-padded to field
    const valid = await verifyClaimProofV1(
      body.proof.proofA, body.proof.proofB, body.proof.proofC,
      [amountField, merkleRootBigint, nullifierHashBigint, recipientField, amountCommitBigint, passwordHashBigint],
    );
    if (!valid) {
      return res.status(400).json({ error: "Invalid ZK proof" });
    }

    // Compute fee
    const feeLamports = (amount * BigInt(config.feeRateBps)) / 10000n;

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    // Resolve PDAs
    const vault = getVaultPDA();
    const merkleTree = getMerkleTreePDA(vault);
    const solVault = getSolVaultPDA();
    const nullifierHashBytes = new Uint8Array(body.nullifierHash);
    const nullifierPDA = getNullifierPDA(nullifierHashBytes);
    const recipient = new PublicKey(body.recipient);

    // Check nullifier not already spent
    const existingNullifier = await connection.getAccountInfo(nullifierPDA);
    if (existingNullifier) {
      return res.status(409).json({ error: "Nullifier already spent — drop already claimed" });
    }

    // Serialize amount and fee as u64 LE
    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(amount);
    const feeBuf = Buffer.alloc(8);
    feeBuf.writeBigUInt64LE(feeLamports);

    // Build claim instruction data
    const instructionData = Buffer.concat([
      CLAIM_DISCRIMINATOR,                     // 8
      new Uint8Array(body.proof.proofA),       // 64
      new Uint8Array(body.proof.proofB),       // 128
      new Uint8Array(body.proof.proofC),       // 64
      new Uint8Array(body.merkleRoot),         // 32
      new Uint8Array(body.nullifierHash),      // 32
      amountBuf,                               // 8
      new Uint8Array(body.amountCommitment),   // 32
      new Uint8Array(body.passwordHash),       // 32
      feeBuf,                                  // 8
    ]);

    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: false },
        { pubkey: solVault, isSigner: false, isWritable: true },
        { pubkey: nullifierPDA, isSigner: false, isWritable: true },
        { pubkey: recipient, isSigner: false, isWritable: true },       // NOT a signer
        { pubkey: relayer.publicKey, isSigner: false, isWritable: true }, // fee_recipient
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },  // payer
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: instructionData,
    });

    // Build and send TX — relayer is the sole signer
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
      ix,
    );
    tx.feePayer = relayer.publicKey;

    const signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
      commitment: "confirmed",
    });

    const recipientAmount = amount - feeLamports;
    console.log(
      `Claim relayed: ${signature} | amount=${amount} | fee=${feeLamports} | net=${recipientAmount} | recipient=${body.recipient}`
    );

    res.json({
      success: true,
      signature,
      recipient: body.recipient,
      amount: body.amount,
      fee: feeLamports.toString(),
      net: recipientAmount.toString(),
    });
  } catch (err: any) {
    console.error("Relay claim error:", err.message);

    if (err.message?.includes("already in use")) {
      return res.status(409).json({ error: "Nullifier already spent" });
    }
    if (err.message?.includes("InvalidProof")) {
      return res.status(400).json({ error: "Invalid ZK proof" });
    }
    if (err.message?.includes("InvalidRoot")) {
      return res.status(400).json({ error: "Merkle root not recognized" });
    }

    res.status(500).json({ error: "Relay failed" });
  }
});

export default router;
