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
import { verifyClaimProofV2, verifyCommitmentOpening, pubkeyToField, bytes32ToBigInt } from "../verify";

const router = Router();

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
  salt: number[];             // 32 bytes: random salt for commitment re-randomization
}

router.post("/claim", async (req: Request, res: Response) => {
  try {
    const body = req.body as CreditClaimRequest;

    if (!body.proof?.proofA || !body.nullifierHash || !body.recipient || !body.inputs || !body.salt) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.inputs.length !== 96) return res.status(400).json({ error: "inputs must be 96 bytes" });
    if (body.salt.length !== 32) return res.status(400).json({ error: "salt must be 32 bytes" });

    // Pre-validate ZK proof off-chain before spending gas
    // inputs = merkle_root(32) + amount_commitment(32) + password_hash(32)
    const inputsBuf = Buffer.from(body.inputs);
    const merkleRootBigint = bytes32ToBigInt(inputsBuf, 0);
    const amountCommitBigint = bytes32ToBigInt(inputsBuf, 32);
    const passwordHashBigint = bytes32ToBigInt(inputsBuf, 64);
    const nullifierHashBigint = bytes32ToBigInt(Buffer.from(body.nullifierHash));
    const recipientPubkey = new PublicKey(body.recipient);
    const recipientField = await pubkeyToField(recipientPubkey.toBytes());

    // V2 public inputs order: [merkle_root, nullifier_hash, recipient_hash, amount_commitment, password_hash]
    const valid = await verifyClaimProofV2(
      body.proof.proofA, body.proof.proofB, body.proof.proofC,
      [merkleRootBigint, nullifierHashBigint, recipientField, amountCommitBigint, passwordHashBigint],
    );
    if (!valid) {
      return res.status(400).json({ error: "Invalid ZK proof" });
    }

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    const nullifierHashBytes = new Uint8Array(body.nullifierHash);
    const vault = getVaultPDA();
    const merkleTree = getMerkleTreePDA(vault);
    const creditNotePDA = getCreditNotePDA(nullifierHashBytes);
    const nullifierPDA = getNullifierPDA(nullifierHashBytes);
    const recipient = recipientPubkey;

    // Check nullifier not spent
    const existingNullifier = await connection.getAccountInfo(nullifierPDA);
    if (existingNullifier) {
      return res.status(409).json({ error: "Nullifier already spent" });
    }

    // Borsh-encode Vec<u8> inputs (inputsBuf already created above for proof validation)
    const inputsLenBuf = Buffer.alloc(4);
    inputsLenBuf.writeUInt32LE(inputsBuf.length);

    // Reduce salt modulo BN254 scalar field prime so Poseidon never panics with InvalidParameters
    const BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const saltRaw = Buffer.from(body.salt);
    const saltBigInt = BigInt("0x" + saltRaw.toString("hex")) % BN254_FR;
    const saltBuf = Buffer.from(saltBigInt.toString(16).padStart(64, "0"), "hex");

    const instructionData = Buffer.concat([
      CLAIM_CREDIT_DISC,
      Buffer.from(body.nullifierHash),
      Buffer.from(body.proof.proofA),
      Buffer.from(body.proof.proofB),
      Buffer.from(body.proof.proofC),
      inputsLenBuf,
      inputsBuf,
      saltBuf,
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
    res.status(500).json({ error: "Relay failed" });
  }
});

// ─── POST /withdraw ──────────────────────────────────────────
interface CreditWithdrawRequest {
  nullifierHash: number[];    // 32 bytes
  opening: number[];          // 72 bytes: amount(8 LE) + blinding(32) + salt(32)
  recipient: string;          // base58 pubkey
}

router.post("/withdraw", async (req: Request, res: Response) => {
  try {
    const body = req.body as CreditWithdrawRequest;

    if (!body.nullifierHash || !body.opening || !body.recipient) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.opening.length !== 72) return res.status(400).json({ error: "opening must be 72 bytes" });

    const relayer: Keypair = req.app.locals.relayerKeypair;
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

    // Off-chain commitment verification — reject bad openings before spending gas
    // CreditNote layout: 8(disc) + 1(bump) + 32(recipient) + 32(commitment) + 32(nullifier) + 32(salt) + 8(created)
    const cnData = creditNoteInfo.data;
    const storedCommitment = cnData.slice(41, 73);  // offset 8+1+32 = 41

    const openingAmount = Buffer.from(body.opening.slice(0, 8)).readBigUInt64LE(0);
    const openingBlinding = new Uint8Array(body.opening.slice(8, 40));
    const openingSalt = new Uint8Array(body.opening.slice(40, 72));

    const commitmentValid = await verifyCommitmentOpening(
      storedCommitment, openingAmount, openingBlinding, openingSalt,
    );
    if (!commitmentValid) {
      return res.status(400).json({ error: "Invalid commitment opening" });
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
    res.status(500).json({ error: "Relay failed" });
  }
});

export default router;
