/**
 * DarkDrop V4 — SPL Credit Note Relay Endpoints
 *
 * POST /api/relay/credit-spl/claim
 *   Relays claim_credit_spl TX. No tokens move; per-mint nullifier + CreditNoteSpl
 *   initialized. Mirrors the SOL /api/relay/credit/claim endpoint with an added
 *   `mint` field and per-mint PDA derivation.
 *
 * POST /api/relay/credit-spl/withdraw
 *   Relays withdraw_credit_spl TX. SPL `token::transfer` CPI moves the
 *   recipient's net + the relayer's fee out of `mint_vault`. Recipient ATA must
 *   already exist; the relayer refuses to auto-create it (would require the
 *   relayer to pay rent for an account observable to chain indexers).
 *
 * Both endpoints: relayer is the sole signer, recipient never signs.
 * Both endpoints target `config.splProgramId` (test program for now) — the live
 * program will move there after the upgrade.
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
import {
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import { createHash } from "crypto";
import { config } from "../config";
import {
  verifyClaimProofV2,
  verifyCommitmentOpening,
  pubkeyToField,
  bytes32ToBigInt,
} from "../verify";

const router = Router();

const SPL_PROGRAM_ID = new PublicKey(config.splProgramId);

function anchorDisc(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

const CLAIM_CREDIT_SPL_DISC = anchorDisc("claim_credit_spl");
const WITHDRAW_CREDIT_SPL_DISC = anchorDisc("withdraw_credit_spl");

// ─── PDA helpers (per-mint namespaces match program-side seeds) ───────────
function getVaultPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], SPL_PROGRAM_ID)[0];
}
function getMintConfigPDA(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("mint_config"), mint.toBuffer()], SPL_PROGRAM_ID
  )[0];
}
function getMerkleTreeSplPDA(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree_spl"), mint.toBuffer()], SPL_PROGRAM_ID
  )[0];
}
function getMintVaultPDA(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("mint_vault"), mint.toBuffer()], SPL_PROGRAM_ID
  )[0];
}
function getNullifierSplPDA(mint: PublicKey, nullifierHash: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier_spl"), mint.toBuffer(), nullifierHash], SPL_PROGRAM_ID
  )[0];
}
function getCreditNoteSplPDA(mint: PublicKey, nullifierHash: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("credit_spl"), mint.toBuffer(), nullifierHash], SPL_PROGRAM_ID
  )[0];
}

// ─── POST /claim ─────────────────────────────────────────────────────────
interface CreditSplClaimRequest {
  mint: string;
  proof: { proofA: number[]; proofB: number[]; proofC: number[] };
  nullifierHash: number[]; // 32 bytes
  recipient: string;
  inputs: number[]; // 96 bytes: merkle_root || amount_commitment || password_hash
  salt: number[]; // 32 bytes
}

router.post("/claim", async (req: Request, res: Response) => {
  try {
    const body = req.body as CreditSplClaimRequest;

    if (
      !body.mint ||
      !body.proof?.proofA ||
      !body.nullifierHash ||
      !body.recipient ||
      !body.inputs ||
      !body.salt
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.inputs.length !== 96) return res.status(400).json({ error: "inputs must be 96 bytes" });
    if (body.salt.length !== 32) return res.status(400).json({ error: "salt must be 32 bytes" });
    if (body.nullifierHash.length !== 32) {
      return res.status(400).json({ error: "nullifierHash must be 32 bytes" });
    }

    // Off-chain V2 proof verification (same proof shape as SOL) — fail fast.
    const inputsBuf = Buffer.from(body.inputs);
    const merkleRootBigint = bytes32ToBigInt(inputsBuf, 0);
    const amountCommitBigint = bytes32ToBigInt(inputsBuf, 32);
    const passwordHashBigint = bytes32ToBigInt(inputsBuf, 64);
    const nullifierHashBigint = bytes32ToBigInt(Buffer.from(body.nullifierHash));

    const mint = new PublicKey(body.mint);
    const recipientPubkey = new PublicKey(body.recipient);
    const recipientField = await pubkeyToField(recipientPubkey.toBytes());

    const valid = await verifyClaimProofV2(
      body.proof.proofA,
      body.proof.proofB,
      body.proof.proofC,
      [merkleRootBigint, nullifierHashBigint, recipientField, amountCommitBigint, passwordHashBigint],
    );
    if (!valid) {
      return res.status(400).json({ error: "Invalid ZK proof" });
    }

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    const nullifierHashBytes = new Uint8Array(body.nullifierHash);
    const vault = getVaultPDA();
    const mintConfig = getMintConfigPDA(mint);
    const merkleTreeSpl = getMerkleTreeSplPDA(mint);
    const nullifierPDA = getNullifierSplPDA(mint, nullifierHashBytes);
    const creditNotePDA = getCreditNoteSplPDA(mint, nullifierHashBytes);

    // Replay guard — Anchor's `init` would error anyway but this returns a
    // clean 409 instead of a confusing on-chain failure.
    const existingNullifier = await connection.getAccountInfo(nullifierPDA);
    if (existingNullifier) {
      return res.status(409).json({ error: "Nullifier already spent" });
    }

    // Borsh: Vec<u8> = len(u32 LE) || bytes
    const inputsLenBuf = Buffer.alloc(4);
    inputsLenBuf.writeUInt32LE(inputsBuf.length);

    // Reduce salt modulo BN254 scalar field — same defensive normalization the
    // SOL route does to keep Poseidon from panicking on an out-of-field input.
    const BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const saltRaw = Buffer.from(body.salt);
    const saltBigInt = BigInt("0x" + saltRaw.toString("hex")) % BN254_FR;
    const saltBuf = Buffer.from(saltBigInt.toString(16).padStart(64, "0"), "hex");

    const instructionData = Buffer.concat([
      CLAIM_CREDIT_SPL_DISC,
      Buffer.from(body.nullifierHash),
      Buffer.from(body.proof.proofA),
      Buffer.from(body.proof.proofB),
      Buffer.from(body.proof.proofC),
      inputsLenBuf,
      inputsBuf,
      saltBuf,
    ]);

    const ix = new TransactionInstruction({
      programId: SPL_PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: mintConfig, isSigner: false, isWritable: false },
        { pubkey: merkleTreeSpl, isSigner: false, isWritable: false },
        { pubkey: nullifierPDA, isSigner: false, isWritable: true },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: recipientPubkey, isSigner: false, isWritable: false },
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: instructionData,
    });

    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: config.v2CreditSplClaimCu }),
      ix,
    );
    tx.feePayer = relayer.publicKey;

    const signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
      commitment: "confirmed",
    });

    console.log(
      `Credit-SPL claim relayed: ${signature} | mint=${body.mint} | recipient=${body.recipient}`
    );

    res.json({
      success: true,
      signature,
      recipient: body.recipient,
      mint: body.mint,
      creditNote: creditNotePDA.toString(),
    });
  } catch (err: any) {
    console.error("Relay credit-spl claim error:", err.message);
    if (err.message?.includes("already in use")) {
      return res.status(409).json({ error: "Nullifier already spent" });
    }
    res.status(500).json({ error: "Relay failed" });
  }
});

// ─── POST /withdraw ──────────────────────────────────────────────────────
interface CreditSplWithdrawRequest {
  mint: string;
  nullifierHash: number[]; // 32 bytes
  opening: number[]; // 72 bytes: amount(8 LE) + blinding(32) + salt(32)
  recipient: string;
  recipientAta?: string; // optional; derived from (mint, recipient) if omitted
  rate?: number; // optional fee override; defaults to config.feeRateBps
}

router.post("/withdraw", async (req: Request, res: Response) => {
  try {
    const body = req.body as CreditSplWithdrawRequest;

    if (!body.mint || !body.nullifierHash || !body.opening || !body.recipient) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (body.opening.length !== 72) return res.status(400).json({ error: "opening must be 72 bytes" });
    if (body.nullifierHash.length !== 32) {
      return res.status(400).json({ error: "nullifierHash must be 32 bytes" });
    }

    const rate = typeof body.rate === "number" ? body.rate : config.feeRateBps;
    if (rate < 0 || rate > 500) {
      return res.status(400).json({ error: "rate out of bounds (0-500 bps)" });
    }

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    const mint = new PublicKey(body.mint);
    const recipient = new PublicKey(body.recipient);
    const nullifierHashBytes = new Uint8Array(body.nullifierHash);

    const vault = getVaultPDA();
    const mintConfig = getMintConfigPDA(mint);
    const creditNotePDA = getCreditNoteSplPDA(mint, nullifierHashBytes);
    const mintVault = getMintVaultPDA(mint);

    // CreditNoteSpl must exist (set by an earlier claim).
    const creditNoteInfo = await connection.getAccountInfo(creditNotePDA);
    if (!creditNoteInfo) {
      return res.status(404).json({ error: "Credit note not found" });
    }

    // Off-chain commitment opening verification. Layout (matches SOL CreditNote
    // — both account types put `commitment` at the same byte range so the same
    // slice works):
    //   8(disc) + 1(bump) + 32(recipient) + 32(commitment) + ...
    const cnData = creditNoteInfo.data;
    const storedCommitment = cnData.slice(41, 73);

    const openingAmount = Buffer.from(body.opening.slice(0, 8)).readBigUInt64LE(0);
    const openingBlinding = new Uint8Array(body.opening.slice(8, 40));
    const openingSalt = new Uint8Array(body.opening.slice(40, 72));

    const commitmentValid = await verifyCommitmentOpening(
      storedCommitment, openingAmount, openingBlinding, openingSalt,
    );
    if (!commitmentValid) {
      return res.status(400).json({ error: "Invalid commitment opening" });
    }

    // Resolve / validate recipient ATA. Frontend may supply it; otherwise we
    // derive. Either way we check it exists on-chain — auto-create would
    // require the relayer to pay rent for a chain-observable account that
    // links us to the recipient.
    const recipientAta = body.recipientAta
      ? new PublicKey(body.recipientAta)
      : getAssociatedTokenAddressSync(mint, recipient);
    const recipientAtaInfo = await connection.getAccountInfo(recipientAta);
    if (!recipientAtaInfo) {
      return res.status(400).json({
        error: "Recipient ATA does not exist. Frontend must create it before withdraw.",
        recipientAta: recipientAta.toBase58(),
      });
    }

    // Payer ATA is required even at rate=0 — Anchor parses + validates the
    // account, just doesn't write to it. If missing, the withdraw fails on
    // chain; surface that here as a 503 so ops knows to pre-create it
    // out-of-band.
    const payerAta = getAssociatedTokenAddressSync(mint, relayer.publicKey);
    const payerAtaInfo = await connection.getAccountInfo(payerAta);
    if (!payerAtaInfo) {
      return res.status(503).json({
        error: "Relayer payer ATA missing for this mint. Admin must pre-create it.",
        mint: body.mint,
        payerAta: payerAta.toBase58(),
      });
    }

    const rateBuf = Buffer.alloc(2);
    rateBuf.writeUInt16LE(rate);

    const openingBuf = Buffer.from(body.opening);
    const openingLenBuf = Buffer.alloc(4);
    openingLenBuf.writeUInt32LE(openingBuf.length);

    const instructionData = Buffer.concat([
      WITHDRAW_CREDIT_SPL_DISC,
      Buffer.from(body.nullifierHash),
      openingLenBuf,
      openingBuf,
      rateBuf,
    ]);

    const ix = new TransactionInstruction({
      programId: SPL_PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: false },
        { pubkey: mintConfig, isSigner: false, isWritable: true },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: mintVault, isSigner: false, isWritable: true },
        { pubkey: recipientAta, isSigner: false, isWritable: true },
        { pubkey: payerAta, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: instructionData,
    });

    const tx = new Transaction().add(ix);
    tx.feePayer = relayer.publicKey;

    const signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
      commitment: "confirmed",
    });

    const fee = (openingAmount * BigInt(rate)) / 10000n;
    const net = openingAmount - fee;

    console.log(
      `Credit-SPL withdraw relayed: ${signature} | mint=${body.mint} | net=${net} | fee=${fee} | recipient=${body.recipient}`
    );

    res.json({
      success: true,
      signature,
      recipient: body.recipient,
      mint: body.mint,
      recipientAta: recipientAta.toBase58(),
    });
  } catch (err: any) {
    console.error("Relay credit-spl withdraw error:", err.message);
    res.status(500).json({ error: "Relay failed" });
  }
});

export default router;
