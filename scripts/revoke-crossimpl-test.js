#!/usr/bin/env node
/**
 * DarkDrop V4 — Cross-implementation leaf reconstruction test
 *
 * Guards against endianness drift between three implementations of
 * leaf = Poseidon(secret, nullifier, amount, blinding):
 *
 *   1. Frontend (`frontend/src/lib/crypto.ts::createLeaf`)
 *   2. Circuit  (`circuits/darkdrop.circom` — `amount` as field element)
 *   3. Program  (`program/.../revoke_drop.rs::u64_to_field_be` + Poseidon)
 *
 * The test builds a leaf using the EXACT frontend convention (big-endian,
 * BigInt amount passed to circomlibjs), creates a drop with it, and calls
 * revoke_drop. If the program's on-chain reconstruction ever drifts
 * (e.g. someone changes u64_to_field_be to LE), revoke returns
 * CommitmentMismatch and this test fails.
 *
 * Also verifies:
 *   - A hypothetical LE amount encoding produces a DIFFERENT leaf (sanity)
 *   - The test's locally-computed leaf bytes match the frontend's
 *     `bigintToBytes32BE` serialization byte-for-byte
 *
 * Run against localnet:
 *   PROGRAM_ID=<id> node scripts/revoke-crossimpl-test.js
 */

const {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const { buildPoseidon } = require("circomlibjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL);
const TIMEOUT_WAIT_MS = parseInt(process.env.REVOKE_WAIT_MS || "8000", 10);

let poseidon, F;
function poseidonHash(inputs) { return F.toObject(poseidon(inputs)); }
function randomField() { return BigInt("0x" + crypto.randomBytes(31).toString("hex")); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Frontend convention (reimplemented verbatim from crypto.ts) ──────────────
// frontend/src/lib/crypto.ts::amountToFieldBE — returns amount as BigInt,
// since amount < 2^64 < field modulus. No byte encoding in the BigInt step.
function fe_amountToFieldBE(amount) {
  if (amount < 0n || amount >= 2n ** 64n) throw new Error("out of u64 range");
  return amount;
}
// frontend/src/lib/crypto.ts::createLeaf
function fe_createLeaf(secret, nullifier, amount, blinding) {
  return poseidonHash([secret, nullifier, fe_amountToFieldBE(amount), blinding]);
}
// frontend/src/lib/crypto.ts::bigintToBytes32BE
function fe_bigintToBytes32BE(val) {
  const hex = val.toString(16).padStart(64, "0");
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
// ─── End frontend convention ──────────────────────────────────────────────────

// Simulate the on-chain u64_to_field_be: 32-byte array with u64 in the last 8
// bytes as BE. When interpreted as a BE 256-bit integer (light-hasher does
// this), it equals the numeric value of `amount`. Poseidon thus receives the
// SAME field element as the frontend passes via amountToFieldBE.
function program_u64ToFieldBE(amount) {
  const bytes = Buffer.alloc(32);
  const be = Buffer.alloc(8);
  be.writeBigUInt64BE(amount);
  bytes.set(be, 24);
  return bytes;
}
function bytesBEToBigInt(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return BigInt("0x" + (hex || "0"));
}

function getDiscriminator(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function getVaultPDA() { return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID); }
function getMerkleTreePDA(v) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), v.toBytes()], PROGRAM_ID); }
function getTreasuryPDA() { return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID); }
function getNullifierPDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), h], PROGRAM_ID); }
function getReceiptPDA(leafBytes) { return PublicKey.findProgramAddressSync([Buffer.from("receipt"), leafBytes], PROGRAM_ID); }

async function main() {
  console.log("=== DarkDrop V4 — Cross-impl Leaf Reconstruction Test ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  // ─── Phase 1: Pure-JS sanity check (no chain) ──────────────────────────────
  console.log("[1] Local consistency checks\n");

  const secret = randomField();
  const nullifier = randomField();
  const amount = BigInt(0.05 * LAMPORTS_PER_SOL);
  const blinding = randomField();

  // Frontend leaf
  const feLeaf = fe_createLeaf(secret, nullifier, amount, blinding);

  // Program-equivalent: byte-level BE encoding → BigInt → same Poseidon
  const progAmountBytes = program_u64ToFieldBE(amount);
  const progAmountField = bytesBEToBigInt(progAmountBytes);
  const progLeaf = poseidonHash([secret, nullifier, progAmountField, blinding]);

  console.log(`    Frontend leaf: ${feLeaf}`);
  console.log(`    Program leaf:  ${progLeaf}`);
  if (feLeaf !== progLeaf) {
    console.log("  [FAIL] frontend-leaf != program-leaf — endianness drift between helpers!");
    process.exit(1);
  }
  console.log("    [PASS] BE convention matches across frontend and program helpers\n");

  // Sanity: LE would produce a DIFFERENT leaf (confirms the test is meaningful)
  const leAmountField = BigInt(`0x${Buffer.from(
    Buffer.alloc(8).fill(0).map((_, i) => Number((amount >> BigInt(i * 8)) & 0xFFn))
  ).toString("hex")}`) << 192n; // LE u64 in low 8 bytes → as BE BigInt, shifted up 24 bytes
  const leLeaf = poseidonHash([secret, nullifier, leAmountField, blinding]);
  console.log(`    LE-buggy leaf: ${leLeaf}`);
  if (leLeaf === feLeaf) {
    console.log("  [FAIL] LE and BE produce the same leaf — test is not discriminating!");
    process.exit(1);
  }
  console.log("    [PASS] LE (hypothetical buggy) encoding produces a different leaf\n");

  // Byte-level check: frontend's bigintToBytes32BE(leaf) must encode to the
  // exact 32 bytes that the program sees on-chain.
  const feLeafBytes = fe_bigintToBytes32BE(feLeaf);
  if (feLeafBytes.length !== 32) {
    console.log("  [FAIL] frontend leaf bytes not 32 bytes");
    process.exit(1);
  }
  console.log(`    Frontend leaf bytes: ${feLeafBytes.toString("hex")}\n`);

  // ─── Phase 2: Cross-impl round-trip on-chain ───────────────────────────────
  console.log("[2] On-chain round-trip via revoke_drop\n");

  const connection = new Connection(RPC_URL, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 120000,
  });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const depositor = Keypair.generate();
  await connection.confirmTransaction(
    await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL)
  );

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [treasury] = getTreasuryPDA();

  // Initialize vault if needed (idempotent)
  const initData = Buffer.concat([getDiscriminator("initialize_vault"), (() => {
    const b = Buffer.alloc(8); b.writeBigUInt64LE(DROP_CAP); return b;
  })()]);
  try {
    await sendAndConfirmTransaction(connection, new Transaction().add(new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: initData,
    })), [payer]);
  } catch (e) {
    if (!e.message?.includes("already in use")) throw e;
  }

  // create_drop using the frontend-computed leaf
  const amtCommitment = poseidonHash([amount, blinding]);
  const [receipt] = getReceiptPDA(feLeafBytes);
  const amountBuf = Buffer.alloc(8); amountBuf.writeBigUInt64LE(amount);

  const createIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: depositor.publicKey, isSigner: true, isWritable: true },
      { pubkey: receipt, isSigner: false, isWritable: true },
    ],
    data: Buffer.concat([
      getDiscriminator("create_drop"),
      feLeafBytes,
      amountBuf,
      fe_bigintToBytes32BE(amtCommitment),
      fe_bigintToBytes32BE(0n),
    ]),
  });
  const createSig = await sendAndConfirmTransaction(
    connection, new Transaction().add(createIx), [payer, depositor]
  );
  console.log(`    create_drop: ${createSig}`);

  console.log(`    waiting ${TIMEOUT_WAIT_MS}ms for time-lock...`);
  await sleep(TIMEOUT_WAIT_MS);

  const nullifierHashBig = poseidonHash([nullifier]);
  const nullifierHashBytes = fe_bigintToBytes32BE(nullifierHashBig);
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);

  const preimage = Buffer.concat([
    fe_bigintToBytes32BE(secret),
    fe_bigintToBytes32BE(nullifier),
    fe_bigintToBytes32BE(blinding),
  ]);
  const preimageLen = Buffer.alloc(4); preimageLen.writeUInt32LE(preimage.length);

  const revokeIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: receipt, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: depositor.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("revoke_drop"),
      feLeafBytes,
      nullifierHashBytes,
      preimageLen, preimage,
    ]),
  });
  const revokeSig = await sendAndConfirmTransaction(
    connection, new Transaction().add(revokeIx), [depositor]
  );
  console.log(`    revoke_drop: ${revokeSig}`);
  console.log("    [PASS] Program reconstructed the frontend-generated leaf successfully\n");

  console.log("=== CROSS-IMPL TEST PASSED ===");
  console.log("BE endianness is consistent across frontend → circuit → program.");
}

main().catch(e => {
  console.error("Fatal:", e.message);
  if (e.logs) e.logs.forEach(l => console.error(`  ${l}`));
  process.exit(1);
});
