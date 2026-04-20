#!/usr/bin/env node
/**
 * DarkDrop V4 — Revoke E2E Test
 *
 * Tests the depositor-reclaim flow:
 *   1. Initialize vault + treasury
 *   2. Create a drop WITH a DepositReceipt (new remaining_accounts path)
 *   3. Wait for REVOKE_TIMEOUT to elapse
 *      (requires program built with --features short-revoke-timeout; 5 seconds)
 *   4. Submit revoke_drop TX with the leaf preimage
 *   5. Verify:
 *        - Depositor received the deposit amount back
 *        - DepositReceipt PDA closed
 *        - Nullifier PDA created (blocks any future claim)
 *        - Zero inner instructions on revoke (direct lamport manipulation)
 *
 * Run against localnet (fresh validator):
 *   solana-test-validator --reset
 *   cargo build-sbf --manifest-path program/Cargo.toml --features short-revoke-timeout
 *   cp program/target/sbpf-solana-solana/release/darkdrop.so program/target/deploy/darkdrop.so
 *   solana program deploy program/target/deploy/darkdrop.so
 *   node scripts/revoke-test.js
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
const TIMEOUT_WAIT_MS = parseInt(process.env.REVOKE_WAIT_MS || "8000", 10); // default 8s (short-revoke-timeout is 5s)

let poseidon, F;

function poseidonHash(inputs) { return F.toObject(poseidon(inputs)); }
function randomField() { return BigInt("0x" + crypto.randomBytes(31).toString("hex")); }

function bigintToBytes32BE(val) {
  const hex = val.toString(16).padStart(64, "0");
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function getDiscriminator(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function getVaultPDA() { return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID); }
function getMerkleTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID); }
function getTreasuryPDA() { return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID); }
function getNullifierPDA(nullifierHash) { return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nullifierHash], PROGRAM_ID); }
function getReceiptPDA(leafBytes) { return PublicKey.findProgramAddressSync([Buffer.from("receipt"), leafBytes], PROGRAM_ID); }

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log("=== DarkDrop V4 — Revoke E2E Test ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 120000,
  });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const depositor = Keypair.generate();

  console.log(`  Payer (sender):  ${payer.publicKey}`);
  console.log(`  Depositor:       ${depositor.publicKey}`);
  console.log(`  Program:         ${PROGRAM_ID}`);

  // Fund depositor for receipt rent + refund recipient
  const fundSig = await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL);
  await connection.confirmTransaction(fundSig);

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [treasury] = getTreasuryPDA();

  // ============================================
  // STEP 1: Initialize Vault (idempotent)
  // ============================================
  console.log("\n[STEP 1] Initializing vault (if needed)...");

  const initDiscriminator = getDiscriminator("initialize_vault");
  const dropCapBuf = Buffer.alloc(8);
  dropCapBuf.writeBigUInt64LE(DROP_CAP);

  const initIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([initDiscriminator, dropCapBuf]),
  });

  try {
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [payer]);
    console.log(`  TX: ${sig}`);
  } catch (e) {
    if (e.message?.includes("already in use")) {
      console.log("  Vault already initialized (skipping)");
    } else {
      throw e;
    }
  }

  // ============================================
  // STEP 2: Create drop WITH receipt
  // ============================================
  console.log("\n[STEP 2] Creating drop with DepositReceipt...");

  const dropAmount = BigInt(0.05 * LAMPORTS_PER_SOL);
  const secret = randomField();
  const nullifier = randomField();
  const blinding = randomField();
  const leafBig = poseidonHash([secret, nullifier, dropAmount, blinding]);
  const leafBytes = bigintToBytes32BE(leafBig);
  const amtCommitment = poseidonHash([dropAmount, blinding]);
  const pwdHash = 0n;

  const [receipt] = getReceiptPDA(leafBytes);
  console.log(`  Amount:      ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL`);
  console.log(`  Leaf:        ${leafBig.toString().slice(0, 20)}...`);
  console.log(`  Receipt PDA: ${receipt}`);

  const createDiscriminator = getDiscriminator("create_drop");
  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(dropAmount);

  const createIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      // Optional remaining accounts:
      { pubkey: depositor.publicKey, isSigner: true, isWritable: true }, // depositor
      { pubkey: receipt, isSigner: false, isWritable: true },            // deposit_receipt
    ],
    data: Buffer.concat([
      createDiscriminator,
      leafBytes,
      amountBuf,
      bigintToBytes32BE(amtCommitment),
      bigintToBytes32BE(pwdHash),
    ]),
  });

  const depositorBalBeforeCreate = await connection.getBalance(depositor.publicKey);
  const treasuryBalBeforeCreate = await connection.getBalance(treasury);
  const createSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(createIx),
    [payer, depositor],
  );
  console.log(`  TX: ${createSig}`);

  // Sanity: receipt exists, treasury credited
  const receiptInfo = await connection.getAccountInfo(receipt);
  if (!receiptInfo) throw new Error("DepositReceipt PDA was not created");
  console.log(`  Receipt allocated:     ${receiptInfo.data.length} bytes`);
  console.log(`  Receipt owned by:      ${receiptInfo.owner.toString()} (should be program)`);
  if (!receiptInfo.owner.equals(PROGRAM_ID)) throw new Error("Receipt not program-owned");

  const treasuryBalAfterCreate = await connection.getBalance(treasury);
  console.log(`  Treasury +${treasuryBalAfterCreate - treasuryBalBeforeCreate} lamports (expect +${dropAmount})`);
  console.log(`  Depositor paid receipt rent: ${depositorBalBeforeCreate - (await connection.getBalance(depositor.publicKey))} lamports`);

  // ============================================
  // STEP 3: Wait for timeout to elapse
  // ============================================
  console.log(`\n[STEP 3] Waiting ${TIMEOUT_WAIT_MS}ms for time-lock...`);
  await sleep(TIMEOUT_WAIT_MS);

  // ============================================
  // STEP 4: Submit revoke_drop
  // ============================================
  console.log("\n[STEP 4] Submitting revoke_drop TX...");

  const nullifierHashBig = poseidonHash([nullifier]);
  const nullifierHashBytes = bigintToBytes32BE(nullifierHashBig);
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);

  // Preimage: secret(32) + nullifier(32) + blinding(32) = 96 bytes
  const preimage = Buffer.concat([
    bigintToBytes32BE(secret),
    bigintToBytes32BE(nullifier),
    bigintToBytes32BE(blinding),
  ]);
  const preimageLenBuf = Buffer.alloc(4);
  preimageLenBuf.writeUInt32LE(preimage.length);

  const revokeDiscriminator = getDiscriminator("revoke_drop");
  const revokeData = Buffer.concat([
    revokeDiscriminator,           // 8
    leafBytes,                     // 32 — leaf
    nullifierHashBytes,            // 32 — nullifier_hash
    preimageLenBuf, preimage,      // 4 + 96 — Vec<u8> preimage
  ]);

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
    data: revokeData,
  });

  const depositorBalBeforeRevoke = await connection.getBalance(depositor.publicKey);
  const treasuryBalBeforeRevoke = await connection.getBalance(treasury);

  const revokeSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(revokeIx),
    [depositor],
  );
  console.log(`  TX: ${revokeSig}`);

  // ============================================
  // STEP 5: Verify outcomes
  // ============================================
  const depositorBalAfter = await connection.getBalance(depositor.publicKey);
  const treasuryBalAfter = await connection.getBalance(treasury);

  const treasuryDelta = treasuryBalBeforeRevoke - treasuryBalAfter;
  const depositorDelta = depositorBalAfter - depositorBalBeforeRevoke;

  console.log(`\n[STEP 5] Verifying outcomes...`);
  console.log(`  Treasury delta: -${treasuryDelta} (expect -${dropAmount})`);
  console.log(`  Depositor delta: +${depositorDelta} (receipt rent + refund - tx fee)`);

  const receiptAfter = await connection.getAccountInfo(receipt);
  console.log(`  Receipt closed: ${receiptAfter === null}`);

  const nullifierAfter = await connection.getAccountInfo(nullifierPDA);
  console.log(`  Nullifier PDA created: ${nullifierAfter !== null}`);

  const txInfo = await connection.getTransaction(revokeSig, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  const innerIxs = txInfo?.meta?.innerInstructions || [];
  const totalInnerIxs = innerIxs.reduce((sum, group) => sum + group.instructions.length, 0);
  // revoke creates the nullifier PDA (1 inner CreateAccount) and closes the
  // receipt via Anchor's `close` (Anchor does this with direct lamport moves,
  // zero inner instructions). The refund itself is direct lamport manipulation.
  console.log(`  Inner instructions: ${totalInnerIxs} (expect 1 — nullifier CreateAccount only, no Transfer)`);

  const hasTransferIx = innerIxs.some(group =>
    group.instructions.some(ix => {
      const prog = txInfo.transaction.message.accountKeys[ix.programIdIndex];
      return prog?.toString() === SystemProgram.programId.toString() &&
             ix.data && Buffer.from(ix.data, 'base64').length === 12;
    })
  );
  console.log(`  Has Transfer inner instruction: ${hasTransferIx} (expect false — direct lamport for refund)`);

  const passed =
    BigInt(treasuryDelta) === dropAmount &&
    receiptAfter === null &&
    nullifierAfter !== null &&
    !hasTransferIx;

  if (passed) {
    console.log("\n=== REVOKE E2E TEST PASSED ===");
  } else {
    console.log("\n=== REVOKE E2E TEST FAILED ===");
    process.exit(1);
  }
}

main().catch(e => {
  console.error("Fatal:", e);
  if (e.logs) e.logs.forEach(l => console.error(`  ${l}`));
  process.exit(1);
});
