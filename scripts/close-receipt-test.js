#!/usr/bin/env node
/**
 * DarkDrop V4 — close_receipt E2E Test
 *
 * Tests the M-01 fix: after a drop with a receipt is claimed normally
 * (not revoked), the depositor can close the orphaned receipt PDA and
 * recover the rent.
 *
 * Flow:
 *   1. Initialize vault if needed
 *   2. Create a drop with a DepositReceipt (7-account path)
 *   3. Claim the drop normally (claim_credit with V2 proof)
 *      - The nullifier PDA is now created
 *      - revoke_drop is blocked from this point forward
 *   4. Call close_receipt as the depositor
 *   5. Verify:
 *      - DepositReceipt PDA is closed
 *      - Depositor balance increased by receipt rent
 *      - Nullifier PDA still exists (untouched)
 *      - CreditNote PDA untouched
 *
 * Run against localnet:
 *   solana-test-validator --reset
 *   cd program && cargo build-sbf
 *   cp target/sbpf-solana-solana/release/darkdrop.so target/deploy/darkdrop.so
 *   solana program deploy program/target/deploy/darkdrop.so
 *   PROGRAM_ID=<id> node scripts/close-receipt-test.js
 *
 * Or against devnet after deploy:
 *   RPC_URL=https://api.devnet.solana.com node scripts/close-receipt-test.js
 */

const {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  ComputeBudgetProgram,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL);
const MERKLE_DEPTH = 20;
const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

let poseidon, F;
function poseidonHash(inputs) { return F.toObject(poseidon(inputs)); }
function randomField() { return BigInt("0x" + crypto.randomBytes(31).toString("hex")); }

function bytesToBigIntBE(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return BigInt("0x" + (hex || "0"));
}
function bigintToBytes32BE(val) {
  const hex = val.toString(16).padStart(64, "0");
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bigintToBE32(val) {
  const hex = BigInt(val).toString(16).padStart(64, "0");
  const buf = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) buf[i] = parseInt(hex.substr(i * 2, 2), 16);
  return buf;
}
function pubkeyToField(pubkeyBytes) {
  const hi = bytesToBigIntBE(pubkeyBytes.slice(0, 16));
  const lo = bytesToBigIntBE(pubkeyBytes.slice(16, 32));
  return poseidonHash([hi, lo]);
}
function getDiscriminator(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function getVaultPDA() { return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID); }
function getMerkleTreePDA(v) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), v.toBytes()], PROGRAM_ID); }
function getTreasuryPDA() { return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID); }
function getNullifierPDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), h], PROGRAM_ID); }
function getCreditNotePDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("credit"), h], PROGRAM_ID); }
function getReceiptPDA(leafBytes) { return PublicKey.findProgramAddressSync([Buffer.from("receipt"), leafBytes], PROGRAM_ID); }
function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

async function main() {
  console.log("=== DarkDrop V4 — close_receipt E2E Test ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 120000,
  });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const depositor = Keypair.generate();
  const recipient = Keypair.generate();

  console.log(`  Payer:     ${payer.publicKey}`);
  console.log(`  Depositor: ${depositor.publicKey}`);
  console.log(`  Recipient: ${recipient.publicKey}`);
  console.log(`  Program:   ${PROGRAM_ID}`);

  // Fund depositor. Airdrop on localnet; transfer from payer on devnet (airdrop rate-limited).
  try {
    const fundSig = await connection.requestAirdrop(depositor.publicKey, 0.1 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(fundSig);
  } catch (e) {
    const fundTx = new Transaction().add(SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: depositor.publicKey,
      lamports: 0.01 * LAMPORTS_PER_SOL,
    }));
    await sendAndConfirmTransaction(connection, fundTx, [payer]);
  }

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [treasury] = getTreasuryPDA();

  // ============================================
  // STEP 1: Initialize Vault (idempotent)
  // ============================================
  console.log("\n[STEP 1] Initializing vault (if needed)...");
  {
    const dropCapBuf = Buffer.alloc(8); dropCapBuf.writeBigUInt64LE(DROP_CAP);
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([getDiscriminator("initialize_vault"), dropCapBuf]),
    });
    try {
      const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [payer]);
      console.log(`  TX: ${sig}`);
    } catch (e) {
      if (e.message?.includes("already in use")) console.log("  (already initialized)");
      else throw e;
    }
  }

  // ============================================
  // STEP 2: Create drop WITH receipt (7-account path)
  // ============================================
  console.log("\n[STEP 2] Creating drop with DepositReceipt...");

  const dropAmount = BigInt(0.04 * LAMPORTS_PER_SOL);
  const secret = randomField();
  const nullifier = randomField();
  const blinding = randomField();
  const leafBig = poseidonHash([secret, nullifier, dropAmount, blinding]);
  const leafBytes = bigintToBytes32BE(leafBig);
  const amtCommitment = poseidonHash([dropAmount, blinding]);
  const [receipt] = getReceiptPDA(leafBytes);

  console.log(`  Amount:      ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL`);
  console.log(`  Leaf:        ${leafBig.toString().slice(0, 20)}...`);
  console.log(`  Receipt PDA: ${receipt}`);

  {
    const amountBuf = Buffer.alloc(8); amountBuf.writeBigUInt64LE(dropAmount);
    const ix = new TransactionInstruction({
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
        leafBytes,
        amountBuf,
        bigintToBytes32BE(amtCommitment),
        bigintToBytes32BE(0n),
      ]),
    });
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [payer, depositor]);
    console.log(`  TX: ${sig}`);
  }

  const receiptInfoAfterCreate = await connection.getAccountInfo(receipt);
  if (!receiptInfoAfterCreate) throw new Error("Receipt PDA missing after create_drop");
  const receiptRent = receiptInfoAfterCreate.lamports;
  console.log(`  Receipt rent: ${receiptRent} lamports`);

  // ============================================
  // STEP 3: Claim the drop normally via claim_credit (V2 proof)
  // ============================================
  console.log("\n[STEP 3] Claiming drop normally (claim_credit)...");

  const treeInfo = await connection.getAccountInfo(merkleTree);
  const treeData = treeInfo.data;
  const nextIndex = treeData.readUInt32LE(8 + 32);
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;
  const filledSubtrees = [];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    filledSubtrees.push(treeData.slice(filledSubtreesOffset + i * 32, filledSubtreesOffset + (i + 1) * 32));
  }
  const leafIndex = nextIndex - 1;
  const onChainRootBigInt = bytesToBigIntBE(onChainRoot);

  const zeroHashes = getZeroHashes();
  const pathElements = [], pathIndices = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit.toString());
    pathElements.push(bit === 0 ? zeroHashes[i].toString() : bytesToBigIntBE(filledSubtrees[i]).toString());
    idx = idx >> 1;
  }

  const recipientField = pubkeyToField(recipient.publicKey.toBytes());
  const nullHashBig = poseidonHash([nullifier]);
  const nullHashBytes = bigintToBytes32BE(nullHashBig);

  const circuitInput = {
    secret: secret.toString(),
    amount: dropAmount.toString(),
    blinding_factor: blinding.toString(),
    nullifier: nullifier.toString(),
    merkle_path: pathElements,
    merkle_indices: pathIndices,
    password: "0",
    merkle_root: onChainRootBigInt.toString(),
    nullifier_hash: nullHashBig.toString(),
    recipient: recipientField.toString(),
    amount_commitment: amtCommitment.toString(),
    password_hash: "0",
  };

  const { proof } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);

  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  const proofB = Buffer.concat([
    bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]),
    bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0]),
  ]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);

  const opaqueInputs = Buffer.concat([onChainRoot, bigintToBytes32BE(amtCommitment), bigintToBytes32BE(0n)]);
  const inputsLen = Buffer.alloc(4); inputsLen.writeUInt32LE(opaqueInputs.length);
  const salt = randomField();

  const [nullifierPDA] = getNullifierPDA(nullHashBytes);
  const [creditNotePDA] = getCreditNotePDA(nullHashBytes);

  {
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: false },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: nullifierPDA, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        getDiscriminator("claim_credit"),
        nullHashBytes,
        proofA, proofB, proofC,
        inputsLen, opaqueInputs,
        bigintToBytes32BE(salt),
      ]),
    });
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), ix);
    const sig = await sendAndConfirmTransaction(connection, tx, [payer]);
    console.log(`  TX: ${sig}`);
  }

  // Sanity: nullifier and credit note exist; receipt still exists (orphan)
  const nullBefore = await connection.getAccountInfo(nullifierPDA);
  const creditBefore = await connection.getAccountInfo(creditNotePDA);
  const receiptBefore = await connection.getAccountInfo(receipt);
  console.log(`  Nullifier PDA exists: ${nullBefore !== null}`);
  console.log(`  CreditNote PDA exists: ${creditBefore !== null}`);
  console.log(`  DepositReceipt still exists (orphaned): ${receiptBefore !== null}`);

  // ============================================
  // STEP 4: Call close_receipt as depositor
  // ============================================
  console.log("\n[STEP 4] Calling close_receipt...");

  const depositorBalBeforeClose = await connection.getBalance(depositor.publicKey);

  {
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: receipt, isSigner: false, isWritable: true },
        { pubkey: depositor.publicKey, isSigner: true, isWritable: true },
      ],
      data: Buffer.concat([getDiscriminator("close_receipt"), leafBytes]),
    });
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [depositor]);
    console.log(`  TX: ${sig}`);
  }

  const depositorBalAfterClose = await connection.getBalance(depositor.publicKey);
  const delta = depositorBalAfterClose - depositorBalBeforeClose;

  // ============================================
  // STEP 5: Verify outcomes
  // ============================================
  console.log("\n[STEP 5] Verifying outcomes...");

  const receiptAfter = await connection.getAccountInfo(receipt);
  const nullAfter = await connection.getAccountInfo(nullifierPDA);
  const creditAfter = await connection.getAccountInfo(creditNotePDA);

  console.log(`  Receipt closed: ${receiptAfter === null}`);
  console.log(`  Depositor delta: +${delta} (expect ~${receiptRent} − tx fee)`);
  console.log(`  Nullifier PDA still exists: ${nullAfter !== null}`);
  console.log(`  CreditNote PDA still exists: ${creditAfter !== null}`);

  // Delta should be positive and close to receiptRent (minus tx fee)
  // Tx fee is ~5000 lamports; receipt rent is ~1.5M lamports. Net should be strongly positive.
  const passed =
    receiptAfter === null &&
    delta > 0 &&
    delta > receiptRent - 100_000 &&  // allow for TX fees
    nullAfter !== null &&
    creditAfter !== null;

  if (passed) {
    console.log("\n=== CLOSE RECEIPT TEST PASSED ===");
    console.log(`  Receipt PDA closed cleanly`);
    console.log(`  Depositor recovered ${delta} lamports (receipt rent minus TX fee)`);
    console.log(`  Nullifier PDA untouched (still blocks future revoke)`);
    console.log(`  CreditNote PDA untouched`);
  } else {
    console.log("\n=== CLOSE RECEIPT TEST FAILED ===");
    if (receiptAfter !== null) console.log("  Receipt not closed");
    if (delta <= 0) console.log(`  Depositor balance did not increase (delta=${delta})`);
    if (delta <= receiptRent - 100_000) console.log(`  Refund too small (delta=${delta}, expected ~${receiptRent})`);
    if (nullAfter === null) console.log("  Nullifier PDA disappeared");
    if (creditAfter === null) console.log("  CreditNote PDA disappeared");
    process.exit(1);
  }
}

main().then(() => process.exit(0)).catch(e => {
  console.error("Fatal:", e);
  if (e.logs) e.logs.forEach(l => console.error(`  ${l}`));
  process.exit(1);
});
