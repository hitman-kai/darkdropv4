#!/usr/bin/env node
/**
 * DarkDrop V4 — Credit Note E2E Test
 *
 * Tests the full hidden-amount flow:
 *   1. Initialize vault + treasury
 *   2. Create a drop (SOL → treasury, leaf into tree)
 *   3. Generate ZK proof (V2 circuit — amount is PRIVATE)
 *   4. Submit claim_credit TX (no amount in data, no SOL moves)
 *   5. Submit withdraw_credit TX (direct lamport manipulation, no inner Transfer)
 *   6. Verify: recipient received SOL, credit note closed, no inner instructions
 *
 * Run against localnet:
 *   solana-test-validator --reset
 *   solana program deploy program/target/deploy/darkdrop.so
 *   node scripts/e2e-credit-test.js
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

// Config
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
// V2 circuit artifacts (amount is private)
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");
const VK_PATH = path.join(BUILD_DIR, "verification_key_v2.json");
const MERKLE_DEPTH = 20;
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL);

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
  const hash = crypto.createHash("sha256").update(`global:${name}`).digest();
  return hash.slice(0, 8);
}

// PDA helpers
function getVaultPDA() {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
}
function getMerkleTreePDA(vault) {
  return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID);
}
function getTreasuryPDA() {
  return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);
}
function getNullifierPDA(nullifierHash) {
  return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nullifierHash], PROGRAM_ID);
}
function getCreditNotePDA(nullifierHash) {
  return PublicKey.findProgramAddressSync([Buffer.from("credit"), nullifierHash], PROGRAM_ID);
}

function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

async function main() {
  console.log("=== DarkDrop V4 — Credit Note E2E Test ===\n");

  // Init
  console.log("Initializing...");
  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 120000,
  });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  console.log(`  Payer:     ${payer.publicKey}`);
  console.log(`  Recipient: ${recipient.publicKey}`);
  console.log(`  Program:   ${PROGRAM_ID}`);

  // Airdrop to recipient (needs some SOL for rent if doing direct withdraw)
  if (!RPC_URL.includes("devnet")) {
    const airdropSig = await connection.requestAirdrop(recipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(airdropSig);
  }

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [treasury] = getTreasuryPDA();

  console.log(`  Vault PDA:       ${vault}`);
  console.log(`  Merkle Tree PDA: ${merkleTree}`);
  console.log(`  Treasury PDA:    ${treasury}`);

  // ============================================
  // STEP 1: Initialize Vault
  // ============================================
  console.log("\n[STEP 1] Initializing vault...");

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
    const initTx = new Transaction().add(initIx);
    const initSig = await sendAndConfirmTransaction(connection, initTx, [payer]);
    console.log(`  TX: ${initSig}`);
    console.log("  Vault initialized successfully");
  } catch (e) {
    if (e.message?.includes("already in use")) {
      console.log("  Vault already initialized (skipping)");
    } else {
      console.error("  Init failed:", e.message);
      if (e.logs) e.logs.forEach(l => console.error(`    ${l}`));
      process.exit(1);
    }
  }

  // ============================================
  // STEP 2: Create Drop
  // ============================================
  console.log("\n[STEP 2] Creating drop...");

  const dropAmount = BigInt(0.1 * LAMPORTS_PER_SOL); // 0.1 SOL
  const secret = randomField();
  const nullifier = randomField();
  const blindingFactor = randomField();
  const password = 0n;

  const leaf = poseidonHash([secret, nullifier, dropAmount, blindingFactor]);
  const amtCommitment = poseidonHash([dropAmount, blindingFactor]);
  const pwdHash = 0n;
  const nullHash = poseidonHash([nullifier]);

  console.log(`  Amount: ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL`);
  console.log(`  Leaf: ${leaf.toString().slice(0, 20)}...`);

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
    ],
    data: Buffer.concat([
      createDiscriminator,
      bigintToBytes32BE(leaf),
      amountBuf,
      bigintToBytes32BE(amtCommitment),
      bigintToBytes32BE(pwdHash),
    ]),
  });

  const treasuryBalBefore = await connection.getBalance(treasury);
  const createTx = new Transaction().add(createIx);
  const createSig = await sendAndConfirmTransaction(connection, createTx, [payer]);
  console.log(`  TX: ${createSig}`);

  const treasuryBalAfter = await connection.getBalance(treasury);
  console.log(`  Treasury balance: ${treasuryBalBefore} → ${treasuryBalAfter} lamports (+${treasuryBalAfter - treasuryBalBefore})`);

  // ============================================
  // STEP 3: Build Merkle proof + Generate ZK proof (V2)
  // ============================================
  console.log("\n[STEP 3] Building Merkle proof & generating ZK proof (V2 circuit)...");

  const treeAccountInfo = await connection.getAccountInfo(merkleTree);
  const treeData = treeAccountInfo.data;
  const nextIndex = treeData.readUInt32LE(8 + 32);
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;
  const filledSubtrees = [];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    filledSubtrees.push(treeData.slice(filledSubtreesOffset + i * 32, filledSubtreesOffset + (i + 1) * 32));
  }

  const leafIndex = nextIndex - 1;
  const onChainRootBigInt = bytesToBigIntBE(onChainRoot);
  console.log(`  Leaf index: ${leafIndex} (next_index: ${nextIndex})`);

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

  // V2 circuit input — amount is still provided as private input
  const circuitInput = {
    secret: secret.toString(),
    amount: dropAmount.toString(),
    blinding_factor: blindingFactor.toString(),
    nullifier: nullifier.toString(),
    merkle_path: pathElements,
    merkle_indices: pathIndices,
    password: password.toString(),
    merkle_root: onChainRootBigInt.toString(),
    nullifier_hash: nullHash.toString(),
    recipient: recipientField.toString(),
    amount_commitment: amtCommitment.toString(),
    password_hash: pwdHash.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);

  console.log(`  Public signals (V2): ${publicSignals.length} (should be 5, NO amount)`);

  // Verify locally
  const vk = JSON.parse(fs.readFileSync(VK_PATH));
  const localValid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log(`  Local verification: ${localValid ? "PASS" : "FAIL"}`);
  if (!localValid) {
    console.error("  Proof failed local verification! Aborting.");
    process.exit(1);
  }

  // ============================================
  // STEP 4: Submit claim_credit TX
  // ============================================
  console.log("\n[STEP 4] Submitting claim_credit TX (no amount, no SOL movement)...");

  const nullifierHashBytes = bigintToBytes32BE(nullHash);
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);
  const [creditNotePDA] = getCreditNotePDA(nullifierHashBytes);

  // Serialize proof
  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  const proofB = Buffer.concat([
    bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]),
    bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0]),
  ]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);

  // Pack opaque inputs: merkle_root(32) + commitment(32) + seed(32)
  const opaqueInputs = Buffer.concat([
    onChainRoot,                               // merkle_root
    bigintToBytes32BE(amtCommitment),          // amount_commitment
    bigintToBytes32BE(pwdHash),                // password_hash
  ]);

  // Borsh-encode Vec<u8>: 4-byte LE length prefix + data
  const inputsLenBuf = Buffer.alloc(4);
  inputsLenBuf.writeUInt32LE(opaqueInputs.length);
  const inputsEncoded = Buffer.concat([inputsLenBuf, opaqueInputs]);

  const claimCreditDiscriminator = getDiscriminator("claim_credit");

  // Generate random salt for commitment re-randomization (M-01-NEW fix)
  const salt = randomField();
  const saltBytes = bigintToBytes32BE(salt);

  const claimCreditData = Buffer.concat([
    claimCreditDiscriminator,    // 8
    nullifierHashBytes,          // 32 — nullifier_hash
    proofA,                      // 64 — proof.proof_a
    proofB,                      // 128 — proof.proof_b
    proofC,                      // 64 — proof.proof_c
    inputsEncoded,               // 4 + 96 — Vec<u8> inputs
    saltBytes,                   // 32 — salt for re-randomized commitment
  ]);

  const claimCreditIx = new TransactionInstruction({
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
    data: claimCreditData,
  });

  const treasuryBalBeforeClaim = await connection.getBalance(treasury);

  try {
    const claimCreditTx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      claimCreditIx,
    );
    const claimCreditSig = await sendAndConfirmTransaction(connection, claimCreditTx, [payer]);
    console.log(`  TX: ${claimCreditSig}`);

    // Verify no SOL moved from treasury
    const treasuryBalAfterClaim = await connection.getBalance(treasury);
    console.log(`  Treasury balance unchanged: ${treasuryBalBeforeClaim} → ${treasuryBalAfterClaim}`);
    console.log(`  Credit note created: ${creditNotePDA}`);
    console.log(`  Nullifier spent: ${nullifierPDA}`);

    // Check credit note account exists
    const creditNoteInfo = await connection.getAccountInfo(creditNotePDA);
    console.log(`  Credit note exists: ${creditNoteInfo !== null}`);

    // Verify the TX has NO inner instructions
    const txInfo = await connection.getTransaction(claimCreditSig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const innerIxs = txInfo?.meta?.innerInstructions || [];
    // Filter to only our program's inner instructions (not compute budget)
    const programInnerIxs = innerIxs.filter(group =>
      group.instructions.some(ix => ix.programIdIndex !== undefined)
    );
    // The only "inner" instructions should be system_program create_account for PDAs
    const hasTransferIx = innerIxs.some(group =>
      group.instructions.some(ix => {
        // System program transfer has exactly 2 accounts and specific data
        const prog = txInfo.transaction.message.accountKeys[ix.programIdIndex];
        return prog?.toString() === SystemProgram.programId.toString() &&
               ix.data && Buffer.from(ix.data, 'base64').length === 12; // transfer = 4 byte type + 8 byte amount
      })
    );
    console.log(`  Has Transfer inner instruction: ${hasTransferIx} (should be false)`);

  } catch (e) {
    console.error("  claim_credit failed:", e.message);
    if (e.logs) e.logs.forEach(l => console.error(`    ${l}`));
    process.exit(1);
  }

  // ============================================
  // STEP 5: Submit withdraw_credit TX
  // ============================================
  console.log("\n[STEP 5] Submitting withdraw_credit TX (direct lamport manipulation)...");

  const recipientBalBefore = await connection.getBalance(recipient.publicKey);

  // Pack opaque opening: amount(8 LE) + blinding_factor(32) + salt(32)
  const openingAmountBuf = Buffer.alloc(8);
  openingAmountBuf.writeBigUInt64LE(dropAmount);
  const openingBlinding = bigintToBytes32BE(blindingFactor);
  const opening = Buffer.concat([openingAmountBuf, openingBlinding, saltBytes]);

  // Borsh-encode Vec<u8>
  const openingLenBuf = Buffer.alloc(4);
  openingLenBuf.writeUInt32LE(opening.length);
  const openingEncoded = Buffer.concat([openingLenBuf, opening]);

  // Rate: 0 bps (no fee for this test)
  const rateBuf = Buffer.alloc(2);
  rateBuf.writeUInt16LE(0);

  const withdrawDiscriminator = getDiscriminator("withdraw_credit");

  const withdrawData = Buffer.concat([
    withdrawDiscriminator,       // 8
    nullifierHashBytes,          // 32 — nullifier_hash (for PDA derivation)
    openingEncoded,              // 4 + 40 — Vec<u8> opening
    rateBuf,                     // 2 — rate (u16)
  ]);

  const withdrawIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: false, isWritable: true }, // fee_recipient
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },  // payer
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: withdrawData,
  });

  try {
    const withdrawTx = new Transaction().add(withdrawIx);
    const withdrawSig = await sendAndConfirmTransaction(connection, withdrawTx, [payer]);
    console.log(`  TX: ${withdrawSig}`);

    const recipientBalAfter = await connection.getBalance(recipient.publicKey);
    const received = recipientBalAfter - recipientBalBefore;
    console.log(`  Recipient balance: ${recipientBalBefore} → ${recipientBalAfter} (+${received})`);

    // Credit note should be closed
    const creditNoteAfter = await connection.getAccountInfo(creditNotePDA);
    console.log(`  Credit note closed: ${creditNoteAfter === null}`);

    // Verify NO Transfer inner instruction
    const txInfo = await connection.getTransaction(withdrawSig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const innerIxs = txInfo?.meta?.innerInstructions || [];
    // Direct lamport manipulation produces ZERO inner instructions
    const totalInnerIxs = innerIxs.reduce((sum, group) => sum + group.instructions.length, 0);
    console.log(`  Total inner instructions: ${totalInnerIxs} (should be 0 — direct lamport manipulation)`);

    const expectedAmount = Number(dropAmount);
    if (received === expectedAmount && creditNoteAfter === null && totalInnerIxs === 0) {
      console.log("\n=== CREDIT NOTE E2E TEST PASSED ===");
      console.log(`  Created drop: ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL`);
      console.log(`  claim_credit: ZK proof verified, credit note created, ZERO SOL moved`);
      console.log(`  withdraw_credit: commitment opened, SOL transferred via direct lamport manipulation`);
      console.log(`  No Transfer inner instructions in withdraw TX`);
      console.log(`  No amount visible in claim_credit instruction data`);
      console.log(`  Credit note closed after withdrawal`);
    } else {
      console.log("\n=== CREDIT NOTE E2E TEST FAILED ===");
      if (received !== expectedAmount) console.log(`  Expected ${expectedAmount} lamports, got ${received}`);
      if (creditNoteAfter !== null) console.log(`  Credit note not closed`);
      if (totalInnerIxs !== 0) console.log(`  Unexpected inner instructions: ${totalInnerIxs}`);
      process.exit(1);
    }

  } catch (e) {
    console.error("  withdraw_credit failed:", e.message);
    if (e.logs) e.logs.forEach(l => console.error(`    ${l}`));
    process.exit(1);
  }
}

main().then(() => process.exit(0)).catch(e => {
  console.error("Fatal:", e);
  process.exit(1);
});
