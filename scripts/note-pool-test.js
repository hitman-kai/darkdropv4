#!/usr/bin/env node
/**
 * DarkDrop V4 — Note Pool E2E Test
 *
 * Tests the full recursive privacy flow:
 *   1. Create a deposit (create_drop)
 *   2. Claim credit (claim_credit) — get a credit note
 *   3. Initialize note pool (if needed)
 *   4. Deposit credit note into note pool (deposit_to_note_pool)
 *   5. Claim from note pool (claim_from_note_pool) — get a FRESH credit note
 *   6. Withdraw from the fresh credit note (withdraw_credit)
 *   7. Verify: recipient got SOL, old credit note closed, pool nullifier exists,
 *      fresh credit note commitment is different from original
 *
 * Usage:
 *   RPC_URL=https://api.devnet.solana.com node scripts/note-pool-test.js
 */

const {
  Connection, Keypair, PublicKey, Transaction, TransactionInstruction,
  SystemProgram, ComputeBudgetProgram, sendAndConfirmTransaction, LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");

// V2 circuit (claim_credit)
const V2_WASM = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const V2_ZKEY = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");

// V3 circuit (note pool)
const V3_WASM = path.join(BUILD_DIR, "note_pool/note_pool_js/note_pool.wasm");
const V3_ZKEY = path.join(BUILD_DIR, "note_pool/note_pool_final.zkey");

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
  const buf = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) buf[i] = parseInt(hex.substr(i * 2, 2), 16);
  return buf;
}

function bigintToBE32(val) { return bigintToBytes32BE(BigInt(val)); }

function pubkeyToField(pubkeyBytes) {
  const hi = bytesToBigIntBE(pubkeyBytes.slice(0, 16));
  const lo = bytesToBigIntBE(pubkeyBytes.slice(16, 32));
  return poseidonHash([hi, lo]);
}

function getDiscriminator(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

// PDA helpers
function getVaultPDA() { return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID); }
function getMerkleTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID); }
function getTreasuryPDA() { return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID); }
function getNullifierPDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), h], PROGRAM_ID); }
function getCreditNotePDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("credit"), h], PROGRAM_ID); }
function getNotePoolPDA() { return PublicKey.findProgramAddressSync([Buffer.from("note_pool")], PROGRAM_ID); }
function getNotePoolTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("note_pool_tree"), vault.toBytes()], PROGRAM_ID); }
function getPoolNullifierPDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("pool_nullifier"), h], PROGRAM_ID); }

// ─────────────── Proof helpers ───────────────

function serializeProof(proof) {
  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  const proofB = Buffer.concat([
    bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]),
    bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0]),
  ]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);
  return { proofA, proofB, proofC };
}

// Read Merkle tree state from account data (works for both MerkleTreeAccount and NotePoolTree)
function readTreeState(treeData) {
  const nextIndex = treeData.readUInt32LE(8 + 32);
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;
  return { nextIndex, onChainRoot, filledSubtreesOffset, treeData };
}

function buildMerkleProof(treeState, leafIndex) {
  const zeroHashes = getZeroHashes();
  const pathElements = [], pathIndices = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit.toString());
    if (bit === 0) {
      pathElements.push(zeroHashes[i].toString());
    } else {
      const start = treeState.filledSubtreesOffset + i * 32;
      pathElements.push(bytesToBigIntBE(treeState.treeData.slice(start, start + 32)).toString());
    }
    idx = idx >> 1;
  }
  return { pathElements, pathIndices };
}

// ─────────────── Main ───────────────

async function main() {
  console.log("=== DarkDrop V4 — Note Pool E2E Test ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, { commitment: "confirmed", confirmTransactionInitialTimeout: 120000 });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [treasury] = getTreasuryPDA();
  const [notePool] = getNotePoolPDA();
  const [notePoolTree] = getNotePoolTreePDA(vault);

  console.log(`  Payer:          ${payer.publicKey}`);
  console.log(`  Recipient:      ${recipient.publicKey}`);
  console.log(`  Note Pool:      ${notePool}`);
  console.log(`  Note Pool Tree: ${notePoolTree}`);

  // ─────────────── STEP 1: Initialize Note Pool ───────────────
  console.log("\n[STEP 1] Initializing note pool...");
  try {
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: false },
        { pubkey: notePool, isSigner: false, isWritable: true },
        { pubkey: notePoolTree, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: getDiscriminator("initialize_note_pool"),
    });
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [payer]);
    console.log(`  TX: ${sig}`);
    console.log("  Note pool initialized");
  } catch (e) {
    if (e.message?.includes("already in use")) {
      console.log("  Note pool already initialized (skipping)");
    } else {
      console.error("  Init failed:", e.message);
      if (e.logs) e.logs.forEach(l => console.error(`    ${l}`));
      process.exit(1);
    }
  }

  // ─────────────── STEP 2: Create Drop ───────────────
  console.log("\n[STEP 2] Creating deposit...");
  const dropAmount = BigInt(0.05 * LAMPORTS_PER_SOL);
  const secret = randomField();
  const nullifier = randomField();
  const blindingFactor = randomField();
  const leaf = poseidonHash([secret, nullifier, dropAmount, blindingFactor]);
  const amtCommitment = poseidonHash([dropAmount, blindingFactor]);

  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(dropAmount);
  const createDropIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("create_drop"),
      bigintToBytes32BE(leaf), amountBuf,
      bigintToBytes32BE(amtCommitment), bigintToBytes32BE(0n),
    ]),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(createDropIx), [payer]);
  console.log(`  Deposited ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL`);

  // ─────────────── STEP 3: Claim Credit (V2 proof) ───────────────
  console.log("\n[STEP 3] Claiming credit (V2 proof, amount hidden)...");

  const nullHash = poseidonHash([nullifier]);
  const pwdHash = 0n;
  const recipientField = pubkeyToField(recipient.publicKey.toBytes());

  const mainTreeInfo = await connection.getAccountInfo(merkleTree);
  const mainTreeState = readTreeState(mainTreeInfo.data);
  const mainLeafIndex = mainTreeState.nextIndex - 1;
  const mainProof = buildMerkleProof(mainTreeState, mainLeafIndex);
  const onChainRootBigInt = bytesToBigIntBE(mainTreeState.onChainRoot);

  const v2Input = {
    secret: secret.toString(), amount: dropAmount.toString(),
    blinding_factor: blindingFactor.toString(), nullifier: nullifier.toString(),
    merkle_path: mainProof.pathElements, merkle_indices: mainProof.pathIndices,
    password: "0",
    merkle_root: onChainRootBigInt.toString(), nullifier_hash: nullHash.toString(),
    recipient: recipientField.toString(), amount_commitment: amtCommitment.toString(),
    password_hash: pwdHash.toString(),
  };

  const { proof: v2Proof } = await snarkjs.groth16.fullProve(v2Input, V2_WASM, V2_ZKEY);
  const v2Serialized = serializeProof(v2Proof);

  const nullifierHashBytes = bigintToBytes32BE(nullHash);
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);
  const [creditNotePDA] = getCreditNotePDA(nullifierHashBytes);

  const opaqueInputs = Buffer.concat([
    mainTreeState.onChainRoot, bigintToBytes32BE(amtCommitment), bigintToBytes32BE(pwdHash),
  ]);
  const inputsLenBuf = Buffer.alloc(4);
  inputsLenBuf.writeUInt32LE(96);

  const claimSalt = randomField();
  const claimSaltBytes = bigintToBytes32BE(claimSalt);

  const claimCreditData = Buffer.concat([
    getDiscriminator("claim_credit"),
    nullifierHashBytes,
    v2Serialized.proofA, v2Serialized.proofB, v2Serialized.proofC,
    inputsLenBuf, opaqueInputs,
    claimSaltBytes,
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

  await sendAndConfirmTransaction(connection, new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), claimCreditIx
  ), [payer]);
  console.log("  Credit note claimed");

  // Record the original stored commitment for later comparison
  const creditNoteInfo = await connection.getAccountInfo(creditNotePDA);
  const originalStoredCommitment = creditNoteInfo.data.slice(8 + 1 + 32, 8 + 1 + 32 + 32);
  console.log(`  Original stored commitment: ${bytesToBigIntBE(originalStoredCommitment).toString(16).slice(0, 16)}...`);

  // ─────────────── STEP 4: Deposit to Note Pool ───────────────
  console.log("\n[STEP 4] Depositing credit note into note pool...");

  const poolSecret = randomField();
  const poolNullifier = randomField();
  const poolBlinding = randomField();

  // Opening: amount(8 LE) + blinding(32) + salt(32) = 72 bytes
  const openingAmountBuf = Buffer.alloc(8);
  openingAmountBuf.writeBigUInt64LE(dropAmount);
  const openingData = Buffer.concat([openingAmountBuf, bigintToBytes32BE(blindingFactor), claimSaltBytes]);
  const openingLenBuf = Buffer.alloc(4);
  openingLenBuf.writeUInt32LE(72);

  // Pool params: pool_secret(32) + pool_nullifier(32) + pool_blinding(32) = 96 bytes
  const poolParamsData = Buffer.concat([
    bigintToBytes32BE(poolSecret), bigintToBytes32BE(poolNullifier), bigintToBytes32BE(poolBlinding),
  ]);
  const poolParamsLenBuf = Buffer.alloc(4);
  poolParamsLenBuf.writeUInt32LE(96);

  const depositToPoolIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: notePool, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: true },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("deposit_to_note_pool"),
      nullifierHashBytes,
      openingLenBuf, openingData,
      poolParamsLenBuf, poolParamsData,
    ]),
  });

  await sendAndConfirmTransaction(connection, new Transaction().add(depositToPoolIx), [payer]);
  console.log("  Credit note deposited to note pool");

  // Verify old credit note is closed
  const closedCreditNote = await connection.getAccountInfo(creditNotePDA);
  console.log(`  Old credit note closed: ${closedCreditNote === null}`);

  // ─────────────── STEP 5: Generate V3 Proof & Claim from Note Pool ───────────────
  console.log("\n[STEP 5] Generating V3 proof and claiming from note pool...");

  // Read note pool tree state
  const poolTreeInfo = await connection.getAccountInfo(notePoolTree);
  const poolTreeState = readTreeState(poolTreeInfo.data);
  const poolLeafIndex = poolTreeState.nextIndex - 1;
  const poolProof = buildMerkleProof(poolTreeState, poolLeafIndex);
  const poolRootBigInt = bytesToBigIntBE(poolTreeState.onChainRoot);

  // New credit note secrets
  const newBlinding = randomField();
  const newSalt = randomField();
  const newRecipientField = pubkeyToField(recipient.publicKey.toBytes());

  // Amount as BN254 field element (big-endian, 32 bytes → bigint)
  const amountFieldBigInt = dropAmount;

  // Compute expected new_stored_commitment (circuit must produce the same)
  const newOrigCommitment = poseidonHash([amountFieldBigInt, newBlinding]);
  const newStoredCommitmentBigInt = poseidonHash([newOrigCommitment, newSalt]);
  const poolNullifierHash = poseidonHash([poolNullifier]);

  // Recipient hi/lo for circuit
  const recipientBytes = recipient.publicKey.toBytes();
  const recipientHi = bytesToBigIntBE(recipientBytes.slice(0, 16));
  const recipientLo = bytesToBigIntBE(recipientBytes.slice(16, 32));

  const v3Input = {
    pool_secret: poolSecret.toString(),
    pool_nullifier: poolNullifier.toString(),
    amount: amountFieldBigInt.toString(),
    pool_blinding_factor: poolBlinding.toString(),
    pool_path: poolProof.pathElements,
    pool_indices: poolProof.pathIndices,
    new_blinding: newBlinding.toString(),
    new_salt: newSalt.toString(),
    recipient_hi: recipientHi.toString(),
    recipient_lo: recipientLo.toString(),
    pool_merkle_root: poolRootBigInt.toString(),
    pool_nullifier_hash: poolNullifierHash.toString(),
    new_stored_commitment: newStoredCommitmentBigInt.toString(),
    recipient_hash: newRecipientField.toString(),
  };

  const { proof: v3Proof } = await snarkjs.groth16.fullProve(v3Input, V3_WASM, V3_ZKEY);
  const v3Serialized = serializeProof(v3Proof);
  console.log("  V3 proof generated");

  // Build claim_from_note_pool instruction
  const poolNullifierHashBytes = bigintToBytes32BE(poolNullifierHash);
  const [freshCreditNotePDA] = getCreditNotePDA(poolNullifierHashBytes);
  const [poolNullifierPDA] = getPoolNullifierPDA(poolNullifierHashBytes);

  const poolInputs = Buffer.concat([
    poolTreeState.onChainRoot,
    bigintToBytes32BE(newStoredCommitmentBigInt),
  ]);
  const poolInputsLenBuf = Buffer.alloc(4);
  poolInputsLenBuf.writeUInt32LE(64);

  const claimFromPoolIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: notePool, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: false },
      { pubkey: freshCreditNotePDA, isSigner: false, isWritable: true },
      { pubkey: poolNullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("claim_from_note_pool"),
      poolNullifierHashBytes,
      v3Serialized.proofA, v3Serialized.proofB, v3Serialized.proofC,
      poolInputsLenBuf, poolInputs,
    ]),
  });

  await sendAndConfirmTransaction(connection, new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), claimFromPoolIx
  ), [payer]);
  console.log("  Fresh credit note claimed from note pool");

  // Verify fresh credit note commitment is DIFFERENT from original
  const freshCreditNoteInfo = await connection.getAccountInfo(freshCreditNotePDA);
  const freshStoredCommitment = freshCreditNoteInfo.data.slice(8 + 1 + 32, 8 + 1 + 32 + 32);
  const commitmentsMatch = Buffer.compare(originalStoredCommitment, freshStoredCommitment) === 0;
  console.log(`  Fresh commitment differs from original: ${!commitmentsMatch}`);

  // Verify pool nullifier exists
  const poolNullifierInfo = await connection.getAccountInfo(poolNullifierPDA);
  console.log(`  Pool nullifier PDA exists: ${poolNullifierInfo !== null}`);

  // ─────────────── STEP 6: Withdraw from Fresh Credit Note ───────────────
  console.log("\n[STEP 6] Withdrawing from fresh credit note...");

  const recipientBalBefore = await connection.getBalance(recipient.publicKey);

  // Opening for fresh credit note: amount(8 LE) + new_blinding(32) + new_salt(32) = 72 bytes
  const freshOpeningAmountBuf = Buffer.alloc(8);
  freshOpeningAmountBuf.writeBigUInt64LE(dropAmount);
  const freshOpening = Buffer.concat([freshOpeningAmountBuf, bigintToBytes32BE(newBlinding), bigintToBytes32BE(newSalt)]);
  const freshOpeningLenBuf = Buffer.alloc(4);
  freshOpeningLenBuf.writeUInt32LE(72);
  const rateBuf = Buffer.alloc(2); // rate = 0

  const withdrawIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: freshCreditNotePDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: false, isWritable: true }, // fee_recipient
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },  // payer
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("withdraw_credit"),
      poolNullifierHashBytes,
      freshOpeningLenBuf, freshOpening,
      rateBuf,
    ]),
  });

  await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [payer]);

  const recipientBalAfter = await connection.getBalance(recipient.publicKey);
  const received = recipientBalAfter - recipientBalBefore;
  console.log(`  Recipient received: ${received / LAMPORTS_PER_SOL} SOL`);
  console.log(`  Expected:           ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL`);
  console.log(`  Match: ${received === Number(dropAmount)}`);

  // Verify fresh credit note is closed
  const closedFresh = await connection.getAccountInfo(freshCreditNotePDA);
  console.log(`  Fresh credit note closed: ${closedFresh === null}`);

  // ─────────────── Summary ───────────────
  console.log("\n" + "=".repeat(60));
  console.log("  RECURSIVE PRIVACY FLOW COMPLETE");
  console.log("=".repeat(60));
  console.log(`  Deposit:   ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL (amount visible)`);
  console.log(`  Claim:     hidden (V2 proof, zero SOL moves)`);
  console.log(`  Pool deposit: hidden (credit note opened, pool leaf inserted)`);
  console.log(`  Pool claim:   hidden (V3 proof, fresh credit note, zero SOL moves)`);
  console.log(`  Withdraw:  ${received / LAMPORTS_PER_SOL} SOL (from fresh note, fully decorrelated)`);
  console.log(`  Commitments unlinkable: ${!commitmentsMatch}`);
  console.log("=".repeat(60));

  if (received !== Number(dropAmount) || commitmentsMatch) {
    console.error("\nFAILED — see above");
    process.exit(1);
  }
}

main().catch(e => {
  console.error("Fatal:", e);
  if (e.logs) e.logs.forEach(l => console.error(`  ${l}`));
  process.exit(1);
});
