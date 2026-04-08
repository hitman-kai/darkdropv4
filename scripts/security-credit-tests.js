#!/usr/bin/env node
/**
 * DarkDrop V4 — Credit Note Security Tests
 *
 * Tests attack vectors against claim_credit and withdraw_credit:
 *   1. Double-withdraw (CreditNote PDA closed after first)
 *   2. Wrong commitment opening (bad amount or blinding)
 *   3. Wrong recipient on withdraw
 *   4. Fake credit note (no prior claim_credit)
 *   5. Amount tampering on withdraw
 *   6. Replay claim_credit (same nullifier twice)
 *
 * Requires a valid drop in the vault. Creates one fresh drop, then runs all tests.
 *
 * Usage:
 *   RPC_URL=https://api.devnet.solana.com node scripts/security-credit-tests.js
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
const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");
const MERKLE_DEPTH = 20;

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
function getMerkleTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID); }
function getTreasuryPDA() { return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID); }
function getNullifierPDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), h], PROGRAM_ID); }
function getCreditNotePDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("credit"), h], PROGRAM_ID); }

function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// ──────────────────── TX builders ────────────────────

function buildClaimCreditIx({ vault, merkleTree, creditNotePDA, nullifierPDA, recipient, payer, nullifierHashBytes, proofA, proofB, proofC, onChainRoot, amtCommitment, pwdHash }) {
  const opaqueInputs = Buffer.concat([onChainRoot, bigintToBytes32BE(amtCommitment), bigintToBytes32BE(pwdHash)]);
  const inputsLenBuf = Buffer.alloc(4);
  inputsLenBuf.writeUInt32LE(opaqueInputs.length);

  const data = Buffer.concat([
    getDiscriminator("claim_credit"),
    nullifierHashBytes,
    proofA, proofB, proofC,
    inputsLenBuf, opaqueInputs,
  ]);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: false },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function buildWithdrawCreditIx({ vault, treasury, creditNotePDA, recipient, feeRecipient, payer, nullifierHashBytes, amount, blindingFactor, rate = 0 }) {
  const openingAmountBuf = Buffer.alloc(8);
  openingAmountBuf.writeBigUInt64LE(amount);
  const opening = Buffer.concat([openingAmountBuf, bigintToBytes32BE(blindingFactor)]);
  const openingLenBuf = Buffer.alloc(4);
  openingLenBuf.writeUInt32LE(opening.length);
  const rateBuf = Buffer.alloc(2);
  rateBuf.writeUInt16LE(rate);

  const data = Buffer.concat([
    getDiscriminator("withdraw_credit"),
    nullifierHashBytes,
    openingLenBuf, opening,
    rateBuf,
  ]);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: true },
      { pubkey: feeRecipient, isSigner: false, isWritable: true },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function buildCreateDropIx({ vault, merkleTree, treasury, payer, leaf, amount, amtCommitment, pwdHash }) {
  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(amount);
  const data = Buffer.concat([
    getDiscriminator("create_drop"),
    bigintToBytes32BE(leaf),
    amountBuf,
    bigintToBytes32BE(amtCommitment),
    bigintToBytes32BE(pwdHash),
  ]);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

// ──────────────────── Proof generation helper ────────────────────

async function generateProofForDrop({ secret, nullifier, dropAmount, blindingFactor, password, merkleTree, connection, recipientPubkey }) {
  const nullHash = poseidonHash([nullifier]);
  const amtCommitment = poseidonHash([dropAmount, blindingFactor]);
  const pwdHash = password ? poseidonHash([password]) : 0n;

  const treeAccountInfo = await connection.getAccountInfo(merkleTree);
  const treeData = treeAccountInfo.data;
  const nextIndex = treeData.readUInt32LE(8 + 32);
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;

  const leafIndex = nextIndex - 1;
  const zeroHashes = getZeroHashes();
  const pathElements = [], pathIndices = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit.toString());
    pathElements.push(bit === 0 ? zeroHashes[i].toString() : bytesToBigIntBE(treeData.slice(filledSubtreesOffset + i * 32, filledSubtreesOffset + (i + 1) * 32)).toString());
    idx = idx >> 1;
  }

  const recipientField = pubkeyToField(recipientPubkey.toBytes());
  const onChainRootBigInt = bytesToBigIntBE(onChainRoot);

  const circuitInput = {
    secret: secret.toString(),
    amount: dropAmount.toString(),
    blinding_factor: blindingFactor.toString(),
    nullifier: nullifier.toString(),
    merkle_path: pathElements,
    merkle_indices: pathIndices,
    password: (password || 0n).toString(),
    merkle_root: onChainRootBigInt.toString(),
    nullifier_hash: nullHash.toString(),
    recipient: recipientField.toString(),
    amount_commitment: amtCommitment.toString(),
    password_hash: pwdHash.toString(),
  };

  const { proof } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);

  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  const proofB = Buffer.concat([bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]), bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0])]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);

  const nullifierHashBytes = bigintToBytes32BE(nullHash);
  return { proofA, proofB, proofC, nullifierHashBytes, onChainRoot, amtCommitment, pwdHash, nullHash };
}

// ──────────────────── Test helpers ────────────────────

async function expectTxFail(connection, tx, signers, expectedError) {
  try {
    await sendAndConfirmTransaction(connection, tx, signers);
    return { passed: false, reason: "TX succeeded but should have failed" };
  } catch (e) {
    const msg = e.message || "";
    const logs = (e.logs || []).join(" ");
    const combined = msg + " " + logs;

    if (expectedError && !combined.includes(expectedError)) {
      // Check for common patterns — "already in use" for PDA exists, custom error codes
      if (expectedError === "already in use" && combined.includes("already in use")) return { passed: true };
      return { passed: false, reason: `Expected "${expectedError}" but got: ${msg.slice(0, 200)}` };
    }
    return { passed: true };
  }
}

// ──────────────────── Main ────────────────────

async function main() {
  console.log("=== DarkDrop V4 — Credit Note Security Tests ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, { commitment: "confirmed", confirmTransactionInitialTimeout: 120000 });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [treasury] = getTreasuryPDA();

  console.log(`  Payer:    ${payer.publicKey}`);
  console.log(`  Program:  ${PROGRAM_ID}`);
  console.log(`  Treasury: ${treasury}\n`);

  let passed = 0, failed = 0;

  function report(name, result) {
    if (result.passed) {
      console.log(`  [PASS] ${name}`);
      passed++;
    } else {
      console.log(`  [FAIL] ${name} — ${result.reason}`);
      failed++;
    }
  }

  // ──────────────── Setup: create a drop and claim it ────────────────

  console.log("[SETUP] Creating drop and claim_credit...");
  const dropAmount = BigInt(0.05 * LAMPORTS_PER_SOL);
  const secret = randomField();
  const nullifier = randomField();
  const blindingFactor = randomField();
  const leaf = poseidonHash([secret, nullifier, dropAmount, blindingFactor]);
  const amtCommitment = poseidonHash([dropAmount, blindingFactor]);

  // create_drop
  const createIx = buildCreateDropIx({ vault, merkleTree, treasury, payer: payer.publicKey, leaf, amount: dropAmount, amtCommitment, pwdHash: 0n });
  await sendAndConfirmTransaction(connection, new Transaction().add(createIx), [payer]);
  console.log("  Drop created");

  // Generate proof
  const proofData = await generateProofForDrop({
    secret, nullifier, dropAmount, blindingFactor, password: 0n,
    merkleTree, connection, recipientPubkey: recipient.publicKey,
  });

  const [nullifierPDA] = getNullifierPDA(proofData.nullifierHashBytes);
  const [creditNotePDA] = getCreditNotePDA(proofData.nullifierHashBytes);

  // claim_credit (valid)
  const claimIx = buildClaimCreditIx({
    vault, merkleTree, creditNotePDA, nullifierPDA,
    recipient: recipient.publicKey, payer: payer.publicKey,
    nullifierHashBytes: proofData.nullifierHashBytes,
    proofA: proofData.proofA, proofB: proofData.proofB, proofC: proofData.proofC,
    onChainRoot: proofData.onChainRoot, amtCommitment: proofData.amtCommitment, pwdHash: proofData.pwdHash,
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), claimIx
  ), [payer]);
  console.log("  claim_credit succeeded");

  // Valid withdraw (for test 1 setup)
  const withdrawIx = buildWithdrawCreditIx({
    vault, treasury, creditNotePDA,
    recipient: recipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
    nullifierHashBytes: proofData.nullifierHashBytes,
    amount: dropAmount, blindingFactor,
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [payer]);
  console.log("  withdraw_credit succeeded (setup complete)\n");

  // ──────────────── TEST 1: Double-withdraw ────────────────
  console.log("[TEST 1] Double-withdraw (CreditNote PDA closed)...");
  {
    const withdrawIx2 = buildWithdrawCreditIx({
      vault, treasury, creditNotePDA,
      recipient: recipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
      nullifierHashBytes: proofData.nullifierHashBytes,
      amount: dropAmount, blindingFactor,
    });
    const tx = new Transaction().add(withdrawIx2);
    const result = await expectTxFail(connection, tx, [payer]);
    report("Double-withdraw rejected (CreditNote PDA closed)", result);
  }

  // ──────────────── TEST 6: Replay claim_credit (same nullifier) ────────────────
  // Must come before tests 2-5 because those need a fresh drop
  console.log("[TEST 6] Replay claim_credit (same nullifier)...");
  {
    const replayIx = buildClaimCreditIx({
      vault, merkleTree, creditNotePDA, nullifierPDA,
      recipient: recipient.publicKey, payer: payer.publicKey,
      nullifierHashBytes: proofData.nullifierHashBytes,
      proofA: proofData.proofA, proofB: proofData.proofB, proofC: proofData.proofC,
      onChainRoot: proofData.onChainRoot, amtCommitment: proofData.amtCommitment, pwdHash: proofData.pwdHash,
    });
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), replayIx);
    const result = await expectTxFail(connection, tx, [payer], "already in use");
    report("Replay claim_credit rejected (nullifier already spent)", result);
  }

  // ──────────────── Setup for tests 2-5: fresh drop + claim_credit ────────────────
  console.log("\n[SETUP] Creating fresh drop for tests 2-5...");
  const secret2 = randomField();
  const nullifier2 = randomField();
  const blindingFactor2 = randomField();
  const leaf2 = poseidonHash([secret2, nullifier2, dropAmount, blindingFactor2]);
  const amtCommitment2 = poseidonHash([dropAmount, blindingFactor2]);

  const createIx2 = buildCreateDropIx({ vault, merkleTree, treasury, payer: payer.publicKey, leaf: leaf2, amount: dropAmount, amtCommitment: amtCommitment2, pwdHash: 0n });
  await sendAndConfirmTransaction(connection, new Transaction().add(createIx2), [payer]);

  const proofData2 = await generateProofForDrop({
    secret: secret2, nullifier: nullifier2, dropAmount, blindingFactor: blindingFactor2, password: 0n,
    merkleTree, connection, recipientPubkey: recipient.publicKey,
  });

  const [nullifierPDA2] = getNullifierPDA(proofData2.nullifierHashBytes);
  const [creditNotePDA2] = getCreditNotePDA(proofData2.nullifierHashBytes);

  const claimIx2 = buildClaimCreditIx({
    vault, merkleTree, creditNotePDA: creditNotePDA2, nullifierPDA: nullifierPDA2,
    recipient: recipient.publicKey, payer: payer.publicKey,
    nullifierHashBytes: proofData2.nullifierHashBytes,
    proofA: proofData2.proofA, proofB: proofData2.proofB, proofC: proofData2.proofC,
    onChainRoot: proofData2.onChainRoot, amtCommitment: proofData2.amtCommitment, pwdHash: proofData2.pwdHash,
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), claimIx2
  ), [payer]);
  console.log("  Fresh claim_credit succeeded\n");

  // ──────────────── TEST 2: Wrong commitment opening — bad amount ────────────────
  console.log("[TEST 2] Wrong amount in opening...");
  {
    const badAmount = dropAmount + 1000n; // slightly different amount
    const withdrawIx = buildWithdrawCreditIx({
      vault, treasury, creditNotePDA: creditNotePDA2,
      recipient: recipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
      nullifierHashBytes: proofData2.nullifierHashBytes,
      amount: badAmount, blindingFactor: blindingFactor2,
    });
    const tx = new Transaction().add(withdrawIx);
    const result = await expectTxFail(connection, tx, [payer], "CommitmentMismatch");
    report("Wrong amount rejected (CommitmentMismatch)", result);
  }

  // ──────────────── TEST 2b: Wrong commitment opening — bad blinding factor ────────────────
  console.log("[TEST 2b] Wrong blinding factor in opening...");
  {
    const badBlinding = randomField(); // completely different blinding
    const withdrawIx = buildWithdrawCreditIx({
      vault, treasury, creditNotePDA: creditNotePDA2,
      recipient: recipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
      nullifierHashBytes: proofData2.nullifierHashBytes,
      amount: dropAmount, blindingFactor: badBlinding,
    });
    const tx = new Transaction().add(withdrawIx);
    const result = await expectTxFail(connection, tx, [payer], "CommitmentMismatch");
    report("Wrong blinding factor rejected (CommitmentMismatch)", result);
  }

  // ──────────────── TEST 3: Wrong recipient ────────────────
  console.log("[TEST 3] Wrong recipient on withdraw...");
  {
    const wrongRecipient = Keypair.generate();
    const withdrawIx = buildWithdrawCreditIx({
      vault, treasury, creditNotePDA: creditNotePDA2,
      recipient: wrongRecipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
      nullifierHashBytes: proofData2.nullifierHashBytes,
      amount: dropAmount, blindingFactor: blindingFactor2,
    });
    const tx = new Transaction().add(withdrawIx);
    const result = await expectTxFail(connection, tx, [payer], "UnauthorizedWithdraw");
    report("Wrong recipient rejected (UnauthorizedWithdraw)", result);
  }

  // ──────────────── TEST 4: Fake credit note ────────────────
  console.log("[TEST 4] Fake credit note (no prior claim_credit)...");
  {
    const fakeNullifierHash = bigintToBytes32BE(randomField());
    const [fakeCreditNote] = getCreditNotePDA(fakeNullifierHash);

    const withdrawIx = buildWithdrawCreditIx({
      vault, treasury, creditNotePDA: fakeCreditNote,
      recipient: recipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
      nullifierHashBytes: fakeNullifierHash,
      amount: dropAmount, blindingFactor: blindingFactor2,
    });
    const tx = new Transaction().add(withdrawIx);
    // Should fail because the CreditNote PDA doesn't exist (AccountNotInitialized or similar)
    const result = await expectTxFail(connection, tx, [payer]);
    report("Fake credit note rejected (PDA doesn't exist)", result);
  }

  // ──────────────── TEST 5: Amount tampering ────────────────
  console.log("[TEST 5] Amount tampering (higher amount, different commitment)...");
  {
    // Try to claim more than deposited. The commitment won't match.
    const tamperedAmount = BigInt(1 * LAMPORTS_PER_SOL); // 1 SOL instead of 0.05
    const withdrawIx = buildWithdrawCreditIx({
      vault, treasury, creditNotePDA: creditNotePDA2,
      recipient: recipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
      nullifierHashBytes: proofData2.nullifierHashBytes,
      amount: tamperedAmount, blindingFactor: blindingFactor2,
    });
    const tx = new Transaction().add(withdrawIx);
    const result = await expectTxFail(connection, tx, [payer], "CommitmentMismatch");
    report("Amount tampering rejected (CommitmentMismatch)", result);
  }

  // ──────────────── Cleanup: valid withdraw of test 2-5 drop ────────────────
  console.log("\n[CLEANUP] Withdrawing test 2-5 credit note...");
  {
    const withdrawIx = buildWithdrawCreditIx({
      vault, treasury, creditNotePDA: creditNotePDA2,
      recipient: recipient.publicKey, feeRecipient: payer.publicKey, payer: payer.publicKey,
      nullifierHashBytes: proofData2.nullifierHashBytes,
      amount: dropAmount, blindingFactor: blindingFactor2,
    });
    await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [payer]);
    console.log("  Cleanup withdraw succeeded");
  }

  // ──────────────── Summary ────────────────
  console.log(`\n${"=".repeat(50)}`);
  console.log(`  RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
  console.log(`${"=".repeat(50)}`);

  if (failed > 0) process.exit(1);
}

main().catch(e => {
  console.error("Fatal:", e);
  process.exit(1);
});
