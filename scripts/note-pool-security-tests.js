#!/usr/bin/env node
/**
 * DarkDrop V4 — Note Pool Security Tests
 *
 * Tests attack vectors against the note pool:
 *   1. Double-claim from pool (same pool nullifier)
 *   2. Claim with wrong pool root
 *   3. Dishonest deposit amount (lie about credit note amount)
 *   4. Claim with tampered new_stored_commitment (proof will fail)
 *
 * Requires: note pool initialized, at least one credit note deposited.
 *
 * Usage:
 *   RPC_URL=https://api.devnet.solana.com node scripts/note-pool-security-tests.js
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
const V2_WASM = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const V2_ZKEY = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");
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
  return poseidonHash([bytesToBigIntBE(pubkeyBytes.slice(0, 16)), bytesToBigIntBE(pubkeyBytes.slice(16, 32))]);
}
function getDiscriminator(name) { return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8); }
function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

function getVaultPDA() { return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID); }
function getMerkleTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID); }
function getTreasuryPDA() { return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID); }
function getNullifierPDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), h], PROGRAM_ID); }
function getCreditNotePDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("credit"), h], PROGRAM_ID); }
function getNotePoolPDA() { return PublicKey.findProgramAddressSync([Buffer.from("note_pool")], PROGRAM_ID); }
function getNotePoolTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("note_pool_tree"), vault.toBytes()], PROGRAM_ID); }
function getPoolNullifierPDA(h) { return PublicKey.findProgramAddressSync([Buffer.from("pool_nullifier"), h], PROGRAM_ID); }

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
    pathElements.push(bit === 0 ? zeroHashes[i].toString() :
      bytesToBigIntBE(treeState.treeData.slice(treeState.filledSubtreesOffset + i * 32, treeState.filledSubtreesOffset + (i + 1) * 32)).toString());
    idx = idx >> 1;
  }
  return { pathElements, pathIndices };
}
function serializeProof(proof) {
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(BN254_FQ - BigInt(proof.pi_a[1]))]);
  const proofB = Buffer.concat([bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]), bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0])]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);
  return { proofA, proofB, proofC };
}

async function expectTxFail(connection, tx, signers, expectedError) {
  try {
    await sendAndConfirmTransaction(connection, tx, signers);
    return { passed: false, reason: "TX succeeded but should have failed" };
  } catch (e) {
    const combined = (e.message || "") + " " + (e.logs || []).join(" ");
    if (expectedError && !combined.includes(expectedError)) {
      return { passed: false, reason: `Expected "${expectedError}" but got: ${(e.message || "").slice(0, 200)}` };
    }
    return { passed: true };
  }
}

// ─── Helper: full deposit → claim_credit → deposit_to_note_pool pipeline ───
async function setupPoolEntry(connection, payer, recipient, vault, merkleTree, treasury, notePool, notePoolTree) {
  const dropAmount = BigInt(0.05 * LAMPORTS_PER_SOL);
  const secret = randomField(), nullifier = randomField(), blindingFactor = randomField();
  const leaf = poseidonHash([secret, nullifier, dropAmount, blindingFactor]);
  const amtCommitment = poseidonHash([dropAmount, blindingFactor]);
  const nullHash = poseidonHash([nullifier]);
  const nullifierHashBytes = bigintToBytes32BE(nullHash);
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);
  const [creditNotePDA] = getCreditNotePDA(nullifierHashBytes);

  // create_drop
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
    data: Buffer.concat([getDiscriminator("create_drop"), bigintToBytes32BE(leaf), amountBuf, bigintToBytes32BE(amtCommitment), bigintToBytes32BE(0n)]),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(createDropIx), [payer]);

  // Generate V2 proof
  const recipientField = pubkeyToField(recipient.publicKey.toBytes());
  const treeInfo = await connection.getAccountInfo(merkleTree);
  const treeState = readTreeState(treeInfo.data);
  const leafIndex = treeState.nextIndex - 1;
  const mp = buildMerkleProof(treeState, leafIndex);
  const rootBigInt = bytesToBigIntBE(treeState.onChainRoot);

  const { proof: v2Proof } = await snarkjs.groth16.fullProve({
    secret: secret.toString(), amount: dropAmount.toString(), blinding_factor: blindingFactor.toString(),
    nullifier: nullifier.toString(), merkle_path: mp.pathElements, merkle_indices: mp.pathIndices,
    password: "0", merkle_root: rootBigInt.toString(), nullifier_hash: nullHash.toString(),
    recipient: recipientField.toString(), amount_commitment: amtCommitment.toString(), password_hash: "0",
  }, V2_WASM, V2_ZKEY);
  const v2s = serializeProof(v2Proof);

  // claim_credit
  const opaqueInputs = Buffer.concat([treeState.onChainRoot, bigintToBytes32BE(amtCommitment), bigintToBytes32BE(0n)]);
  const il = Buffer.alloc(4); il.writeUInt32LE(96);
  const claimSalt = randomField();
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
    data: Buffer.concat([getDiscriminator("claim_credit"), nullifierHashBytes, v2s.proofA, v2s.proofB, v2s.proofC, il, opaqueInputs, bigintToBytes32BE(claimSalt)]),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), claimCreditIx
  ), [payer]);

  // deposit_to_note_pool
  const poolSecret = randomField(), poolNullifier = randomField(), poolBlinding = randomField();
  const openBuf = Buffer.alloc(8); openBuf.writeBigUInt64LE(dropAmount);
  const opening = Buffer.concat([openBuf, bigintToBytes32BE(blindingFactor), bigintToBytes32BE(claimSalt)]);
  const ol = Buffer.alloc(4); ol.writeUInt32LE(72);
  const poolParams = Buffer.concat([bigintToBytes32BE(poolSecret), bigintToBytes32BE(poolNullifier), bigintToBytes32BE(poolBlinding)]);
  const pl = Buffer.alloc(4); pl.writeUInt32LE(96);

  const depositPoolIx = new TransactionInstruction({
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
    data: Buffer.concat([getDiscriminator("deposit_to_note_pool"), nullifierHashBytes, ol, opening, pl, poolParams]),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(depositPoolIx), [payer]);

  return { dropAmount, poolSecret, poolNullifier, poolBlinding };
}

// ─────────────── Main ───────────────

async function main() {
  console.log("=== DarkDrop V4 — Note Pool Security Tests ===\n");

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

  console.log(`  Payer:    ${payer.publicKey}`);
  console.log(`  Program:  ${PROGRAM_ID}\n`);

  let passed = 0, failed = 0;
  function report(name, result) {
    if (result.passed) { console.log(`  [PASS] ${name}`); passed++; }
    else { console.log(`  [FAIL] ${name} — ${result.reason}`); failed++; }
  }

  // Setup: deposit a credit note into the pool and do a valid claim
  console.log("[SETUP] Creating pool entry (deposit → claim_credit → deposit_to_pool)...");
  const entry = await setupPoolEntry(connection, payer, recipient, vault, merkleTree, treasury, notePool, notePoolTree);
  console.log("  Pool entry created\n");

  // Generate a valid V3 proof for tests
  const poolTreeInfo = await connection.getAccountInfo(notePoolTree);
  const poolTreeState = readTreeState(poolTreeInfo.data);
  const poolLeafIndex = poolTreeState.nextIndex - 1;
  const poolProof = buildMerkleProof(poolTreeState, poolLeafIndex);
  const poolRootBigInt = bytesToBigIntBE(poolTreeState.onChainRoot);

  const newBlinding = randomField(), newSalt = randomField();
  const recipientBytes = recipient.publicKey.toBytes();
  const recipientHi = bytesToBigIntBE(recipientBytes.slice(0, 16));
  const recipientLo = bytesToBigIntBE(recipientBytes.slice(16, 32));
  const newRecipientField = pubkeyToField(recipientBytes);
  const newOrigCommitment = poseidonHash([entry.dropAmount, newBlinding]);
  const newStoredCommitmentBigInt = poseidonHash([newOrigCommitment, newSalt]);
  const poolNullifierHash = poseidonHash([entry.poolNullifier]);
  const poolNullifierHashBytes = bigintToBytes32BE(poolNullifierHash);

  const v3Input = {
    pool_secret: entry.poolSecret.toString(), pool_nullifier: entry.poolNullifier.toString(),
    amount: entry.dropAmount.toString(), pool_blinding_factor: entry.poolBlinding.toString(),
    pool_path: poolProof.pathElements, pool_indices: poolProof.pathIndices,
    new_blinding: newBlinding.toString(), new_salt: newSalt.toString(),
    recipient_hi: recipientHi.toString(), recipient_lo: recipientLo.toString(),
    pool_merkle_root: poolRootBigInt.toString(), pool_nullifier_hash: poolNullifierHash.toString(),
    new_stored_commitment: newStoredCommitmentBigInt.toString(), recipient_hash: newRecipientField.toString(),
  };
  const { proof: v3Proof } = await snarkjs.groth16.fullProve(v3Input, V3_WASM, V3_ZKEY);
  const v3s = serializeProof(v3Proof);

  // Valid claim (setup for test 1)
  const [freshCreditPDA] = getCreditNotePDA(poolNullifierHashBytes);
  const [poolNullifierPDA] = getPoolNullifierPDA(poolNullifierHashBytes);
  const poolInputs = Buffer.concat([poolTreeState.onChainRoot, bigintToBytes32BE(newStoredCommitmentBigInt)]);
  const pil = Buffer.alloc(4); pil.writeUInt32LE(64);

  const validClaimIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: notePool, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: false },
      { pubkey: freshCreditPDA, isSigner: false, isWritable: true },
      { pubkey: poolNullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([getDiscriminator("claim_from_note_pool"), poolNullifierHashBytes, v3s.proofA, v3s.proofB, v3s.proofC, pil, poolInputs]),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), validClaimIx
  ), [payer]);
  console.log("[SETUP] Valid pool claim succeeded\n");

  // ─── TEST 1: Double-claim from pool (same nullifier) ───
  console.log("[TEST 1] Double-claim from pool (same pool nullifier)...");
  {
    // Try to claim again with the same pool nullifier — PDA already exists
    const [dupCreditPDA] = getCreditNotePDA(poolNullifierHashBytes);
    const [dupPoolNullPDA] = getPoolNullifierPDA(poolNullifierHashBytes);
    const replayIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: false },
        { pubkey: notePool, isSigner: false, isWritable: true },
        { pubkey: notePoolTree, isSigner: false, isWritable: false },
        { pubkey: dupCreditPDA, isSigner: false, isWritable: true },
        { pubkey: dupPoolNullPDA, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([getDiscriminator("claim_from_note_pool"), poolNullifierHashBytes, v3s.proofA, v3s.proofB, v3s.proofC, pil, poolInputs]),
    });
    const result = await expectTxFail(connection, new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), replayIx
    ), [payer], "already in use");
    report("Double-claim rejected (pool nullifier PDA already exists)", result);
  }

  // ─── TEST 2: Claim with wrong pool root ───
  console.log("[TEST 2] Claim with wrong pool root...");
  {
    // Create a second pool entry for a fresh proof with a fake root
    console.log("  Setting up fresh pool entry...");
    const entry2 = await setupPoolEntry(connection, payer, recipient, vault, merkleTree, treasury, notePool, notePoolTree);

    const nb2 = randomField(), ns2 = randomField();
    const no2 = poseidonHash([entry2.dropAmount, nb2]);
    const nsc2 = poseidonHash([no2, ns2]);
    const pnh2 = poseidonHash([entry2.poolNullifier]);
    const pnhBytes2 = bigintToBytes32BE(pnh2);

    // Use a FAKE root (random bytes)
    const fakeRoot = crypto.randomBytes(32);
    const fakePoolInputs = Buffer.concat([fakeRoot, bigintToBytes32BE(nsc2)]);
    const fpil = Buffer.alloc(4); fpil.writeUInt32LE(64);

    // We can't generate a valid proof for a fake root, so just submit garbage proof bytes
    const garbageProofA = crypto.randomBytes(64);
    const garbageProofB = crypto.randomBytes(128);
    const garbageProofC = crypto.randomBytes(64);

    const [cp2] = getCreditNotePDA(pnhBytes2);
    const [pnp2] = getPoolNullifierPDA(pnhBytes2);
    const fakeRootIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: false },
        { pubkey: notePool, isSigner: false, isWritable: true },
        { pubkey: notePoolTree, isSigner: false, isWritable: false },
        { pubkey: cp2, isSigner: false, isWritable: true },
        { pubkey: pnp2, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([getDiscriminator("claim_from_note_pool"), pnhBytes2, garbageProofA, garbageProofB, garbageProofC, fpil, fakePoolInputs]),
    });
    const result = await expectTxFail(connection, new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), fakeRootIx
    ), [payer], "InvalidRoot");
    report("Wrong pool root rejected (InvalidRoot)", result);
  }

  // ─── TEST 3: Dishonest deposit amount ───
  console.log("[TEST 3] Dishonest deposit amount (lie about credit note amount)...");
  {
    // Create a credit note with amount X, then try to deposit it claiming amount Y
    const dropAmount = BigInt(0.05 * LAMPORTS_PER_SOL);
    const sec = randomField(), nul = randomField(), bf = randomField();
    const lf = poseidonHash([sec, nul, dropAmount, bf]);
    const ac = poseidonHash([dropAmount, bf]);
    const nh = poseidonHash([nul]);
    const nhb = bigintToBytes32BE(nh);
    const [npda] = getNullifierPDA(nhb);
    const [cpda] = getCreditNotePDA(nhb);

    // create_drop
    const ab = Buffer.alloc(8); ab.writeBigUInt64LE(dropAmount);
    await sendAndConfirmTransaction(connection, new Transaction().add(new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([getDiscriminator("create_drop"), bigintToBytes32BE(lf), ab, bigintToBytes32BE(ac), bigintToBytes32BE(0n)]),
    })), [payer]);

    // claim_credit
    const rf = pubkeyToField(recipient.publicKey.toBytes());
    const ti = await connection.getAccountInfo(merkleTree);
    const ts = readTreeState(ti.data);
    const li = ts.nextIndex - 1;
    const mp = buildMerkleProof(ts, li);
    const rb = bytesToBigIntBE(ts.onChainRoot);
    const { proof: p2 } = await snarkjs.groth16.fullProve({
      secret: sec.toString(), amount: dropAmount.toString(), blinding_factor: bf.toString(),
      nullifier: nul.toString(), merkle_path: mp.pathElements, merkle_indices: mp.pathIndices,
      password: "0", merkle_root: rb.toString(), nullifier_hash: nh.toString(),
      recipient: rf.toString(), amount_commitment: ac.toString(), password_hash: "0",
    }, V2_WASM, V2_ZKEY);
    const s2 = serializeProof(p2);
    const oi = Buffer.concat([ts.onChainRoot, bigintToBytes32BE(ac), bigintToBytes32BE(0n)]);
    const il2 = Buffer.alloc(4); il2.writeUInt32LE(96);
    const salt = randomField();
    await sendAndConfirmTransaction(connection, new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: merkleTree, isSigner: false, isWritable: false },
          { pubkey: cpda, isSigner: false, isWritable: true },
          { pubkey: npda, isSigner: false, isWritable: true },
          { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([getDiscriminator("claim_credit"), nhb, s2.proofA, s2.proofB, s2.proofC, il2, oi, bigintToBytes32BE(salt)]),
      })
    ), [payer]);

    // Try deposit_to_note_pool with WRONG amount (1 SOL instead of 0.05)
    const fakeAmount = BigInt(1 * LAMPORTS_PER_SOL);
    const fakeAmtBuf = Buffer.alloc(8); fakeAmtBuf.writeBigUInt64LE(fakeAmount);
    const fakeOpening = Buffer.concat([fakeAmtBuf, bigintToBytes32BE(bf), bigintToBytes32BE(salt)]);
    const fol = Buffer.alloc(4); fol.writeUInt32LE(72);
    const pp = Buffer.concat([bigintToBytes32BE(randomField()), bigintToBytes32BE(randomField()), bigintToBytes32BE(randomField())]);
    const ppl = Buffer.alloc(4); ppl.writeUInt32LE(96);

    const dishonestIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: false },
        { pubkey: notePool, isSigner: false, isWritable: true },
        { pubkey: notePoolTree, isSigner: false, isWritable: true },
        { pubkey: cpda, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([getDiscriminator("deposit_to_note_pool"), nhb, fol, fakeOpening, ppl, pp]),
    });
    const result = await expectTxFail(connection, new Transaction().add(dishonestIx), [payer], "CommitmentMismatch");
    report("Dishonest deposit amount rejected (CommitmentMismatch)", result);
  }

  // ─── TEST 4: Claim with invalid proof (tampered commitment) ───
  console.log("[TEST 4] Claim with garbage proof bytes...");
  {
    const fakeNullHash = bigintToBytes32BE(randomField());
    const [fakeCreditPDA] = getCreditNotePDA(fakeNullHash);
    const [fakePoolNullPDA] = getPoolNullifierPDA(fakeNullHash);

    const fakeInputs = Buffer.concat([poolTreeState.onChainRoot, bigintToBytes32BE(randomField())]);
    const fil = Buffer.alloc(4); fil.writeUInt32LE(64);

    const garbageIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: false },
        { pubkey: notePool, isSigner: false, isWritable: true },
        { pubkey: notePoolTree, isSigner: false, isWritable: false },
        { pubkey: fakeCreditPDA, isSigner: false, isWritable: true },
        { pubkey: fakePoolNullPDA, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        getDiscriminator("claim_from_note_pool"), fakeNullHash,
        crypto.randomBytes(64), crypto.randomBytes(128), crypto.randomBytes(64),
        fil, fakeInputs,
      ]),
    });
    const result = await expectTxFail(connection, new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), garbageIx
    ), [payer], "InvalidProof");
    report("Invalid proof rejected (InvalidProof)", result);
  }

  // ─── Summary ───
  console.log(`\n${"=".repeat(50)}`);
  console.log(`  RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
  console.log(`${"=".repeat(50)}`);
  if (failed > 0) process.exit(1);
}

main().catch(e => {
  console.error("Fatal:", e);
  if (e.logs) e.logs.forEach(l => console.error(`  ${l}`));
  process.exit(1);
});
