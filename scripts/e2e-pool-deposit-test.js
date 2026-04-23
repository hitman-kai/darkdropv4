#!/usr/bin/env node
/**
 * DarkDrop V4 — create_drop_to_pool E2E
 *
 * One-TX pool entry, full round trip:
 *   1. initialize_vault (skipped if vault exists)
 *   2. initialize_note_pool (skipped if pool exists)
 *   3. create_drop_to_pool (the new instruction — SOL straight into pool)
 *   4. claim_from_note_pool (V3 proof) -> fresh CreditNote for recipient
 *   5. withdraw_credit -> recipient receives SOL
 *
 * Works on localnet (fresh validator, fresh program) or devnet (post
 * create_drop_to_pool deploy). Uses v2 tree layout (ROOT_HISTORY_SIZE=256,
 * filled_subtrees at offset 8272).
 *
 * Usage:
 *   RPC_URL=http://127.0.0.1:8899 node scripts/e2e-pool-deposit-test.js
 *   RPC_URL=https://api.devnet.solana.com node scripts/e2e-pool-deposit-test.js
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
const os = require("os");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey(
  process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU"
);
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(os.homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");

const V3_WASM = path.join(BUILD_DIR, "note_pool/note_pool_js/note_pool.wasm");
const V3_ZKEY = path.join(BUILD_DIR, "note_pool/note_pool_final.zkey");

const MERKLE_DEPTH = 20;
const ROOT_HISTORY_SIZE = 256; // v2
const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// v2 tree layout offsets
const TREE_NEXT_INDEX_OFFSET = 40;
const TREE_CURRENT_ROOT_OFFSET = 48;
const TREE_FILLED_SUBTREES_OFFSET = 8 + 32 + 4 + 4 + 32 + ROOT_HISTORY_SIZE * 32; // 8272

let poseidon, F;

// ───── Helpers ─────
function poseidonHash(inputs) { return F.toObject(poseidon(inputs)); }
function randomField() { return BigInt("0x" + crypto.randomBytes(31).toString("hex")); }

function bytesToBigIntBE(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return BigInt("0x" + (hex || "0"));
}
function bigintToBytes32BE(val) {
  const hex = BigInt(val).toString(16).padStart(64, "0");
  const buf = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) buf[i] = parseInt(hex.substr(i * 2, 2), 16);
  return buf;
}
function u64LE(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }
function u32LE(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; }

function pubkeyToField(pubkey) {
  const bytes = pubkey.toBytes();
  return poseidonHash([bytesToBigIntBE(bytes.slice(0, 16)), bytesToBigIntBE(bytes.slice(16, 32))]);
}

function getDiscriminator(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

function pda(seeds) { return PublicKey.findProgramAddressSync(seeds, PROGRAM_ID)[0]; }

function serializeProof(proof) {
  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBytes32BE(BigInt(proof.pi_a[0])), bigintToBytes32BE(proofA_y_neg)]);
  const proofB = Buffer.concat([
    bigintToBytes32BE(BigInt(proof.pi_b[0][1])), bigintToBytes32BE(BigInt(proof.pi_b[0][0])),
    bigintToBytes32BE(BigInt(proof.pi_b[1][1])), bigintToBytes32BE(BigInt(proof.pi_b[1][0])),
  ]);
  const proofC = Buffer.concat([bigintToBytes32BE(BigInt(proof.pi_c[0])), bigintToBytes32BE(BigInt(proof.pi_c[1]))]);
  return { proofA, proofB, proofC };
}

function readTreeV2(data) {
  const nextIndex = data.readUInt32LE(TREE_NEXT_INDEX_OFFSET);
  const currentRoot = data.slice(TREE_CURRENT_ROOT_OFFSET, TREE_CURRENT_ROOT_OFFSET + 32);
  const filledSubtrees = [];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const off = TREE_FILLED_SUBTREES_OFFSET + i * 32;
    filledSubtrees.push(data.slice(off, off + 32));
  }
  return { nextIndex, currentRoot, filledSubtrees };
}

// Build merkle proof for the latest leaf using the shortcut — valid on
// fresh state because no one else has inserted after us.
function buildLatestLeafProof(tree, leafIndex) {
  const zeros = getZeroHashes();
  const pathElements = [], pathIndices = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit.toString());
    pathElements.push(bit === 0
      ? zeros[i].toString()
      : bytesToBigIntBE(tree.filledSubtrees[i]).toString());
    idx >>= 1;
  }
  return { pathElements, pathIndices };
}

// ───── Main ─────
async function main() {
  console.log("=== create_drop_to_pool E2E ===\n");
  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, { commitment: "confirmed", confirmTransactionInitialTimeout: 120000 });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  const vault = pda([Buffer.from("vault")]);
  const notePool = pda([Buffer.from("note_pool")]);
  const notePoolTree = pda([Buffer.from("note_pool_tree"), vault.toBytes()]);
  const merkleTree = pda([Buffer.from("merkle_tree"), vault.toBytes()]);
  const treasury = pda([Buffer.from("treasury")]);

  console.log(`  RPC:          ${RPC_URL}`);
  console.log(`  Payer:        ${payer.publicKey}`);
  console.log(`  Recipient:    ${recipient.publicKey}`);

  // ── STEP 1/2: ensure vault + note pool initialized ──
  console.log("\n[1] vault + note_pool init (idempotent)");
  const vaultInfo = await connection.getAccountInfo(vault);
  if (!vaultInfo) {
    console.log("  initializing vault...");
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([getDiscriminator("initialize_vault"), u64LE(100 * LAMPORTS_PER_SOL)]),
    });
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [payer]);
    console.log(`  TX: ${sig}`);
  } else {
    console.log("  vault exists");
  }

  const poolInfo = await connection.getAccountInfo(notePool);
  if (!poolInfo) {
    console.log("  initializing note pool...");
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
  } else {
    console.log("  note pool exists");
  }

  // ── STEP 3: create_drop_to_pool ──
  console.log("\n[3] create_drop_to_pool");
  const amount = BigInt(0.02 * LAMPORTS_PER_SOL);
  const poolSecret = randomField();
  const poolNullifier = randomField();
  const poolBlinding = randomField();

  const poolParams = Buffer.concat([
    bigintToBytes32BE(poolSecret),
    bigintToBytes32BE(poolNullifier),
    bigintToBytes32BE(poolBlinding),
  ]);

  const amountBytes = bigintToBytes32BE(amount); // u64 as BE 32-byte field
  const poolLeafBig = poseidonHash([poolSecret, poolNullifier, amount, poolBlinding]);

  const createIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: notePool, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("create_drop_to_pool"),
      u64LE(amount),
      u32LE(poolParams.length), poolParams,
    ]),
  });

  const treasuryBefore = (await connection.getAccountInfo(treasury)).lamports;
  const sig3 = await sendAndConfirmTransaction(connection, new Transaction().add(createIx), [payer]);
  console.log(`  TX: ${sig3}`);

  const treasuryAfter = (await connection.getAccountInfo(treasury)).lamports;
  console.log(`  treasury delta: +${treasuryAfter - treasuryBefore} (expect +${amount})`);
  if (BigInt(treasuryAfter - treasuryBefore) !== amount) throw new Error("treasury delta mismatch");

  // Read pool tree state, verify leaf
  const poolTreeData = (await connection.getAccountInfo(notePoolTree)).data;
  if (poolTreeData.length !== 8912) throw new Error(`pool tree size ${poolTreeData.length} != 8912 (v2)`);
  const poolTree = readTreeV2(poolTreeData);
  const leafIndex = poolTree.nextIndex - 1;
  console.log(`  pool leaf index: ${leafIndex}`);
  console.log(`  pool root: ${bytesToBigIntBE(poolTree.currentRoot).toString().slice(0, 20)}...`);

  // ── STEP 4: claim_from_note_pool ──
  console.log("\n[4] claim_from_note_pool (V3 proof)");
  const merkleProof = buildLatestLeafProof(poolTree, leafIndex);
  const poolRootBig = bytesToBigIntBE(poolTree.currentRoot);
  const poolNullifierHashBig = poseidonHash([poolNullifier]);
  const poolNullifierHashBytes = bigintToBytes32BE(poolNullifierHashBig);
  const recipientField = pubkeyToField(recipient.publicKey);

  // Fresh credit note params (V3 creates a NEW CreditNote with new secret/blinding/salt)
  const newBlinding = randomField();
  const newSalt = randomField();
  const originalCommitment = poseidonHash([amount, newBlinding]);
  const newStoredCommitment = poseidonHash([originalCommitment, newSalt]);

  // Circuit needs recipient split into hi/lo halves like claim.rs does
  const recipientBytes = recipient.publicKey.toBytes();
  const recipientHi = bytesToBigIntBE(recipientBytes.slice(0, 16));
  const recipientLo = bytesToBigIntBE(recipientBytes.slice(16, 32));

  const circuitInput = {
    pool_secret: poolSecret.toString(),
    pool_nullifier: poolNullifier.toString(),
    amount: amount.toString(),
    pool_blinding_factor: poolBlinding.toString(),
    pool_path: merkleProof.pathElements,
    pool_indices: merkleProof.pathIndices,
    new_blinding: newBlinding.toString(),
    new_salt: newSalt.toString(),
    recipient_hi: recipientHi.toString(),
    recipient_lo: recipientLo.toString(),
    pool_merkle_root: poolRootBig.toString(),
    pool_nullifier_hash: poolNullifierHashBig.toString(),
    new_stored_commitment: newStoredCommitment.toString(),
    recipient_hash: recipientField.toString(),
  };

  console.log("  generating V3 proof (can take 5-15s)...");
  const { proof: v3Proof } = await snarkjs.groth16.fullProve(circuitInput, V3_WASM, V3_ZKEY);
  const { proofA, proofB, proofC } = serializeProof(v3Proof);

  // Public inputs packed: pool_root(32) + new_stored_commitment(32) = 64 bytes
  // (pool_nullifier_hash and recipient are handled via instruction args / derived)
  const opaqueInputs = Buffer.concat([
    poolTree.currentRoot,
    bigintToBytes32BE(newStoredCommitment),
  ]);

  const creditNotePDA = pda([Buffer.from("credit"), poolNullifierHashBytes]);
  const poolNullifierAccount = pda([Buffer.from("pool_nullifier"), poolNullifierHashBytes]);

  const claimIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: notePool, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: false },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: poolNullifierAccount, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("claim_from_note_pool"),
      poolNullifierHashBytes,
      proofA, proofB, proofC,
      u32LE(opaqueInputs.length), opaqueInputs,
    ]),
  });
  const tx4 = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
    claimIx,
  );
  const sig4 = await sendAndConfirmTransaction(connection, tx4, [payer]);
  console.log(`  TX: ${sig4}`);

  // ── STEP 5: withdraw_credit ──
  console.log("\n[5] withdraw_credit (recipient gets SOL)");
  const recipientBefore = await connection.getBalance(recipient.publicKey);
  const opening = Buffer.concat([u64LE(amount), bigintToBytes32BE(newBlinding), bigintToBytes32BE(newSalt)]);
  const rateBuf = Buffer.alloc(2); // rate = 0 (direct, no fee)

  const withdrawIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },  // recipient
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },       // payer (also fee recipient post I-04)
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("withdraw_credit"),
      poolNullifierHashBytes,
      u32LE(opening.length), opening,
      rateBuf,
    ]),
  });
  const sig5 = await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [payer]);
  console.log(`  TX: ${sig5}`);

  const recipientAfter = await connection.getBalance(recipient.publicKey);
  const delta = recipientAfter - recipientBefore;
  console.log(`  recipient delta: +${delta} (expect +${amount})`);

  const treasuryFinal = (await connection.getAccountInfo(treasury)).lamports;
  console.log(`  treasury final: ${treasuryFinal}`);

  if (BigInt(delta) !== amount) throw new Error("recipient received wrong amount");

  console.log("\n=== TEST PASSED ===");
  console.log("  create_drop_to_pool -> claim_from_note_pool -> withdraw_credit: full round trip succeeded");
}

main().then(() => process.exit(0)).catch((e) => {
  console.error("FATAL:", e.message || e);
  if (e.logs) e.logs.forEach((l) => console.error("  " + l));
  process.exit(1);
});
