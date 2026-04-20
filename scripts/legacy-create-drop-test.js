#!/usr/bin/env node
/**
 * DarkDrop V4 — Legacy create_drop backward-compat test
 *
 * Regression guard for the seeder and any unupdated client that passes the
 * ORIGINAL five accounts to create_drop (no remaining_accounts for
 * DepositReceipt). Fails loudly if the new DepositReceipt path ever becomes
 * required instead of optional.
 *
 * Checks:
 *   1. create_drop with 5 accounts succeeds
 *   2. No DepositReceipt PDA is created for that leaf
 *   3. claim_credit still works on the drop (V2 proof round-trip)
 *
 * Run:
 *   PROGRAM_ID=<id> RPC_URL=http://127.0.0.1:8899 node scripts/legacy-create-drop-test.js
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
  console.log("=== DarkDrop V4 — Legacy create_drop Compat Test ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 120000,
  });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [treasury] = getTreasuryPDA();

  // ─── Init vault if needed ─────────────────────────────────────────────────
  const dropCapBuf = Buffer.alloc(8); dropCapBuf.writeBigUInt64LE(DROP_CAP);
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
      data: Buffer.concat([getDiscriminator("initialize_vault"), dropCapBuf]),
    })), [payer]);
  } catch (e) {
    if (!e.message?.includes("already in use")) throw e;
  }

  // ─── Step 1: create_drop with EXACTLY 5 accounts (legacy seeder path) ────
  console.log("[1] create_drop with 5 declared accounts only (no remaining_accounts)");

  const dropAmount = BigInt(0.03 * LAMPORTS_PER_SOL);
  const secret = randomField();
  const nullifier = randomField();
  const blinding = randomField();
  const leafBig = poseidonHash([secret, nullifier, dropAmount, blinding]);
  const leafBytes = bigintToBytes32BE(leafBig);
  const amtCommitment = poseidonHash([dropAmount, blinding]);
  const [expectedReceipt] = getReceiptPDA(leafBytes);

  const amountBuf = Buffer.alloc(8); amountBuf.writeBigUInt64LE(dropAmount);
  const createIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      // EXACTLY the 5 accounts the seeder sends. NO remaining_accounts.
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      getDiscriminator("create_drop"),
      leafBytes,
      amountBuf,
      bigintToBytes32BE(amtCommitment),
      bigintToBytes32BE(0n),
    ]),
  });

  const treasuryBefore = await connection.getBalance(treasury);
  const createSig = await sendAndConfirmTransaction(
    connection, new Transaction().add(createIx), [payer]
  );
  const treasuryAfter = await connection.getBalance(treasury);
  console.log(`    TX: ${createSig}`);
  console.log(`    Treasury: +${treasuryAfter - treasuryBefore} (expect +${dropAmount})`);
  if (BigInt(treasuryAfter - treasuryBefore) !== dropAmount) {
    console.log("  [FAIL] treasury delta mismatch");
    process.exit(1);
  }
  console.log("    [PASS] create_drop with 5 accounts succeeded\n");

  // ─── Step 2: Confirm NO DepositReceipt was created ────────────────────────
  console.log("[2] Verify no DepositReceipt PDA exists for this leaf");
  const receiptInfo = await connection.getAccountInfo(expectedReceipt);
  if (receiptInfo !== null) {
    console.log(`  [FAIL] receipt unexpectedly exists: ${expectedReceipt}`);
    console.log(`         data length=${receiptInfo.data.length}, owner=${receiptInfo.owner}`);
    process.exit(1);
  }
  console.log(`    Receipt PDA ${expectedReceipt}: not created`);
  console.log("    [PASS] legacy drops produce no receipt (revoke is unavailable as designed)\n");

  // ─── Step 3: claim_credit on the legacy drop still works ─────────────────
  console.log("[3] Running claim_credit on the legacy-created drop (V2 proof)");

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

  const opaqueInputs = Buffer.concat([
    onChainRoot,
    bigintToBytes32BE(amtCommitment),
    bigintToBytes32BE(0n),
  ]);
  const inputsLen = Buffer.alloc(4); inputsLen.writeUInt32LE(opaqueInputs.length);
  const salt = randomField();

  const [nullifierPDA] = getNullifierPDA(nullHashBytes);
  const [creditNotePDA] = getCreditNotePDA(nullHashBytes);

  const claimIx = new TransactionInstruction({
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

  const claimSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), claimIx),
    [payer]
  );
  console.log(`    TX: ${claimSig}`);

  const creditInfo = await connection.getAccountInfo(creditNotePDA);
  if (!creditInfo) {
    console.log("  [FAIL] CreditNote PDA not created");
    process.exit(1);
  }
  const nullInfo = await connection.getAccountInfo(nullifierPDA);
  if (!nullInfo) {
    console.log("  [FAIL] Nullifier PDA not created");
    process.exit(1);
  }
  console.log("    [PASS] claim_credit succeeded on the legacy-created drop\n");

  console.log("=== LEGACY COMPAT TEST PASSED ===");
  console.log("Seeder's 5-account create_drop path is safe after the upgrade.");
}

main().then(() => process.exit(0)).catch(e => {
  console.error("Fatal:", e.message);
  if (e.logs) e.logs.forEach(l => console.error(`  ${l}`));
  process.exit(1);
});
