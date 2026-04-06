#!/usr/bin/env node
/**
 * DarkDrop V4 — Security Tests
 *
 * Tests:
 *   1. Double-claim: same nullifier must fail on second claim
 *   2. Invalid proof: garbage proof bytes must fail with InvalidProof
 *   3. Wrong password: wrong password must fail
 *   4. Wrong recipient: proof for wallet A, claim TX with wallet B must fail
 *   5. Amount tampering: proof for 0.1 SOL, claim with 1 SOL must fail
 *   6. Exhausted root: root pushed out of 30-root history must fail
 *
 * Runs against localnet:
 *   solana-test-validator --reset
 *   solana program deploy target/deploy/darkdrop.so --url localhost
 *   node scripts/security-tests.js
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
const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_final.zkey");
const VK_PATH = path.join(BUILD_DIR, "verification_key.json");
const MERKLE_DEPTH = 20;
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL);

// BN254 base field modulus
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
  const hash = crypto.createHash("sha256").update(`global:${name}`).digest();
  return hash.slice(0, 8);
}

function getVaultPDA() {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
}
function getMerkleTreePDA(vault) {
  return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID);
}
function getSolVaultPDA() {
  return PublicKey.findProgramAddressSync([Buffer.from("sol_vault")], PROGRAM_ID);
}
function getNullifierPDA(nullifierHash) {
  return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nullifierHash], PROGRAM_ID);
}

function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

// Read on-chain tree state and compute merkle proof for a given leaf index
async function getOnChainMerkleProof(connection, merkleTree, leafIndex) {
  const treeAccountInfo = await connection.getAccountInfo(merkleTree);
  const treeData = treeAccountInfo.data;
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;
  const filledSubtrees = [];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    filledSubtrees.push(treeData.slice(filledSubtreesOffset + i * 32, filledSubtreesOffset + (i + 1) * 32));
  }

  const zeroHashes = getZeroHashes();
  const pathElements = [];
  const pathIndices = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit.toString());
    if (bit === 0) {
      pathElements.push(zeroHashes[i].toString());
    } else {
      pathElements.push(bytesToBigIntBE(filledSubtrees[i]).toString());
    }
    idx = idx >> 1;
  }

  return {
    root: onChainRoot,
    rootBigInt: bytesToBigIntBE(onChainRoot),
    pathElements,
    pathIndices,
  };
}

// Create a drop and return all values needed for claiming
async function createDrop(connection, payer, amount) {
  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [solVault] = getSolVaultPDA();

  const secret = randomField();
  const nullifier = randomField();
  const blindingFactor = randomField();

  const leaf = poseidonHash([secret, nullifier, amount, blindingFactor]);
  const amtCommitment = poseidonHash([amount, blindingFactor]);
  const nullHash = poseidonHash([nullifier]);

  // Read next_index before insert
  const treeAccountInfo = await connection.getAccountInfo(merkleTree);
  const nextIndex = treeAccountInfo.data.readUInt32LE(8 + 32);

  const createDiscriminator = getDiscriminator("create_drop");
  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(amount);

  const createIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: solVault, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      createDiscriminator,
      bigintToBytes32BE(leaf),
      amountBuf,
      bigintToBytes32BE(amtCommitment),
      bigintToBytes32BE(0n), // no password
    ]),
  });

  const tx = new Transaction().add(createIx);
  await sendAndConfirmTransaction(connection, tx, [payer]);

  return {
    secret,
    nullifier,
    amount,
    blindingFactor,
    leaf,
    amtCommitment,
    nullHash,
    leafIndex: nextIndex,
  };
}

// Create a password-protected drop
async function createDropWithPassword(connection, payer, amount, password) {
  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [solVault] = getSolVaultPDA();

  const secret = randomField();
  const nullifier = randomField();
  const blindingFactor = randomField();

  const leaf = poseidonHash([secret, nullifier, amount, blindingFactor]);
  const amtCommitment = poseidonHash([amount, blindingFactor]);
  const pwdHash = poseidonHash([password]);
  const nullHash = poseidonHash([nullifier]);

  const treeAccountInfo = await connection.getAccountInfo(merkleTree);
  const nextIndex = treeAccountInfo.data.readUInt32LE(8 + 32);

  const createDiscriminator = getDiscriminator("create_drop");
  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(amount);

  const createIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: solVault, isSigner: false, isWritable: true },
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

  const tx = new Transaction().add(createIx);
  await sendAndConfirmTransaction(connection, tx, [payer]);

  return {
    secret,
    nullifier,
    amount,
    blindingFactor,
    password,
    leaf,
    amtCommitment,
    pwdHash,
    nullHash,
    leafIndex: nextIndex,
  };
}

// Generate a ZK proof for claiming
async function generateProof(drop, recipientPubkey, merkleProof, overrides = {}) {
  const recipientField = pubkeyToField(recipientPubkey.toBytes());
  const password = overrides.password !== undefined ? overrides.password : (drop.password || 0n);
  const pwdHash = password !== 0n ? poseidonHash([password]) : 0n;

  const circuitInput = {
    secret: drop.secret.toString(),
    amount: (overrides.amount || drop.amount).toString(),
    blinding_factor: drop.blindingFactor.toString(),
    nullifier: drop.nullifier.toString(),
    merkle_path: merkleProof.pathElements,
    merkle_indices: merkleProof.pathIndices,
    password: password.toString(),
    merkle_root: merkleProof.rootBigInt.toString(),
    nullifier_hash: drop.nullHash.toString(),
    recipient: recipientField.toString(),
    amount_commitment: drop.amtCommitment.toString(),
    password_hash: (overrides.pwdHash !== undefined ? overrides.pwdHash : (drop.pwdHash || 0n)).toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

// Build claim TX data
function buildClaimTxData(proof, merkleRoot, nullifierHash, amount, amtCommitment, pwdHash) {
  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  const proofB = Buffer.concat([
    bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]),
    bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0]),
  ]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);

  const claimDiscriminator = getDiscriminator("claim");
  const claimAmountBuf = Buffer.alloc(8);
  claimAmountBuf.writeBigUInt64LE(amount);

  const feeBuf = Buffer.alloc(8); // fee_lamports = 0 for direct claims
  feeBuf.writeBigUInt64LE(0n);

  return Buffer.concat([
    claimDiscriminator,
    proofA,
    proofB,
    proofC,
    merkleRoot,
    bigintToBytes32BE(nullifierHash),
    claimAmountBuf,
    bigintToBytes32BE(amtCommitment),
    bigintToBytes32BE(pwdHash),
    feeBuf,
  ]);
}

// Submit a claim TX
async function submitClaim(connection, payer, recipient, claimData) {
  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [solVault] = getSolVaultPDA();

  const nullifierHashOffset = 8 + 64 + 128 + 64 + 32; // after discriminator + proofA + proofB + proofC + merkle_root
  const nullifierHashBytes = claimData.slice(nullifierHashOffset, nullifierHashOffset + 32);
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);

  const claimIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: solVault, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: false, isWritable: true }, // fee_recipient
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: claimData,
  });

  const claimTx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    claimIx,
  );
  return await sendAndConfirmTransaction(connection, claimTx, [payer]);
}

// Expect a TX to fail with a specific error
async function expectFailure(name, txPromise, expectedError) {
  try {
    await txPromise;
    console.log(`  FAIL: ${name} — expected failure but TX succeeded`);
    return false;
  } catch (e) {
    const msg = e.message || "";
    const logs = e.logs || [];
    const allText = msg + " " + logs.join(" ");
    if (expectedError && !allText.includes(expectedError)) {
      console.log(`  FAIL: ${name} — failed but not with expected error "${expectedError}"`);
      console.log(`    Got: ${msg.slice(0, 200)}`);
      if (logs.length) console.log(`    Logs: ${logs.slice(-3).join("\n          ")}`);
      return false;
    }
    console.log(`  PASS: ${name}`);
    return true;
  }
}

async function initializeVault(connection, payer) {
  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [solVault] = getSolVaultPDA();

  const initDiscriminator = getDiscriminator("initialize_vault");
  const dropCapBuf = Buffer.alloc(8);
  dropCapBuf.writeBigUInt64LE(DROP_CAP);

  const initIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: solVault, isSigner: false, isWritable: false },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([initDiscriminator, dropCapBuf]),
  });

  try {
    const tx = new Transaction().add(initIx);
    await sendAndConfirmTransaction(connection, tx, [payer]);
    console.log("  Vault initialized");
  } catch (e) {
    if (e.message?.includes("already in use")) {
      console.log("  Vault already initialized (skipping)");
    } else {
      throw e;
    }
  }
}

async function main() {
  console.log("=== DarkDrop V4 — Security Tests ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 120000,
  });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  console.log(`Payer: ${payer.publicKey}`);
  console.log(`RPC:   ${RPC_URL}\n`);

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);

  // Initialize vault
  await initializeVault(connection, payer);

  let passed = 0;
  let failed = 0;

  // ============================================
  // TEST 1: Double-claim
  // ============================================
  console.log("\n[TEST 1] Double-claim prevention...");
  {
    const recipient = Keypair.generate();
    if (!RPC_URL.includes("devnet")) {
      await connection.requestAirdrop(recipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
      await new Promise(r => setTimeout(r, 1000));
    }

    const drop = await createDrop(connection, payer, BigInt(0.05 * LAMPORTS_PER_SOL));
    console.log(`  Drop created at index ${drop.leafIndex}`);

    const merkleProof = await getOnChainMerkleProof(connection, merkleTree, drop.leafIndex);
    const { proof } = await generateProof(drop, recipient.publicKey, merkleProof);

    const claimData = buildClaimTxData(
      proof, merkleProof.root, drop.nullHash,
      drop.amount, drop.amtCommitment, 0n,
    );

    // First claim should succeed
    await submitClaim(connection, payer, recipient.publicKey, claimData);
    console.log("  First claim succeeded");

    // Second claim with same nullifier should fail
    const ok = await expectFailure(
      "Double-claim rejected",
      submitClaim(connection, payer, recipient.publicKey, claimData),
      null, // Anchor init constraint fails — "already in use" or custom error
    );
    if (ok) passed++; else failed++;
  }

  // ============================================
  // TEST 2: Invalid proof (garbage bytes)
  // ============================================
  console.log("\n[TEST 2] Invalid proof rejection...");
  {
    const recipient = Keypair.generate();
    const drop = await createDrop(connection, payer, BigInt(0.05 * LAMPORTS_PER_SOL));
    console.log(`  Drop created at index ${drop.leafIndex}`);

    // Build claim data with garbage proof bytes
    const garbageProof = {
      pi_a: [randomField().toString(), randomField().toString()],
      pi_b: [[randomField().toString(), randomField().toString()], [randomField().toString(), randomField().toString()]],
      pi_c: [randomField().toString(), randomField().toString()],
    };

    const merkleProof = await getOnChainMerkleProof(connection, merkleTree, drop.leafIndex);
    const claimData = buildClaimTxData(
      garbageProof, merkleProof.root, drop.nullHash,
      drop.amount, drop.amtCommitment, 0n,
    );

    const ok = await expectFailure(
      "Garbage proof rejected",
      submitClaim(connection, payer, recipient.publicKey, claimData),
      "InvalidProof",
    );
    if (ok) passed++; else failed++;
  }

  // ============================================
  // TEST 3: Wrong password
  // ============================================
  console.log("\n[TEST 3] Wrong password rejection...");
  {
    const recipient = Keypair.generate();
    if (!RPC_URL.includes("devnet")) {
      await connection.requestAirdrop(recipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
      await new Promise(r => setTimeout(r, 1000));
    }

    const correctPassword = 12345n;
    const wrongPassword = 99999n;
    const drop = await createDropWithPassword(connection, payer, BigInt(0.05 * LAMPORTS_PER_SOL), correctPassword);
    console.log(`  Password-protected drop created at index ${drop.leafIndex}`);

    const merkleProof = await getOnChainMerkleProof(connection, merkleTree, drop.leafIndex);

    // Try to generate proof with wrong password — this should fail at proof generation
    // because the circuit constraints won't be satisfied
    try {
      await generateProof(drop, recipient.publicKey, merkleProof, { password: wrongPassword, pwdHash: drop.pwdHash });
      // If proof generation somehow succeeded, submit and expect on-chain failure
      console.log("  FAIL: Wrong password — proof generation should have failed");
      failed++;
    } catch (e) {
      console.log(`  PASS: Wrong password rejected at proof generation (circuit constraint failure)`);
      passed++;
    }
  }

  // ============================================
  // TEST 4: Wrong recipient
  // ============================================
  console.log("\n[TEST 4] Wrong recipient rejection...");
  {
    const intendedRecipient = Keypair.generate();
    const wrongRecipient = Keypair.generate();

    if (!RPC_URL.includes("devnet")) {
      await connection.requestAirdrop(intendedRecipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
      await connection.requestAirdrop(wrongRecipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
      await new Promise(r => setTimeout(r, 1000));
    }

    const drop = await createDrop(connection, payer, BigInt(0.05 * LAMPORTS_PER_SOL));
    console.log(`  Drop created at index ${drop.leafIndex}`);

    const merkleProof = await getOnChainMerkleProof(connection, merkleTree, drop.leafIndex);

    // Generate proof for intended recipient
    const { proof } = await generateProof(drop, intendedRecipient.publicKey, merkleProof);

    // Build claim data with proof for intended recipient
    const claimData = buildClaimTxData(
      proof, merkleProof.root, drop.nullHash,
      drop.amount, drop.amtCommitment, 0n,
    );

    // Submit claim TX with wrong recipient — the on-chain recipient hash won't match
    const ok = await expectFailure(
      "Wrong recipient rejected",
      submitClaim(connection, payer, wrongRecipient.publicKey, claimData),
      "InvalidProof",
    );
    if (ok) passed++; else failed++;
  }

  // ============================================
  // TEST 5: Amount tampering
  // ============================================
  console.log("\n[TEST 5] Amount tampering rejection...");
  {
    const recipient = Keypair.generate();
    if (!RPC_URL.includes("devnet")) {
      await connection.requestAirdrop(recipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
      await new Promise(r => setTimeout(r, 1000));
    }

    const realAmount = BigInt(0.05 * LAMPORTS_PER_SOL);
    const tamperedAmount = BigInt(1 * LAMPORTS_PER_SOL);

    const drop = await createDrop(connection, payer, realAmount);
    console.log(`  Drop created at index ${drop.leafIndex} (real amount: ${Number(realAmount) / LAMPORTS_PER_SOL} SOL)`);

    const merkleProof = await getOnChainMerkleProof(connection, merkleTree, drop.leafIndex);

    // Generate valid proof for real amount
    const { proof } = await generateProof(drop, recipient.publicKey, merkleProof);

    // Build claim data but substitute tampered amount
    const claimData = buildClaimTxData(
      proof, merkleProof.root, drop.nullHash,
      tamperedAmount, // tampered!
      drop.amtCommitment, 0n,
    );

    const ok = await expectFailure(
      "Amount tampering rejected",
      submitClaim(connection, payer, recipient.publicKey, claimData),
      "InvalidProof",
    );
    if (ok) passed++; else failed++;
  }

  // ============================================
  // TEST 6: Exhausted root (31+ drops to push root out of history)
  // ============================================
  console.log("\n[TEST 6] Exhausted root rejection...");
  {
    const recipient = Keypair.generate();
    if (!RPC_URL.includes("devnet")) {
      await connection.requestAirdrop(recipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
      await new Promise(r => setTimeout(r, 1000));
    }

    // Create a drop and save its root
    const targetDrop = await createDrop(connection, payer, BigInt(0.05 * LAMPORTS_PER_SOL));
    const targetMerkleProof = await getOnChainMerkleProof(connection, merkleTree, targetDrop.leafIndex);
    const savedRoot = Buffer.from(targetMerkleProof.root);
    console.log(`  Target drop at index ${targetDrop.leafIndex}, saving root...`);

    // Generate proof using current root (before it's pushed out)
    const { proof } = await generateProof(targetDrop, recipient.publicKey, targetMerkleProof);

    // Create 31 more drops to push the saved root out of the 30-root history
    console.log("  Creating 31 drops to exhaust root history...");
    for (let i = 0; i < 31; i++) {
      await createDrop(connection, payer, BigInt(0.01 * LAMPORTS_PER_SOL));
      if ((i + 1) % 10 === 0) console.log(`    ${i + 1}/31 drops created`);
    }
    console.log("    31/31 drops created");

    // Build claim data using the saved (now-expired) root
    const claimData = buildClaimTxData(
      proof, savedRoot, targetDrop.nullHash,
      targetDrop.amount, targetDrop.amtCommitment, 0n,
    );

    const ok = await expectFailure(
      "Exhausted root rejected",
      submitClaim(connection, payer, recipient.publicKey, claimData),
      "InvalidRoot",
    );
    if (ok) passed++; else failed++;
  }

  // ============================================
  // SUMMARY
  // ============================================
  console.log(`\n${"=".repeat(50)}`);
  console.log(`Security Tests: ${passed} passed, ${failed} failed out of ${passed + failed}`);
  console.log(`${"=".repeat(50)}`);

  if (failed > 0) process.exit(1);
}

main().catch(e => {
  console.error("Fatal:", e);
  process.exit(1);
});
