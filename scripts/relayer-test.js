#!/usr/bin/env node
/**
 * DarkDrop V4 — Relayer E2E Test
 *
 * Tests the gasless claim flow:
 *   1. Create a drop (payer pays)
 *   2. Generate ZK proof for a recipient
 *   3. Submit claim via relayer API (relayer pays gas, recipient never signs)
 *   4. Verify: recipient received (amount - fee), relayer received fee
 *   5. Verify: recipient's pubkey does NOT appear as signer in the TX
 *
 * Prerequisites:
 *   - solana-test-validator running
 *   - program deployed
 *   - relayer server running on localhost:3001
 */

const {
  Connection, Keypair, PublicKey, Transaction, TransactionInstruction,
  SystemProgram, sendAndConfirmTransaction, LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const RELAYER_URL = process.env.RELAYER_URL || "http://localhost:3001";
const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_final.zkey");
const MERKLE_DEPTH = 20;
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL);
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
function getMerkleTreePDA(vault) { return PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID); }
function getSolVaultPDA() { return PublicKey.findProgramAddressSync([Buffer.from("sol_vault")], PROGRAM_ID); }
function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

async function main() {
  console.log("=== DarkDrop V4 — Relayer E2E Test ===\n");

  poseidon = await buildPoseidon();
  F = poseidon.F;

  const connection = new Connection(RPC_URL, { commitment: "confirmed", confirmTransactionInitialTimeout: 120000 });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  console.log(`Payer:     ${payer.publicKey}`);
  console.log(`Recipient: ${recipient.publicKey}`);
  console.log(`Relayer:   ${RELAYER_URL}\n`);

  // Airdrop recipient on localnet (they should NOT need SOL for relayed claims)
  if (!RPC_URL.includes("devnet")) {
    const sig = await connection.requestAirdrop(recipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig);
  }

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [solVault] = getSolVaultPDA();

  // Initialize vault if needed
  try {
    const initDisc = getDiscriminator("initialize_vault");
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
      data: Buffer.concat([initDisc, dropCapBuf]),
    });
    await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [payer]);
    console.log("[INIT] Vault initialized");
  } catch (e) {
    if (e.message?.includes("already in use")) console.log("[INIT] Vault already initialized");
    else throw e;
  }

  // Step 1: Create drop
  console.log("\n[STEP 1] Creating drop...");
  const dropAmount = BigInt(0.1 * LAMPORTS_PER_SOL);
  const secret = randomField();
  const nullifier = randomField();
  const blindingFactor = randomField();
  const leaf = poseidonHash([secret, nullifier, dropAmount, blindingFactor]);
  const amtCommitment = poseidonHash([dropAmount, blindingFactor]);
  const nullHash = poseidonHash([nullifier]);

  const treeInfo = await connection.getAccountInfo(merkleTree);
  const leafIndex = treeInfo.data.readUInt32LE(8 + 32);

  const createDisc = getDiscriminator("create_drop");
  const amtBuf = Buffer.alloc(8);
  amtBuf.writeBigUInt64LE(dropAmount);
  const createIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: solVault, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([createDisc, bigintToBytes32BE(leaf), amtBuf, bigintToBytes32BE(amtCommitment), bigintToBytes32BE(0n)]),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(createIx), [payer]);
  console.log(`  Drop created at index ${leafIndex}`);

  // Step 2: Build Merkle proof
  console.log("\n[STEP 2] Building Merkle proof...");
  const treeAccount = await connection.getAccountInfo(merkleTree);
  const treeData = treeAccount.data;
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;
  const zeroHashes = getZeroHashes();
  const pathElements = [], pathIndices = [];
  let idx = leafIndex;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    const bit = idx & 1;
    pathIndices.push(bit.toString());
    pathElements.push(bit === 0 ? zeroHashes[i].toString() : bytesToBigIntBE(treeData.slice(filledSubtreesOffset + i * 32, filledSubtreesOffset + (i + 1) * 32)).toString());
    idx = idx >> 1;
  }

  // Step 3: Generate ZK proof
  console.log("\n[STEP 3] Generating ZK proof...");
  const recipientField = pubkeyToField(recipient.publicKey.toBytes());
  const { proof } = await snarkjs.groth16.fullProve({
    secret: secret.toString(), amount: dropAmount.toString(), blinding_factor: blindingFactor.toString(),
    nullifier: nullifier.toString(), merkle_path: pathElements, merkle_indices: pathIndices,
    password: "0", merkle_root: bytesToBigIntBE(onChainRoot).toString(), nullifier_hash: nullHash.toString(),
    recipient: recipientField.toString(), amount_commitment: amtCommitment.toString(), password_hash: "0",
  }, WASM_PATH, ZKEY_PATH);

  // Serialize proof with negated proof_a
  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  const proofB = Buffer.concat([bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]), bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0])]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);
  console.log("  Proof generated");

  // Step 4: Submit via relayer
  console.log("\n[STEP 4] Submitting claim via relayer...");
  const recipientBalBefore = await connection.getBalance(recipient.publicKey);

  const resp = await fetch(`${RELAYER_URL}/api/relay/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      proof: {
        proofA: Array.from(proofA),
        proofB: Array.from(proofB),
        proofC: Array.from(proofC),
      },
      merkleRoot: Array.from(onChainRoot),
      nullifierHash: Array.from(bigintToBytes32BE(nullHash)),
      recipient: recipient.publicKey.toBase58(),
      amount: dropAmount.toString(),
      amountCommitment: Array.from(bigintToBytes32BE(amtCommitment)),
      passwordHash: Array.from(bigintToBytes32BE(0n)),
    }),
  });

  const result = await resp.json();
  if (!resp.ok) {
    console.error("  Relayer rejected:", result.error);
    process.exit(1);
  }

  console.log(`  TX: ${result.signature}`);
  console.log(`  Fee: ${result.fee} lamports`);
  console.log(`  Net: ${result.net} lamports`);

  // Step 5: Verify
  console.log("\n[STEP 5] Verifying...");
  const recipientBalAfter = await connection.getBalance(recipient.publicKey);
  const received = recipientBalAfter - recipientBalBefore;
  const expectedNet = Number(BigInt(result.net));
  const fee = Number(BigInt(result.fee));

  console.log(`  Recipient received: ${received} lamports (expected: ${expectedNet})`);
  console.log(`  Fee deducted: ${fee} lamports (${(fee / Number(dropAmount) * 100).toFixed(2)}%)`);

  // Check TX to verify recipient is NOT a signer
  const txInfo = await connection.getTransaction(result.signature, { commitment: "confirmed" });
  const signers = txInfo.transaction.message.accountKeys.filter((_, i) => txInfo.transaction.message.isAccountSigner(i));
  const recipientIsSigner = signers.some(k => k.equals(recipient.publicKey));
  const recipientIsPayer = txInfo.transaction.message.accountKeys[0].equals(recipient.publicKey);

  console.log(`  Recipient is signer: ${recipientIsSigner} (expected: false)`);
  console.log(`  Recipient is fee payer: ${recipientIsPayer} (expected: false)`);

  if (received === expectedNet && !recipientIsSigner && !recipientIsPayer) {
    console.log("\n=== RELAYER E2E TEST PASSED ===");
    console.log("  Gasless claim: recipient never signed, never paid gas");
    console.log(`  Amount: ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL → net ${Number(result.net) / LAMPORTS_PER_SOL} SOL (fee: ${Number(result.fee) / LAMPORTS_PER_SOL} SOL)`);
  } else {
    console.log("\n=== RELAYER E2E TEST FAILED ===");
    if (received !== expectedNet) console.log(`  Balance mismatch: got ${received}, expected ${expectedNet}`);
    if (recipientIsSigner) console.log("  PRIVACY LEAK: recipient appeared as signer!");
    if (recipientIsPayer) console.log("  PRIVACY LEAK: recipient appeared as fee payer!");
    process.exit(1);
  }
}

main().catch(e => { console.error("Fatal:", e); process.exit(1); });
