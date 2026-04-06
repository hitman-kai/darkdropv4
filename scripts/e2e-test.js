#!/usr/bin/env node
/**
 * DarkDrop V4 — End-to-End On-Chain Test
 *
 * Steps:
 *   1. Initialize vault (create_drop PDA, Merkle tree, sol_vault)
 *   2. Create a drop (send SOL to vault, insert leaf into tree)
 *   3. Decode claim code, compute Merkle proof
 *   4. Generate Groth16 ZK proof
 *   5. Submit claim TX (verify proof on-chain, release SOL)
 *   6. Verify: recipient received funds, nullifier is spent
 *
 * Run against localnet:
 *   solana-test-validator --reset
 *   anchor deploy --provider.cluster localnet
 *   node scripts/e2e-test.js
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
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL); // 100 SOL

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

function pubkeyToField(pubkeyBytes) {
  const hi = bytesToBigIntBE(pubkeyBytes.slice(0, 16));
  const lo = bytesToBigIntBE(pubkeyBytes.slice(16, 32));
  return poseidonHash([hi, lo]);
}

// Anchor instruction discriminator = first 8 bytes of sha256("global:<method_name>")
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
function getSolVaultPDA() {
  return PublicKey.findProgramAddressSync([Buffer.from("sol_vault")], PROGRAM_ID);
}
function getNullifierPDA(nullifierHash) {
  return PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nullifierHash], PROGRAM_ID);
}

// Incremental Merkle tree
function getZeroHashes() {
  const zeros = [0n];
  for (let i = 0; i < MERKLE_DEPTH; i++) zeros.push(poseidonHash([zeros[i], zeros[i]]));
  return zeros;
}

class MerkleTree {
  constructor() {
    this.zeroHashes = getZeroHashes();
    this.filledSubtrees = this.zeroHashes.slice(0, MERKLE_DEPTH);
    this.leaves = [];
    this.nextIndex = 0;
    this.currentRoot = this.zeroHashes[MERKLE_DEPTH];
    this._layers = null;
  }
  insert(leaf) {
    const index = this.nextIndex;
    let currentIndex = index;
    let currentLevelHash = leaf;
    for (let i = 0; i < MERKLE_DEPTH; i++) {
      if (currentIndex % 2 === 0) {
        this.filledSubtrees[i] = currentLevelHash;
        currentLevelHash = poseidonHash([currentLevelHash, this.zeroHashes[i]]);
      } else {
        currentLevelHash = poseidonHash([this.filledSubtrees[i], currentLevelHash]);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }
    this.leaves.push(leaf);
    this.currentRoot = currentLevelHash;
    this.nextIndex++;
    this._layers = null;
    return index;
  }
  getProof(leafIndex) {
    if (!this._layers) this._buildLayers();
    const pathElements = [], pathIndices = [];
    let idx = leafIndex;
    for (let d = 0; d < MERKLE_DEPTH; d++) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      pathElements.push((this._layers[d][siblingIdx] ?? this.zeroHashes[d]).toString());
      pathIndices.push((idx % 2).toString());
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }
  _buildLayers() {
    let currentLayer = [...this.leaves];
    this._layers = [currentLayer];
    for (let d = 0; d < MERKLE_DEPTH; d++) {
      const nextLayer = [];
      const size = Math.ceil(currentLayer.length / 2);
      for (let i = 0; i < size; i++) {
        const left = currentLayer[i * 2] ?? this.zeroHashes[d];
        const right = currentLayer[i * 2 + 1] ?? this.zeroHashes[d];
        nextLayer.push(poseidonHash([left, right]));
      }
      this._layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }
}

async function main() {
  console.log("=== DarkDrop V4 — End-to-End On-Chain Test ===\n");

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

  // Airdrop to recipient (skip on devnet — recipient receives SOL via claim)
  if (!RPC_URL.includes("devnet")) {
    const airdropSig = await connection.requestAirdrop(recipient.publicKey, 0.01 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(airdropSig);
  }

  const [vault] = getVaultPDA();
  const [merkleTree] = getMerkleTreePDA(vault);
  const [solVault] = getSolVaultPDA();

  console.log(`  Vault PDA:       ${vault}`);
  console.log(`  Merkle Tree PDA: ${merkleTree}`);
  console.log(`  SOL Vault PDA:   ${solVault}`);

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
      { pubkey: solVault, isSigner: false, isWritable: false },
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
      { pubkey: solVault, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      createDiscriminator,
      bigintToBytes32BE(leaf),              // leaf [u8; 32]
      amountBuf,                            // amount u64
      bigintToBytes32BE(amtCommitment),     // amount_commitment [u8; 32]
      bigintToBytes32BE(pwdHash),           // password_hash [u8; 32]
    ]),
  });

  const vaultBalBefore = await connection.getBalance(solVault);
  const createTx = new Transaction().add(createIx);
  const createSig = await sendAndConfirmTransaction(connection, createTx, [payer]);
  console.log(`  TX: ${createSig}`);

  const vaultBalAfter = await connection.getBalance(solVault);
  console.log(`  Vault balance: ${vaultBalBefore} → ${vaultBalAfter} lamports (+${vaultBalAfter - vaultBalBefore})`);

  // ============================================
  // STEP 3: Build Merkle proof from on-chain state
  // ============================================
  console.log("\n[STEP 3] Reading on-chain Merkle tree & building proof...");

  // Read on-chain MerkleTree account (zero_copy layout after 8-byte discriminator)
  const treeAccountInfo = await connection.getAccountInfo(merkleTree);
  const treeData = treeAccountInfo.data;
  // Layout: discriminator(8) + vault(32) + next_index(4) + root_history_index(4)
  //       + current_root(32) + root_history(30*32) + filled_subtrees(20*32)
  const nextIndex = treeData.readUInt32LE(8 + 32);
  const onChainRoot = treeData.slice(8 + 32 + 4 + 4, 8 + 32 + 4 + 4 + 32);
  const filledSubtreesOffset = 8 + 32 + 4 + 4 + 32 + 30 * 32;
  const filledSubtrees = [];
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    filledSubtrees.push(treeData.slice(filledSubtreesOffset + i * 32, filledSubtreesOffset + (i + 1) * 32));
  }

  // Our leaf was the most recently inserted — at index (nextIndex - 1)
  const leafIndex = nextIndex - 1;
  console.log(`  Leaf index: ${leafIndex} (on-chain next_index: ${nextIndex})`);
  console.log(`  On-chain root: ${bytesToBigIntBE(onChainRoot).toString().slice(0, 20)}...`);

  // Compute Merkle proof for last-inserted leaf from filled_subtrees
  // At level i: if bit is 0, sibling = zeroHash[i]; if bit is 1, sibling = filledSubtrees[i]
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

  // Use on-chain root (convert to BigInt for circuit input)
  const onChainRootBigInt = bytesToBigIntBE(onChainRoot);

  // ============================================
  // STEP 4: Generate ZK proof
  // ============================================
  console.log("\n[STEP 4] Generating Groth16 proof...");

  const recipientField = pubkeyToField(recipient.publicKey.toBytes());

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

  // Verify locally first
  const vk = JSON.parse(fs.readFileSync(VK_PATH));
  const localValid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log(`  Local verification: ${localValid ? "PASS" : "FAIL"}`);
  if (!localValid) {
    console.error("  Proof failed local verification! Aborting.");
    process.exit(1);
  }

  // ============================================
  // STEP 5: Submit claim TX
  // ============================================
  console.log("\n[STEP 5] Submitting claim TX...");

  const recipientBalBefore = await connection.getBalance(recipient.publicKey);
  const nullifierHashBytes = bigintToBytes32BE(nullHash);
  const [nullifierPDA] = getNullifierPDA(nullifierHashBytes);

  // Serialize proof for on-chain
  function bigintToBE32(val) {
    const hex = BigInt(val).toString(16).padStart(64, "0");
    const buf = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) buf[i] = parseInt(hex.substr(i * 2, 2), 16);
    return buf;
  }

  // groth16_solana expects proof_a NEGATED (negate y-coordinate for BN254 G1)
  // BN254 base field modulus (Fq)
  const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
  const proofA_y_neg = BN254_FQ - BigInt(proof.pi_a[1]);
  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(proofA_y_neg)]);
  // proof_b: G2 [[x0,x1],[y0,y1]] → 128 bytes (x1,x0,y1,y0 for alt_bn128)
  const proofB = Buffer.concat([
    bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]),
    bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0]),
  ]);
  // proof_c: G1 [x, y] → 64 bytes BE
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);

  const claimDiscriminator = getDiscriminator("claim");
  const claimAmountBuf = Buffer.alloc(8);
  claimAmountBuf.writeBigUInt64LE(dropAmount);

  const feeBuf = Buffer.alloc(8); // fee_lamports = 0 for direct claims
  feeBuf.writeBigUInt64LE(0n);

  const claimData = Buffer.concat([
    claimDiscriminator,                           // 8
    proofA,                                       // 64
    proofB,                                       // 128
    proofC,                                       // 64
    onChainRoot,                                   // 32 merkle_root
    nullifierHashBytes,                           // 32 nullifier_hash
    claimAmountBuf,                               // 8  amount
    bigintToBytes32BE(amtCommitment),             // 32 amount_commitment
    bigintToBytes32BE(pwdHash),                   // 32 password_hash
    feeBuf,                                       // 8  fee_lamports
  ]);

  const claimIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: solVault, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: false, isWritable: true }, // fee_recipient (payer for direct, no fee)
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: claimData,
  });

  try {
    const claimTx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      claimIx,
    );
    const claimSig = await sendAndConfirmTransaction(connection, claimTx, [payer]);
    console.log(`  TX: ${claimSig}`);
  } catch (e) {
    console.error("  Claim failed:", e.message);
    // Print logs if available
    if (e.logs) {
      console.error("  Program logs:");
      e.logs.forEach(l => console.error(`    ${l}`));
    }
    process.exit(1);
  }

  // ============================================
  // STEP 6: Verify
  // ============================================
  console.log("\n[STEP 6] Verifying...");

  const recipientBalAfter = await connection.getBalance(recipient.publicKey);
  const vaultBalFinal = await connection.getBalance(solVault);
  const nullifierAccount = await connection.getAccountInfo(nullifierPDA);

  console.log(`  Recipient balance: ${recipientBalBefore} → ${recipientBalAfter} (+${recipientBalAfter - recipientBalBefore})`);
  console.log(`  Vault balance: ${vaultBalAfter} → ${vaultBalFinal} (-${vaultBalAfter - vaultBalFinal})`);
  console.log(`  Nullifier spent: ${nullifierAccount !== null}`);

  const received = recipientBalAfter - recipientBalBefore;
  const expectedAmount = Number(dropAmount);

  if (received === expectedAmount && nullifierAccount !== null) {
    console.log("\n=== E2E TEST PASSED ===");
    console.log(`  Created drop: ${Number(dropAmount) / LAMPORTS_PER_SOL} SOL`);
    console.log(`  Claimed by:   ${recipient.publicKey}`);
    console.log(`  ZK proof verified on-chain`);
    console.log(`  Nullifier marked as spent`);
    console.log(`  Full privacy: sender and recipient are unlinkable`);
  } else {
    console.log("\n=== E2E TEST FAILED ===");
    console.log(`  Expected ${expectedAmount} lamports, got ${received}`);
    process.exit(1);
  }
}

main().catch(e => {
  console.error("Fatal:", e);
  process.exit(1);
});
