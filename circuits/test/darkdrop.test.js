// DarkDrop V4 — Circuit Test Suite
//
// Tests the full DarkDrop claim circuit:
//   1. Valid claim (happy path)
//   2. Valid claim with password
//   3. No-password claim (password_hash = 0)
//   4. Wrong nullifier (should fail)
//   5. Wrong amount (should fail)
//   6. Wrong merkle proof (should fail)
//   7. Wrong password (should fail)
//   8. Zero amount (should fail)
//   9. Amount overflow (should fail)

const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");

const DEPTH = 20;
const BUILD_DIR = path.join(__dirname, "../build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_final.zkey");
const VK_PATH = path.join(BUILD_DIR, "verification_key.json");

let poseidon, F;

// ============================================================
// Helpers
// ============================================================

function poseidonHash(inputs) {
  return F.toObject(poseidon(inputs));
}

// Convert a pubkey (any BigInt) to a valid BN254 field element via Poseidon.
// Mirrors on-chain logic: split 32-byte pubkey into two 128-bit halves, hash them.
// This prevents ~13% of pubkeys (those > BN254 field modulus) from causing mismatches.
function pubkeyToField(pubkeyBigInt) {
  const mask128 = (BigInt(1) << BigInt(128)) - BigInt(1);
  const lo = pubkeyBigInt & mask128;
  const hi = (pubkeyBigInt >> BigInt(128)) & mask128;
  return poseidonHash([hi, lo]);
}

// Build a Merkle tree from an array of leaves, returns { root, layers }
function buildMerkleTree(leaves) {
  // Pad to 2^DEPTH leaves with zeros
  const treeSize = 2 ** DEPTH;
  const paddedLeaves = [...leaves];

  // Compute zero hashes for empty subtrees
  const zeroHashes = [BigInt(0)];
  for (let i = 0; i < DEPTH; i++) {
    zeroHashes.push(poseidonHash([zeroHashes[i], zeroHashes[i]]));
  }

  // Fill with zeros
  while (paddedLeaves.length < treeSize) {
    paddedLeaves.push(BigInt(0));
  }

  const layers = [paddedLeaves];

  let currentLayer = paddedLeaves;
  for (let d = 0; d < DEPTH; d++) {
    const nextLayer = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      nextLayer.push(poseidonHash([currentLayer[i], currentLayer[i + 1]]));
    }
    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return { root: currentLayer[0], layers, zeroHashes };
}

// Get Merkle proof for leaf at `index`
function getMerkleProof(layers, index) {
  const pathElements = [];
  const pathIndices = [];

  let idx = index;
  for (let d = 0; d < DEPTH; d++) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    pathElements.push(layers[d][siblingIdx].toString());
    pathIndices.push((idx % 2).toString());
    idx = Math.floor(idx / 2);
  }

  return { pathElements, pathIndices };
}

// Create a drop: returns { leaf, secret, nullifier, amount, blinding, nullifierHash, commitment }
function createDrop(amountVal, passwordVal = BigInt(0)) {
  const secret = BigInt("0x" + require("crypto").randomBytes(31).toString("hex"));
  const nullifier = BigInt("0x" + require("crypto").randomBytes(31).toString("hex"));
  const blinding_factor = BigInt("0x" + require("crypto").randomBytes(31).toString("hex"));
  const amount = BigInt(amountVal);
  const password = passwordVal;

  const leaf = poseidonHash([secret, nullifier, amount, blinding_factor]);
  const nullifier_hash = poseidonHash([nullifier]);
  const amount_commitment = poseidonHash([amount, blinding_factor]);
  const password_hash = password !== BigInt(0) ? poseidonHash([password]) : BigInt(0);

  return {
    secret, nullifier, amount, blinding_factor, password,
    leaf, nullifier_hash, amount_commitment, password_hash,
  };
}

// Build full circuit input for a claim
// recipient is a raw pubkey BigInt — hashed via Poseidon to guarantee valid field element
function buildClaimInput(drop, merkleRoot, pathElements, pathIndices, recipient) {
  const recipientField = pubkeyToField(recipient);
  return {
    // Private
    secret: drop.secret.toString(),
    amount: drop.amount.toString(),
    blinding_factor: drop.blinding_factor.toString(),
    nullifier: drop.nullifier.toString(),
    merkle_path: pathElements,
    merkle_indices: pathIndices,
    password: drop.password.toString(),

    // Public
    merkle_root: merkleRoot.toString(),
    nullifier_hash: drop.nullifier_hash.toString(),
    recipient: recipientField.toString(),
    amount_commitment: drop.amount_commitment.toString(),
    password_hash: drop.password_hash.toString(),
  };
}

async function generateAndVerify(input) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
  const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  return { valid, proof, publicSignals };
}

async function expectProofFails(input, testName) {
  try {
    await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
    console.log(`  FAIL: ${testName} — proof should not have been generated`);
    return false;
  } catch (e) {
    console.log(`  PASS: ${testName} — correctly rejected (${e.message.slice(0, 60)}...)`);
    return true;
  }
}

// ============================================================
// Tests
// ============================================================

async function runTests() {
  console.log("Initializing Poseidon...");
  poseidon = await buildPoseidon();
  F = poseidon.F;

  // Check build artifacts exist
  if (!fs.existsSync(ZKEY_PATH)) {
    console.error("ERROR: Build artifacts not found. Run trusted setup first.");
    process.exit(1);
  }

  const recipient = BigInt("0xDEADBEEF12345678");

  // --- Create several drops and build a tree ---
  console.log("\nCreating test drops...");
  const drop1 = createDrop(500000000);               // 0.5 SOL, no password
  const drop2 = createDrop(1000000000);               // 1 SOL, no password
  const drop3 = createDrop(100000, BigInt("42"));     // 0.0001 SOL, password=42
  const drop4 = createDrop(1);                         // minimum: 1 lamport

  const leaves = [drop1.leaf, drop2.leaf, drop3.leaf, drop4.leaf];
  console.log(`Building Merkle tree (depth ${DEPTH}, ${leaves.length} leaves)...`);
  const { root, layers } = buildMerkleTree(leaves);
  console.log(`Merkle root: ${root.toString().slice(0, 20)}...`);

  let passed = 0;
  let failed = 0;

  // ---- TEST 1: Valid claim, no password ----
  console.log("\n[TEST 1] Valid claim — 0.5 SOL, no password");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 0);
    const input = buildClaimInput(drop1, root, pathElements, pathIndices, recipient);
    const { valid } = await generateAndVerify(input);
    if (valid) { console.log("  PASS: Proof verified"); passed++; }
    else { console.log("  FAIL: Proof did not verify"); failed++; }
  }

  // ---- TEST 2: Valid claim, different drop ----
  console.log("\n[TEST 2] Valid claim — 1 SOL, no password");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 1);
    const input = buildClaimInput(drop2, root, pathElements, pathIndices, recipient);
    const { valid } = await generateAndVerify(input);
    if (valid) { console.log("  PASS: Proof verified"); passed++; }
    else { console.log("  FAIL: Proof did not verify"); failed++; }
  }

  // ---- TEST 3: Valid claim with password ----
  console.log("\n[TEST 3] Valid claim — with password");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 2);
    const input = buildClaimInput(drop3, root, pathElements, pathIndices, recipient);
    const { valid } = await generateAndVerify(input);
    if (valid) { console.log("  PASS: Proof verified with password"); passed++; }
    else { console.log("  FAIL: Password-protected proof did not verify"); failed++; }
  }

  // ---- TEST 4: Minimum amount (1 lamport) ----
  console.log("\n[TEST 4] Valid claim — minimum amount (1 lamport)");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 3);
    const input = buildClaimInput(drop4, root, pathElements, pathIndices, recipient);
    const { valid } = await generateAndVerify(input);
    if (valid) { console.log("  PASS: Proof verified for 1 lamport"); passed++; }
    else { console.log("  FAIL: Minimum amount proof failed"); failed++; }
  }

  // ---- TEST 5: Wrong nullifier hash (should fail) ----
  console.log("\n[TEST 5] Invalid — wrong nullifier hash");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 0);
    const input = buildClaimInput(drop1, root, pathElements, pathIndices, recipient);
    input.nullifier_hash = "999999"; // wrong
    const ok = await expectProofFails(input, "Wrong nullifier hash");
    if (ok) passed++; else failed++;
  }

  // ---- TEST 6: Wrong amount commitment (should fail) ----
  console.log("\n[TEST 6] Invalid — wrong amount commitment");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 0);
    const input = buildClaimInput(drop1, root, pathElements, pathIndices, recipient);
    input.amount_commitment = "888888"; // wrong
    const ok = await expectProofFails(input, "Wrong amount commitment");
    if (ok) passed++; else failed++;
  }

  // ---- TEST 7: Wrong merkle root (should fail) ----
  console.log("\n[TEST 7] Invalid — wrong merkle root");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 0);
    const input = buildClaimInput(drop1, root, pathElements, pathIndices, recipient);
    input.merkle_root = "777777"; // wrong
    const ok = await expectProofFails(input, "Wrong merkle root");
    if (ok) passed++; else failed++;
  }

  // ---- TEST 8: Wrong password (should fail) ----
  console.log("\n[TEST 8] Invalid — wrong password");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 2);
    const input = buildClaimInput(drop3, root, pathElements, pathIndices, recipient);
    input.password = "99"; // wrong password (correct is 42)
    const ok = await expectProofFails(input, "Wrong password");
    if (ok) passed++; else failed++;
  }

  // ---- TEST 9: Zero amount (should fail) ----
  console.log("\n[TEST 9] Invalid — zero amount");
  {
    const zeroDrop = createDrop(0);
    const zeroLeaves = [zeroDrop.leaf];
    const { root: zRoot, layers: zLayers } = buildMerkleTree(zeroLeaves);
    const { pathElements, pathIndices } = getMerkleProof(zLayers, 0);
    const input = buildClaimInput(zeroDrop, zRoot, pathElements, pathIndices, recipient);
    const ok = await expectProofFails(input, "Zero amount");
    if (ok) passed++; else failed++;
  }

  // ---- TEST 10: Proof binds to recipient (different recipient fails verification) ----
  console.log("\n[TEST 10] Recipient binding — proof for recipient A fails for recipient B");
  {
    const { pathElements, pathIndices } = getMerkleProof(layers, 0);
    const input = buildClaimInput(drop1, root, pathElements, pathIndices, recipient);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);

    // Tamper: change recipient in public signals
    // Public signals order: [merkle_root, nullifier_hash, recipient, amount_commitment, password_hash]
    const tamperedSignals = [...publicSignals];
    tamperedSignals[2] = "123456789"; // different recipient
    const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
    const valid = await snarkjs.groth16.verify(vk, tamperedSignals, proof);
    if (!valid) { console.log("  PASS: Tampered recipient correctly rejected"); passed++; }
    else { console.log("  FAIL: Tampered recipient was accepted"); failed++; }
  }

  // ---- TEST 11: Recipient pubkey exceeding BN254 field modulus ----
  console.log("\n[TEST 11] Valid claim — recipient pubkey > field modulus (overflow case)");
  {
    // This pubkey exceeds the BN254 scalar field modulus (~2^254).
    // Without the Poseidon hash fix, this would cause a proof/verification mismatch.
    const overflowPubkey = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    const { pathElements, pathIndices } = getMerkleProof(layers, 0);
    const input = buildClaimInput(drop1, root, pathElements, pathIndices, overflowPubkey);
    const { valid } = await generateAndVerify(input);
    if (valid) { console.log("  PASS: Overflow pubkey handled correctly via Poseidon hash"); passed++; }
    else { console.log("  FAIL: Overflow pubkey proof failed"); failed++; }
  }

  // ---- Summary ----
  console.log(`\n${"=".repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
  if (failed === 0) {
    console.log("ALL TESTS PASSED");
  } else {
    console.log("SOME TESTS FAILED");
    process.exit(1);
  }
}

runTests().catch((e) => {
  console.error("Fatal error:", e);
  process.exit(1);
});
