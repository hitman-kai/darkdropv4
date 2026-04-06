// Generate valid test inputs for the DarkDrop minimal test circuit
// Uses circomlibjs Poseidon to compute hashes that match the circuit

const { buildPoseidon } = require("circomlibjs");

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F; // finite field

  // === Step 1: Generate random private inputs ===
  const secret = BigInt("12345678901234567890");
  const nullifier = BigInt("98765432109876543210");
  const amount = BigInt("500000000"); // 0.5 SOL in lamports
  const blinding_factor = BigInt("11111111111111111111");
  const recipient = BigInt("55555555555555555555");

  // === Step 2: Compute leaf hash = Poseidon(secret, nullifier, amount, blinding) ===
  const leaf = poseidon([secret, nullifier, amount, blinding_factor]);
  const leafBN = F.toObject(leaf);
  console.error("leaf:", leafBN.toString());

  // === Step 3: Build a small Merkle tree (depth 3) ===
  // We'll put our leaf at index 0 and fill the rest with zeros
  const DEPTH = 3;
  const ZERO = BigInt("0");

  // Compute zero hashes for empty tree
  let zeroHashes = [ZERO];
  for (let i = 0; i < DEPTH; i++) {
    const h = poseidon([zeroHashes[i], zeroHashes[i]]);
    zeroHashes.push(F.toObject(h));
  }

  // Build tree with leaf at index 0
  // Level 0 leaves: [leaf, 0, 0, 0, 0, 0, 0, 0]
  let levels = [];
  let currentLevel = [leafBN, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];
  levels.push(currentLevel);

  for (let d = 0; d < DEPTH; d++) {
    let nextLevel = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const h = poseidon([currentLevel[i], currentLevel[i + 1]]);
      nextLevel.push(F.toObject(h));
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  const merkle_root = currentLevel[0]; // Root

  // Merkle path for leaf at index 0: siblings at each level
  // Index 0 binary = [0, 0, 0] → leaf is always on the LEFT
  const merkle_path = [
    ZERO.toString(),                    // sibling at level 0 (leaf 1)
    zeroHashes[1].toString(),           // sibling at level 1 (hash of leaves 2,3)
    zeroHashes[2].toString(),           // sibling at level 2 (hash of subtree 4-7)
  ];
  const merkle_indices = ["0", "0", "0"]; // leaf is on the left at every level

  // Verify: manually hash up
  let current = leafBN;
  for (let i = 0; i < DEPTH; i++) {
    const sibling = BigInt(merkle_path[i]);
    const idx = parseInt(merkle_indices[i]);
    let left, right;
    if (idx === 0) {
      left = current; right = sibling;
    } else {
      left = sibling; right = current;
    }
    const h = poseidon([left, right]);
    current = F.toObject(h);
  }
  console.error("computed root:", current.toString());
  console.error("expected root:", merkle_root.toString());
  console.error("roots match:", current === merkle_root);

  // === Step 4: Compute nullifier_hash = Poseidon(nullifier) ===
  const nullifier_hash = F.toObject(poseidon([nullifier]));

  // === Step 5: Compute amount_commitment = Poseidon(amount, blinding_factor) ===
  const amount_commitment = F.toObject(poseidon([amount, blinding_factor]));

  // === Build circuit input ===
  const input = {
    // Private inputs
    secret: secret.toString(),
    amount: amount.toString(),
    blinding_factor: blinding_factor.toString(),
    nullifier: nullifier.toString(),
    merkle_path: merkle_path,
    merkle_indices: merkle_indices,

    // Public inputs
    merkle_root: merkle_root.toString(),
    nullifier_hash: nullifier_hash.toString(),
    recipient: recipient.toString(),
    amount_commitment: amount_commitment.toString(),
  };

  console.log(JSON.stringify(input, null, 2));
}

main().catch(console.error);
