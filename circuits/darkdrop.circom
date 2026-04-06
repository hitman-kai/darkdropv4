pragma circom 2.1.0;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./lib/merkle_tree.circom";

// DarkDrop V4 Claim Circuit
//
// Proves that the claimer knows the secret preimage of a leaf in the Merkle tree
// without revealing which leaf, and that the claimed amount matches the committed amount.
//
// Privacy properties:
//   - Leaf identity hidden (Merkle proof reveals nothing about which leaf)
//   - Amount hidden (Poseidon commitment hides value)
//   - Nullifier prevents double-claim without linking to leaf
//   - Recipient bound to proof (prevents front-running)
//   - Optional password protection (ForceEqualIfEnabled)
//
// Estimated constraints at depth 20: ~5,200

template DarkDropClaim(merkle_depth) {

    // === PRIVATE INPUTS (from claim code, never revealed on-chain) ===
    signal input secret;
    signal input amount;
    signal input blinding_factor;
    signal input nullifier;
    signal input merkle_path[merkle_depth];
    signal input merkle_indices[merkle_depth];
    signal input password;                        // 0 if no password

    // === PUBLIC INPUTS (visible on-chain, verified by program) ===
    signal input merkle_root;
    signal input nullifier_hash;
    signal input recipient;                       // recipient pubkey (bound to proof)
    signal input amount_commitment;               // Poseidon(amount, blinding_factor)
    signal input password_hash;                   // Poseidon(password), 0 if no password

    // === CONSTRAINT 1: Leaf construction ===
    // Prove I know the preimage of a valid leaf
    // leaf = Poseidon(secret, nullifier, amount, blinding_factor)
    component leaf_hash = Poseidon(4);
    leaf_hash.inputs[0] <== secret;
    leaf_hash.inputs[1] <== nullifier;
    leaf_hash.inputs[2] <== amount;
    leaf_hash.inputs[3] <== blinding_factor;

    // === CONSTRAINT 2: Merkle tree membership ===
    // Prove this leaf exists in the tree with the given root
    component tree = MerkleTreeVerifier(merkle_depth);
    tree.leaf <== leaf_hash.out;
    tree.root <== merkle_root;
    for (var i = 0; i < merkle_depth; i++) {
        tree.path[i] <== merkle_path[i];
        tree.indices[i] <== merkle_indices[i];
    }

    // === CONSTRAINT 3: Nullifier hash ===
    // Prove the nullifier_hash matches the nullifier I know
    // This links the proof to the nullifier without revealing which leaf
    component null_hash = Poseidon(1);
    null_hash.inputs[0] <== nullifier;
    nullifier_hash === null_hash.out;

    // === CONSTRAINT 4: Amount commitment ===
    // Prove the committed amount matches what I'm claiming
    // Poseidon-based commitment: cheaper in-circuit than EC Pedersen (~200 vs ~192/bit)
    component amt_commit = Poseidon(2);
    amt_commit.inputs[0] <== amount;
    amt_commit.inputs[1] <== blinding_factor;
    amount_commitment === amt_commit.out;

    // === CONSTRAINT 5: Amount range proof ===
    // Prove amount > 0 and fits in 64 bits (prevents overflow attacks)
    // Num2Bits decomposes into bits and constrains each to be 0 or 1
    component range = Num2Bits(64);
    range.in <== amount;

    // Amount must be > 0 (at least 1 lamport)
    component is_zero = IsZero();
    is_zero.in <== amount;
    is_zero.out === 0; // amount is NOT zero

    // === CONSTRAINT 6: Password verification (optional) ===
    // If password_hash != 0, prove I know the password
    // If password_hash == 0, password is unchecked (any value accepted)
    component pwd_hash = Poseidon(1);
    pwd_hash.inputs[0] <== password;

    component pwd_hash_is_zero = IsZero();
    pwd_hash_is_zero.in <== password_hash;

    // enabled = 1 when password_hash != 0 (password protection is active)
    signal pwd_enabled;
    pwd_enabled <== 1 - pwd_hash_is_zero.out;

    component pwd_check = ForceEqualIfEnabled();
    pwd_check.enabled <== pwd_enabled;
    pwd_check.in[0] <== pwd_hash.out;
    pwd_check.in[1] <== password_hash;

    // === CONSTRAINT 7: Bind proof to recipient ===
    // Prevents front-running: proof is only valid for this specific recipient
    // Square ensures recipient is included in the constraint system
    signal recipient_sq <== recipient * recipient;
}

// Instantiate with depth 20 (supports ~1M drops)
// V2: amount is now PRIVATE — not exposed to verifier. Still constrained by leaf hash, commitment, range check.
component main {public [merkle_root, nullifier_hash, recipient, amount_commitment, password_hash]} = DarkDropClaim(20);
