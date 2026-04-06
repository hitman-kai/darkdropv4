pragma circom 2.1.0;

include "../../_study/circomlib/circuits/poseidon.circom";
include "../../_study/circomlib/circuits/bitify.circom";
include "../../_study/circomlib/circuits/comparators.circom";
include "../../_study/circomlib/circuits/switcher.circom";

// === MINIMAL DARKDROP TEST CIRCUIT ===
// Tests the core patterns we'll use in the full circuit:
// 1. Poseidon leaf hashing
// 2. Simple Merkle proof (depth 3 for fast testing)
// 3. Nullifier hash
// 4. Amount commitment (Poseidon-based)
// 5. Range check (Num2Bits)

template MerkleTreeVerifier(depth) {
    signal input leaf;
    signal input root;
    signal input path[depth];
    signal input indices[depth];

    // Verify each index is binary
    for (var i = 0; i < depth; i++) {
        indices[i] * (indices[i] - 1) === 0;
    }

    // Hash up the tree
    component switchers[depth];
    component hashers[depth];

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        switchers[i] = Switcher();
        switchers[i].sel <== indices[i];
        switchers[i].L <== hashes[i];
        switchers[i].R <== path[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        hashes[i + 1] <== hashers[i].out;
    }

    // Root must match
    root === hashes[depth];
}

template DarkDropClaimTest() {
    var depth = 3; // Small depth for testing

    // === PRIVATE INPUTS ===
    signal input secret;
    signal input amount;
    signal input blinding_factor;
    signal input nullifier;
    signal input merkle_path[depth];
    signal input merkle_indices[depth];

    // === PUBLIC INPUTS ===
    signal input merkle_root;
    signal input nullifier_hash;
    signal input recipient;
    signal input amount_commitment;

    // === CONSTRAINT 1: Leaf construction ===
    component leaf_hash = Poseidon(4);
    leaf_hash.inputs[0] <== secret;
    leaf_hash.inputs[1] <== nullifier;
    leaf_hash.inputs[2] <== amount;
    leaf_hash.inputs[3] <== blinding_factor;

    // === CONSTRAINT 2: Merkle tree membership ===
    component tree = MerkleTreeVerifier(depth);
    tree.leaf <== leaf_hash.out;
    tree.root <== merkle_root;
    for (var i = 0; i < depth; i++) {
        tree.path[i] <== merkle_path[i];
        tree.indices[i] <== merkle_indices[i];
    }

    // === CONSTRAINT 3: Nullifier hash ===
    component null_hash = Poseidon(1);
    null_hash.inputs[0] <== nullifier;
    nullifier_hash === null_hash.out;

    // === CONSTRAINT 4: Amount commitment ===
    component amt_commit = Poseidon(2);
    amt_commit.inputs[0] <== amount;
    amt_commit.inputs[1] <== blinding_factor;
    amount_commitment === amt_commit.out;

    // === CONSTRAINT 5: Amount range proof (64-bit) ===
    component range = Num2Bits(64);
    range.in <== amount;

    // === CONSTRAINT 6: Bind proof to recipient (prevent front-running) ===
    signal recipient_sq <== recipient * recipient;
}

component main {public [merkle_root, nullifier_hash, recipient, amount_commitment]} = DarkDropClaimTest();
