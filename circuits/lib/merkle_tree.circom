pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

// Verifies a Merkle proof: proves that `leaf` exists in a tree with `root`.
// Uses Poseidon(2) for hashing and Switcher for left/right ordering.
//
// Inputs:
//   leaf          - the leaf value to prove membership for
//   root          - the expected Merkle root (public)
//   path[depth]   - sibling hashes along the path from leaf to root
//   indices[depth] - direction at each level (0 = leaf is left, 1 = leaf is right)
//
// Constraints: ~205 per level (Poseidon(2) + Switcher + binary check)

template MerkleTreeVerifier(depth) {
    signal input leaf;
    signal input root;
    signal input path[depth];
    signal input indices[depth];

    // Enforce each index is binary
    for (var i = 0; i < depth; i++) {
        indices[i] * (indices[i] - 1) === 0;
    }

    // Hash from leaf to root
    component switchers[depth];
    component hashers[depth];

    signal hashes[depth + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Order the pair based on direction bit
        switchers[i] = Switcher();
        switchers[i].sel <== indices[i];
        switchers[i].L <== hashes[i];
        switchers[i].R <== path[i];

        // Hash the ordered pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        hashes[i + 1] <== hashers[i].out;
    }

    // Computed root must match expected root
    root === hashes[depth];
}
