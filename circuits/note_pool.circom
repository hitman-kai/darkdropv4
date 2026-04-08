pragma circom 2.1.0;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./lib/merkle_tree.circom";

// Note Pool Claim Circuit — Second-Layer Merkle Mixer for Credit Notes
//
// This circuit enables "recursive privacy": a credit note deposited into the
// note pool can be redeemed as a FRESH credit note with no on-chain linkage
// to the original. The first ZK proof (claim_credit) hides which deposit
// was claimed. This second ZK proof hides which credit note is being redeemed.
//
// Pool leaf: Poseidon(pool_secret, pool_nullifier, amount, pool_blinding_factor)
//   - pool_secret and pool_nullifier are fresh secrets (not reused from L1)
//   - amount is the VERIFIED amount from the credit note (program-constructed leaf)
//   - pool_blinding_factor is a fresh random scalar
//
// The circuit proves:
//   1. I know the preimage of a leaf in the note pool Merkle tree
//   2. The leaf's nullifier matches the declared nullifier_hash
//   3. The amount is positive and fits in u64
//   4. The new credit note commitment encodes the SAME amount with fresh randomness
//   5. The proof is bound to a specific recipient
//
// Constraint estimate: ~5,200 (20-level Merkle + 5 Poseidon + range check)

template NotePoolClaim(merkle_depth) {

    // === PRIVATE INPUTS ===
    signal input pool_secret;                     // random secret for pool leaf
    signal input pool_nullifier;                  // random nullifier for pool leaf
    signal input amount;                          // amount from the credit note
    signal input pool_blinding_factor;            // random blinding for pool leaf
    signal input pool_path[merkle_depth];         // Merkle proof siblings
    signal input pool_indices[merkle_depth];       // Merkle proof direction bits
    signal input new_blinding;                    // fresh blinding for new credit note
    signal input new_salt;                        // fresh salt for re-randomization
    signal input recipient_hi;                    // recipient pubkey high 128 bits
    signal input recipient_lo;                    // recipient pubkey low 128 bits

    // === PUBLIC INPUTS ===
    signal input pool_merkle_root;                // current root of the note pool tree
    signal input pool_nullifier_hash;             // Poseidon(pool_nullifier) — prevents double-claim
    signal input new_stored_commitment;           // Poseidon(Poseidon(amount, new_blinding), new_salt)
    signal input recipient_hash;                  // Poseidon(recipient_hi, recipient_lo)

    // === CONSTRAINT 1: Pool leaf construction ===
    // pool_leaf = Poseidon(pool_secret, pool_nullifier, amount, pool_blinding_factor)
    component leaf_hash = Poseidon(4);
    leaf_hash.inputs[0] <== pool_secret;
    leaf_hash.inputs[1] <== pool_nullifier;
    leaf_hash.inputs[2] <== amount;
    leaf_hash.inputs[3] <== pool_blinding_factor;

    // === CONSTRAINT 2: Merkle tree membership ===
    // Prove this leaf exists in the note pool tree with the given root
    component tree = MerkleTreeVerifier(merkle_depth);
    tree.leaf <== leaf_hash.out;
    tree.root <== pool_merkle_root;
    for (var i = 0; i < merkle_depth; i++) {
        tree.path[i] <== pool_path[i];
        tree.indices[i] <== pool_indices[i];
    }

    // === CONSTRAINT 3: Nullifier hash ===
    // Prove pool_nullifier_hash matches the pool_nullifier I know
    component null_hash = Poseidon(1);
    null_hash.inputs[0] <== pool_nullifier;
    pool_nullifier_hash === null_hash.out;

    // === CONSTRAINT 4: Amount range check ===
    // amount > 0 and fits in 64 bits
    component range = Num2Bits(64);
    range.in <== amount;

    component is_zero = IsZero();
    is_zero.in <== amount;
    is_zero.out === 0; // amount is NOT zero

    // === CONSTRAINT 5: New credit note commitment ===
    // Prove the new commitment encodes the SAME amount with fresh randomness.
    // new_stored_commitment = Poseidon(Poseidon(amount, new_blinding), new_salt)
    // This matches the re-randomized commitment scheme used by CreditNote PDAs.
    component new_original = Poseidon(2);
    new_original.inputs[0] <== amount;
    new_original.inputs[1] <== new_blinding;

    component new_rerandomized = Poseidon(2);
    new_rerandomized.inputs[0] <== new_original.out;
    new_rerandomized.inputs[1] <== new_salt;

    new_stored_commitment === new_rerandomized.out;

    // === CONSTRAINT 6: Bind proof to recipient ===
    // recipient_hash = Poseidon(recipient_hi, recipient_lo)
    component recipient_hasher = Poseidon(2);
    recipient_hasher.inputs[0] <== recipient_hi;
    recipient_hasher.inputs[1] <== recipient_lo;
    recipient_hash === recipient_hasher.out;
}

// Instantiate with depth 20 (same as main DarkDrop tree — supports ~1M pool entries)
component main {public [pool_merkle_root, pool_nullifier_hash, new_stored_commitment, recipient_hash]} = NotePoolClaim(20);
