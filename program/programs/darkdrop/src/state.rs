use anchor_lang::prelude::*;

// Merkle tree depth — supports 2^20 = 1,048,576 drops
pub const MERKLE_DEPTH: usize = 20;

// Number of recent roots to keep (handles concurrent drops)
pub const ROOT_HISTORY_SIZE: usize = 30;

// Maximum drop amount in lamports (safety cap — 100 SOL initially)
pub const MAX_DROP_AMOUNT: u64 = 100_000_000_000;

// Number of public inputs in the Groth16 proof
// [merkle_root, nullifier_hash, recipient, amount_commitment, password_hash, amount]
pub const NR_PUBLIC_INPUTS: usize = 6;

// Auto-generated Poseidon zero hashes for Merkle tree initialization.
// zeros[0] = 0
// zeros[i+1] = Poseidon(zeros[i], zeros[i])
// Generated with circomlib's Poseidon (same as circuit).
// DO NOT EDIT — regenerate with: node scripts/generate_zero_hashes.js
pub const ZERO_HASHES: [[u8; 32]; MERKLE_DEPTH + 1] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [32, 152, 245, 251, 158, 35, 158, 171, 60, 234, 195, 242, 123, 129, 228, 129, 220, 49, 36, 213, 95, 254, 213, 35, 168, 57, 238, 132, 70, 182, 72, 100],
    [16, 105, 103, 61, 205, 177, 34, 99, 223, 48, 26, 111, 245, 132, 167, 236, 38, 26, 68, 203, 157, 198, 141, 240, 103, 164, 119, 68, 96, 177, 241, 225],
    [24, 244, 51, 49, 83, 126, 226, 175, 46, 61, 117, 141, 80, 247, 33, 6, 70, 124, 110, 234, 80, 55, 29, 213, 40, 213, 126, 178, 184, 86, 210, 56],
    [7, 249, 216, 55, 203, 23, 176, 211, 99, 32, 255, 233, 59, 165, 35, 69, 241, 183, 40, 87, 26, 86, 130, 101, 202, 172, 151, 85, 157, 188, 149, 42],
    [43, 148, 207, 94, 135, 70, 179, 245, 201, 99, 31, 76, 93, 243, 41, 7, 166, 153, 197, 140, 148, 178, 173, 77, 123, 92, 236, 22, 57, 24, 63, 85],
    [45, 238, 147, 197, 166, 102, 69, 150, 70, 234, 125, 34, 204, 169, 225, 188, 254, 215, 30, 105, 81, 185, 83, 97, 29, 17, 221, 163, 46, 160, 157, 120],
    [7, 130, 149, 229, 162, 43, 132, 233, 130, 207, 96, 30, 182, 57, 89, 123, 139, 5, 21, 168, 140, 181, 172, 127, 168, 164, 170, 190, 60, 135, 52, 157],
    [47, 165, 229, 241, 143, 96, 39, 166, 80, 27, 236, 134, 69, 100, 71, 42, 97, 107, 46, 39, 74, 65, 33, 26, 68, 76, 190, 58, 153, 243, 204, 97],
    [14, 136, 67, 118, 208, 216, 253, 33, 236, 183, 128, 56, 158, 148, 31, 102, 228, 94, 122, 204, 227, 226, 40, 171, 62, 33, 86, 166, 20, 252, 215, 71],
    [27, 114, 1, 218, 114, 73, 79, 30, 40, 113, 122, 209, 165, 46, 180, 105, 249, 88, 146, 249, 87, 113, 53, 51, 222, 97, 117, 229, 218, 25, 10, 242],
    [31, 141, 136, 34, 114, 94, 54, 56, 82, 0, 192, 178, 1, 36, 152, 25, 166, 230, 225, 228, 101, 8, 8, 181, 190, 188, 107, 250, 206, 125, 118, 54],
    [44, 93, 130, 246, 108, 145, 75, 175, 185, 112, 21, 137, 186, 140, 252, 251, 97, 98, 176, 161, 42, 207, 136, 168, 208, 135, 154, 4, 113, 181, 248, 90],
    [20, 197, 65, 72, 160, 148, 11, 184, 32, 149, 127, 90, 223, 63, 161, 19, 78, 245, 196, 170, 161, 19, 244, 100, 100, 88, 242, 112, 224, 191, 191, 208],
    [25, 13, 51, 177, 47, 152, 111, 150, 30, 16, 192, 238, 68, 216, 185, 175, 17, 190, 37, 88, 140, 173, 137, 212, 22, 17, 142, 75, 244, 235, 232, 12],
    [34, 249, 138, 169, 206, 112, 65, 82, 172, 23, 53, 73, 20, 173, 115, 237, 17, 103, 174, 101, 150, 175, 81, 10, 165, 179, 100, 147, 37, 224, 108, 146],
    [42, 124, 124, 155, 108, 229, 136, 11, 159, 111, 34, 141, 114, 191, 106, 87, 90, 82, 111, 41, 198, 110, 204, 238, 248, 183, 83, 211, 139, 186, 115, 35],
    [46, 129, 134, 229, 88, 105, 142, 193, 198, 122, 249, 193, 77, 70, 63, 252, 71, 0, 67, 201, 194, 152, 139, 149, 77, 117, 221, 100, 63, 54, 185, 146],
    [15, 87, 197, 87, 30, 154, 78, 171, 73, 226, 200, 207, 5, 13, 174, 148, 138, 239, 110, 173, 100, 115, 146, 39, 53, 70, 36, 157, 28, 31, 241, 15],
    [24, 48, 238, 103, 181, 251, 85, 74, 213, 246, 61, 67, 136, 128, 14, 28, 254, 120, 227, 16, 105, 125, 70, 228, 60, 156, 227, 97, 52, 247, 44, 202],
    [33, 52, 231, 106, 197, 210, 26, 171, 24, 108, 43, 225, 221, 143, 132, 238, 136, 10, 30, 70, 234, 247, 18, 249, 211, 113, 182, 223, 34, 25, 31, 62],
];

/// Vault — holds all drop funds and program configuration.
/// PDA seeds: [b"vault"]
#[account]
pub struct Vault {
    /// PDA bump seed
    pub bump: u8,
    /// Authority that can update configuration
    pub authority: Pubkey,
    /// Total number of drops created
    pub total_drops: u64,
    /// Total number of claims processed
    pub total_claims: u64,
    /// Maximum allowed drop amount in lamports
    pub drop_cap: u64,
    /// Associated Merkle tree account
    pub merkle_tree: Pubkey,
    /// Total lamports deposited via create_drop (for sweep limit enforcement)
    pub total_deposited: u64,
    /// Total lamports withdrawn via claim + withdraw_credit (for sweep limit enforcement)
    pub total_withdrawn: u64,
}

impl Vault {
    pub const SIZE: usize = 8  // discriminator
        + 1   // bump
        + 32  // authority
        + 8   // total_drops
        + 8   // total_claims
        + 8   // drop_cap
        + 32  // merkle_tree
        + 8   // total_deposited
        + 8;  // total_withdrawn
}

/// MerkleTree — stores the incremental Merkle tree state.
/// PDA seeds: [b"merkle_tree", vault.key()]
///
/// Uses the incremental (append-only) Merkle tree algorithm:
/// - filled_subtrees[i] stores the hash at level i of the last "left" subtree
/// - Insertions only touch one path (O(depth) operations)
/// - root_history stores recent roots for concurrent drop support
#[account(zero_copy(unsafe))]
#[repr(C)]
#[derive(Debug)]
pub struct MerkleTreeAccount {
    /// Associated vault
    pub vault: Pubkey,
    /// Next available leaf index
    pub next_index: u32,
    /// Index into root_history circular buffer
    pub root_history_index: u32,
    /// Current Merkle root
    pub current_root: [u8; 32],
    /// Circular buffer of recent roots
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Filled subtrees at each level (for incremental insertion)
    pub filled_subtrees: [[u8; 32]; MERKLE_DEPTH],
}

impl MerkleTreeAccount {
    /// Check if a root exists in the history
    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        if *root == self.current_root {
            return true;
        }
        for i in 0..ROOT_HISTORY_SIZE {
            if self.root_history[i] == *root {
                return true;
            }
        }
        false
    }
}

/// NullifierAccount — PDA created per spent nullifier.
/// PDA seeds: [b"nullifier", nullifier_hash.as_ref()]
/// Existence of this account = nullifier has been spent.
/// Uses Anchor's `init` constraint: if PDA already exists, TX fails.
#[account]
pub struct NullifierAccount {
    /// The nullifier hash (for reference)
    pub nullifier_hash: [u8; 32],
}

impl NullifierAccount {
    pub const SIZE: usize = 8   // discriminator
        + 32; // nullifier_hash
}

/// Treasury — program-owned account that holds SOL.
/// Direct lamport manipulation (no CPI) for withdrawals.
/// PDA seeds: [b"treasury"]
#[account]
pub struct Treasury {
    pub bump: u8,
}

impl Treasury {
    pub const SIZE: usize = 8 + 1; // discriminator + bump
}

/// CreditNote — holds a committed amount for later withdrawal.
/// PDA seeds: [b"credit", nullifier_hash]
///
/// The stored commitment is re-randomized: stored = Poseidon(original_commitment, salt).
/// This prevents an indexer from matching CreditNote.commitment against deposit-time
/// amount_commitment values, breaking the deposit→claim linkage (M-01-NEW fix).
#[account]
pub struct CreditNote {
    pub bump: u8,
    pub recipient: Pubkey,
    pub commitment: [u8; 32],
    pub nullifier_hash: [u8; 32],
    pub salt: [u8; 32],
    pub created_at: i64,
}

impl CreditNote {
    pub const SIZE: usize = 8   // discriminator
        + 1    // bump
        + 32   // recipient
        + 32   // commitment
        + 32   // nullifier_hash
        + 32   // salt
        + 8;   // created_at
}

/// NotePoolTree — stores the second-layer Merkle tree for credit note mixing.
/// PDA seeds: [b"note_pool_tree", vault.key()]
///
/// Same incremental Merkle tree algorithm as MerkleTreeAccount.
/// Leaves are program-constructed: Poseidon(pool_secret, pool_nullifier, verified_amount, pool_blinding).
/// The verified_amount comes from opening the credit note commitment on-chain,
/// which eliminates the dishonest leaf problem from base DarkDrop (I-01 fix).
#[account(zero_copy(unsafe))]
#[repr(C)]
#[derive(Debug)]
pub struct NotePoolTree {
    /// Associated vault
    pub vault: Pubkey,
    /// Next available leaf index
    pub next_index: u32,
    /// Index into root_history circular buffer
    pub root_history_index: u32,
    /// Current Merkle root
    pub current_root: [u8; 32],
    /// Circular buffer of recent roots
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Filled subtrees at each level (for incremental insertion)
    pub filled_subtrees: [[u8; 32]; MERKLE_DEPTH],
}

impl NotePoolTree {
    /// Check if a root exists in the history
    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        if *root == self.current_root {
            return true;
        }
        for i in 0..ROOT_HISTORY_SIZE {
            if self.root_history[i] == *root {
                return true;
            }
        }
        false
    }
}

/// PoolNullifierAccount — PDA created per spent note pool nullifier.
/// PDA seeds: [b"pool_nullifier", pool_nullifier_hash.as_ref()]
/// Prevents double-claiming from the note pool.
#[account]
pub struct PoolNullifierAccount {
    pub nullifier_hash: [u8; 32],
}

impl PoolNullifierAccount {
    pub const SIZE: usize = 8 + 32;
}

/// NotePool — configuration account for the note pool.
/// PDA seeds: [b"note_pool"]
#[account]
pub struct NotePool {
    pub bump: u8,
    pub total_deposits: u64,
    pub total_claims: u64,
}

impl NotePool {
    pub const SIZE: usize = 8 + 1 + 8 + 8;
}

/// Groth16 proof data submitted by the claimer
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ProofData {
    /// Proof point A (G1) — 64 bytes
    pub proof_a: [u8; 64],
    /// Proof point B (G2) — 128 bytes
    pub proof_b: [u8; 128],
    /// Proof point C (G1) — 64 bytes
    pub proof_c: [u8; 64],
}
