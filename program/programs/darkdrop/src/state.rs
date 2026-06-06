use anchor_lang::prelude::*;

// Merkle tree depth — supports 2^20 = 1,048,576 drops
pub const MERKLE_DEPTH: usize = 20;

// Number of recent roots to keep (handles concurrent drops).
// Bumped from 30 → 256 in schema v2. At 15–30 deposits/day on devnet the
// 30-slot buffer rotated in ~1–2 days, silently expiring any claim code
// whose embedded tree snapshot aged past the window. 256 extends that to
// ~1–2 weeks — tolerable for ordinary usage.
pub const ROOT_HISTORY_SIZE: usize = 256;

// Previous root_history capacity, used only by the schema-v2 migration
// handler to recognise un-migrated accounts and shift bytes correctly.
pub const ROOT_HISTORY_SIZE_V1: usize = 30;

// Maximum drop amount in lamports (safety cap — 100 SOL initially)
pub const MAX_DROP_AMOUNT: u64 = 100_000_000_000;

// Minimum deposit to prevent tree pollution and Merkle root DoS (0.00001 SOL)
pub const MIN_DEPOSIT_LAMPORTS: u64 = 10_000;

// Time-lock before a depositor can revoke an unclaimed drop.
// The `short-revoke-timeout` feature is for localnet/devnet testing so the
// 30-day wait doesn't have to elapse in real time.
#[cfg(feature = "short-revoke-timeout")]
pub const REVOKE_TIMEOUT: i64 = 5;

#[cfg(not(feature = "short-revoke-timeout"))]
pub const REVOKE_TIMEOUT: i64 = 2_592_000;

// Delay between propose_authority_rotation and accept_authority_rotation.
// Gives the current authority a 24-hour window to revoke a proposal if the
// current signing key was compromised and used to propose a malicious
// successor. Reuses the `short-revoke-timeout` feature gate so the same
// localnet/devnet test flag shortens both admin-gated delays (Audit 05 L-01).
#[cfg(feature = "short-revoke-timeout")]
pub const ROTATION_DELAY: i64 = 5;

#[cfg(not(feature = "short-revoke-timeout"))]
pub const ROTATION_DELAY: i64 = 86_400;

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
        // Audit 06 L-02 / issue #16: scan the FULL circular buffer, skipping
        // (not stopping at) sentinel slots. The schema-v2 migration of a V1
        // ring that had wrapped preserves all 30 V1 slots as live roots while
        // root_history_index points mid-ring; the remaining slots are
        // sentinel-filled. A backward walk that breaks on the first sentinel
        // orphans the live roots that sit after a sentinel in descending-ring
        // order and wrongly rejects their (valid) claim codes — a liveness
        // regression. A full scan is layout-independent (partial fill, full
        // wrap, and migrated-from-wrapped-V1 all resolve correctly) and
        // repairs already-migrated trees purely on the read path. Cost is
        // ROOT_HISTORY_SIZE in-memory 32-byte compares — negligible.
        //
        // Soundness: the empty-tree sentinel is never a real stored root, so
        // we reject it up front and never compare it against a slot. This
        // means neither a sentinel query nor a sentinel-filled slot can ever
        // produce a false positive.
        let sentinel = ZERO_HASHES[MERKLE_DEPTH];
        if *root == sentinel {
            return false;
        }
        if *root == self.current_root {
            return true;
        }
        for candidate in self.root_history.iter() {
            if *candidate == *root {
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

/// DepositReceipt — created at deposit time if the depositor wants the
/// ability to revoke an unclaimed drop after `REVOKE_TIMEOUT` seconds.
///
/// Keyed by the full leaf (one receipt per drop). Rent is paid by the
/// depositor (not by the sender/relayer) so the depositor owns the PDA
/// and recovers the rent on close.
///
/// The receipt is the only on-chain link between a depositor wallet and
/// a specific leaf. Anyone can see the receipt exists, but without the
/// leaf preimage no link to the claim/withdraw can be inferred.
#[account]
pub struct DepositReceipt {
    pub bump: u8,
    pub depositor: Pubkey,
    pub amount: u64,
    pub created_at: i64,
    pub leaf: [u8; 32],
}

impl DepositReceipt {
    pub const SIZE: usize = 8   // discriminator
        + 1    // bump
        + 32   // depositor
        + 8    // amount
        + 8    // created_at
        + 32;  // leaf
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
        // Audit 06 L-02 / issue #16: scan the FULL circular buffer, skipping
        // (not stopping at) sentinel slots. The schema-v2 migration of a V1
        // ring that had wrapped preserves all 30 V1 slots as live roots while
        // root_history_index points mid-ring; the remaining slots are
        // sentinel-filled. A backward walk that breaks on the first sentinel
        // orphans the live roots that sit after a sentinel in descending-ring
        // order and wrongly rejects their (valid) claim codes — a liveness
        // regression. A full scan is layout-independent (partial fill, full
        // wrap, and migrated-from-wrapped-V1 all resolve correctly) and
        // repairs already-migrated trees purely on the read path. Cost is
        // ROOT_HISTORY_SIZE in-memory 32-byte compares — negligible.
        //
        // Soundness: the empty-tree sentinel is never a real stored root, so
        // we reject it up front and never compare it against a slot. This
        // means neither a sentinel query nor a sentinel-filled slot can ever
        // produce a false positive.
        let sentinel = ZERO_HASHES[MERKLE_DEPTH];
        if *root == sentinel {
            return false;
        }
        if *root == self.current_root {
            return true;
        }
        for candidate in self.root_history.iter() {
            if *candidate == *root {
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

/// PendingAuthority — sidecar PDA representing an in-flight authority
/// rotation proposal. Invariant: at most one pending proposal per vault at
/// a time (PDA seeds are keyed by vault, not candidate pubkey), closing
/// the door on ghost-proposal pile-ups. Created by
/// `propose_authority_rotation`, closed by `revoke_authority_rotation`
/// (current authority) or `accept_authority_rotation` (new authority).
/// PDA seeds: [b"pending_authority", vault.key()]
#[account]
pub struct PendingAuthority {
    pub bump: u8,
    pub vault: Pubkey,
    pub proposer: Pubkey,
    pub new_authority: Pubkey,
    pub proposed_at: i64,
}

impl PendingAuthority {
    pub const SIZE: usize = 8   // discriminator
        + 1    // bump
        + 32   // vault
        + 32   // proposer
        + 32   // new_authority
        + 8;   // proposed_at
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

// ─── SPL / multi-mint extension ──────────────────────────────────────────────
//
// All types below are strictly additive. They use distinct PDA seed prefixes
// (`*_spl`) so the SOL flow's existing PDAs (`merkle_tree`, `note_pool_tree`,
// `nullifier`, `pool_nullifier`, `credit`, `treasury`) remain byte-identical
// and any claim/credit/deposit issued before this change continues to resolve
// against unchanged seed namespaces.
//
// Per-mint isolation: each supported mint M gets its own MintConfig PDA, its
// own pair of trees (main + note pool), and its own nullifier namespaces. The
// shared Vault PDA continues to track SOL-only obligation counters; per-mint
// obligation counters live on each mint's MintConfig.

/// MintConfig — per-mint state record.
/// PDA seeds: [b"mint_config", mint.as_ref()]
///
/// Created by `initialize_mint_config(mint)` at the vault authority's
/// discretion. Existence of this account = the mint is registered. The
/// trees and mint vault are populated by a later, separate instruction so
/// `initialize_mint_config` stays small and individually auditable.
///
/// The `paused` flag is an admin kill-switch that disables new deposits
/// for this mint without affecting outstanding withdrawals, so users
/// always have a path to exit even for a paused mint.
#[account]
pub struct MintConfig {
    /// PDA bump seed.
    pub bump: u8,
    /// The SPL mint this record governs.
    pub mint: Pubkey,
    /// Unix timestamp of registration. Set once at init.
    pub registered_at: i64,
    /// Pubkey of the per-mint main Merkle tree (`MerkleTreeSpl`). Set to
    /// `Pubkey::default()` at init; populated by a later
    /// `initialize_mint_trees`-style instruction.
    pub merkle_tree: Pubkey,
    /// Pubkey of the per-mint note pool tree (`NotePoolTreeSpl`). Same
    /// lifecycle as `merkle_tree`.
    pub note_pool_tree: Pubkey,
    /// Pubkey of the per-mint program-owned token custody account. Set to
    /// `Pubkey::default()` at init; populated when the mint vault is
    /// created.
    pub mint_vault: Pubkey,
    /// Total deposited for this mint, in its base units.
    /// Floor enforced by per-mint `admin_sweep_spl`.
    pub total_deposited: u64,
    /// Total withdrawn for this mint, in its base units.
    pub total_withdrawn: u64,
    /// Admin kill-switch. When true, new deposits for this mint must fail
    /// with `MintPaused`. Outstanding credit notes can still withdraw.
    pub paused: bool,
}

impl MintConfig {
    pub const SIZE: usize = 8   // discriminator
        + 1    // bump
        + 32   // mint
        + 8    // registered_at
        + 32   // merkle_tree
        + 32   // note_pool_tree
        + 32   // mint_vault
        + 8    // total_deposited
        + 8    // total_withdrawn
        + 1;   // paused
}

/// MerkleTreeSpl — per-mint variant of `MerkleTreeAccount`.
/// PDA seeds: [b"merkle_tree_spl", mint.as_ref()]
///
/// Identical layout to `MerkleTreeAccount`; the only differences are the
/// seed prefix and the embedded `mint` cross-reference. `ROOT_HISTORY_SIZE`
/// and `MERKLE_DEPTH` match the SOL trees so SPL claim codes inherit the
/// same root-rotation behavior.
#[account(zero_copy(unsafe))]
#[repr(C)]
#[derive(Debug)]
pub struct MerkleTreeSpl {
    /// Associated vault (same singleton as the SOL path).
    pub vault: Pubkey,
    /// Mint this tree is bound to. Cross-checked against the ix `mint`
    /// argument on every write.
    pub mint: Pubkey,
    /// Next available leaf index.
    pub next_index: u32,
    /// Index into root_history circular buffer.
    pub root_history_index: u32,
    /// Current Merkle root.
    pub current_root: [u8; 32],
    /// Circular buffer of recent roots.
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Filled subtrees at each level (for incremental insertion).
    pub filled_subtrees: [[u8; 32]; MERKLE_DEPTH],
}

impl MerkleTreeSpl {
    /// Check if a root exists in the history.
    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        // Audit 06 L-02 / issue #16: scan the FULL circular buffer, skipping
        // (not stopping at) sentinel slots. The schema-v2 migration of a V1
        // ring that had wrapped preserves all 30 V1 slots as live roots while
        // root_history_index points mid-ring; the remaining slots are
        // sentinel-filled. A backward walk that breaks on the first sentinel
        // orphans the live roots that sit after a sentinel in descending-ring
        // order and wrongly rejects their (valid) claim codes — a liveness
        // regression. A full scan is layout-independent (partial fill, full
        // wrap, and migrated-from-wrapped-V1 all resolve correctly) and
        // repairs already-migrated trees purely on the read path. Cost is
        // ROOT_HISTORY_SIZE in-memory 32-byte compares — negligible.
        //
        // Soundness: the empty-tree sentinel is never a real stored root, so
        // we reject it up front and never compare it against a slot. This
        // means neither a sentinel query nor a sentinel-filled slot can ever
        // produce a false positive.
        let sentinel = ZERO_HASHES[MERKLE_DEPTH];
        if *root == sentinel {
            return false;
        }
        if *root == self.current_root {
            return true;
        }
        for candidate in self.root_history.iter() {
            if *candidate == *root {
                return true;
            }
        }
        false
    }
}

/// NotePoolTreeSpl — per-mint variant of `NotePoolTree`.
/// PDA seeds: [b"note_pool_tree_spl", mint.as_ref()]
#[account(zero_copy(unsafe))]
#[repr(C)]
#[derive(Debug)]
pub struct NotePoolTreeSpl {
    /// Associated vault.
    pub vault: Pubkey,
    /// Mint this tree is bound to.
    pub mint: Pubkey,
    /// Next available leaf index.
    pub next_index: u32,
    /// Index into root_history circular buffer.
    pub root_history_index: u32,
    /// Current Merkle root.
    pub current_root: [u8; 32],
    /// Circular buffer of recent roots.
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Filled subtrees at each level (for incremental insertion).
    pub filled_subtrees: [[u8; 32]; MERKLE_DEPTH],
}

impl NotePoolTreeSpl {
    /// Check if a root exists in the history.
    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        // Audit 06 L-02 / issue #16: scan the FULL circular buffer, skipping
        // (not stopping at) sentinel slots. The schema-v2 migration of a V1
        // ring that had wrapped preserves all 30 V1 slots as live roots while
        // root_history_index points mid-ring; the remaining slots are
        // sentinel-filled. A backward walk that breaks on the first sentinel
        // orphans the live roots that sit after a sentinel in descending-ring
        // order and wrongly rejects their (valid) claim codes — a liveness
        // regression. A full scan is layout-independent (partial fill, full
        // wrap, and migrated-from-wrapped-V1 all resolve correctly) and
        // repairs already-migrated trees purely on the read path. Cost is
        // ROOT_HISTORY_SIZE in-memory 32-byte compares — negligible.
        //
        // Soundness: the empty-tree sentinel is never a real stored root, so
        // we reject it up front and never compare it against a slot. This
        // means neither a sentinel query nor a sentinel-filled slot can ever
        // produce a false positive.
        let sentinel = ZERO_HASHES[MERKLE_DEPTH];
        if *root == sentinel {
            return false;
        }
        if *root == self.current_root {
            return true;
        }
        for candidate in self.root_history.iter() {
            if *candidate == *root {
                return true;
            }
        }
        false
    }
}

/// NullifierAccountSpl — per-mint nullifier record.
/// PDA seeds: [b"nullifier_spl", mint.as_ref(), nullifier_hash.as_ref()]
///
/// Strictly separated from the SOL `[b"nullifier", hash]` namespace. The
/// cross-namespace collision probability is 2^-256, so the separation is
/// for audit-surface clarity, not necessity — each mint's lifecycle stays
/// independently auditable.
#[account]
pub struct NullifierAccountSpl {
    /// The nullifier hash (for reference).
    pub nullifier_hash: [u8; 32],
}

impl NullifierAccountSpl {
    pub const SIZE: usize = 8 + 32;
}

/// PoolNullifierAccountSpl — per-mint pool nullifier record.
/// PDA seeds: [b"pool_nullifier_spl", mint.as_ref(), nullifier_hash.as_ref()]
#[account]
pub struct PoolNullifierAccountSpl {
    pub nullifier_hash: [u8; 32],
}

impl PoolNullifierAccountSpl {
    pub const SIZE: usize = 8 + 32;
}

/// CreditNoteSpl — wider variant of `CreditNote` that carries the source mint.
/// PDA seeds: [b"credit_spl", mint.as_ref(), nullifier_hash.as_ref()]
///
/// The existing `CreditNote` type is unchanged: legacy SOL credit notes
/// continue to resolve against `[b"credit", nullifier_hash]` via the
/// existing `withdraw_credit` ix. SPL claim codes issued after this change
/// land in the SPL namespace and are withdrawn via `withdraw_credit_spl`
/// (to be added), which reads this wider layout.
///
/// `commitment` is the same re-randomized form as `CreditNote.commitment`
/// (M-01-NEW); the `mint` is stored alongside, not folded into the
/// commitment. The PDA seeds include `mint` for symmetry with
/// `NullifierAccountSpl`, so a hypothetical (negligible-probability)
/// cross-mint nullifier_hash collision cannot cause a credit-note PDA
/// collision either.
#[account]
pub struct CreditNoteSpl {
    pub bump: u8,
    pub recipient: Pubkey,
    pub commitment: [u8; 32],
    pub nullifier_hash: [u8; 32],
    pub salt: [u8; 32],
    pub created_at: i64,
    pub mint: Pubkey,
}

impl CreditNoteSpl {
    pub const SIZE: usize = 8   // discriminator
        + 1    // bump
        + 32   // recipient
        + 32   // commitment
        + 32   // nullifier_hash
        + 32   // salt
        + 8    // created_at
        + 32;  // mint
}

#[cfg(test)]
mod is_known_root_tests {
    //! Issue #16 — L-02 regression: is_known_root skips valid roots on
    //! migrated+wrapped root buffers. These tests cover all four tree
    //! variants (MerkleTreeAccount, NotePoolTree, MerkleTreeSpl,
    //! NotePoolTreeSpl) against three layouts plus a soundness guard.
    use super::*;

    const SENTINEL: [u8; 32] = ZERO_HASHES[MERKLE_DEPTH];

    /// A distinct, definitely-non-sentinel root. First byte 0xA0 can never
    /// collide with the sentinel (ZERO_HASHES[MERKLE_DEPTH][0] == 33).
    fn root(n: u16) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = 0xA0;
        r[1] = (n >> 8) as u8;
        r[2] = (n & 0xff) as u8;
        r
    }

    /// Schema-v2 migration output for a V1 ring that had WRAPPED: the 30 V1
    /// slots (0..30) all hold distinct live roots, slots 30..256 are
    /// sentinel-filled, and root_history_index points mid-ring. This is the
    /// exact state described in issue #16's deterministic reproduction.
    fn migrated_wrapped_history() -> [[u8; 32]; ROOT_HISTORY_SIZE] {
        let mut h = [SENTINEL; ROOT_HISTORY_SIZE];
        for i in 0..ROOT_HISTORY_SIZE_V1 {
            h[i] = root(i as u16);
        }
        h
    }

    /// Fresh native-V2 tree, partially filled. Writes increment-then-write
    /// from index 1, so slot 0 stays sentinel and slots 1..=k are live.
    fn partial_fill_history(k: usize) -> [[u8; 32]; ROOT_HISTORY_SIZE] {
        let mut h = [SENTINEL; ROOT_HISTORY_SIZE];
        for i in 1..=k {
            h[i] = root(i as u16);
        }
        h
    }

    /// Fully-wrapped buffer: every one of the 256 slots holds a live root.
    fn fully_wrapped_history() -> [[u8; 32]; ROOT_HISTORY_SIZE] {
        let mut h = [SENTINEL; ROOT_HISTORY_SIZE];
        for i in 0..ROOT_HISTORY_SIZE {
            h[i] = root(i as u16);
        }
        h
    }

    /// Run the full scenario matrix against one tree variant. `$ctor` is a
    /// closure `(index, current_root, history) -> Box<TreeType>`.
    macro_rules! is_known_root_suite {
        ($name:ident, $ctor:expr) => {
            #[test]
            fn $name() {
                let ctor = $ctor;

                // ── Scenario 1: migrated-from-wrapped-V1 (the #16 repro) ──
                // index points mid-ring at slot 5; current_root is the most
                // recent live root. Slot 20 sits AFTER a sentinel in
                // descending-ring order (5->0->wrap->255=sentinel), so the
                // backward-walk-break version never examines it.
                let tree = ctor(5u32, root(5), migrated_wrapped_history());
                assert!(
                    tree.is_known_root(&root(20)),
                    "{}: live root orphaned after sentinel (slot 20) must be known",
                    stringify!($name)
                );
                assert!(
                    tree.is_known_root(&root(6)),
                    "{}: live root in slot 6 must be known",
                    stringify!($name)
                );
                assert!(
                    tree.is_known_root(&root(29)),
                    "{}: live root in last V1 slot (29) must be known",
                    stringify!($name)
                );
                assert!(
                    tree.is_known_root(&root(0)),
                    "{}: live root in slot 0 must be known",
                    stringify!($name)
                );
                assert!(
                    tree.is_known_root(&root(5)),
                    "{}: current_root must be known",
                    stringify!($name)
                );
                // Soundness: the sentinel is never a stored root.
                assert!(
                    !tree.is_known_root(&SENTINEL),
                    "{}: sentinel must never match (soundness guard)",
                    stringify!($name)
                );
                // Soundness: an unstored root is never known.
                assert!(
                    !tree.is_known_root(&root(99)),
                    "{}: unstored root must not match",
                    stringify!($name)
                );

                // ── Scenario 2: native-V2 partial fill (no regression) ──
                let tree = ctor(10u32, root(10), partial_fill_history(10));
                assert!(tree.is_known_root(&root(1)), "{}: partial slot 1", stringify!($name));
                assert!(tree.is_known_root(&root(5)), "{}: partial slot 5", stringify!($name));
                assert!(tree.is_known_root(&root(10)), "{}: partial current", stringify!($name));
                assert!(!tree.is_known_root(&SENTINEL), "{}: partial sentinel", stringify!($name));
                assert!(!tree.is_known_root(&root(50)), "{}: partial unstored", stringify!($name));

                // ── Scenario 3: fully-wrapped (no regression) ──
                let tree = ctor(100u32, root(100), fully_wrapped_history());
                assert!(tree.is_known_root(&root(0)), "{}: wrapped slot 0", stringify!($name));
                assert!(tree.is_known_root(&root(255)), "{}: wrapped slot 255", stringify!($name));
                assert!(tree.is_known_root(&root(100)), "{}: wrapped current", stringify!($name));
                assert!(!tree.is_known_root(&SENTINEL), "{}: wrapped sentinel", stringify!($name));
            }
        };
    }

    is_known_root_suite!(main_merkle_tree, |index, current, history| Box::new(
        MerkleTreeAccount {
            vault: Pubkey::default(),
            next_index: 0,
            root_history_index: index,
            current_root: current,
            root_history: history,
            filled_subtrees: [[0u8; 32]; MERKLE_DEPTH],
        }
    ));

    is_known_root_suite!(note_pool_tree, |index, current, history| Box::new(NotePoolTree {
        vault: Pubkey::default(),
        next_index: 0,
        root_history_index: index,
        current_root: current,
        root_history: history,
        filled_subtrees: [[0u8; 32]; MERKLE_DEPTH],
    }));

    is_known_root_suite!(merkle_tree_spl, |index, current, history| Box::new(MerkleTreeSpl {
        vault: Pubkey::default(),
        mint: Pubkey::default(),
        next_index: 0,
        root_history_index: index,
        current_root: current,
        root_history: history,
        filled_subtrees: [[0u8; 32]; MERKLE_DEPTH],
    }));

    is_known_root_suite!(note_pool_tree_spl, |index, current, history| Box::new(
        NotePoolTreeSpl {
            vault: Pubkey::default(),
            mint: Pubkey::default(),
            next_index: 0,
            root_history_index: index,
            current_root: current,
            root_history: history,
            filled_subtrees: [[0u8; 32]; MERKLE_DEPTH],
        }
    ));
}
