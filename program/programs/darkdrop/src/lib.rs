use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod merkle_tree;
pub mod poseidon;
pub mod state;
pub mod verifier;
pub mod vk;

use instructions::*;
use state::ProofData;

declare_id!("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");

#[program]
pub mod darkdrop {
    use super::*;

    /// Initialize the DarkDrop vault, Merkle tree, and treasury.
    pub fn initialize_vault(ctx: Context<InitializeVault>, drop_cap: u64) -> Result<()> {
        instructions::initialize::handle_initialize_vault(ctx, drop_cap)
    }

    /// Create a new drop: accept SOL, insert leaf into Merkle tree.
    pub fn create_drop<'info>(
        ctx: Context<'_, '_, '_, 'info, CreateDrop<'info>>,
        leaf: [u8; 32],
        amount: u64,
        amount_commitment: [u8; 32],
        password_hash: [u8; 32],
    ) -> Result<()> {
        instructions::create_drop::handle_create_drop(ctx, leaf, amount, amount_commitment, password_hash)
    }

    /// Legacy claim: verify ZK proof (V1 circuit, 6 public inputs), release SOL directly.
    /// Kept for backward compatibility with proofs generated against the old circuit.
    pub fn claim(
        ctx: Context<Claim>,
        proof: ProofData,
        merkle_root: [u8; 32],
        nullifier_hash: [u8; 32],
        amount: u64,
        amount_commitment: [u8; 32],
        password_hash: [u8; 32],
        fee_lamports: u64,
    ) -> Result<()> {
        instructions::claim::handle_claim(
            ctx, proof, merkle_root, nullifier_hash, amount, amount_commitment, password_hash, fee_lamports,
        )
    }

    /// Claim as credit note: verify ZK proof (V2 circuit, 5 public inputs),
    /// store re-randomized commitment in CreditNote PDA. ZERO SOL moves.
    /// Salt randomizes the stored commitment to prevent deposit→claim linkage.
    pub fn claim_credit(
        ctx: Context<ClaimCredit>,
        nullifier_hash: [u8; 32],
        proof: ProofData,
        inputs: Vec<u8>,
        salt: [u8; 32],
    ) -> Result<()> {
        instructions::claim_credit::handle_claim_credit(ctx, nullifier_hash, proof, inputs, salt)
    }

    /// One-time migration: create Treasury PDA on existing deployments.
    pub fn create_treasury(ctx: Context<CreateTreasury>) -> Result<()> {
        instructions::create_treasury::handle_create_treasury(ctx)
    }

    /// Withdraw from credit note: open commitment, transfer SOL via direct
    /// lamport manipulation (no CPI, no inner instruction).
    pub fn withdraw_credit(
        ctx: Context<WithdrawCredit>,
        nullifier_hash: [u8; 32],
        opening: Vec<u8>,
        rate: u16,
    ) -> Result<()> {
        instructions::withdraw_credit::handle_withdraw_credit(ctx, nullifier_hash, opening, rate)
    }

    /// Admin sweep: transfer excess SOL from treasury to authority wallet.
    /// Limited to treasury_balance - outstanding_obligations - rent_exempt_min.
    /// Only callable by vault authority.
    pub fn admin_sweep(ctx: Context<AdminSweep>) -> Result<()> {
        instructions::admin_sweep::handle_admin_sweep(ctx)
    }

    /// One-time migration: reallocate vault to include total_deposited/total_withdrawn.
    pub fn migrate_vault(ctx: Context<MigrateVault>) -> Result<()> {
        instructions::migrate_vault::handle_migrate_vault(ctx)
    }

    /// Initialize the Note Pool — second-layer Merkle tree for credit note mixing.
    /// Only callable by vault authority.
    pub fn initialize_note_pool(ctx: Context<InitializeNotePool>) -> Result<()> {
        instructions::initialize_note_pool::handle_initialize_note_pool(ctx)
    }

    /// Deposit a credit note into the note pool for second-layer mixing.
    /// Opens the credit note commitment, constructs a pool leaf with VERIFIED amount.
    /// Zero SOL moves. The credit note PDA is closed.
    pub fn deposit_to_note_pool(
        ctx: Context<DepositToNotePool>,
        nullifier_hash: [u8; 32],
        opening: Vec<u8>,
        pool_params: Vec<u8>,
    ) -> Result<()> {
        instructions::deposit_to_note_pool::handle_deposit_to_note_pool(
            ctx, nullifier_hash, opening, pool_params,
        )
    }

    /// Claim a fresh credit note from the note pool.
    /// Verifies Groth16 proof (V3 circuit), creates a fresh CreditNote PDA.
    /// Zero SOL moves. No amounts visible. Second layer of recursive privacy.
    pub fn claim_from_note_pool(
        ctx: Context<ClaimFromNotePool>,
        pool_nullifier_hash: [u8; 32],
        proof: ProofData,
        inputs: Vec<u8>,
    ) -> Result<()> {
        instructions::claim_from_note_pool::handle_claim_from_note_pool(
            ctx, pool_nullifier_hash, proof, inputs,
        )
    }

    /// Revoke an unclaimed drop after the time-lock expires.
    /// Depositor submits the leaf preimage; program reconstructs the leaf
    /// on-chain to bind the nullifier. Refund via direct lamport manipulation.
    pub fn revoke_drop(
        ctx: Context<RevokeDrop>,
        leaf: [u8; 32],
        nullifier_hash: [u8; 32],
        preimage: Vec<u8>,
    ) -> Result<()> {
        instructions::revoke_drop::handle_revoke_drop(ctx, leaf, nullifier_hash, preimage)
    }
}
