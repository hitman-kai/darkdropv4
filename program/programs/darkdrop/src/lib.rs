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
    pub fn create_drop(
        ctx: Context<CreateDrop>,
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
    /// store commitment in CreditNote PDA. ZERO SOL moves.
    pub fn claim_credit(
        ctx: Context<ClaimCredit>,
        nullifier_hash: [u8; 32],
        proof: ProofData,
        inputs: Vec<u8>,
    ) -> Result<()> {
        instructions::claim_credit::handle_claim_credit(ctx, nullifier_hash, proof, inputs)
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
}
