use anchor_lang::prelude::*;
use anchor_spl::token::Mint;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::verifier::verify_proof_v3;
use crate::poseidon::{poseidon_hash, pubkey_to_field};

/// SPL parallel of `claim_from_note_pool`. Second-layer claim path —
/// the user proves knowledge of an opening for a leaf in the per-mint
/// `NotePoolTreeSpl` and receives a fresh `CreditNoteSpl` keyed by the
/// pool nullifier hash. Withdraw is via `withdraw_credit_spl` against
/// that new credit note.
///
/// Structurally mirrors `claim_from_note_pool.rs`:
///   - V3 verifier (4 public inputs in the same order).
///   - `inputs` is the same opaque 64-byte vector: pool_merkle_root ||
///     new_stored_commitment.
///   - No salt parameter — the circuit folds new_blinding/new_salt
///     into `new_stored_commitment` itself, so the on-chain code
///     stores that value directly. A cosmetic salt is derived from
///     `Poseidon(pool_nullifier_hash, new_stored_commitment)` so the
///     credit-note `salt` field looks indistinguishable from a
///     claim_credit_spl one (prevents an indexer from labeling
///     pool-origin notes by an all-zero salt).
///   - Note pool tree is READ-ONLY — no `mut`, no tree state change.
///
/// Differences from SOL flow:
///   1. Reads pool root from per-mint `NotePoolTreeSpl`.
///   2. Nullifier PDA in per-mint namespace
///      `[b"pool_nullifier_spl", mint, pool_nullifier_hash]`.
///   3. CreditNoteSpl carries `mint` so withdraw_credit_spl knows
///      which mint vault to debit.
///   4. Bumps the global `vault.total_claims` counter — same convention as
///      every other claim path (claim_credit, claim_credit_spl,
///      claim_from_note_pool). There is no `NotePoolSpl` singleton, so
///      unlike the SOL pool claim there is no additional per-layer counter
///      to bump here. (issue #47 — Audit #7 I-02.)
///
/// ZERO TOKEN MOVEMENT.
pub fn handle_claim_from_note_pool_spl(
    ctx: Context<ClaimFromNotePoolSpl>,
    pool_nullifier_hash: [u8; 32],
    proof: ProofData,
    inputs: Vec<u8>,
) -> Result<()> {
    require!(inputs.len() == 64, DarkDropError::InvalidInputLength);

    let pool_merkle_root: [u8; 32] = inputs[0..32].try_into().unwrap();
    let new_stored_commitment: [u8; 32] = inputs[32..64].try_into().unwrap();

    // Validate pool merkle root against the per-mint pool tree.
    let tree = ctx.accounts.note_pool_tree_spl.load()?;
    require!(
        tree.is_known_root(&pool_merkle_root),
        DarkDropError::InvalidRoot
    );
    drop(tree);

    // Recipient field element — same Poseidon(hi_128, lo_128) encoding
    // as claim_credit_spl. Duplicated locally to keep this file off
    // private symbols in audited claim_from_note_pool.rs.
    let recipient_hash = pubkey_to_field(&ctx.accounts.recipient.key());

    // 4 public inputs, V3 order.
    let public_inputs: [[u8; 32]; 4] = [
        pool_merkle_root,
        pool_nullifier_hash,
        new_stored_commitment,
        recipient_hash,
    ];

    verify_proof_v3(&proof, &public_inputs)?;

    // Stored commitment is `new_stored_commitment` directly — the V3
    // circuit already encodes the re-randomization
    // (Poseidon(Poseidon(amount, new_blinding), new_salt)).
    let credit = &mut ctx.accounts.credit_note_spl;
    credit.bump = ctx.bumps.credit_note_spl;
    credit.recipient = ctx.accounts.recipient.key();
    credit.commitment = new_stored_commitment;
    credit.nullifier_hash = pool_nullifier_hash;
    // Cosmetic on-chain-derived salt — matches the audited claim_from_note_pool
    // behavior so this credit note's `salt` slot is indistinguishable from
    // a claim_credit_spl note's at the indexer layer.
    credit.salt = poseidon_hash(&pool_nullifier_hash, &new_stored_commitment);
    credit.created_at = Clock::get()?.unix_timestamp;
    credit.mint = ctx.accounts.mint.key();

    // Pool nullifier — Anchor `init` enforces single-use.
    ctx.accounts.pool_nullifier_account_spl.nullifier_hash = pool_nullifier_hash;

    // Global cross-asset/cross-layer claim counter — bumped by every claim
    // path (documented in module comment; issue #47 — Audit #7 I-02).
    let vault = &mut ctx.accounts.vault;
    vault.total_claims = vault.total_claims
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    emit!(NotePoolClaimSpl {
        mint: ctx.accounts.mint.key(),
        pool_nullifier_hash,
        recipient: ctx.accounts.recipient.key(),
        timestamp: credit.created_at,
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(pool_nullifier_hash: [u8; 32])]
pub struct ClaimFromNotePoolSpl<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [b"mint_config", mint.key().as_ref()],
        bump = mint_config.bump,
        has_one = mint,
    )]
    pub mint_config: Account<'info, MintConfig>,

    /// Read-only — pool root is checked against this tree's
    /// root_history; the tree itself is not mutated.
    #[account(
        seeds = [b"note_pool_tree_spl", mint.key().as_ref()],
        bump,
    )]
    pub note_pool_tree_spl: AccountLoader<'info, NotePoolTreeSpl>,

    /// Pool nullifier PDA — Anchor `init` enforces single-use.
    /// Disjoint namespace from `nullifier_spl` (main-tree claims) so
    /// SPL pool and SPL main claims with a hypothetically colliding
    /// hash never interact.
    #[account(
        init,
        payer = payer,
        space = PoolNullifierAccountSpl::SIZE,
        seeds = [b"pool_nullifier_spl", mint.key().as_ref(), pool_nullifier_hash.as_ref()],
        bump,
    )]
    pub pool_nullifier_account_spl: Account<'info, PoolNullifierAccountSpl>,

    /// Fresh CreditNoteSpl — same `[b"credit_spl", mint, nullifier_hash]`
    /// seed shape as `claim_credit_spl`. The fact that the nullifier_hash
    /// here came from the pool side is invisible from the PDA address.
    #[account(
        init,
        payer = payer,
        space = CreditNoteSpl::SIZE,
        seeds = [b"credit_spl", mint.key().as_ref(), pool_nullifier_hash.as_ref()],
        bump,
    )]
    pub credit_note_spl: Account<'info, CreditNoteSpl>,

    pub mint: Account<'info, Mint>,

    /// CHECK: Recipient — any account, NOT a signer. Bound by the V3
    /// proof via Poseidon(pubkey).
    pub recipient: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct NotePoolClaimSpl {
    pub mint: Pubkey,
    pub pool_nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub timestamp: i64,
}
