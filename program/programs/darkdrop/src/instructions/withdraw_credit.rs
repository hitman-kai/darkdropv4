use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::{poseidon_hash, u64_to_field_be};

/// Withdraw a credit note: open the Poseidon commitment, transfer SOL via direct
/// lamport manipulation (no CPI, no inner instruction).
///
/// The `opening` parameter is an opaque byte vector containing:
///   [0..8]   amount (u64 little-endian)
///   [8..40]  blinding factor (32 bytes)
///   [40..72] salt (32 bytes) — caller-supplied; used only as a fallback (see below)
///
/// Audit 06 M-02 — salt handling. The V2 proof does not bind the salt, so a
/// gasless relayer can substitute the salt it passes to `claim_credit`. To stop
/// that from bricking a user's withdraw, this handler tries the AUTHORITATIVE
/// on-chain `credit.salt` FIRST: for a standard `claim_credit` note that is the
/// exact salt baked into `credit.commitment`, so the withdraw succeeds no matter
/// which salt the relayer chose.
///
/// It then falls back to the caller-supplied salt. This fallback is REQUIRED for
/// note-pool (`claim_from_note_pool`) credit notes: those store a *decoy*
/// `credit.salt` (a value derived from the pool nullifier, see
/// claim_from_note_pool.rs) for indistinguishability, while the real salt is
/// baked into the proof-bound commitment and is known only to the recipient.
/// The fallback opens those. It adds no attack surface — pool commitments are
/// proof-bound, and for standard notes the authoritative check already matched.
///
/// Verification (either branch satisfies):
///   Poseidon(Poseidon(amount, blinding), credit.salt)  == commitment   (standard)
///   Poseidon(Poseidon(amount, blinding), caller_salt)   == commitment   (pool)
///
/// Fee is computed from `rate` (basis points). rate=50 → 0.5% fee.
/// No field is named "amount", "fee", or "lamports".
///
/// SOL transfer uses direct lamport manipulation on the program-owned treasury.
/// This produces NO inner CPI instruction — Solscan shows only account balance
/// deltas, not a decoded "Transfer" instruction.
pub fn handle_withdraw_credit(
    ctx: Context<WithdrawCredit>,
    _nullifier_hash: [u8; 32],
    opening: Vec<u8>,
    rate: u16,
) -> Result<()> {
    // Parse opaque opening (72 bytes: amount + blinding + caller salt).
    require!(opening.len() == 72, DarkDropError::InvalidInputLength);

    let amount = u64::from_le_bytes(opening[0..8].try_into().unwrap());
    let blinding_factor: [u8; 32] = opening[8..40].try_into().unwrap();
    let caller_salt: [u8; 32] = opening[40..72].try_into().unwrap();

    let credit = &ctx.accounts.credit_note;

    // Verify recipient matches the credit note
    require!(
        ctx.accounts.recipient.key() == credit.recipient,
        DarkDropError::UnauthorizedWithdraw
    );

    // Audit 07 L-03 (defense-in-depth): reject any self-alias of the treasury PDA.
    // The lamport transfers below debit `treasury` then credit `recipient`/`payer`;
    // if either aliased `treasury` they'd share one lamports cell, netting the
    // principal to zero. Benign in practice (recipient is proof-bound), but the
    // explicit guard removes the edge and makes the invariant visible.
    let treasury_key = ctx.accounts.treasury.key();
    require!(
        ctx.accounts.recipient.key() != treasury_key,
        DarkDropError::UnauthorizedWithdraw
    );
    require!(
        ctx.accounts.payer.key() != treasury_key,
        DarkDropError::UnauthorizedWithdraw
    );

    // Recompute the re-randomized commitment (Audit 06 M-02). original is fixed;
    // the salt is what differs between standard and pool notes:
    //   original = Poseidon(amount, blinding_factor)
    // Try the AUTHORITATIVE on-chain credit.salt first (defeats relayer salt
    // substitution for standard notes), then fall back to the caller-supplied
    // salt (required for note-pool notes, whose credit.salt is a decoy).
    let amount_bytes = u64_to_field_be(amount);
    let original_commitment = poseidon_hash(&amount_bytes, &blinding_factor);
    let matches_stored =
        poseidon_hash(&original_commitment, &credit.salt) == credit.commitment;
    let matches_caller =
        poseidon_hash(&original_commitment, &caller_salt) == credit.commitment;
    require!(
        matches_stored || matches_caller,
        DarkDropError::CommitmentMismatch
    );

    // Validate amount
    require!(amount > 0, DarkDropError::ZeroAmount);

    // Cap fee rate at 500 bps (5%) to prevent malicious relayers from stealing funds.
    // A relayer sets rate in instruction data — without this cap, rate=9999 would
    // take 99.99% of the withdrawal. Users in direct mode set rate=0.
    const MAX_FEE_RATE: u16 = 500;
    require!(rate <= MAX_FEE_RATE, DarkDropError::FeeTooHigh);

    // Compute fee from basis points: fee = amount * rate / 10000
    let fee = if rate > 0 {
        (amount as u128)
            .checked_mul(rate as u128)
            .ok_or(DarkDropError::Overflow)?
            .checked_div(10000)
            .ok_or(DarkDropError::Overflow)? as u64
    } else {
        0u64
    };

    let recipient_amount = amount.checked_sub(fee)
        .ok_or(DarkDropError::Overflow)?;

    // Check treasury has enough SOL (minus rent-exempt minimum)
    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(Treasury::SIZE);
    let available = ctx.accounts.treasury.to_account_info().lamports()
        .checked_sub(min_balance)
        .ok_or(DarkDropError::InsufficientBalance)?;
    require!(amount <= available, DarkDropError::InsufficientBalance);

    // === DIRECT LAMPORT MANIPULATION ===
    // No CPI → no inner instruction → no decoded "Transfer" on Solscan.
    // Only account balance deltas visible in transaction metadata.

    // Debit treasury (program-owned — we can decrease its lamports)
    {
        let treasury_info = ctx.accounts.treasury.to_account_info();
        let mut treasury_lamports = treasury_info.try_borrow_mut_lamports()?;
        **treasury_lamports = (**treasury_lamports)
            .checked_sub(amount)
            .ok_or(DarkDropError::Overflow)?;
    }

    // Credit recipient
    {
        let recipient_info = ctx.accounts.recipient.to_account_info();
        let mut recipient_lamports = recipient_info.try_borrow_mut_lamports()?;
        **recipient_lamports = (**recipient_lamports)
            .checked_add(recipient_amount)
            .ok_or(DarkDropError::Overflow)?;
    }

    // Credit the fee to payer (I-04: fee_recipient was constrained to equal
    // payer since Audit 03, making it a redundant account slot).
    if fee > 0 {
        let payer_info = ctx.accounts.payer.to_account_info();
        let mut payer_lamports = payer_info.try_borrow_mut_lamports()?;
        **payer_lamports = (**payer_lamports)
            .checked_add(fee)
            .ok_or(DarkDropError::Overflow)?;
    }

    // Track total withdrawn for sweep limit enforcement
    let vault = &mut ctx.accounts.vault;
    vault.total_withdrawn = vault.total_withdrawn
        .checked_add(amount)
        .ok_or(DarkDropError::Overflow)?;

    emit!(CreditWithdrawn {
        nullifier_hash: credit.nullifier_hash,
        recipient: credit.recipient,
        timestamp: Clock::get()?.unix_timestamp,
    });

    // CreditNote PDA is closed by Anchor's `close = payer` constraint

    Ok(())
}

#[derive(Accounts)]
#[instruction(nullifier_hash: [u8; 32])]
pub struct WithdrawCredit<'info> {
    #[account(mut, seeds = [b"vault"], bump = vault.bump)]
    pub vault: Account<'info, Vault>,

    /// Program-owned treasury — direct lamport manipulation
    #[account(
        mut,
        seeds = [b"treasury"],
        bump = treasury.bump,
    )]
    pub treasury: Account<'info, Treasury>,

    /// CreditNote — closed after withdrawal (rent returned to payer)
    #[account(
        mut,
        seeds = [b"credit", nullifier_hash.as_ref()],
        bump = credit_note.bump,
        close = payer,
    )]
    pub credit_note: Account<'info, CreditNote>,

    /// CHECK: Recipient — must match credit_note.recipient
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct CreditWithdrawn {
    pub nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub timestamp: i64,
}
