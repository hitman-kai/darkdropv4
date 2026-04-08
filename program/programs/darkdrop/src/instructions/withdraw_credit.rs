use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::poseidon_hash;

/// Withdraw a credit note: open the Poseidon commitment, transfer SOL via direct
/// lamport manipulation (no CPI, no inner instruction).
///
/// The `opening` parameter is an opaque byte vector containing:
///   [0..8]   amount (u64 little-endian)
///   [8..40]  blinding factor (32 bytes)
///   [40..72] salt (32 bytes) — used to verify re-randomized commitment
///
/// Verification: Poseidon(Poseidon(amount, blinding), salt) == stored_commitment
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
    // Parse opaque opening (72 bytes: amount + blinding + salt)
    require!(opening.len() == 72, DarkDropError::InvalidInputLength);

    let amount = u64::from_le_bytes(opening[0..8].try_into().unwrap());
    let blinding_factor: [u8; 32] = opening[8..40].try_into().unwrap();
    let salt: [u8; 32] = opening[40..72].try_into().unwrap();

    let credit = &ctx.accounts.credit_note;

    // Verify recipient matches the credit note
    require!(
        ctx.accounts.recipient.key() == credit.recipient,
        DarkDropError::UnauthorizedWithdraw
    );

    // Recompute the re-randomized commitment:
    //   original = Poseidon(amount, blinding_factor)
    //   stored   = Poseidon(original, salt)
    let amount_bytes = u64_to_field_be(amount);
    let original_commitment = poseidon_hash(&amount_bytes, &blinding_factor);
    let computed_commitment = poseidon_hash(&original_commitment, &salt);

    // Verify re-randomized commitment matches stored value
    require!(
        computed_commitment == credit.commitment,
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
    **ctx.accounts.treasury.to_account_info().try_borrow_mut_lamports()? -= amount;

    // Credit recipient
    **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += recipient_amount;

    // Credit fee_recipient (if fee > 0)
    if fee > 0 {
        **ctx.accounts.fee_recipient.to_account_info().try_borrow_mut_lamports()? += fee;
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

/// Convert a u64 to a 32-byte big-endian field element.
fn u64_to_field_be(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
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

    /// CHECK: Fee recipient — must be the payer (signer) to prevent fee diversion.
    #[account(mut, constraint = fee_recipient.key() == payer.key())]
    pub fee_recipient: UncheckedAccount<'info>,

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
