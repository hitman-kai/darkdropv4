use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;

/// Close an unused DepositReceipt and return rent to the depositor.
///
/// Unconditional close: the depositor decides when closure is safe (typically
/// after they see their drop was claimed, so revoke is no longer needed).
/// There is no on-chain check that the drop was claimed because either
/// supplying the preimage or supplying the nullifier_hash would create a new
/// privacy linkage source that the M-01 fix is trying to avoid. See
/// Audit #4's M-01 analysis for the full reasoning.
///
/// Closing prematurely surrenders the revoke option — self-harm only, not a
/// security concern.
pub fn handle_close_receipt(
    ctx: Context<CloseReceipt>,
    _leaf: [u8; 32],
) -> Result<()> {
    let receipt = &ctx.accounts.deposit_receipt;

    // Critical authorization check. Anchor's `close = depositor` only routes
    // lamports to the provided account; it does NOT verify that the caller is
    // the receipt's recorded depositor. Without this check, any signer could
    // close any receipt and steal the rent.
    require_keys_eq!(
        ctx.accounts.depositor.key(),
        receipt.depositor,
        DarkDropError::InvalidDepositReceipt
    );

    emit!(DepositReceiptClosed {
        leaf: receipt.leaf,
        depositor: receipt.depositor,
        timestamp: Clock::get()?.unix_timestamp,
    });

    // Anchor's `close = depositor` constraint closes the PDA and returns rent.

    Ok(())
}

#[derive(Accounts)]
#[instruction(leaf: [u8; 32])]
pub struct CloseReceipt<'info> {
    /// DepositReceipt PDA — closed, rent returned to depositor.
    #[account(
        mut,
        seeds = [b"receipt", leaf.as_ref()],
        bump = deposit_receipt.bump,
        close = depositor,
    )]
    pub deposit_receipt: Account<'info, DepositReceipt>,

    #[account(mut)]
    pub depositor: Signer<'info>,
}

#[event]
pub struct DepositReceiptClosed {
    pub leaf: [u8; 32],
    pub depositor: Pubkey,
    pub timestamp: i64,
}
