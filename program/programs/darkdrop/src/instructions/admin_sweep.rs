use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;

/// Admin sweep: transfer excess SOL from treasury to the vault authority wallet.
/// Only callable by the vault authority.
///
/// Sweep is limited to: treasury_balance - outstanding_obligations - rent_exempt_min
/// where outstanding_obligations = total_deposited - total_withdrawn.
/// This prevents sweeping funds that belong to outstanding credit notes.
pub fn handle_admin_sweep(ctx: Context<AdminSweep>) -> Result<()> {
    let treasury = &ctx.accounts.treasury;
    let vault = &ctx.accounts.vault;
    let authority = &ctx.accounts.authority;

    let treasury_lamports = treasury.to_account_info().lamports();
    let rent = Rent::get()?;
    let rent_exempt_min = rent.minimum_balance(Treasury::SIZE);

    // Outstanding obligations: deposits not yet withdrawn
    let outstanding = vault.total_deposited
        .checked_sub(vault.total_withdrawn)
        .ok_or(DarkDropError::Overflow)?;

    // Available for sweep: treasury balance minus obligations minus rent
    let reserved = outstanding
        .checked_add(rent_exempt_min)
        .ok_or(DarkDropError::Overflow)?;

    let sweep_amount = treasury_lamports
        .checked_sub(reserved)
        .ok_or(DarkDropError::InsufficientBalance)?;

    require!(sweep_amount > 0, DarkDropError::ZeroAmount);

    // Direct lamport manipulation — treasury is program-owned
    **treasury.to_account_info().try_borrow_mut_lamports()? -= sweep_amount;
    **authority.to_account_info().try_borrow_mut_lamports()? += sweep_amount;

    emit!(TreasurySweep {
        authority: authority.key(),
        amount: sweep_amount,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!("Swept {} lamports to authority", sweep_amount);
    Ok(())
}

#[derive(Accounts)]
pub struct AdminSweep<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"treasury"],
        bump = treasury.bump,
    )]
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[event]
pub struct TreasurySweep {
    pub authority: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}
