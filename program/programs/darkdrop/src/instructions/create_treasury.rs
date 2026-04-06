use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;

/// One-time migration: create the program-owned Treasury PDA.
/// Called on existing deployments where vault and merkle_tree already exist
/// but treasury does not.
/// Only the vault authority can call this.
pub fn handle_create_treasury(ctx: Context<CreateTreasury>) -> Result<()> {
    let treasury = &mut ctx.accounts.treasury;
    treasury.bump = ctx.bumps.treasury;

    msg!("Treasury PDA created");
    Ok(())
}

#[derive(Accounts)]
pub struct CreateTreasury<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = authority,
        space = Treasury::SIZE,
        seeds = [b"treasury"],
        bump,
    )]
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}
