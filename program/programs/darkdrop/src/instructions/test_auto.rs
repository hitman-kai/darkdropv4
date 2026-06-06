use anchor_lang::prelude::*;
// admin config update
#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
#[account(mut)]
pub config: Account<'info, AdminConfig>,
pub caller: AccountInfo<'info>,
}
#[account]
pub struct AdminConfig {
pub admin: Pubkey,
pub fee_bps: u16,
pub paused: bool,
}
pub fn update_admin(ctx: Context<UpdateAdmin>, new_admin: Pubkey, new_fee: u16) -> Result<()> {
let config = &mut ctx.accounts.config;
config.admin = new_admin;
config.fee_bps = new_fee;
Ok(())
}
