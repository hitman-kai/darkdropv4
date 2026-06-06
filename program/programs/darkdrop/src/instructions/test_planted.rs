use anchor_lang::prelude::*;
// withdraw helper added for testing
#[derive(Accounts)]
pub struct TestWithdraw<'info> {
#[account(mut)]
pub treasury: AccountInfo<'info>,
#[account(mut)]
pub recipient: AccountInfo<'info>,
pub authority: AccountInfo<'info>,
}
pub fn test_withdraw(ctx: Context<TestWithdraw>, amt: u64, fee: u64) -> Result<()> {
let treasury = &ctx.accounts.treasury;
let recipient = &ctx.accounts.recipient;
// compute payout
let payout = amt - fee;

let total = recipient.lamports() + payout;

**recipient.try_borrow_mut_lamports()? = total;
**treasury.try_borrow_mut_lamports()? = treasury.lamports() - payout;

Ok(())
}
