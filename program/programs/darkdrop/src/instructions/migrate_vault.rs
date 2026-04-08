use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;

/// One-time migration: reallocate the Vault account to include new fields
/// (total_deposited, total_withdrawn). Only callable by the vault authority.
///
/// Uses raw AccountInfo because the old vault account is too small to
/// deserialize as the new Vault struct.
pub fn handle_migrate_vault(ctx: Context<MigrateVault>) -> Result<()> {
    let vault_info = &ctx.accounts.vault;
    let authority = &ctx.accounts.authority;

    // Verify the vault PDA
    let (expected_vault, _bump) = Pubkey::find_program_address(
        &[b"vault"],
        ctx.program_id,
    );
    require!(vault_info.key() == expected_vault, DarkDropError::InvalidProof);

    // Verify authority matches what's stored in the vault
    // authority is at offset 8 (discriminator) + 1 (bump) = 9, length 32
    let vault_data = vault_info.try_borrow_data()?;
    let stored_authority = Pubkey::try_from(&vault_data[9..41]).unwrap();
    require!(stored_authority == authority.key(), DarkDropError::UnauthorizedWithdraw);
    let old_len = vault_data.len();
    drop(vault_data);

    // Realloc to new size if needed
    if old_len < Vault::SIZE {
        let rent = Rent::get()?;
        let new_min = rent.minimum_balance(Vault::SIZE);
        let old_min = rent.minimum_balance(old_len);
        let lamports_needed = new_min.saturating_sub(old_min);

        if lamports_needed > 0 {
            // Transfer additional rent from authority
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: authority.to_account_info(),
                        to: vault_info.to_account_info(),
                    },
                ),
                lamports_needed,
            )?;
        }

        vault_info.realloc(Vault::SIZE, false)?;
    }

    // Write the new fields at the end of the old data
    // total_deposited at offset old_size, total_withdrawn at old_size + 8
    let mut vault_data = vault_info.try_borrow_mut_data()?;
    let td_offset = Vault::SIZE - 16; // total_deposited
    let tw_offset = Vault::SIZE - 8;  // total_withdrawn
    vault_data[td_offset..td_offset + 8].copy_from_slice(&0u64.to_le_bytes());
    vault_data[tw_offset..tw_offset + 8].copy_from_slice(&0u64.to_le_bytes());

    msg!("Vault migrated to V2 (added total_deposited, total_withdrawn). Old size: {}, new size: {}", old_len, Vault::SIZE);
    Ok(())
}

#[derive(Accounts)]
pub struct MigrateVault<'info> {
    /// CHECK: Raw vault account — cannot deserialize as new Vault struct yet.
    /// Verified via PDA derivation and authority check in handler.
    #[account(mut)]
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}
