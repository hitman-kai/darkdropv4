use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::merkle_tree::merkle_tree_append;

/// Create a new drop: accept SOL via CPI to treasury, insert leaf into Merkle tree.
///
/// The SOL transfer is a CPI to system_program (sender → treasury).
/// system_program::transfer can send TO a program-owned account — only the
/// `from` account must be system-owned.
pub fn handle_create_drop(
    ctx: Context<CreateDrop>,
    leaf: [u8; 32],
    amount: u64,
    _amount_commitment: [u8; 32],
    _password_hash: [u8; 32],
) -> Result<()> {
    // Validate amount
    require!(amount > 0, DarkDropError::ZeroAmount);
    require!(
        amount <= ctx.accounts.vault.drop_cap,
        DarkDropError::AmountExceedsCap
    );

    // Transfer SOL from sender to treasury via CPI.
    // system_program::transfer only requires `from` to be system-owned.
    // `to` can be any account (including program-owned treasury).
    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.sender.to_account_info(),
                to: ctx.accounts.treasury.to_account_info(),
            },
        ),
        amount,
    )?;

    // Insert leaf into Merkle tree
    let tree = &mut ctx.accounts.merkle_tree.load_mut()?;
    let leaf_index = tree.next_index;
    merkle_tree_append(tree, leaf)?;

    // Update vault stats
    let vault = &mut ctx.accounts.vault;
    vault.total_drops = vault.total_drops
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;
    vault.total_deposited = vault.total_deposited
        .checked_add(amount)
        .ok_or(DarkDropError::Overflow)?;

    // Emit event for client indexing.
    // amount_commitment and password_hash deliberately omitted to prevent
    // deposit→claim linkage and password brute-forcing (M-03-NEW fix).
    emit!(DropCreated {
        leaf_index,
        leaf,
        merkle_root: tree.current_root,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!("Drop created: index={}", leaf_index);

    Ok(())
}

#[derive(Accounts)]
pub struct CreateDrop<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"merkle_tree", vault.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Program-owned treasury PDA that holds SOL
    #[account(
        mut,
        seeds = [b"treasury"],
        bump = treasury.bump,
    )]
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub sender: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct DropCreated {
    pub leaf_index: u32,
    pub leaf: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: i64,
}
