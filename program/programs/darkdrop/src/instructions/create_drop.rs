use anchor_lang::prelude::*;
use anchor_lang::system_program;
use anchor_lang::Discriminator;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::merkle_tree::merkle_tree_append;

/// Create a new drop: accept SOL via CPI to treasury, insert leaf into Merkle tree.
///
/// Backward-compatible DepositReceipt support:
///   If `ctx.remaining_accounts` contains exactly two accounts, they are treated as
///   [depositor (signer, mut), deposit_receipt (PDA, mut)] and a DepositReceipt is
///   created. Legacy clients passing only the five declared accounts continue to
///   work unchanged — just without the ability to revoke later.
///
/// The receipt is seeded by the full leaf and rent is paid by the depositor,
/// so the depositor (not the `sender`/relayer) is the sole party who can later
/// revoke the drop after the time-lock expires.
pub fn handle_create_drop<'info>(
    ctx: Context<'_, '_, '_, 'info, CreateDrop<'info>>,
    leaf: [u8; 32],
    amount: u64,
    _amount_commitment: [u8; 32],
    _password_hash: [u8; 32],
) -> Result<()> {
    // Validate amount
    require!(amount >= MIN_DEPOSIT_LAMPORTS, DarkDropError::BelowMinDeposit);
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
    let current_root;
    let leaf_index;
    {
        let tree = &mut ctx.accounts.merkle_tree.load_mut()?;
        leaf_index = tree.next_index;
        merkle_tree_append(tree, leaf)?;
        current_root = tree.current_root;
    }

    // Update vault stats
    {
        let vault = &mut ctx.accounts.vault;
        vault.total_drops = vault.total_drops
            .checked_add(1)
            .ok_or(DarkDropError::Overflow)?;
        vault.total_deposited = vault.total_deposited
            .checked_add(amount)
            .ok_or(DarkDropError::Overflow)?;
    }

    // Optional: create DepositReceipt via remaining_accounts (backward-compat).
    //
    // Inlined here to avoid invariant-lifetime gymnastics when threading the
    // remaining accounts through a helper function.
    if ctx.remaining_accounts.len() >= 2 {
        let depositor_info = &ctx.remaining_accounts[0];
        let receipt_info = &ctx.remaining_accounts[1];

        require!(depositor_info.is_signer, DarkDropError::InvalidDepositReceipt);
        require!(depositor_info.is_writable, DarkDropError::InvalidDepositReceipt);
        require!(receipt_info.is_writable, DarkDropError::InvalidDepositReceipt);

        let (expected_pda, receipt_bump) = Pubkey::find_program_address(
            &[b"receipt", leaf.as_ref()],
            ctx.program_id,
        );
        require_keys_eq!(
            receipt_info.key(),
            expected_pda,
            DarkDropError::InvalidDepositReceipt
        );

        // Explicit existence check for a clearer error than system_program's
        // AccountAlreadyInUse. Kept for debuggability.
        require!(
            receipt_info.lamports() == 0 && receipt_info.data_is_empty(),
            DarkDropError::LeafAlreadyDeposited
        );

        let rent = Rent::get()?;
        let space = DepositReceipt::SIZE;
        let lamports = rent.minimum_balance(space);

        let bump_slice = [receipt_bump];
        let seed_slices: [&[u8]; 3] = [b"receipt", leaf.as_ref(), &bump_slice];
        let signer_seeds: &[&[&[u8]]] = &[&seed_slices];

        system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::CreateAccount {
                    from: depositor_info.clone(),
                    to: receipt_info.clone(),
                },
                signer_seeds,
            ),
            lamports,
            space as u64,
            ctx.program_id,
        )?;

        let receipt = DepositReceipt {
            bump: receipt_bump,
            depositor: depositor_info.key(),
            amount,
            created_at: Clock::get()?.unix_timestamp,
            leaf,
        };

        let mut data = receipt_info.try_borrow_mut_data()?;
        data[..8].copy_from_slice(&DepositReceipt::DISCRIMINATOR);
        let mut writer: &mut [u8] = &mut data[8..];
        AnchorSerialize::serialize(&receipt, &mut writer)
            .map_err(|_| error!(DarkDropError::Overflow))?;
    }

    emit!(DropCreated {
        leaf_index,
        leaf,
        merkle_root: current_root,
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
    //
    // Optional remaining accounts (backward-compat):
    //   [0] depositor (signer, mut) — pays receipt rent, authorized to revoke
    //   [1] deposit_receipt (mut)   — PDA [b"receipt", leaf]
}

#[event]
pub struct DropCreated {
    pub leaf_index: u32,
    pub leaf: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: i64,
}
