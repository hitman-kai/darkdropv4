use anchor_lang::prelude::*;
use crate::state::*;

/// Initialize the Note Pool — a second-layer Merkle tree for credit note mixing.
/// Called once by the vault authority to enable recursive privacy.
pub fn handle_initialize_note_pool(ctx: Context<InitializeNotePool>) -> Result<()> {
    let note_pool = &mut ctx.accounts.note_pool;
    note_pool.bump = ctx.bumps.note_pool;
    note_pool.total_deposits = 0;
    note_pool.total_claims = 0;

    let tree = &mut ctx.accounts.note_pool_tree.load_init()?;
    tree.vault = ctx.accounts.vault.key();
    tree.next_index = 0;
    tree.root_history_index = 0;

    for i in 0..MERKLE_DEPTH {
        tree.filled_subtrees[i] = ZERO_HASHES[i];
    }

    tree.current_root = ZERO_HASHES[MERKLE_DEPTH];

    // Initialize ALL root_history slots (closes Audit 04 L-01).
    for i in 0..ROOT_HISTORY_SIZE {
        tree.root_history[i] = ZERO_HASHES[MERKLE_DEPTH];
    }

    msg!("Note pool initialized");
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeNotePool<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = authority,
        space = NotePool::SIZE,
        seeds = [b"note_pool"],
        bump,
    )]
    pub note_pool: Account<'info, NotePool>,

    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<NotePoolTree>(),
        seeds = [b"note_pool_tree", vault.key().as_ref()],
        bump,
    )]
    /// CHECK: Initialized as zero_copy account
    pub note_pool_tree: AccountLoader<'info, NotePoolTree>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}
