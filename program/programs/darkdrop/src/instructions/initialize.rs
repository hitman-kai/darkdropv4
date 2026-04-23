use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;

/// Initialize the DarkDrop vault, Merkle tree, and program-owned treasury.
/// Called once to set up the program.
pub fn handle_initialize_vault(ctx: Context<InitializeVault>, drop_cap: u64) -> Result<()> {
    require!(drop_cap >= MIN_DEPOSIT_LAMPORTS, DarkDropError::ZeroAmount);
    require!(drop_cap <= MAX_DROP_AMOUNT, DarkDropError::AmountExceedsCap);

    // Initialize vault
    let vault = &mut ctx.accounts.vault;
    vault.bump = ctx.bumps.vault;
    vault.authority = ctx.accounts.authority.key();
    vault.total_drops = 0;
    vault.total_claims = 0;
    vault.drop_cap = drop_cap;
    vault.merkle_tree = ctx.accounts.merkle_tree.key();
    vault.total_deposited = 0;
    vault.total_withdrawn = 0;

    // Initialize treasury
    let treasury = &mut ctx.accounts.treasury;
    treasury.bump = ctx.bumps.treasury;

    // Initialize Merkle tree
    let tree = &mut ctx.accounts.merkle_tree.load_init()?;
    tree.vault = vault.key();
    tree.next_index = 0;
    tree.root_history_index = 0;

    // Initialize filled_subtrees with zero hashes
    for i in 0..MERKLE_DEPTH {
        tree.filled_subtrees[i] = ZERO_HASHES[i];
    }

    // Compute initial root (empty tree root)
    tree.current_root = ZERO_HASHES[MERKLE_DEPTH];

    // Initialize ALL root_history slots to the empty-tree root (closes
    // Audit 03 L-03-NEW: previously only slot 0 was seeded, leaving slots
    // 1..N as raw zero bytes that is_known_root would scan wastefully).
    for i in 0..ROOT_HISTORY_SIZE {
        tree.root_history[i] = ZERO_HASHES[MERKLE_DEPTH];
    }

    msg!("DarkDrop vault initialized. Drop cap: {} lamports", drop_cap);
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = Vault::SIZE,
        seeds = [b"vault"],
        bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = authority,
        // zero_copy accounts: 8 discriminator + size of struct
        space = 8 + std::mem::size_of::<MerkleTreeAccount>(),
        seeds = [b"merkle_tree", vault.key().as_ref()],
        bump,
    )]
    /// CHECK: Initialized as zero_copy account
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// Program-owned treasury that holds SOL.
    /// Direct lamport manipulation for withdrawals (no CPI, no inner instruction).
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
