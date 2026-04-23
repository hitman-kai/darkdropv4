use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_lang::solana_program::system_instruction;

use crate::errors::DarkDropError;
use crate::state::*;

/// Schema v2 migration: reallocate MerkleTreeAccount and NotePoolTree to
/// the new ROOT_HISTORY_SIZE=256 layout. Existing roots and filled_subtrees
/// are preserved; the 226 newly-allocated root_history slots are seeded
/// with ZERO_HASHES[MERKLE_DEPTH] so is_known_root never scans raw-zero
/// bytes (this also closes the Audit 04 L-01 and Audit 03 L-03-NEW
/// findings for pre-existing accounts).
///
/// Idempotent: each tree is checked independently; if it's already at
/// NEW_TREE_SIZE this side of the migration is a no-op. Authority is
/// charged only the net rent diff (0 if already migrated). The whole
/// instruction is atomic — either both trees migrate or neither does.
///
/// Authority check: verified against the vault's stored authority.
/// Cannot be called without signer control of that key.
pub fn handle_migrate_schema_v2(ctx: Context<MigrateSchemaV2>) -> Result<()> {
    let authority_key = ctx.accounts.authority.key();

    // Vault is still the v2-post-Audit-03 layout; load and check authority.
    let vault = &ctx.accounts.vault;
    require!(
        vault.authority == authority_key,
        DarkDropError::UnauthorizedWithdraw
    );

    migrate_one_tree(
        &ctx.accounts.merkle_tree,
        &ctx.accounts.authority,
        &ctx.accounts.system_program,
        "merkle_tree",
    )?;

    migrate_one_tree(
        &ctx.accounts.note_pool_tree,
        &ctx.accounts.authority,
        &ctx.accounts.system_program,
        "note_pool_tree",
    )?;

    msg!("schema_v2 migration complete");
    Ok(())
}

/// Migrate a single zero-copy tree account (MerkleTreeAccount or NotePoolTree
/// — both share the same byte layout) from ROOT_HISTORY_SIZE_V1=30 to 256.
///
/// Idempotent per-account: returns Ok(()) if already at NEW_TREE_SIZE.
fn migrate_one_tree<'info>(
    tree_info: &AccountInfo<'info>,
    authority: &Signer<'info>,
    system_program: &Program<'info, System>,
    label: &str,
) -> Result<()> {
    let current_len = tree_info.data_len();

    // Compute the two expected sizes from the const so they stay in lockstep
    // with state.rs if anything changes.
    const DISC: usize = 8;
    const HEADER: usize = 32 /* vault */ + 4 /* next_index */ + 4 /* root_history_index */ + 32 /* current_root */;
    const FILLED_SUBTREES: usize = MERKLE_DEPTH * 32;
    const OLD_TREE_SIZE: usize = DISC + HEADER + ROOT_HISTORY_SIZE_V1 * 32 + FILLED_SUBTREES;
    const NEW_TREE_SIZE: usize = DISC + HEADER + ROOT_HISTORY_SIZE * 32 + FILLED_SUBTREES;

    // Derived offsets (same on both trees because layouts match).
    const OLD_FILLED_SUBTREES_OFFSET: usize = DISC + HEADER + ROOT_HISTORY_SIZE_V1 * 32;
    const NEW_FILLED_SUBTREES_OFFSET: usize = DISC + HEADER + ROOT_HISTORY_SIZE * 32;
    const NEW_ROOT_HISTORY_START: usize = DISC + HEADER;

    if current_len == NEW_TREE_SIZE {
        msg!("{}: already migrated", label);
        return Ok(());
    }
    require!(current_len == OLD_TREE_SIZE, DarkDropError::InvalidAccountSize);

    // Save the old filled_subtrees bytes BEFORE realloc corrupts their
    // position (they live in the middle of the new root_history array).
    let mut saved_subtrees = [0u8; FILLED_SUBTREES];
    {
        let data = tree_info.try_borrow_data()?;
        saved_subtrees.copy_from_slice(
            &data[OLD_FILLED_SUBTREES_OFFSET..OLD_FILLED_SUBTREES_OFFSET + FILLED_SUBTREES],
        );
    }

    // Fund the rent diff from the authority.
    let rent = Rent::get()?;
    let needed = rent.minimum_balance(NEW_TREE_SIZE);
    let have = tree_info.lamports();
    if needed > have {
        let diff = needed - have;
        invoke(
            &system_instruction::transfer(authority.key, tree_info.key, diff),
            &[
                authority.to_account_info(),
                tree_info.clone(),
                system_program.to_account_info(),
            ],
        )?;
    }

    // Grow the account. zero_init=true zeros bytes [OLD_TREE_SIZE..NEW_TREE_SIZE].
    tree_info.realloc(NEW_TREE_SIZE, true)?;

    // Rewrite the root_history tail (slots V1..256) with the empty-tree
    // root, then stamp filled_subtrees into its new home. This also erases
    // the old filled_subtrees bytes that now sit in root_history slots
    // 30..~50.
    {
        let mut data = tree_info.try_borrow_mut_data()?;

        // Slots 0..V1 are existing real roots — leave them untouched.
        // Slots V1..256 need seeding.
        for slot in ROOT_HISTORY_SIZE_V1..ROOT_HISTORY_SIZE {
            let off = NEW_ROOT_HISTORY_START + slot * 32;
            data[off..off + 32].copy_from_slice(&ZERO_HASHES[MERKLE_DEPTH]);
        }

        data[NEW_FILLED_SUBTREES_OFFSET..NEW_FILLED_SUBTREES_OFFSET + FILLED_SUBTREES]
            .copy_from_slice(&saved_subtrees);
    }

    msg!("{}: migrated {} -> {} bytes", label, OLD_TREE_SIZE, NEW_TREE_SIZE);
    Ok(())
}

#[derive(Accounts)]
pub struct MigrateSchemaV2<'info> {
    #[account(seeds = [b"vault"], bump = vault.bump)]
    pub vault: Account<'info, Vault>,

    /// CHECK: Raw account — cannot deserialize as the new MerkleTreeAccount
    /// struct until the realloc completes. Verified via PDA derivation.
    #[account(
        mut,
        seeds = [b"merkle_tree", vault.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountInfo<'info>,

    /// CHECK: Same as above for the note pool tree.
    #[account(
        mut,
        seeds = [b"note_pool_tree", vault.key().as_ref()],
        bump,
    )]
    pub note_pool_tree: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}
