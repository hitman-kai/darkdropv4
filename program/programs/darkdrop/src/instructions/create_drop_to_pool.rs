use anchor_lang::prelude::*;
use anchor_lang::system_program;

use crate::errors::DarkDropError;
use crate::merkle_tree::note_pool_tree_append;
use crate::poseidon::poseidon_hash_4;
use crate::state::*;

/// Deposit SOL directly into the Note Pool layer. Single-TX equivalent of
/// `create_drop` → `claim_credit` → `deposit_to_note_pool`.
///
/// Privacy: the depositor's wallet is only linked on-chain to a pool leaf.
/// The V3 Groth16 circuit hides the pool-leaf → recipient linkage at claim
/// time, so an observer learns (depositor, amount) but not (depositor,
/// recipient). Same base-layer privacy as legacy create_drop, plus the
/// note-pool claim-side privacy — without the three-TX correlation that
/// the compose-three-existing-ixs approach would create.
///
/// No dishonest-leaf risk (Audit I-01): `amount` is the value actually
/// transferred via CPI. The pool leaf is constructed on-chain using that
/// verified amount — there is no commitment-scheme opening that could lie.
///
/// `pool_params` is opaque bytes (96 total):
///   [0..32]  pool_secret
///   [32..64] pool_nullifier
///   [64..96] pool_blinding
pub fn handle_create_drop_to_pool(
    ctx: Context<CreateDropToPool>,
    amount: u64,
    pool_params: Vec<u8>,
) -> Result<()> {
    // Amount validation (same envelope as create_drop).
    require!(amount >= MIN_DEPOSIT_LAMPORTS, DarkDropError::BelowMinDeposit);
    require!(
        amount <= ctx.accounts.vault.drop_cap,
        DarkDropError::AmountExceedsCap
    );

    // Pool preimage parsing.
    require!(pool_params.len() == 96, DarkDropError::InvalidInputLength);
    let pool_secret: [u8; 32] = pool_params[0..32].try_into().unwrap();
    let pool_nullifier: [u8; 32] = pool_params[32..64].try_into().unwrap();
    let pool_blinding: [u8; 32] = pool_params[64..96].try_into().unwrap();

    // Transfer SOL sender -> treasury via CPI (matches feedback_sol_transfer_cpi:
    // inner CPI keeps the amount visually subordinate on Solscan relative to a
    // top-level System transfer).
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

    // Construct pool leaf with the VERIFIED amount (the u64 we just moved).
    // Must match the V3 circuit: Poseidon(pool_secret, pool_nullifier, amount, pool_blinding).
    let amount_bytes = u64_to_field_be(amount);
    let pool_leaf =
        poseidon_hash_4(&pool_secret, &pool_nullifier, &amount_bytes, &pool_blinding);

    // Append pool_leaf to note_pool_tree.
    let (leaf_index, pool_root) = {
        let tree = &mut ctx.accounts.note_pool_tree.load_mut()?;
        let idx = tree.next_index;
        note_pool_tree_append(tree, pool_leaf)?;
        (idx, tree.current_root)
    };

    // Counter bookkeeping. total_deposited is the obligation floor for
    // admin_sweep; pool-entered SOL must be protected from sweep until
    // withdrawn through claim_from_note_pool + withdraw_credit.
    {
        let vault = &mut ctx.accounts.vault;
        vault.total_drops = vault.total_drops
            .checked_add(1)
            .ok_or(DarkDropError::Overflow)?;
        vault.total_deposited = vault.total_deposited
            .checked_add(amount)
            .ok_or(DarkDropError::Overflow)?;
    }
    {
        let note_pool = &mut ctx.accounts.note_pool;
        note_pool.total_deposits = note_pool.total_deposits
            .checked_add(1)
            .ok_or(DarkDropError::Overflow)?;
    }

    emit!(DropCreatedInPool {
        leaf_index,
        pool_leaf,
        pool_merkle_root: pool_root,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!("pool drop: index={}", leaf_index);
    Ok(())
}

fn u64_to_field_be(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}

#[derive(Accounts)]
pub struct CreateDropToPool<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"note_pool"],
        bump = note_pool.bump,
    )]
    pub note_pool: Account<'info, NotePool>,

    #[account(
        mut,
        seeds = [b"note_pool_tree", vault.key().as_ref()],
        bump,
    )]
    pub note_pool_tree: AccountLoader<'info, NotePoolTree>,

    /// Program-owned treasury — same PDA the base layer uses. Pool deposits
    /// pool their SOL here; claim_from_note_pool -> withdraw_credit is how
    /// recipients extract it.
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
pub struct DropCreatedInPool {
    pub leaf_index: u32,
    pub pool_leaf: [u8; 32],
    pub pool_merkle_root: [u8; 32],
    pub timestamp: i64,
}
