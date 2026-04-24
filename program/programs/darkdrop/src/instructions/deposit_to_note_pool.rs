use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::{poseidon_hash, poseidon_hash_4};
use crate::merkle_tree::note_pool_tree_append;

/// Deposit a credit note into the note pool for second-layer mixing.
///
/// The user opens their credit note commitment (reveals amount + blinding + salt),
/// and provides pool_secret, pool_nullifier, pool_blinding for the new pool leaf.
///
/// CRITICAL: The program constructs the pool leaf ON-CHAIN using the VERIFIED amount.
/// pool_leaf = Poseidon4(pool_secret, pool_nullifier, verified_amount, pool_blinding)
/// Single Poseidon call with arity 4 via `poseidon_hash_4`. Must match the V3
/// circuit's leaf constraint exactly (see circuits/note_pool.circom) — any change
/// here breaks proof verification for the entire pool.
///
/// This eliminates the dishonest leaf problem (Audit I-01): the user cannot lie about
/// the amount because the program opens and verifies the credit note commitment first.
///
/// The `opening` parameter is an opaque byte vector:
///   [0..8]   amount (u64 little-endian)
///   [8..40]  blinding_factor (32 bytes)
///   [40..72] salt (32 bytes)
///
/// The `pool_params` parameter is an opaque byte vector:
///   [0..32]  pool_secret
///   [32..64] pool_nullifier
///   [64..96] pool_blinding_factor
pub fn handle_deposit_to_note_pool(
    ctx: Context<DepositToNotePool>,
    _nullifier_hash: [u8; 32],
    opening: Vec<u8>,
    pool_params: Vec<u8>,
) -> Result<()> {
    // Parse credit note opening (72 bytes)
    require!(opening.len() == 72, DarkDropError::InvalidInputLength);
    let amount = u64::from_le_bytes(opening[0..8].try_into().unwrap());
    let blinding_factor: [u8; 32] = opening[8..40].try_into().unwrap();
    let salt: [u8; 32] = opening[40..72].try_into().unwrap();

    // Parse pool parameters (96 bytes)
    require!(pool_params.len() == 96, DarkDropError::InvalidInputLength);
    let pool_secret: [u8; 32] = pool_params[0..32].try_into().unwrap();
    let pool_nullifier: [u8; 32] = pool_params[32..64].try_into().unwrap();
    let pool_blinding: [u8; 32] = pool_params[64..96].try_into().unwrap();

    let credit = &ctx.accounts.credit_note;

    // Verify recipient owns the credit note
    require!(
        ctx.accounts.recipient.key() == credit.recipient,
        DarkDropError::UnauthorizedWithdraw
    );

    // Verify the credit note commitment opening:
    // Poseidon(Poseidon(amount, blinding_factor), salt) == stored_commitment
    let amount_bytes = u64_to_field_be(amount);
    let original_commitment = poseidon_hash(&amount_bytes, &blinding_factor);
    let computed_commitment = poseidon_hash(&original_commitment, &salt);
    require!(
        computed_commitment == credit.commitment,
        DarkDropError::CommitmentMismatch
    );

    require!(amount > 0, DarkDropError::ZeroAmount);

    // Construct pool leaf ON-CHAIN using the VERIFIED amount.
    // leaf = Poseidon(pool_secret, pool_nullifier, amount, pool_blinding)
    // Must match the circuit: Poseidon(4) with inputs in the same order.
    let pool_leaf = poseidon_hash_4(&pool_secret, &pool_nullifier, &amount_bytes, &pool_blinding);

    // Insert leaf into note pool Merkle tree
    let tree = &mut ctx.accounts.note_pool_tree.load_mut()?;
    let leaf_index = tree.next_index;
    note_pool_tree_append(tree, pool_leaf)?;

    // Update note pool stats
    let note_pool = &mut ctx.accounts.note_pool;
    note_pool.total_deposits = note_pool.total_deposits
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    emit!(NotePoolDeposit {
        leaf_index,
        pool_merkle_root: tree.current_root,
        timestamp: Clock::get()?.unix_timestamp,
    });

    // CreditNote PDA is closed by Anchor's `close = payer` constraint.
    // Zero SOL moves. The amount stays in the treasury.

    Ok(())
}

fn u64_to_field_be(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}

#[derive(Accounts)]
#[instruction(nullifier_hash: [u8; 32])]
pub struct DepositToNotePool<'info> {
    #[account(seeds = [b"vault"], bump = vault.bump)]
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

    /// CreditNote being deposited — closed after deposit (rent returned to payer)
    #[account(
        mut,
        seeds = [b"credit", nullifier_hash.as_ref()],
        bump = credit_note.bump,
        close = payer,
    )]
    pub credit_note: Account<'info, CreditNote>,

    /// Recipient — must match credit_note.recipient and must sign
    pub recipient: Signer<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct NotePoolDeposit {
    pub leaf_index: u32,
    pub pool_merkle_root: [u8; 32],
    pub timestamp: i64,
}
