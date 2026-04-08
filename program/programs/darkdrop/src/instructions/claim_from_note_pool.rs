use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::verifier::verify_proof_v3;
use crate::poseidon::poseidon_hash;

/// Claim a fresh credit note from the note pool.
///
/// Verifies a Groth16 proof (V3 circuit, 4 public inputs) proving the caller
/// knows the opening of a leaf in the note pool Merkle tree. Creates a FRESH
/// CreditNote PDA with a new re-randomized commitment encoding the same amount.
///
/// This is the second layer of recursive privacy:
///   Layer 1: claim_credit hides which deposit was claimed
///   Layer 2: claim_from_note_pool hides which credit note is being redeemed
///
/// The `inputs` parameter is an opaque byte vector containing:
///   [0..32]  pool_merkle_root
///   [32..64] new_stored_commitment (re-randomized fresh commitment)
///
/// Zero SOL moves. No amounts visible.
pub fn handle_claim_from_note_pool(
    ctx: Context<ClaimFromNotePool>,
    pool_nullifier_hash: [u8; 32],
    proof: ProofData,
    inputs: Vec<u8>,
) -> Result<()> {
    // Parse opaque inputs (64 bytes)
    require!(inputs.len() == 64, DarkDropError::InvalidInputLength);

    let pool_merkle_root: [u8; 32] = inputs[0..32].try_into().unwrap();
    let new_stored_commitment: [u8; 32] = inputs[32..64].try_into().unwrap();

    // Validate pool Merkle root
    let tree = ctx.accounts.note_pool_tree.load()?;
    require!(
        tree.is_known_root(&pool_merkle_root),
        DarkDropError::InvalidRoot
    );
    drop(tree);

    // Compute recipient field element: Poseidon(pubkey_hi_128, pubkey_lo_128)
    let recipient_hash = pubkey_to_field(&ctx.accounts.recipient.key());

    // Build public inputs — 4 elements (V3 circuit)
    // Order matches circuit signal declaration order:
    //   [0] pool_merkle_root
    //   [1] pool_nullifier_hash
    //   [2] new_stored_commitment
    //   [3] recipient_hash
    let public_inputs: [[u8; 32]; 4] = [
        pool_merkle_root,
        pool_nullifier_hash,
        new_stored_commitment,
        recipient_hash,
    ];

    // Verify Groth16 proof (V3 circuit — note pool)
    verify_proof_v3(&proof, &public_inputs)?;

    // Create fresh CreditNote PDA with the new commitment.
    // The commitment is re-randomized by the circuit: Poseidon(Poseidon(amount, new_blinding), new_salt).
    // This is completely unlinkable to the original credit note's commitment.
    let credit = &mut ctx.accounts.credit_note;
    credit.bump = ctx.bumps.credit_note;
    credit.recipient = ctx.accounts.recipient.key();
    credit.commitment = new_stored_commitment;
    credit.nullifier_hash = pool_nullifier_hash;
    credit.salt = [0u8; 32]; // salt is baked into new_stored_commitment by the circuit
    credit.created_at = Clock::get()?.unix_timestamp;

    // Store pool nullifier (double-claim prevention)
    ctx.accounts.pool_nullifier_account.nullifier_hash = pool_nullifier_hash;

    // Update note pool stats
    let note_pool = &mut ctx.accounts.note_pool;
    note_pool.total_claims = note_pool.total_claims
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    emit!(NotePoolClaim {
        pool_nullifier_hash,
        recipient: ctx.accounts.recipient.key(),
        timestamp: credit.created_at,
    });

    // NO SOL TRANSFER. NO AMOUNT ANYWHERE.

    Ok(())
}

/// Convert a Pubkey to a BN254 field element via Poseidon hash.
fn pubkey_to_field(pubkey: &Pubkey) -> [u8; 32] {
    let bytes = pubkey.to_bytes();
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..32].copy_from_slice(&bytes[0..16]);
    lo[16..32].copy_from_slice(&bytes[16..32]);
    poseidon_hash(&hi, &lo)
}

#[derive(Accounts)]
#[instruction(pool_nullifier_hash: [u8; 32])]
pub struct ClaimFromNotePool<'info> {
    #[account(seeds = [b"vault"], bump = vault.bump)]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"note_pool"],
        bump = note_pool.bump,
    )]
    pub note_pool: Account<'info, NotePool>,

    #[account(
        seeds = [b"note_pool_tree", vault.key().as_ref()],
        bump,
    )]
    pub note_pool_tree: AccountLoader<'info, NotePoolTree>,

    /// Fresh CreditNote PDA — keyed by pool_nullifier_hash (unique per pool claim)
    #[account(
        init,
        payer = payer,
        space = CreditNote::SIZE,
        seeds = [b"credit", pool_nullifier_hash.as_ref()],
        bump,
    )]
    pub credit_note: Account<'info, CreditNote>,

    /// Pool nullifier PDA — prevents double-claim from note pool
    #[account(
        init,
        payer = payer,
        space = PoolNullifierAccount::SIZE,
        seeds = [b"pool_nullifier", pool_nullifier_hash.as_ref()],
        bump,
    )]
    pub pool_nullifier_account: Account<'info, PoolNullifierAccount>,

    /// CHECK: Recipient — any account, NOT a signer.
    /// Bound by the ZK proof via Poseidon(pubkey).
    pub recipient: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct NotePoolClaim {
    pub pool_nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub timestamp: i64,
}
