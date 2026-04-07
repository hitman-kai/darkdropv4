use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::verifier::verify_proof_v2;
use crate::poseidon::poseidon_hash;

/// Claim a drop as a credit note: verify ZK proof, store commitment, mark nullifier spent.
///
/// ZERO SOL moves in this instruction. The amount is a private input in the ZK proof
/// (not visible in instruction data or events). Only the Poseidon commitment is stored.
///
/// The `inputs` parameter is an opaque byte vector containing:
///   [0..32]  merkle_root
///   [32..64] commitment (Poseidon(amount, blinding_factor))
///   [64..96] seed (password_hash)
///
/// No field is named "amount", "fee", or "lamports" in the IDL.
pub fn handle_claim_credit(
    ctx: Context<ClaimCredit>,
    nullifier_hash: [u8; 32],
    proof: ProofData,
    inputs: Vec<u8>,
) -> Result<()> {
    // Parse opaque inputs
    require!(inputs.len() == 96, DarkDropError::InvalidInputLength);

    let merkle_root: [u8; 32] = inputs[0..32].try_into().unwrap();
    let amount_commitment: [u8; 32] = inputs[32..64].try_into().unwrap();
    let password_hash: [u8; 32] = inputs[64..96].try_into().unwrap();

    // Validate merkle root
    let tree = ctx.accounts.merkle_tree.load()?;
    require!(
        tree.is_known_root(&merkle_root),
        DarkDropError::InvalidRoot
    );
    drop(tree);

    // Compute recipient field element: Poseidon(pubkey_hi_128, pubkey_lo_128)
    let recipient_hash = pubkey_to_field(&ctx.accounts.recipient.key());

    // Build public inputs — 5 elements, NO amount
    // Order matches circuit signal declaration order:
    //   [0] merkle_root       (signal input merkle_root)
    //   [1] nullifier_hash    (signal input nullifier_hash)
    //   [2] recipient         (signal input recipient)
    //   [3] amount_commitment (signal input amount_commitment)
    //   [4] password_hash     (signal input password_hash)
    let public_inputs: [[u8; 32]; 5] = [
        merkle_root,
        nullifier_hash,
        recipient_hash,
        amount_commitment,
        password_hash,
    ];

    // Verify Groth16 proof (v2 circuit — 5 public inputs)
    verify_proof_v2(&proof, &public_inputs)?;

    // Initialize CreditNote PDA
    let credit = &mut ctx.accounts.credit_note;
    credit.bump = ctx.bumps.credit_note;
    credit.recipient = ctx.accounts.recipient.key();
    credit.commitment = amount_commitment;
    credit.nullifier_hash = nullifier_hash;
    credit.created_at = Clock::get()?.unix_timestamp;

    // Store nullifier (double-claim prevention)
    ctx.accounts.nullifier_account.nullifier_hash = nullifier_hash;

    // Update vault stats
    let vault = &mut ctx.accounts.vault;
    vault.total_claims = vault.total_claims
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    emit!(CreditCreated {
        nullifier_hash,
        recipient: ctx.accounts.recipient.key(),
        timestamp: credit.created_at,
    });

    // NO SOL TRANSFER — NO AMOUNT IN INSTRUCTION DATA OR EVENTS
    // Commitment deliberately omitted from event to prevent deposit→claim linkage.

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
#[instruction(nullifier_hash: [u8; 32])]
pub struct ClaimCredit<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [b"merkle_tree", vault.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    /// CreditNote PDA — stores committed amount for later withdrawal
    #[account(
        init,
        payer = payer,
        space = CreditNote::SIZE,
        seeds = [b"credit", nullifier_hash.as_ref()],
        bump,
    )]
    pub credit_note: Account<'info, CreditNote>,

    /// Nullifier PDA — double-claim prevention
    #[account(
        init,
        payer = payer,
        space = NullifierAccount::SIZE,
        seeds = [b"nullifier", nullifier_hash.as_ref()],
        bump,
    )]
    pub nullifier_account: Account<'info, NullifierAccount>,

    /// CHECK: Recipient — any account, NOT a signer.
    /// Bound by the ZK proof via Poseidon(pubkey).
    pub recipient: UncheckedAccount<'info>,

    /// Fee payer (relayer in gasless mode, claimer in direct mode)
    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct CreditCreated {
    pub nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub timestamp: i64,
}
