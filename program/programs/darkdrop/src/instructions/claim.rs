use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::verifier::verify_proof;
use crate::poseidon::poseidon_hash;

/// Legacy claim: verify ZK proof (V1 circuit, 6 public inputs), release SOL directly.
/// Uses the V1 verification key for backward compatibility.
/// SOL transferred via direct lamport manipulation (no CPI, no inner instruction).
pub fn handle_claim(
    ctx: Context<Claim>,
    proof: ProofData,
    merkle_root: [u8; 32],
    nullifier_hash: [u8; 32],
    amount: u64,
    amount_commitment: [u8; 32],
    password_hash: [u8; 32],
    fee_lamports: u64,
) -> Result<()> {
    // Validate amount
    require!(amount > 0, DarkDropError::ZeroAmount);
    require!(
        amount <= ctx.accounts.vault.drop_cap,
        DarkDropError::AmountExceedsCap
    );

    // Validate fee — cap at 5% to prevent malicious relayers
    let max_fee = amount / 20; // 5%
    require!(fee_lamports <= max_fee, DarkDropError::FeeTooHigh);

    // Check merkle root is known
    let tree = ctx.accounts.merkle_tree.load()?;
    require!(
        tree.is_known_root(&merkle_root),
        DarkDropError::InvalidRoot
    );
    drop(tree);

    // Build public inputs array (V1: 6 elements including amount)
    let recipient_hash = pubkey_to_field(&ctx.accounts.recipient.key());
    let amount_field = u64_to_field_be(amount);

    let public_inputs: [[u8; 32]; 6] = [
        amount_field,         // [0] amount
        merkle_root,          // [1] merkle_root
        nullifier_hash,       // [2] nullifier_hash
        recipient_hash,       // [3] recipient (Poseidon hash of pubkey)
        amount_commitment,    // [4] amount_commitment
        password_hash,        // [5] password_hash
    ];

    // Verify Groth16 proof (V1 circuit)
    verify_proof(&proof, &public_inputs)?;

    // Check treasury has enough balance
    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(Treasury::SIZE);
    let available = ctx.accounts.treasury.to_account_info().lamports()
        .checked_sub(min_balance)
        .ok_or(DarkDropError::InsufficientBalance)?;
    require!(amount <= available, DarkDropError::InsufficientBalance);

    let recipient_amount = amount.checked_sub(fee_lamports)
        .ok_or(DarkDropError::Overflow)?;

    // Direct lamport manipulation — no CPI, no inner instruction
    **ctx.accounts.treasury.to_account_info().try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? += recipient_amount;
    if fee_lamports > 0 {
        **ctx.accounts.fee_recipient.to_account_info().try_borrow_mut_lamports()? += fee_lamports;
    }

    // Update vault stats
    let vault = &mut ctx.accounts.vault;
    vault.total_claims = vault.total_claims
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    // Store nullifier hash in the nullifier account
    let nullifier_account = &mut ctx.accounts.nullifier_account;
    nullifier_account.nullifier_hash = nullifier_hash;

    emit!(DropClaimed {
        nullifier_hash,
        recipient: ctx.accounts.recipient.key(),
        amount,
        fee_lamports,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!("Drop claimed: {} lamports to {} (fee: {})",
        recipient_amount, ctx.accounts.recipient.key(), fee_lamports);

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

/// Convert a u64 amount to a 32-byte big-endian field element.
fn u64_to_field_be(amount: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&amount.to_be_bytes());
    bytes
}

#[derive(Accounts)]
#[instruction(
    proof: ProofData,
    merkle_root: [u8; 32],
    nullifier_hash: [u8; 32],
)]
pub struct Claim<'info> {
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

    /// Program-owned treasury
    #[account(
        mut,
        seeds = [b"treasury"],
        bump = treasury.bump,
    )]
    pub treasury: Account<'info, Treasury>,

    /// Nullifier PDA — init fails if already exists (double-spend prevention)
    #[account(
        init,
        payer = payer,
        space = NullifierAccount::SIZE,
        seeds = [b"nullifier", nullifier_hash.as_ref()],
        bump,
    )]
    pub nullifier_account: Account<'info, NullifierAccount>,

    /// CHECK: Recipient receives SOL — any account, NOT a signer.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    /// CHECK: Fee recipient — must be the payer (signer) to prevent fee diversion.
    #[account(mut, constraint = fee_recipient.key() == payer.key())]
    pub fee_recipient: UncheckedAccount<'info>,

    /// Fee payer — the relayer (gasless) or the claimer (direct).
    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct DropClaimed {
    pub nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub amount: u64,
    pub fee_lamports: u64,
    pub timestamp: i64,
}
