use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::{poseidon_hash_1, poseidon_hash_4};

/// Revoke an unclaimed drop after the time-lock expires.
///
/// Safety: the depositor submits the full leaf preimage (secret, nullifier,
/// blinding). The program reconstructs leaf = Poseidon(secret, nullifier,
/// receipt.amount, blinding) and verifies it matches receipt.leaf. This pins
/// the nullifier to the ACTUAL preimage used at deposit time, so the
/// nullifier PDA created here is the same one a legitimate claim would have
/// created — closing the double-payout window.
///
/// The `preimage` parameter is an opaque byte vector:
///   [0..32]   secret
///   [32..64]  nullifier
///   [64..96]  blinding_factor
///
/// No field is named "amount", "secret", or "nullifier" in the IDL.
pub fn handle_revoke_drop(
    ctx: Context<RevokeDrop>,
    leaf: [u8; 32],
    nullifier_hash: [u8; 32],
    preimage: Vec<u8>,
) -> Result<()> {
    require!(preimage.len() == 96, DarkDropError::InvalidInputLength);

    let secret: [u8; 32] = preimage[0..32].try_into().unwrap();
    let nullifier: [u8; 32] = preimage[32..64].try_into().unwrap();
    let blinding: [u8; 32] = preimage[64..96].try_into().unwrap();

    let receipt = &ctx.accounts.deposit_receipt;

    // Receipt PDA derivation already enforced leaf↔receipt binding via seeds.
    // Belt-and-suspenders: verify the stored leaf matches the passed leaf arg.
    require!(receipt.leaf == leaf, DarkDropError::UnauthorizedRevoke);

    // Only the original depositor can revoke.
    require_keys_eq!(
        ctx.accounts.depositor.key(),
        receipt.depositor,
        DarkDropError::UnauthorizedRevoke
    );

    // Time-lock enforcement.
    let now = Clock::get()?.unix_timestamp;
    let unlock_at = receipt.created_at
        .checked_add(REVOKE_TIMEOUT)
        .ok_or(DarkDropError::Overflow)?;
    require!(now >= unlock_at, DarkDropError::RevokeTooEarly);

    // Verify preimage against the stored leaf.
    // leaf = Poseidon(secret, nullifier, amount, blinding)
    // The amount comes from the receipt (not user-supplied) so it can't be
    // tampered with — the depositor must know the exact preimage they used.
    let amount_bytes = u64_to_field_be(receipt.amount);
    let computed_leaf = poseidon_hash_4(&secret, &nullifier, &amount_bytes, &blinding);
    require!(computed_leaf == receipt.leaf, DarkDropError::CommitmentMismatch);

    // Verify nullifier_hash = Poseidon(nullifier). The circuit enforces this
    // same constraint, so claim and revoke derive the same nullifier PDA.
    let computed_null_hash = poseidon_hash_1(&nullifier);
    require!(
        computed_null_hash == nullifier_hash,
        DarkDropError::CommitmentMismatch
    );

    // Persist the nullifier (Anchor's `init` on nullifier_account already
    // fails if the PDA exists — this is the mutex with claim_credit).
    ctx.accounts.nullifier_account.nullifier_hash = nullifier_hash;

    let refund = receipt.amount;
    require!(refund > 0, DarkDropError::ZeroAmount);

    // Obligation-aware refund bound — mirrors admin_sweep's outstanding
    // calculation. The refund must fit within the outstanding obligation pool
    // (deposits not yet withdrawn) AND the treasury must still be rent-exempt
    // after the refund. A buggy total_deposited/total_withdrawn counter or an
    // unexpected treasury drain will surface here before funds move.
    let vault = &ctx.accounts.vault;
    let outstanding = vault.total_deposited
        .checked_sub(vault.total_withdrawn)
        .ok_or(DarkDropError::Overflow)?;
    require!(refund <= outstanding, DarkDropError::InsufficientBalance);

    let rent = Rent::get()?;
    let rent_exempt_min = rent.minimum_balance(Treasury::SIZE);
    let treasury_lamports = ctx.accounts.treasury.to_account_info().lamports();
    let available = treasury_lamports
        .checked_sub(rent_exempt_min)
        .ok_or(DarkDropError::InsufficientBalance)?;
    require!(refund <= available, DarkDropError::InsufficientBalance);

    // === DIRECT LAMPORT MANIPULATION ===
    // Zero CPI, zero inner instructions. Only balance deltas visible.
    **ctx.accounts.treasury.to_account_info().try_borrow_mut_lamports()? -= refund;
    **ctx.accounts.depositor.to_account_info().try_borrow_mut_lamports()? += refund;

    // Track for admin_sweep obligation accounting.
    let vault = &mut ctx.accounts.vault;
    vault.total_withdrawn = vault.total_withdrawn
        .checked_add(refund)
        .ok_or(DarkDropError::Overflow)?;

    emit!(DropRevoked {
        leaf: receipt.leaf,
        depositor: receipt.depositor,
        timestamp: now,
    });

    // DepositReceipt PDA is closed by Anchor's `close = depositor` constraint
    // (rent returned to depositor).

    Ok(())
}

fn u64_to_field_be(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}

#[derive(Accounts)]
#[instruction(leaf: [u8; 32], nullifier_hash: [u8; 32])]
pub struct RevokeDrop<'info> {
    #[account(mut, seeds = [b"vault"], bump = vault.bump)]
    pub vault: Account<'info, Vault>,

    /// Program-owned treasury — direct lamport manipulation
    #[account(
        mut,
        seeds = [b"treasury"],
        bump = treasury.bump,
    )]
    pub treasury: Account<'info, Treasury>,

    /// DepositReceipt — proves this signer created this drop.
    /// Closed after successful revoke (rent returned to depositor).
    #[account(
        mut,
        seeds = [b"receipt", leaf.as_ref()],
        bump = deposit_receipt.bump,
        close = depositor,
    )]
    pub deposit_receipt: Account<'info, DepositReceipt>,

    /// Nullifier PDA — shared namespace with claim_credit, so the first of
    /// {claim, revoke} wins and the second fails with "already in use".
    #[account(
        init,
        payer = depositor,
        space = NullifierAccount::SIZE,
        seeds = [b"nullifier", nullifier_hash.as_ref()],
        bump,
    )]
    pub nullifier_account: Account<'info, NullifierAccount>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct DropRevoked {
    pub leaf: [u8; 32],
    pub depositor: Pubkey,
    pub timestamp: i64,
}
