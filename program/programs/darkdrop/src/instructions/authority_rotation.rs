use anchor_lang::prelude::*;

use crate::errors::DarkDropError;
use crate::state::{PendingAuthority, Vault, ROTATION_DELAY};

/// Propose a new vault authority. Creates the PendingAuthority sidecar
/// PDA seeded by vault — only one pending proposal can exist at a time,
/// so `init` fails with `AccountAlreadyInitialized` if another is in
/// flight. Clear it first with `revoke_authority_rotation`.
///
/// No state change to `vault.authority` until `accept_authority_rotation`
/// runs signed by the new authority. Closes Audit 04 L-03 (previously no
/// recovery path for compromised authority keys).
pub fn handle_propose_authority_rotation(
    ctx: Context<ProposeAuthorityRotation>,
    new_authority: Pubkey,
) -> Result<()> {
    let pending = &mut ctx.accounts.pending_authority;
    pending.bump = ctx.bumps.pending_authority;
    pending.vault = ctx.accounts.vault.key();
    pending.proposer = ctx.accounts.authority.key();
    pending.new_authority = new_authority;
    pending.proposed_at = Clock::get()?.unix_timestamp;

    emit!(AuthorityRotationProposed {
        vault: pending.vault,
        proposer: pending.proposer,
        new_authority,
        timestamp: pending.proposed_at,
    });

    Ok(())
}

/// Current authority withdraws its own proposal. Closes the sidecar PDA
/// and returns rent to the authority.
pub fn handle_revoke_authority_rotation(
    ctx: Context<RevokeAuthorityRotation>,
) -> Result<()> {
    emit!(AuthorityRotationRevoked {
        vault: ctx.accounts.vault.key(),
        by: ctx.accounts.authority.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });
    Ok(())
}

/// Finalize the rotation. Must be signed by the new authority (whose
/// pubkey was recorded in the sidecar at propose time). Flips
/// `vault.authority` and closes the sidecar.
pub fn handle_accept_authority_rotation(
    ctx: Context<AcceptAuthorityRotation>,
) -> Result<()> {
    let signer_key = ctx.accounts.new_authority.key();
    require!(
        ctx.accounts.pending_authority.new_authority == signer_key,
        DarkDropError::PendingAuthorityMismatch
    );

    // Time-lock: block acceptance until ROTATION_DELAY seconds have elapsed
    // since propose. Lets a legitimate authority detect and revoke a proposal
    // made with a stolen key. saturating_sub defends against clock skew
    // (post-propose timestamps older than proposed_at collapse to 0, which
    // will simply fail the comparison and force a retry later).
    let now = Clock::get()?.unix_timestamp;
    let elapsed = now.saturating_sub(ctx.accounts.pending_authority.proposed_at);
    require!(elapsed >= ROTATION_DELAY, DarkDropError::RotationTooEarly);

    let vault = &mut ctx.accounts.vault;
    let previous = vault.authority;
    vault.authority = signer_key;

    emit!(AuthorityRotationAccepted {
        vault: vault.key(),
        previous,
        new_authority: signer_key,
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct ProposeAuthorityRotation<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = authority,
        space = PendingAuthority::SIZE,
        seeds = [b"pending_authority", vault.key().as_ref()],
        bump,
    )]
    pub pending_authority: Account<'info, PendingAuthority>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeAuthorityRotation<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"pending_authority", vault.key().as_ref()],
        bump = pending_authority.bump,
        close = authority,
    )]
    pub pending_authority: Account<'info, PendingAuthority>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAuthorityRotation<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    /// Closed on successful acceptance. Rent goes to the new authority.
    #[account(
        mut,
        seeds = [b"pending_authority", vault.key().as_ref()],
        bump = pending_authority.bump,
        close = new_authority,
    )]
    pub pending_authority: Account<'info, PendingAuthority>,

    /// The signer claiming the rotation. Authorization checked in handler
    /// against pending_authority.new_authority — Anchor's close= only
    /// routes lamports, it does not verify identity.
    #[account(mut)]
    pub new_authority: Signer<'info>,
}

#[event]
pub struct AuthorityRotationProposed {
    pub vault: Pubkey,
    pub proposer: Pubkey,
    pub new_authority: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AuthorityRotationRevoked {
    pub vault: Pubkey,
    pub by: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AuthorityRotationAccepted {
    pub vault: Pubkey,
    pub previous: Pubkey,
    pub new_authority: Pubkey,
    pub timestamp: i64,
}
