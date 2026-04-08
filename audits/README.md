# DarkDrop V4 — Security Audits

**Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`  
**Cluster:** Devnet

This directory contains all security audit reports for the DarkDrop V4 Solana program.

---

## Audit Summary

| # | Report | Date | Scope | Findings |
|---|--------|------|-------|----------|
| 1 | [Manual Review](AUDIT-01-MANUAL-REVIEW.md) | April 6, 2026 | Fee system, credit notes, treasury, relay trust model | 1 HIGH (fixed), 2 MEDIUM (accepted), 1 LOW |
| 2 | [Code Review](AUDIT-02-CODE-REVIEW.md) | April 7, 2026 | Full instruction-level review, all modules | 2 HIGH, 4 MEDIUM, 4 LOW, 7 INFO |
| 3 | [Post-Fix Review](AUDIT-03-POST-FIX-REVIEW.md) | April 8, 2026 | Fix verification (H-01, M-01, L-03) + admin_sweep + full re-audit | 1 HIGH, 3 MEDIUM, 3 LOW, 4 INFO |

---

## Fix Tracker

| Finding | Audit | Severity | Status | Fix Details |
|---------|-------|----------|--------|-------------|
| Fee rate uncapped (99.99% steal) | #1 | HIGH | **FIXED** | `MAX_FEE_RATE = 500` bps cap in withdraw_credit, 5% cap in legacy claim |
| Legacy claim fee_recipient unbound | #2 H-01 | HIGH | **FIXED** | `fee_recipient.key() == payer.key()` constraint |
| withdraw_credit fee_recipient unbound | #2 M-01 | MEDIUM | **FIXED** | `fee_recipient.key() == payer.key()` constraint |
| Event commitment linkage | #2 L-03 | LOW | **FIXED** | Commitment removed from CreditCreated event |
| admin_sweep drains treasury with outstanding credit notes | #3 H-01 | HIGH | **Open** | Needs timelock or obligation tracking |
| CreditNote PDA leaks commitment on-chain | #3 M-01 | MEDIUM | **Open** | L-03 fix incomplete — account data still linkable |
| admin_sweep emits no event | #3 M-02 | MEDIUM | **Open** | Needs event for monitoring |
| DropCreated event leaks linkable fields | #3 M-03 | MEDIUM | **Open** | Remove amount_commitment + password_hash from event |
| create_drop leaf unverified | #2 H-02 | HIGH | **Accepted** | Design limitation of commitment-scheme mixers |
| No drop_cap validation | #2 L-01 | LOW | **Open** | Add min/max check |
| No authority rotation | #2 L-02 | LOW | **Open** | Add update_authority instruction |
| Root history zero-initialized | #2 M-03 / #3 L-03 | LOW | **Open** | Initialize all slots to empty-tree root |

---

## Audit Methodology

All audits were conducted as adversarial third-party reviews examining:

- Signer and owner checks on all accounts
- PDA derivation correctness and seed collision potential
- Integer overflow/underflow in arithmetic operations
- Fee manipulation and treasury drain vectors
- Double-spend prevention (nullifier reuse, cross-instruction replay)
- ZK proof bypass scenarios (V1/V2 cross-verification, invalid proofs)
- Direct lamport manipulation safety
- Privacy leakage through events and on-chain account data
- Admin privilege escalation and rug-pull vectors

---

## Reporting Security Issues

See [SECURITY.md](../SECURITY.md) for the responsible disclosure policy.
