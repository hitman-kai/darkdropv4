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
| 3 | [Post-Fix Review](AUDIT-03-POST-FIX-REVIEW.md) | April 8, 2026 | Fix verification (H-01, M-01, L-03) + `admin_sweep` + full re-audit | 1 HIGH, 3 MEDIUM, 3 LOW, 4 INFO (HIGH + 3 MEDIUMs all fixed in-audit) |
| 4 | [Post-Revoke Review](AUDIT-04-POST-REVOKE.md) | April 20, 2026 | V3 Note Pool layer + `revoke_drop` + `DepositReceipt` + counter invariants + privacy analysis | 0 CRITICAL, 0 HIGH, 1 MEDIUM (fixed in-cycle), 4 LOW, 4 INFO |
| 5 | [Schema v2 + Pool Deposit](AUDIT-05-SCHEMA-V2-AND-POOL-DEPOSIT.md) | April 24, 2026 | `create_drop_to_pool` + `migrate_schema_v2` + `authority_rotation` + I-04/L-03-NEW fix verification + cross-layer invariants | 0 CRITICAL, 0 HIGH, 0 MEDIUM, 3 LOW (1 fixed in-cycle), 4 INFO |

---

## Fix Tracker

| Finding | Audit | Severity | Status | Fix Details |
|---------|-------|----------|--------|-------------|
| Fee rate uncapped (99.99% steal) | #1 | HIGH | **FIXED** | `MAX_FEE_RATE = 500` bps cap in withdraw_credit, 5% cap in legacy claim |
| Legacy claim fee_recipient unbound | #2 H-01 | HIGH | **FIXED** | `fee_recipient.key() == payer.key()` constraint |
| withdraw_credit fee_recipient unbound | #2 M-01 | MEDIUM | **FIXED** | `fee_recipient.key() == payer.key()` constraint |
| Event commitment linkage | #2 L-03 | LOW | **FIXED** | Commitment removed from CreditCreated event |
| admin_sweep drains treasury with outstanding credit notes | #3 H-01-NEW | HIGH | **FIXED** | Vault tracks `total_deposited`/`total_withdrawn`; sweep limited to `treasury − outstanding − rent` |
| CreditNote PDA leaks commitment on-chain | #3 M-01-NEW | MEDIUM | **FIXED** | Stored commitment re-randomized with salt: `Poseidon(original_commitment, salt)` |
| admin_sweep emits no event | #3 M-02-NEW | MEDIUM | **FIXED** | `TreasurySweep` event added |
| DropCreated event leaks linkable fields | #3 M-03-NEW | MEDIUM | **FIXED** | `amount_commitment` + `password_hash` removed from event |
| create_drop leaf unverified | #2 H-02 | HIGH | **Accepted** | Design limitation of commitment-scheme mixers (see I-01 in later audits) |
| No drop_cap validation | #2 L-01 / #3 L-01-NEW / #4 L-02 | LOW | **FIXED** | `initialize.rs:8-9` enforces `drop_cap ∈ [MIN_DEPOSIT_LAMPORTS, MAX_DROP_AMOUNT]`. Landed Apr 14, 2026 (`02e0aa8`). Audit #4 misclassified this as open; re-verified closed in Audit #5. |
| No authority rotation | #2 L-02 / #3 L-02-NEW / #4 L-03 | LOW | **FIXED** | `authority_rotation.rs` triple (propose/revoke/accept) with `PendingAuthority` sidecar PDA; single-in-flight invariant. Added Audit #5 cycle. |
| Authority rotation acceptance has no time-lock | #5 L-01 | LOW | **FIXED (in-cycle)** | 24-hour `ROTATION_DELAY` enforced in `accept_authority_rotation` via `saturating_sub` against `pending.proposed_at`. Deployed TX `5R4eiMaw…kaDWu`. |
| Root history zero-initialized (main tree) | #2 M-03 / #3 L-03-NEW | LOW | **FIXED** | `initialize.rs:43-45` seeds all 256 slots on fresh init; `migrate_schema_v2` seeds slots `[30..256]` on pre-existing trees. |
| Root history zero-initialized (note_pool_tree) | #4 L-01 | LOW | **FIXED** | `initialize_note_pool.rs:24-26` seeds all 256 slots; `migrate_schema_v2` also covers pre-existing note pool tree. |
| Orphan DepositReceipt rent lock after normal claim | #4 M-01 | MEDIUM | **FIXED** | `close_receipt` instruction added (Audit 04 cycle); unconditional depositor-signed close with explicit `depositor == receipt.depositor` check |
| Deposit-side privacy leak inherent to receipt design | #4 L-04 | LOW | **Documentation only; inherent to design** | Creating a receipt establishes a permanent `depositor ↔ (leaf, amount)` on-chain linkage indexed forever. Fixed in code is not possible; ARCHITECTURE.md updated to document |
| Note pool has no revoke mechanism | #4 I-01 | INFO | **Accepted design** | Document in user-facing materials |
| Malicious relayer can set depositor = relayer in receipt | #4 I-02 | INFO | **Trust model** | Frontend/client-lib guardrail |
| groth16-solana 0.0.3 pre-release | #2 / #3 I-02 / #4 I-03 | INFO | **Pinned in Cargo.lock** | Consider upgrade or vendoring |
| Redundant fee_recipient after H-01/M-01 fixes | #3 I-04 / #4 I-04 | INFO | **FIXED** | `fee_recipient` account removed from `claim` and `withdraw_credit`; fee credits `payer` directly. Frontend + relayer ABI updated. |
| `migrate_schema_v2` emits no event | #5 L-02 | LOW | **Open** | Add `SchemaV2MigrationCompleted` event for indexer/observability parity with `TreasurySweep`. |
| `create_drop_to_pool` has no revoke option | #5 L-03 | LOW | **Doc-only (accepted design, same class as #4 I-01)** | Update `ARCHITECTURE.md` + `/drop/create` UI to warn that pool-path deposits cannot be revoked. |
| `deposit_to_note_pool` doc misdescribes leaf hashing | #5 I-01 | INFO | **Open** | Doc comment says "2-level hash tree" but code uses single `poseidon_hash_4`. Fix comment to prevent edit-trap. |
| `migrate_schema_v2` byte-order invariant uncommented | #5 I-02 | INFO | **Open** | Pin the "loop-must-precede-filled_subtrees-copy AND cover full slot range" invariant in a comment. |

---

## Audit Methodology

All audits were conducted as adversarial third-party reviews examining:

- Signer and owner checks on all accounts
- PDA derivation correctness and seed collision potential
- Integer overflow/underflow in arithmetic operations
- Fee manipulation and treasury drain vectors
- Double-spend prevention (nullifier reuse, cross-instruction replay)
- ZK proof bypass scenarios (V1/V2/V3 cross-verification, invalid proofs)
- Direct lamport manipulation safety
- Privacy leakage through events and on-chain account data
- Admin privilege escalation and rug-pull vectors
- Cross-instruction counter invariants (`total_deposited` / `total_withdrawn`)
- Feature-flag gating in production builds (Audit 04+)
- Cross-layer privacy analysis (base + note pool + revoke)

---

## Reporting Security Issues

See [SECURITY.md](../SECURITY.md) for the responsible disclosure policy.
