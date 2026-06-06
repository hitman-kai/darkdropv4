# Audit #7 — Jelleo Ruleset Cross-Check (Second Opinion)

**Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`
**Cluster:** Devnet
**Date:** June 6, 2026
**Scope:** Full instruction surface (`program/programs/darkdrop/src/instructions/*`) + `state.rs` + `verifier.rs`, cross-checked against the **Jelleo Solana Security ruleset** (SOL-001 … SOL-020 — `github.com/Copenhagen0x/solana-security-guidance`).
**Method:** Independent second-opinion pass. Two review rounds (pass 1: the value-moving core — `create_drop`, `claim_credit`, `withdraw_credit`, `revoke_drop`, SPL twins, `state.rs`, `verifier.rs`; pass 2: the remainder — note-pool layer, `realloc` migrations, authority lifecycle, init/admin). Each round used multiple independent rule-family reviewers followed by adversarial 3-lens verification (refuter / exploit-constructor / Anchor-Rust-semantics) of every candidate finding to separate "pattern matched" from "exploitable in this code's context."

---

## Executive summary

This was a fresh, ruleset-grounded re-review of the shipped GSig1 program. **No new exploitable defect was found.** The program is well hardened by six prior cycles, and the ruleset's signature bug classes (unauthenticated clock, reinit, missing owner/signer, scalar malleability, close-drain, CPI-without-authority, Token-program confusion) are either absent or correctly defended.

- **0 new CRITICAL / 0 new HIGH.**
- The single finding with real exploit potential — the base-layer **dishonest-leaf over-claim** — is **not new**: it is the already-accepted Audit #2 **H-02** (commitment-mixer trust model). Re-confirmed here; disposition unchanged.
- **SOL-013 (Token-2022):** confirmed a real but fail-safe scope gap; already tracked as Audit #6 **M-04** (Open). Not exploitable in this code.
- **5 new LOW/INFO items** (defense-in-depth + hygiene), filed as individual issues.
- Whole-system soundness still depends on the **trusted-setup ceremony**, tracked separately as **#23 (P0, launch-blocker)** — out of scope for a program-code review.

**Findings:** 0 CRITICAL, 0 HIGH (new), 0 MEDIUM (new), 3 LOW, 2 INFO. Plus re-confirmation of 1 accepted HIGH (H-02) and 1 open MEDIUM (M-04).

| ID | Rule | Title | Severity | Status |
|----|------|-------|----------|--------|
| L-01 | SOL-014 | Direct-lamport `+=`/`-=` not `checked_*` (relies on `overflow-checks` profile flag) | LOW | Open (hardening) |
| L-02 | GEN | `withdraw_credit[_spl]` lacks the obligation-floor check that `revoke_drop`/`admin_sweep` enforce | LOW | Open (defense-in-depth) |
| L-03 | GEN | `withdraw_credit` has no explicit `recipient/payer != treasury` self-alias guard | LOW | Open (defense-in-depth) |
| I-01 | GEN | Stale `NR_PUBLIC_INPUTS = 6` constant + obsolete comment (dead code) | INFO | Open (cleanup) |
| I-02 | GEN | `total_claims` counter divergence between SOL and SPL note-pool claims (telemetry) | INFO | Open (cleanup) |
| (H-02) | GEN | Base-layer dishonest-leaf over-claim — **re-confirmed, accepted** | HIGH (accepted) | Accepted (see #2 H-02) |
| (M-04) | SOL-013 | Token-2022 scope exclusion — **re-confirmed, fail-safe** | MEDIUM | Open (see #6 M-04) |

---

## Re-confirmed prior items (no new issue filed)

### H-02 (re-confirmed) — base-layer dishonest-leaf over-claim · Accepted

`create_drop(leaf, amount)` (and `create_drop_spl`) insert the fully client-supplied `leaf` into the Merkle tree while transferring `amount`, with **no on-chain check that the amount encoded inside the leaf equals the deposited `amount`**. The V2 circuit (`circuits/darkdrop.circom`) binds the *withdraw* amount to the *in-leaf* amount (same private `amount` signal in Constraint 1 and Constraint 4) but **cannot** bind the in-leaf amount to the deposited lamports — `secret`/`nullifier` are private witnesses, so the program cannot recompute the leaf on-chain without destroying privacy. `withdraw_credit` (`withdraw_credit.rs:100-106`) bounds the payout only by treasury solvency, so a dust depositor can commit a large in-leaf amount and withdraw other depositors' pooled SOL.

- **Raw severity:** HIGH (cross-user theft from the shared pool). **Disposition:** **Accepted** — identical to Audit #2 **H-02** (`audits/README.md` Fix Tracker), the inherent trust model of commitment-scheme mixers (Tornado-class). Not a regression.
- **Mitigation already in tree:** the note-pool *direct* entry `create_drop_to_pool` / `create_drop_to_pool_spl` builds the pool leaf on-chain from the literal CPI-transferred amount (the I-01 fix) and is the honest path. `deposit_to_note_pool` opens an existing base-layer credit note, so it **carries forward (does not widen)** this assumption.
- **Action:** none in code (cryptographically un-fixable in the base layer). If live TVL has grown materially since H-02 was accepted, revisit the acceptance decision and/or steer deposits to the pool path. Documented in `ARCHITECTURE.md §13`.

### M-04 (re-confirmed) — Token-2022 scope exclusion · fail-safe

Every SPL ingress uses `anchor_spl::token` typed accounts (`Program<'info, Token>`, `Account<'info, Mint>`, `Account<'info, TokenAccount>`), which lock to legacy SPL Token and **reject Token-2022 at Anchor account validation** (`AccountOwnedByWrongProgram`) before any handler runs. Verified there is **no `UncheckedAccount`/`AccountInfo` mint or token-account ingress** through which a Token-2022 account could be smuggled. The rule's worst case (wrong program receives the invocation / transfer-fee mismatch) **cannot occur** for the supported set — legacy SPL has no transfer-fee extension, so `amount`-debited == `amount`-credited and the `mint_vault` solvency math is exact.

- **Severity:** MEDIUM (functional gap, not a vulnerability). **Status:** Open — tracked as Audit #6 **M-04**; issue body already staged at `.audit-issues/M-04-token-2022-rejection.body.md`. The only useful action is a clearer error or finalizing the documented decision; do not relax the binding without a Token-2022 design+audit pass with transfer-fee accounting on every ingress.

### System soundness — trusted setup · tracked as #23

The validity of every claim/withdraw rests on the Groth16 verifying keys in `vk.rs` and the off-chain circuits (`darkdrop.circom` V2, `note_pool.circom` V3), which are **out of scope** for a program-code review. Pre-ceremony VKs are forgeable; this is already tracked as **#23 (P0, soundness, launch-blocker)**. A dedicated circuit + ceremony audit is the highest-leverage remaining work.

---

## New findings

### [L-01] Direct-lamport `+=`/`-=` not `checked_*` — safety depends on the `overflow-checks` profile flag · SOL-014

`withdraw_credit.rs:113,116,121`, `revoke_drop.rs:97-98`, `admin_sweep.rs:37-38` mutate lamports with raw `**acct.try_borrow_mut_lamports()? -= / +=` rather than `checked_*`. Today this is safe: `program/Cargo.toml` sets `[profile.release] overflow-checks = true`, so the deployed build **panics (aborts) on overflow/underflow** instead of silently wrapping — the exact "silent wrap is the financial bug" mechanism SOL-014 warns about does not exist. The treasury debits are additionally pre-bounded by the solvency checks. The hardening: make safety independent of a profile flag (a future `Cargo.toml` change or a copy of this code into a crate without that flag would silently reintroduce the wrap). **Severity: LOW (hardening).**

### [L-02] `withdraw_credit[_spl]` lacks the obligation-floor check `revoke_drop`/`admin_sweep` enforce · GEN

`revoke_drop.rs:81-85` and `admin_sweep.rs:20-32` both compute `outstanding = total_deposited - total_withdrawn` and bound the moved amount by it. `withdraw_credit.rs:100-128` (and `withdraw_credit_spl.rs:90-93`) do **not** — the only gate is treasury/`mint_vault` solvency. Under honest leaves this is harmless (the commitment opening + solvency already bound it). It is an asymmetry, not an exploit. **Honest caveat:** adding `require!(total_withdrawn + amount <= total_deposited)` would **not** fix H-02 (an aggregate cap doesn't stop intra-pool theft when the pool holds other users' deposits) and could introduce a withdraw-DoS if counters ever skew. File for symmetry/visibility; weigh the DoS trade-off before applying. **Severity: LOW (defense-in-depth).**

### [L-03] `withdraw_credit` has no explicit `recipient/payer != treasury` self-alias guard · GEN

`withdraw_credit.rs:113-122` does direct-lamport debit on `treasury` then credit on `recipient` (and `payer` if `fee>0`), with no `require!` that `recipient`/`payer` differ from `treasury`. Benign: Solana duplicate-account dedup makes an aliased credit net-zero the principal, and `recipient` is pinned to `credit.recipient`; worst case is a self-inflicted accounting oddity, not a drain. A one-line guard removes the edge entirely. **Severity: LOW (defense-in-depth).**

### [I-01] Stale `NR_PUBLIC_INPUTS = 6` constant + obsolete comment · GEN

`state.rs:43-45` defines `pub const NR_PUBLIC_INPUTS: usize = 6` with a comment listing `[…, password_hash, amount]` — `password_hash` was removed (#20) and `amount` is private in V2/V3. The constant is **dead** (referenced nowhere; live counts are `vk.rs` `V2/V3_NR_PUBLIC_INPUTS = 4` and the `[[u8;32];4]` types). Delete it so a future maintainer can't wire the retired 6-input shape into a length check. **Severity: INFO (cleanup).**

### [I-02] `total_claims` counter divergence between SOL and SPL note-pool claims · GEN

`claim_from_note_pool.rs:82` bumps `note_pool.total_claims` (not `vault.total_claims`); `claim_from_note_pool_spl.rs:93` bumps `vault.total_claims` (no `NotePoolSpl` counter exists). Structurally identical operations update different counters, so neither is a complete global claim count. Pure telemetry — verified that `total_claims` is never read by any solvency/sweep/authorization/proof logic. Reconcile for consistency. **Severity: INFO (cleanup).**

---

## Verified clean (pattern-matched but sound — no action)

- **SOL-006 / SOL-008** — every privileged mutation has a `Signer`; `create_drop`'s manual `remaining_accounts` receipt path verifies the canonical PDA via `find_program_address`, `is_signer`, `is_writable`, emptiness, and signs `create_account` with the matching canonical bump.
- **SOL-007 / SOL-017 / SOL-019** — the only manual buffer write (`create_drop.rs:132-136`) targets a freshly-created, program-owned PDA and stamps the correct discriminator; every read goes through typed `Account<…>` (owner + discriminator enforced). `migrate_vault` reads stored authority from a raw `AccountInfo` without an explicit owner check but is address-pinned to the canonical vault PDA → not exploitable.
- **SOL-009 / SOL-020** — both vault-PDA-signed `token::transfer` CPIs (`withdraw_credit_spl`, `admin_sweep_spl`) verify caller authority upstream (commitment+recipient / `has_one = authority`+`Signer`). No `SetAuthority` paths.
- **SOL-010** — bare `init` everywhere; no `init_if_needed`.
- **SOL-011** — `close = …` accounts (`CreditNote`, `CreditNoteSpl`, `DepositReceipt`, `PendingAuthority`) hold only rent + metadata; the value lives in `treasury`/`mint_vault` and is moved/bounded before close; rent routes to authorization-checked parties.
- **SOL-005** — the two `realloc` sites (`migrate_vault`, `migrate_schema_v2`) are size-pinned, rent-funded, idempotent, authority-gated, and respect `MAX_PERMITTED_DATA_INCREASE`; the stale-`filled_subtrees` scrub invariant in `migrate_schema_v2` is explicit and correct.
- **SOL-016** — every stored `.bump` is set from `ctx.bumps`/`find_program_address` at init and re-validated by `seeds + bump = <stored>` on each read; singletons / unique-seed PDAs make non-canonical pre-creation impossible.
- **SOL-001 / SOL-018** — no caller-supplied clock persisted (only `Clock::get()` for `REVOKE_TIMEOUT`/`ROTATION_DELAY`); no hardcoded system-program literal.
- **Crypto/state integrity** — claim↔revoke nullifier mutex (`[b"nullifier", h]` + `init`) sound; pool-nullifier mutex sound; `verifier.rs` canonical-input guard (`require_canonical_inputs`) correctly rejects `>= r` on every live path, closing the `n + r` malleability double-spend (#17/F1); `is_known_root` full-scan + sentinel reject sound (no false-positive root acceptance).
- **Authority lifecycle** — `authority_rotation` two-step + 24h `ROTATION_DELAY` (clock-skew-safe `saturating_sub`) + single-pending `init` is sound; `pause_deposits` is authority-gated and affects only the deposit side (users can always exit a paused mint).

---

## Rule coverage matrix

| Rule | Result | Rule | Result |
|------|--------|------|--------|
| SOL-001 | Clean | SOL-011 | Clean |
| SOL-002 | (H-02 accepted, value-conservation) | SOL-012 | Clean |
| SOL-005 | Clean | SOL-013 | M-04 (fail-safe, Open) |
| SOL-006 | Clean | SOL-014 | L-01 (hardening) |
| SOL-007 | Clean (address-pinned) | SOL-015 | Clean (redundant has_one) |
| SOL-008 | Clean | SOL-016 | Clean |
| SOL-009 | Clean | SOL-017 | Clean |
| SOL-010 | Clean (no init_if_needed) | SOL-018 | Clean |
|         |        | SOL-019 | Clean |
|         |        | SOL-020 | N/A (no SetAuthority) |

---

## Out of scope

- The Groth16 **circuits** (`circuits/darkdrop.circom` V2, `circuits/note_pool.circom` V3) and the **trusted-setup ceremony** (`vk.rs` keys) — soundness assumed; tracked as **#23**.
- Frontend / relayer / client libraries.
- The dependency `groth16-solana 0.0.3` (pre-release; pinned — prior INFO).

*This report is an independent cross-check against the Jelleo ruleset; it confirms the program's hardened state and surfaces only low/informational hardening items beyond the already-accepted H-02 and the open M-04.*
