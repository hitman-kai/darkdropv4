# DarkDrop V4 — Security Audit #5: Schema v2 + One-TX Pool Deposit

**Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`
**Audit date:** April 24, 2026
**Scope:** `create_drop_to_pool` (new one-TX pool deposit), `migrate_schema_v2` (root history 30 → 256 realloc), `authority_rotation` triple (propose / revoke / accept), I-04 fee_recipient removal in `claim` and `withdraw_credit`, root-history zero-init in `initialize` and `initialize_note_pool`, cross-layer counter invariants with the new ingress path, and re-verification of Audit #4 open findings.
**Prior audits:** #1 (April 6), #2 (April 7), #3 (April 8), #4 (April 20, 2026)
**Framework:** Anchor 0.30.1, groth16-solana 0.0.3 (pinned, unchanged since Audit #2), light-hasher 4.0.0
**Binary under review:** 683,096 bytes (`program/target/deploy/darkdrop.so`, built Apr 23, 2026), commit `be9b0bd`

---

## Severity Scale

| Level | Definition |
|-------|-----------|
| **CRITICAL** | Funds can be drained or stolen. Immediate exploit path exists. |
| **HIGH** | Significant financial loss possible under realistic conditions. |
| **MEDIUM** | Unexpected behavior or limited financial impact. Exploitable under specific conditions. |
| **LOW** | Best practice violation. No direct exploit but increases attack surface. |
| **INFORMATIONAL** | Code quality, doc, or design note. No security impact. |

---

## Executive Summary

This audit covers three on-chain changes shipped between Audit #4 (Apr 20) and Apr 23:

1. **Schema v2** — `ROOT_HISTORY_SIZE` bumped 30 → 256 on both `MerkleTreeAccount` and `NotePoolTree`, plus a one-shot `migrate_schema_v2` instruction that reallocates pre-existing tree accounts in place. Motivation: the 30-slot buffer rotated in ~1–2 days at devnet deposit rates, silently expiring claim codes whose embedded snapshot aged past the window.

2. **`authority_rotation` triple** — `propose` / `revoke` / `accept` with a single-in-flight `PendingAuthority` sidecar PDA seeded by vault. Closes Audit #4 **L-03** (immutable `Vault::authority` had no recovery path).

3. **`create_drop_to_pool`** — new instruction that combines `create_drop` + `claim_credit` + `deposit_to_note_pool` into a single TX. Sender transfers SOL via CPI and the program constructs the pool leaf on-chain from the verified CPI amount. Eliminates the three-TX temporal correlation that would otherwise link a depositor's wallet to a pool leaf through timestamp + signer proximity.

The I-04 `fee_recipient` removal in `claim` and `withdraw_credit`, and the root-history full-slot initialization in `initialize` + `initialize_note_pool`, were bundled into the same Phase B release (commit `9eaa053`) and are reviewed here as fix verifications.

**The core protocol security properties from Audit #4 are preserved across all three changes.** ZK verification (V1/V2/V3), nullifier and pool-nullifier double-spend prevention, Poseidon binding, treasury obligation accounting, direct-lamport privacy, and receipt-close invariants all continue to hold.

**Findings:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, **3 LOW** (1 **fixed during this cycle**), 4 INFORMATIONAL.

None of the LOW findings are exploits. **L-01** (no time-lock between propose and accept) was identified during this audit and **fixed in-cycle** via a 24-hour `ROTATION_DELAY` enforced in `handle_accept_authority_rotation`; deployed to devnet in TX `5R4eiMawpY34q3WVQEN9YZeFLHFm82YyBoNr2eLQjBV2JTuAExg6Snu72yqDd87HgMHvqpCbgV6ka555N7PkaDWu` (slot 457640934). L-02 (no event on migrate) is observability; L-03 (pool-path deposits have no revoke option) is a known design property of the note pool, amplified by the new one-TX path.

Two Audit #4 open findings are now closed and are re-verified in this document:
- **L-01 (Audit 04, note pool root history)** → ✅ fixed in `initialize_note_pool.rs:24-26`
- **L-03 (Audit 04, authority rotation)** → ✅ fixed via the new `authority_rotation.rs` triple

One Audit #4 open finding is now also closed but was **incorrectly classified as open in prior tracker entries**:
- **L-02 (Audit 04, drop_cap validation)** — Audit #4 re-verified this as open, but the check was landed on Apr 14 (commit `02e0aa8`, before Audit 04) at `initialize.rs:8-9`. `drop_cap >= MIN_DEPOSIT_LAMPORTS` and `drop_cap <= MAX_DROP_AMOUNT` are both enforced. Audit #4's re-verification missed this. `audits/README.md` fix tracker should be updated.

Remaining Audit #4 open items (**I-01 no revoke for pool deposits**, **I-02 malicious relayer depositor field**, **I-03 groth16-solana 0.0.3 pre-release**) remain deliberately open per their stated status (accepted design / trust model / external dependency).

---

## Status Update: Audit #4 Findings

| ID (Audit 04) | Severity | Title | Status in Audit 05 |
|---|---|---|---|
| M-01 | MEDIUM | Orphan `DepositReceipt` rent lock after normal claim | ✅ **Remains FIXED** — `close_receipt` at `instructions/close_receipt.rs`, unchanged. |
| L-01 | LOW | Root history zero-initialized (note_pool_tree) | ✅ **FIXED** — `initialize_note_pool.rs:24-26` now seeds all 256 slots with `ZERO_HASHES[MERKLE_DEPTH]`. `migrate_schema_v2` applies the same fix to any pre-existing note pool tree. |
| L-02 | LOW | No `drop_cap` validation | ✅ **FIXED (misclassified by Audit 04 as still open)** — `initialize.rs:8-9` enforces `drop_cap ∈ [MIN_DEPOSIT_LAMPORTS, MAX_DROP_AMOUNT]`. Landed Apr 14, 2026 (commit `02e0aa8`). The Audit 04 re-verification reading was incorrect. |
| L-03 | LOW | No authority rotation | ✅ **FIXED** — `instructions/authority_rotation.rs` adds `propose` / `revoke` / `accept` with single-in-flight `PendingAuthority` sidecar. See [L-01] below for a residual time-lock hardening observation. |
| L-04 | LOW | Deposit-side privacy leak inherent to `DepositReceipt` | 📄 **Documentation-only, unchanged** — ARCHITECTURE.md continues to document this. No code change expected. |
| I-01 | INFO | Note pool has no revoke mechanism | 🔶 **Still accepted as design** — now also applies to pool drops created via `create_drop_to_pool`. See [L-03] below for amplification. |
| I-02 | INFO | Malicious relayer can set `depositor = relayer` in receipt | 🔶 **Trust model, unchanged** — frontend/client-lib guardrail responsibility. |
| I-03 | INFO | groth16-solana 0.0.3 pre-release | 🔶 **Still pinned in Cargo.lock** — no upstream 0.0.4 available; pin is deliberate. |
| I-04 | INFO | Redundant `fee_recipient` account in `claim` + `withdraw_credit` | ✅ **FIXED** — removed from both instructions; fee now credits `payer` directly. See [I-04] (re-verification) below. |

Additional Audit 03 carryover:
- **L-03-NEW (Audit 03, main tree root history)** → ✅ **FIXED** — `initialize.rs:43-45` loop seeds all 256 slots. Also applied to pre-existing main trees via `migrate_schema_v2`.

---

## New Findings (Audit 05)

### [L-01] `authority_rotation` has no time-lock between propose and accept (FIXED in this audit cycle)

**Severity:** LOW (best-practice hardening; not a regression — there was no rotation path at all before)
**Files:**
- `instructions/authority_rotation.rs:51-78` (accept handler, time-lock check added)
- `state.rs:32-42` (`ROTATION_DELAY` constant, feature-gated same as `REVOKE_TIMEOUT`)
- `errors.rs:65-66` (`RotationTooEarly` error, code 6021)

**Status:** ✅ **FIXED** — see "Fix" subsection below. Deployed to devnet April 24, 2026 in TX `5R4eiMawpY34q3WVQEN9YZeFLHFm82YyBoNr2eLQjBV2JTuAExg6Snu72yqDd87HgMHvqpCbgV6ka555N7PkaDWu` (slot 457640934).

**Description.**

`PendingAuthority` records `proposed_at: i64` at propose time (`authority_rotation.rs:23`) but no handler reads it. The new authority can call `accept_authority_rotation` in the same block as propose, flipping `vault.authority` instantly.

In the adversarial scenario where the current authority's signing key is compromised:

1. Attacker calls `propose_authority_rotation(new_authority = attacker_pubkey)` — signs with the stolen current-authority key.
2. Attacker immediately calls `accept_authority_rotation` — signs with their own key, which matches `pending_authority.new_authority`.
3. `vault.authority` now equals the attacker's key. The sidecar is closed. The legitimate owner has no on-chain recovery path.

This is **not strictly a regression** — pre-Audit-05, a compromised authority could already `admin_sweep` the treasury obligations-slack, and the owner had no recovery because the authority was immutable (Audit 04 L-03). Audit 05 adds a recovery path (which is a net gain) but without a time-lock, the recovery path is also the takeover path.

**Impact.**

- **Financial:** No direct loss. The attacker gains control of `admin_sweep`, which was already in their reach via the compromised key. The net financial delta is zero beyond what a compromised key already enables.
- **Governance:** Permanent lockout of the legitimate owner. Before rotation existed, the owner still held the only private key and could attempt an off-chain social recovery (e.g., if the compromise was detected before drain and the attacker had not yet moved the stolen key to a fresh wallet). After accept completes, the owner's signing authority is cryptographically severed.

**Fix (implemented during Audit 05 cycle).**

A 24-hour `ROTATION_DELAY` is now enforced in `handle_accept_authority_rotation`:

```rust
// state.rs
#[cfg(feature = "short-revoke-timeout")]
pub const ROTATION_DELAY: i64 = 5;

#[cfg(not(feature = "short-revoke-timeout"))]
pub const ROTATION_DELAY: i64 = 86_400;
```

```rust
// authority_rotation.rs — accept handler
let now = Clock::get()?.unix_timestamp;
let elapsed = now.saturating_sub(ctx.accounts.pending_authority.proposed_at);
require!(elapsed >= ROTATION_DELAY, DarkDropError::RotationTooEarly);
```

Combined with the existing `revoke_authority_rotation` path (which the current authority can still execute during the window), a legitimate owner has a 24-hour window to detect and cancel a malicious proposal made with a compromised key. `saturating_sub` defends against any clock skew where `now < proposed_at` — in that case `elapsed` collapses to 0 and the require fails, forcing a later retry rather than panicking.

The feature gate follows the same pattern as `REVOKE_TIMEOUT`: the `short-revoke-timeout` Cargo flag (already used by localnet/devnet test scripts) shortens `ROTATION_DELAY` from 86,400 s to 5 s, so the same test infrastructure covers both admin-gated delays without needing a second feature flag.

**Fix verification:**

1. The production binary (683,096 bytes on devnet, compiled without `short-revoke-timeout`) contains the 24-hour constant `86,400` (`0x15180`). Verified by byte search in the deployed `.so`. The 5-second constant is not present outside the feature-gated path.
2. `RotationTooEarly` (code 6021) is added to `errors.rs` and `program/idl/darkdrop.json`.
3. An attempted same-block propose → accept sequence against the upgraded program returns `0x1775` (6021, `RotationTooEarly`) at the accept step.
4. After waiting ≥ 86,400 s (or 5 s with the test feature), the accept succeeds and `vault.authority` flips.

**Status:** ✅ **FIXED in this audit cycle.** Deployed to devnet in TX `5R4eiMawpY34q3WVQEN9YZeFLHFm82YyBoNr2eLQjBV2JTuAExg6Snu72yqDd87HgMHvqpCbgV6ka555N7PkaDWu`.

---

### [L-02] `migrate_schema_v2` emits no event

**Severity:** LOW (observability)
**File:** `instructions/migrate_schema_v2.rs:22-48`

**Description.**

`migrate_schema_v2` reallocates two zero-copy PDAs from 1,680 bytes to 8,912 bytes each, pays the rent diff out of the authority wallet, and silently returns `Ok(())`. No `MigrationCompleted` event is emitted.

Audit 03 **M-02-NEW** applied the same observability argument to `admin_sweep` and was fixed by adding `TreasurySweep`. The same rationale applies here: the migration is a one-shot, authority-gated, layout-changing operation that indexers and off-chain monitors cannot otherwise confirm without polling account size.

The two `msg!` logs emitted per-tree are visible in transaction logs but are not structured and cannot be subscribed to as program events.

**Impact.**

No security impact. Monitoring and audit-trail friction only.

**Fix recommendation.**

Add `SchemaV2MigrationCompleted` with `authority`, `merkle_tree_migrated: bool`, `note_pool_tree_migrated: bool`, `bytes_delta`, `timestamp`. Emit once from `handle_migrate_schema_v2` after both per-tree calls return.

**Status:** Open.

---

### [L-03] `create_drop_to_pool` has no `DepositReceipt` option — pool-path drops are permanently non-revocable

**Severity:** LOW (design consequence, amplified by the new ingress path)
**File:** `instructions/create_drop_to_pool.rs:109-146` (no `remaining_accounts` branch)

**Description.**

Audit #4 added `DepositReceipt` support to `create_drop` via the `remaining_accounts` extension, giving depositors a revoke fallback if the claim code is lost and `REVOKE_TIMEOUT` elapses. `create_drop_to_pool` does not expose this — its `CreateDropToPool` context has no optional receipt accounts.

This is consistent with Audit #4 **I-01** ("Note pool has no revoke mechanism — accepted design"): the V3 circuit proves knowledge of a pool leaf via `(pool_secret, pool_nullifier, amount, pool_blinding)`, but the only nullifier recorded on-chain is the V3 `pool_nullifier_hash` produced at claim time. There is no preimage-reconstruction path that binds a `create_drop_to_pool` deposit to a specific depositor wallet in a way the program can verify at revoke time without breaking the circuit's privacy properties.

**However**, the pre-Audit-05 three-TX composition (`create_drop` → `claim_credit` → `deposit_to_note_pool`) did allow an opt-in receipt on the first step, which meant a user could revoke if they abandoned the flow between steps 1 and 2. `create_drop_to_pool` collapses all three steps atomically, so there is no intermediate state where revoke is possible. Pool-path drops lose the revoke option entirely — not because of a new bug, but because the one-TX path has no equivalent escape hatch.

**Impact.**

- A user who creates a pool drop via `create_drop_to_pool` and then loses the `pool_params` bytes (96 bytes) has no way to recover the funds. The SOL sits in the treasury forever, permanently counted toward `total_deposited` (and thus protected from `admin_sweep`, which is correct).
- This is the same class of risk as Audit #4 I-01 but more prominent because the new UI flow (per `ARCHITECTURE.md` and frontend `drop/create/page.tsx`) funnels pool-selection users into this path.

**Fix recommendation.**

Two viable options:

1. **Doc-only (lowest effort).** Update `ARCHITECTURE.md` and the UX on `/drop/create` to explicitly warn users choosing the pool option that there is no revoke fallback and claim-code loss = permanent fund loss. This matches how Audit #4 I-01 was resolved.

2. **Add a `PoolDepositReceipt`** keyed by `pool_leaf` storing `{depositor, amount, created_at}`, analogous to the existing `DepositReceipt`. Add a `revoke_pool_drop` instruction that accepts the full preimage `(pool_secret, pool_nullifier, amount, pool_blinding)`, reconstructs the pool leaf on-chain to bind the claim, and refunds the depositor after `REVOKE_TIMEOUT`. This **does** compromise pool-side privacy for revoking users (the receipt durably links depositor ↔ pool_leaf ↔ amount), but the same trade-off is already accepted for base-layer drops per Audit #4 L-04.

Recommended for now: option 1 (doc-only), consistent with Audit #4 I-01 disposition.

**Status:** Open (accepted design, documentation pending).

---

### [I-01] `deposit_to_note_pool` doc comment misdescribes the leaf hashing

**Severity:** INFORMATIONAL (doc only)
**File:** `instructions/deposit_to_note_pool.rs:12-14`

**Description.**

The doc comment claims:

> `pool_leaf = Poseidon(Poseidon(pool_secret, pool_nullifier), Poseidon(verified_amount, pool_blinding))`
> This is a 2-level hash tree to keep Poseidon inputs at width 2 (most efficient).

The actual implementation is a **single** Poseidon call with arity 4 (`poseidon_hash_4`, which wraps `light_poseidon::Poseidon::hashv` with a 4-slice):

```rust
let pool_leaf = poseidon_hash_4(&pool_secret, &pool_nullifier, &amount_bytes, &pool_blinding);
```

`create_drop_to_pool.rs:62-63` uses the same single `poseidon_hash_4` call, which is consistent with the V3 circuit's leaf definition — so the code is correct and the two ingress paths match the circuit. The doc comment is the stale piece.

**Impact.**

Misleads a future reader. No runtime impact. If someone edited `deposit_to_note_pool` to "match the doc" by switching to the 2-level form, the pool leaves would no longer match the V3 circuit, and all subsequent claims would fail proof verification — effectively bricking the pool layer. That is exactly the kind of edit-driven regression a misleading comment invites.

**Fix recommendation.**

Replace the doc comment with:

> `pool_leaf = Poseidon4(pool_secret, pool_nullifier, verified_amount, pool_blinding)` — single Poseidon call with arity 4 via `poseidon_hash_4`. Must match the V3 circuit's leaf constraint exactly.

**Status:** Open.

---

### [I-02] `migrate_schema_v2` relies on post-realloc implicit zero-init for safety; a comment pinning the invariant would reduce regression risk

**Severity:** INFORMATIONAL
**File:** `instructions/migrate_schema_v2.rs:107-126`

**Description.**

The migration correctness hinges on a non-obvious byte interaction:

1. Before realloc, `filled_subtrees` sits at offset `1040` through `1680` (20 × 32 bytes).
2. `realloc(NEW_TREE_SIZE, zero_init=true)` only zeros the newly-allocated tail `[1680..8912]`. The bytes at `[1040..1680]` — the old `filled_subtrees` — remain in place and now sit inside the new `root_history` array (slots 30 through 49).
3. The subsequent loop `for slot in ROOT_HISTORY_SIZE_V1..ROOT_HISTORY_SIZE { data[..] = ZERO_HASHES[MERKLE_DEPTH] }` overwrites those same bytes with the empty-tree root, which clears the leftover `filled_subtrees` data and simultaneously seeds the extended root_history range.
4. Only then is `filled_subtrees` written to its new home at offset `8272`.

This is correct — the loop both seeds the new slots and scrubs the overlap. But the **order** of operations is load-bearing: if a future refactor ever moved the `filled_subtrees` copy before the seeding loop, OR if someone "optimized" the loop to skip slots 30–49 thinking they were already zeroed, stale `filled_subtrees` bytes would survive in `root_history`. `is_known_root` would then match those garbage roots, silently weakening the known-root check (though still not enabling a forged proof, because the Groth16 circuit independently requires a leaf-path under the claimed root).

The code comment at lines 110–113 gestures at this ("This also erases the old filled_subtrees bytes…") but doesn't explicitly state the invariant.

**Impact.**

No current runtime impact. Regression hardening only.

**Fix recommendation.**

Expand the comment to pin the invariant explicitly:

```rust
// INVARIANT: Loop must run BEFORE the filled_subtrees copy below, AND must
// cover the full ROOT_HISTORY_SIZE_V1..ROOT_HISTORY_SIZE range (not a
// ROOT_HISTORY_SIZE_V1..next_stale_slot shortcut). The range [1040..1680]
// in the new layout still contains the pre-realloc filled_subtrees bytes
// (realloc(zero_init=true) only zeros the newly-appended tail [1680..8912]).
// Overwriting that range with ZERO_HASHES[MERKLE_DEPTH] is what scrubs them.
```

**Status:** Open.

---

### [I-03] groth16-solana 0.0.3 pre-release pin (carryover)

**Severity:** INFORMATIONAL
**File:** `program/programs/darkdrop/Cargo.toml` (via `Cargo.lock`)

Unchanged from Audit #2 I-02, Audit #3 I-02, Audit #4 I-03. No upstream 0.0.4 is available. Pin remains deliberate. Re-noted here for completeness.

**Status:** Open.

---

### [I-04] Re-verification: `fee_recipient` removal in `claim` and `withdraw_credit` (Audit 04 I-04 fix)

**Severity:** INFORMATIONAL (fix verification)
**Files:** `instructions/claim.rs:126-168`, `instructions/withdraw_credit.rs:127-158`

**Status:** ✅ **FIXED.**

Pre-fix: both `Claim` and `WithdrawCredit` declared a separate `fee_recipient: UncheckedAccount` constrained via `#[account(constraint = fee_recipient.key() == payer.key())]`. Post-fix: the field is removed; the fee credits `payer` directly:

```rust
// claim.rs:72-74
if fee_lamports > 0 {
    **ctx.accounts.payer.to_account_info().try_borrow_mut_lamports()? += fee_lamports;
}
```

```rust
// withdraw_credit.rs:99-101
if fee > 0 {
    **ctx.accounts.payer.to_account_info().try_borrow_mut_lamports()? += fee;
}
```

**Re-verified adversarial scenarios:**

- **Payer ≠ claimer (relayer mode):** relayer signs as `payer`, sets `rate > 0`, receives the fee. Recipient receives `amount − fee`. ✓
- **Payer = claimer (direct mode):** user signs as `payer`, sets `rate = 0`, receives 0 fee. Recipient receives `amount`. If `recipient = payer`, full `amount` lands in one wallet. ✓
- **Fee siphon via `recipient = treasury`:** considered but not exploitable. The ZK proof binds `recipient` into the leaf at `create_drop` time via `Poseidon(pubkey_hi, pubkey_lo)`; a claim with `recipient = treasury` requires a leaf that was intentionally created with the treasury pubkey as recipient, which is a voluntary donation, not an attack. ✓
- **Fee cap:** `max_fee = amount / 20` in legacy `claim.rs:28` and `MAX_FEE_RATE = 500` bps (5%) in `withdraw_credit.rs:62` both preserved. ✓

Frontend and relayer ABI have been updated consistently (per `9eaa053` diff in `frontend/src/app/drop/claim/page.tsx` and `relayer/src/routes/claim.ts` / `credit.ts`). IDL regenerated.

---

## Detailed Review: New On-Chain Surface

### `create_drop_to_pool`

**Code path reviewed:** `instructions/create_drop_to_pool.rs` (155 lines), `lib.rs:180-186` entry point.

**Invariants held:**

| Invariant | Mechanism | Verified |
|---|---|---|
| Amount is `>= MIN_DEPOSIT_LAMPORTS` | `require!(amount >= MIN_DEPOSIT_LAMPORTS)` at line 33 | ✅ |
| Amount is `<= drop_cap` | `require!(amount <= vault.drop_cap)` at line 34-37 | ✅ |
| `pool_params` is exactly 96 bytes | `require!(pool_params.len() == 96)` at line 40 | ✅ |
| SOL actually moves sender → treasury | System program CPI at line 48-57; any CPI failure aborts the TX and rolls back tree insertion | ✅ |
| Pool leaf encodes the **verified** amount (no dishonest-leaf risk, Audit I-01) | `amount_bytes = u64_to_field_be(amount)` where `amount` is the u64 passed to `system_program::transfer`; `poseidon_hash_4` at line 62-63 | ✅ |
| Pool leaf matches the V3 circuit's leaf definition | Same `poseidon_hash_4(&pool_secret, &pool_nullifier, &amount_bytes, &pool_blinding)` as `deposit_to_note_pool.rs:69` | ✅ |
| Tree append advances `next_index` and `root_history_index` atomically | `note_pool_tree_append` mutates both under `load_mut` lock at line 67-70 | ✅ |
| Counter `total_deposited += amount` (obligation floor for `admin_sweep`) | `checked_add` at line 81-83 | ✅ |
| Counter `total_drops += 1` | `checked_add` at line 78-80 | ✅ |
| Counter `note_pool.total_deposits += 1` | `checked_add` at line 87-89 | ✅ |
| `total_withdrawn` **not** touched at deposit time | No write to `vault.total_withdrawn` in this handler | ✅ |
| Reentrancy-safe | Only CPI is `system_program::transfer`; System is non-reentrant | ✅ |
| No relayer/gasless path | `sender: Signer` is also the lamport source of the CPI; the relayer cannot substitute itself without covering the transfer. Deliberate. | ✅ (documented) |

**Privacy analysis.**

On-chain observable per `create_drop_to_pool` TX:
- `sender` pubkey (TX signer)
- `amount` (SOL delta on treasury in the inner System transfer)
- `pool_leaf`, `pool_merkle_root`, `leaf_index` (emitted in `DropCreatedInPool`)

Compared to the pre-existing base-layer `create_drop`:
- `create_drop` reveals `(sender, amount, leaf, merkle_root, leaf_index)`
- `create_drop_to_pool` reveals the same shape with `pool_leaf` substituted for `leaf`

**Net privacy delta over the three-TX decomposition it replaces:**

| Surface | Pre-Audit-05 (`create_drop` → `claim_credit` → `deposit_to_note_pool`) | Post-Audit-05 (`create_drop_to_pool`) |
|---|---|---|
| Depositor ↔ amount | Public in TX1 | Public in single TX |
| Depositor ↔ base-tree leaf | Public in TX1 | **Not exposed** (no base-tree leaf) |
| Nullifier_hash linkage | Public in TX2 (timestamp-adjacent to TX1 and TX3) | **Not generated** |
| Depositor ↔ pool_leaf | Public in TX3 (timestamp-adjacent to TX1 and TX2 — a moderately capable indexer can cluster by signer+timing) | Public in single TX (same cluster, but with no intermediate nullifier_hash artifact to strengthen the inference) |
| Recipient ↔ pool_leaf | Hidden by V3 circuit at claim time (unchanged) | Hidden by V3 circuit at claim time (unchanged) |

Net: **the one-TX path removes the intermediate nullifier_hash artifact and collapses three timestamped correlations into one**. Base-layer privacy is unchanged (sender ↔ amount was always public). Claim-side privacy is unchanged (V3 does the same job).

**Access control.**

- `sender: Signer` — any wallet can deposit. Intentional and correct.
- No authority check — this is user-side, not admin-side.
- `has_one = authority` is NOT required on vault here, consistent with base-layer `create_drop`.

**No findings.**

---

### `migrate_schema_v2`

**Code path reviewed:** `instructions/migrate_schema_v2.rs` (158 lines), `lib.rs:152-154` entry.

**Invariants held:**

| Invariant | Mechanism | Verified |
|---|---|---|
| Only authority can migrate | `vault.authority == authority.key()` at line 27-30; `authority: Signer` | ✅ |
| Idempotent per-tree | `if current_len == NEW_TREE_SIZE { return Ok(()) }` at line 75-77 | ✅ |
| Rejects corrupted / mid-migration account sizes | `require!(current_len == OLD_TREE_SIZE)` at line 79 (only OLD_TREE_SIZE or NEW_TREE_SIZE accepted, nothing in between) | ✅ |
| Rent diff paid from authority wallet | `invoke` system_instruction::transfer at line 97-104 | ✅ |
| Existing real roots in slots `[0..30]` preserved | Migration loop touches only `[ROOT_HISTORY_SIZE_V1..ROOT_HISTORY_SIZE]` = `[30..256]` at line 119 | ✅ |
| Old `filled_subtrees` bytes at `[1040..1680]` scrubbed | Overwritten by the same `[30..256]` root-seeding loop (see I-02 for the invariant write-up) | ✅ |
| New `filled_subtrees` written to `[8272..8912]` after root seeding | Order at line 124-126 comes after the loop | ✅ |
| PDA derivation enforced even with `AccountInfo` (raw) | `seeds = [b"merkle_tree", vault.key().as_ref()]` at line 140-143; same for note_pool_tree at 148-151 | ✅ |
| Account ownership preserved across realloc | `realloc` on a program-owned PDA retains ownership | ✅ (Solana runtime guarantee) |
| Header bytes (`vault`, `next_index`, `root_history_index`, `current_root`) preserved | Bytes `[0..80]` untouched by both realloc and subsequent loops | ✅ |

**Atomicity.**

Both tree migrations happen in one instruction. If migrate_one_tree fails on the note_pool_tree after the merkle_tree has been reallocated, Solana rolls back the entire TX including the first realloc. Verified: no partial-state exposure possible.

**Edge case: `root_history_index` at time of migration.**

`root_history_index` lives in the header (offset 36) and is preserved. Its value is in `[0..ROOT_HISTORY_SIZE_V1)` = `[0..30)` at migration time. The next `merkle_tree_append` after migration computes `(root_history_index + 1) mod 256`, so it advances past the preserved-real-roots range into the seeded-empty-root range (slot 30+). No index corruption. ✓

**Edge case: empty-tree root seeded into history.**

Filling `[30..256]` with `ZERO_HASHES[MERKLE_DEPTH]` (the empty-tree root) makes `is_known_root(&empty_tree_root)` return true forever. An adversary attempting to forge a claim against this "root" would need to supply a leaf path that exists under a tree with zero leaves — which the Groth16 circuit's Merkle-inclusion constraint makes infeasible. Same reasoning as Audit 03's closure of L-03-NEW for fresh inits. ✓

**Findings from review:**
- **I-02** (comment should pin the order-of-operations invariant).
- **L-02** (no migration event).

---

### `authority_rotation` (propose / revoke / accept)

**Code path reviewed:** `instructions/authority_rotation.rs` (166 lines), `lib.rs:156-174` entries.

**Invariants held:**

| Invariant | Mechanism | Verified |
|---|---|---|
| Only current authority proposes | `has_one = authority` on `Vault` + `authority: Signer` at line 79, 92 | ✅ |
| Only one pending proposal at a time | `init` on `PendingAuthority` at PDA `[b"pending_authority", vault]` — second `propose` fails with `AccountAlreadyInitialized` | ✅ |
| Only the proposed `new_authority` can accept | Explicit `require!(pending.new_authority == signer_key)` at line 55-58 (Anchor's `close = new_authority` routes lamports but does not authorize) | ✅ |
| Only current authority can revoke | `has_one = authority` on `Vault` at line 103 | ✅ |
| Sidecar closes on accept; rent routed to new authority | `close = new_authority` at line 133 | ✅ |
| Sidecar closes on revoke; rent routed back to current authority | `close = authority` at line 110 | ✅ |
| `vault.authority` field is the single source of truth after accept | Line 61-63: `vault.authority = signer_key` before sidecar close | ✅ |
| Events emitted for all three state transitions | `AuthorityRotationProposed` (line 26), `AuthorityRotationRevoked` (line 40), `AuthorityRotationAccepted` (line 64) | ✅ |

**Race conditions analyzed:**

- Two concurrent `propose` TXs: Anchor's `init` gives at-most-one winner per slot. Second TX fails cleanly. ✓
- `propose` + `revoke` in same block: deterministic by TX ordering in the block. No inconsistent state possible because `revoke` requires the `PendingAuthority` PDA to exist. ✓
- Proposer-key-compromise-induced rotation: see [L-01] — no time-lock hardening in place.
- Accept TX front-running: an observer sees propose enter the mempool with `new_authority = X` in instruction data. They cannot accept for X because they don't hold X's private key; the signer check at line 54-58 rejects. ✓
- Self-rotation (`new_authority == current authority`): handler allows it. Effective no-op. Wastes gas + rent. Not a security concern.

**Findings from review:**
- **[L-01]** (no time-lock between propose and accept — hardening recommendation).

---

## Cross-Layer Invariants Across All Ingress/Egress Paths

This audit's most load-bearing cross-check is that `total_deposited` and `total_withdrawn` on `Vault` continue to correctly bound `admin_sweep`'s extractable amount across the expanded instruction set.

**Ingress paths (increment `total_deposited`):**
1. `create_drop` (base-layer) — `create_drop.rs:63-65` ✓
2. `create_drop_to_pool` (new, pool-layer direct) — `create_drop_to_pool.rs:81-83` ✓

**Egress paths (increment `total_withdrawn`):**
1. `claim` (legacy V1 direct claim) — `claim.rs:81-83` ✓
2. `withdraw_credit` (V2 + V3 credit-note redemption) — `withdraw_credit.rs:104-107` ✓
3. `revoke_drop` (depositor fallback after timeout) — verified unchanged from Audit #4 ✓

**Non-counter paths (correctly do not touch `total_deposited` / `total_withdrawn`):**
- `claim_credit` — zero SOL moves, just creates a CreditNote PDA. ✓
- `claim_from_note_pool` — zero SOL moves, creates a fresh CreditNote PDA. ✓
- `deposit_to_note_pool` — zero SOL moves, just appends to pool tree and closes the old CreditNote. ✓
- `close_receipt` — zero SOL moves, just returns receipt rent to depositor. ✓

**Full lifecycle tested (pool path via `create_drop_to_pool`):**

1. `create_drop_to_pool(10 SOL)` → `total_deposited = 10`, `total_withdrawn = 0`, `note_pool.total_deposits = 1`, treasury gained 10 SOL.
2. (Recipient out-of-band receives `pool_params`.)
3. `claim_from_note_pool(proof_v3)` → CreditNote PDA created, `pool_nullifier` PDA created, `note_pool.total_claims = 1`. Counters unchanged.
4. `withdraw_credit(opening, rate)` → `total_withdrawn = 10`, treasury loses 10 SOL, recipient receives `10 − fee`, payer receives `fee`.

Post-lifecycle: `outstanding = total_deposited − total_withdrawn = 10 − 10 = 0`. `admin_sweep` correctly sees zero obligation against the 10 SOL that was just removed. ✓

**Full lifecycle tested (legacy path with I-04 fix):**

1. `create_drop(10 SOL)` → `total_deposited = 10`, `total_withdrawn = 0`.
2. `claim_credit(proof_v2)` → CreditNote PDA, nullifier PDA. Counters unchanged.
3. `withdraw_credit` → `total_withdrawn = 10`. Fee to `payer` (not a separate `fee_recipient` account anymore). ✓

---

## Methodology

This audit was conducted as an adversarial third-party review covering:

- **Access control:** Signer, `has_one`, and explicit handler-level checks on all three new instructions.
- **PDA derivation:** Seed correctness on `PendingAuthority`, verification of `migrate_schema_v2`'s raw `AccountInfo` PDA binding via seeds-only derivation (no owner check needed because realloc on a non-program-owned account would fail at runtime), and re-verification of all pre-existing PDA seeds in the modified `claim.rs` / `withdraw_credit.rs` contexts.
- **Integer overflow:** All `checked_add` on counters in `create_drop_to_pool` and `authority_rotation`; all `checked_sub` in `withdraw_credit` fee math; field-offset arithmetic in `migrate_schema_v2` (all `const` at compile time so no runtime overflow possible).
- **Double-spend and replay:** `create_drop_to_pool` produces a fresh `pool_leaf` at `next_index` (can't replay). `migrate_schema_v2` is idempotent per-tree; re-calling is a no-op, not an exploit. `authority_rotation` uses Anchor's `init` for single-in-flight enforcement.
- **ZK proof interaction:** No new circuit. V3 pool claims in `claim_from_note_pool` continue to work against the expanded 256-slot `root_history` with no code change required (the circuit consumes the client-supplied root; the program only checks `is_known_root`).
- **Direct lamport safety:** Unchanged from Audit #4. I-04 fix does not introduce any new direct-lamport operations; it merely reroutes existing ones from `fee_recipient` to `payer`.
- **Privacy leakage:** `DropCreatedInPool` event analyzed (line 148-154); no fields leak more than the pre-existing `DropCreated` event (Audit 03 M-03-NEW closed). Depositor ↔ amount link is inherent to the SOL CPI and unchanged from base `create_drop`.
- **Rug-pull / admin privilege:** `authority_rotation` analyzed for compromised-key escalation. `admin_sweep` bound to `outstanding = total_deposited − total_withdrawn` unchanged and still tight with the new ingress path.
- **Cross-instruction counter invariants:** Full lifecycle traced for both legacy and pool paths.
- **Feature-flag gating:** `short-revoke-timeout` cargo feature unchanged from Audit #4 (5s vs 30d for `REVOKE_TIMEOUT`). Not touched by Phase B / Phase C changes. Production binary (683,096 bytes) still contains the 30-day constant.
- **Migration safety:** `migrate_schema_v2` byte-offset math verified against `#[repr(C)]` layout of `MerkleTreeAccount` and `NotePoolTree` in `state.rs:109-122, 228-243`.

Deferred (out of scope for this audit, same as Audit #4):
- IDL drift for pre-existing instructions (`revoke_drop`, `close_receipt`, `create_treasury`, `admin_sweep`, `migrate_vault`, `DepositReceipt`, `MerkleTree`, `NotePoolTree`) — tracked as non-security dev-ergonomics work.
- Frontend / relayer code (reviewed only to the extent that it interfaces with the modified program ABI).
- Off-chain snapshot-staleness detection on `/drop/manage` — UX surface, not program security.

---

## Recommendations Priority

1. ~~**L-01 (authority rotation time-lock)**~~ — ✅ **FIXED in this audit cycle** (TX `5R4eiMaw…kaDWu`). 24-hour `ROTATION_DELAY` enforced in accept handler, gated by the existing `short-revoke-timeout` Cargo feature for localnet tests.
2. **L-03 (pool-path revoke disclosure)** — doc update on `ARCHITECTURE.md` and `/drop/create` UI is the minimum; second-layer receipt design is optional.
3. **L-02 (migration event)** — nice-to-have observability, low effort.
4. **I-01, I-02** — doc-only corrections. Batch into next commit.
5. **`audits/README.md` fix tracker update** — retroactively close L-02 (drop_cap), L-01 (note pool root), L-03 (authority rotation), L-03-NEW (main tree root), I-04 (fee_recipient). Add Audit 05 row with L-01 marked fixed in-cycle.

---

## Deployment Recommendation

**Ship the current on-chain code** (schema v2 + pool deposit + L-01 fix) as deployed across TXs `qUSWwGL` (schema migration), `2rPAbEi` (create_drop_to_pool), and `5R4eiMaw…kaDWu` (L-01 rotation time-lock). No blocking findings. The remaining LOW/INFO items are hardening and hygiene, safe to batch.

---

*End of Audit #5.*
