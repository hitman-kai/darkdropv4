# DarkDrop V4 — Security Audit #3: Post-Fix Full Review

**Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`  
**Audit date:** April 8, 2026  
**Scope:** All 7 instruction handlers and supporting modules in `program/programs/darkdrop/src/`  
**Prior audits:** Audit #1 (April 6), Audit #2 (April 7)  
**Context:** This audit follows the deployment of fixes for H-01, M-01, and L-03 from Audit #2, plus the addition of the `admin_sweep` instruction.  
**Framework:** Anchor 0.30.1, groth16-solana 0.0.3, light-hasher 4.0.0

---

## Severity Scale

| Level | Definition |
|-------|-----------|
| **CRITICAL** | Funds can be drained or stolen. Immediate exploit path exists. |
| **HIGH** | Significant financial loss possible under realistic conditions. |
| **MEDIUM** | Unexpected behavior or limited financial impact. Exploitable under specific conditions. |
| **LOW** | Best practice violation. No direct exploit but increases attack surface. |
| **INFORMATIONAL** | Code quality, gas optimization, or design notes. No security impact. |

---

## Executive Summary

This is a full re-audit of the DarkDrop V4 program after fixes were applied for findings H-01, M-01, and L-03 from Audit #2. The `admin_sweep` instruction was also added since Audit #2.

**All three targeted fixes are correctly implemented.** H-01 and M-01 (fee_recipient not bound to payer) are resolved by Anchor constraints in both `claim.rs` and `withdraw_credit.rs`. L-03 (event commitment linkage) is resolved by removing the commitment from the `CreditCreated` event.

This full review identified **1 HIGH**, **3 MEDIUM**, **3 LOW**, and **4 INFORMATIONAL** findings. Of these, the HIGH and two MEDIUMs have been **fixed and deployed** during this audit cycle:

- **H-01-NEW (FIXED):** `admin_sweep` rug-pull mitigated via `total_deposited`/`total_withdrawn` obligation tracking.
- **M-02-NEW (FIXED):** `TreasurySweep` event added to `admin_sweep`.
- **M-03-NEW (FIXED):** `amount_commitment` and `password_hash` removed from `DropCreated` event.

The remaining open MEDIUM is **M-01-NEW**: CreditNote PDA stores commitment on-chain, allowing deposit-to-claim linkage during the credit note lifetime window. This is partially mitigated by the M-03-NEW fix.

**No CRITICAL findings.** The core ZK verification, nullifier double-spend prevention, and commitment scheme are correctly implemented.

---

## Fix Verification: H-01, M-01, L-03

### H-01 — Legacy `claim` fee_recipient not bound by ZK proof

**Original finding (Audit #2):** `fee_recipient` was an unchecked account. Any address could collect fees. A man-in-the-middle could replay proofs with their own fee_recipient.

**Fix applied:** `claim.rs:157`
```rust
#[account(mut, constraint = fee_recipient.key() == payer.key())]
pub fee_recipient: UncheckedAccount<'info>,
```

**Verification:** ✅ **CORRECTLY FIXED.** The constraint ensures only the transaction signer (payer) can receive fees. A MITM attacker who intercepts proof data cannot redirect fees because they would need to be the signer. The constraint is enforced at the Anchor account validation level, before any instruction logic runs.

**Residual concern:** The fee_recipient account is now redundant — it must always equal payer. Consider removing it entirely and sending fees directly to the payer account. This simplifies the interface and removes one account from the transaction.

---

### M-01 — `withdraw_credit` fee_recipient not bound to payer

**Original finding (Audit #2):** Same issue as H-01 but in `withdraw_credit`.

**Fix applied:** `withdraw_credit.rs:141`
```rust
#[account(mut, constraint = fee_recipient.key() == payer.key())]
pub fee_recipient: UncheckedAccount<'info>,
```

**Verification:** ✅ **CORRECTLY FIXED.** Identical fix pattern as H-01. Fee diversion by malicious relayers is no longer possible.

---

### L-03 — Event commitment linkage defeats privacy model

**Original finding (Audit #2):** `CreditCreated` event emitted `commitment`, which matched `amount_commitment` in `DropCreated`, creating a direct deposit→claim link.

**Fix applied:** `claim_credit.rs:77-81`
```rust
emit!(CreditCreated {
    nullifier_hash,
    recipient: ctx.accounts.recipient.key(),
    timestamp: credit.created_at,
});
// Commitment deliberately omitted from event to prevent deposit→claim linkage.
```

**Verification:** ✅ **EVENT FIX CORRECT.** The `CreditCreated` event no longer contains the commitment. Event-to-event correlation is eliminated.

**However:** See finding [M-01-NEW] below — the commitment is still readable from CreditNote PDA account data on-chain, creating an alternative linkage vector.

---

## New Findings

### [H-01-NEW] `admin_sweep` can drain treasury while credit notes are outstanding — rug-pull vector

**Severity:** HIGH  
**File:** `instructions/admin_sweep.rs:8-28`

**Description:**

The `admin_sweep` instruction transfers the entire treasury balance (minus rent-exempt minimum) to the vault authority in a single transaction. There is no check for outstanding credit notes. Attack scenario:

```
1. Users deposit 100 SOL total into treasury.
2. Users call claim_credit — credit notes created, nullifiers spent.
   Treasury still holds 100 SOL (claim_credit moves zero SOL).
3. Authority calls admin_sweep — drains 100 SOL to authority wallet.
4. Users call withdraw_credit — fails with InsufficientBalance.
   Users' credit notes are now worthless. Nullifiers are spent.
   Users cannot re-claim because nullifier PDAs already exist.
```

The authority effectively steals all deposited funds. The users have no recourse — their nullifiers are burned and their credit notes point to an empty treasury.

**Impact:** Complete loss of all deposited funds held in credit notes. This is the highest-impact finding because it requires only a single compromised/malicious authority key and a single transaction.

**Why this is worse than Audit #2's M-02 (no timelock):** M-02 noted the lack of a timelock as a general concern. This finding identifies the specific, concrete attack: the credit note model creates a window where deposits are in the treasury but withdrawals haven't happened yet. `admin_sweep` can exploit exactly this window.

**Recommendation (choose one or combine):**

1. **Track outstanding credit note obligations.** Add a `pending_credit_amount: u64` field to the Vault. Increment on `claim_credit` (but amount is private — this is not possible without breaking the privacy model).

2. **Limit sweep to excess balance.** Track `total_deposited` and `total_withdrawn` in the Vault. Only allow sweeping `treasury_balance - (total_deposited - total_withdrawn) - rent`. This acts as a conservative bound.

3. **Add a timelock.** Authority calls `initiate_sweep(amount)`, then must wait N slots (e.g., 1 day on mainnet) before calling `execute_sweep`. Users can withdraw during the delay.

4. **Remove admin_sweep entirely** and accept that stuck funds (legacy sol_vault ~0.2 SOL) are permanently lost. This is the nuclear option but eliminates the rug vector completely.

5. **Multi-sig requirement.** Require 2-of-N signers for sweep operations.

**Note:** Option 1 is fundamentally incompatible with the privacy model (tracking credit amounts reveals them). Option 2 is the most practical — it prevents sweeping funds that haven't been withdrawn yet, without revealing individual amounts.

---

### [M-01-NEW] CreditNote PDA leaks commitment on-chain — L-03 fix incomplete

**Severity:** MEDIUM  
**File:** `instructions/claim_credit.rs:62-66`, `state.rs:143-158`

**Description:**

The L-03 fix correctly removed `commitment` from the `CreditCreated` event. However, the `CreditNote` PDA account stores `commitment: [u8; 32]` as an on-chain field:

```rust
// state.rs
pub struct CreditNote {
    pub bump: u8,
    pub recipient: Pubkey,
    pub commitment: [u8; 32],      // ← still on-chain
    pub nullifier_hash: [u8; 32],
    pub created_at: i64,
}
```

An observer can:
1. Index `DropCreated` events → collect `(leaf_index, amount_commitment)` pairs.
2. Watch for `CreditNote` PDA creations → read `commitment` field from account data.
3. Match `CreditNote.commitment == DropCreated.amount_commitment` → link deposit to claim.

This creates the same deposit→claim linkage that L-03 was meant to eliminate, just via a different data path (account data instead of events).

**Mitigating factor:** The CreditNote PDA only exists between `claim_credit` and `withdraw_credit`. If the user withdraws in the same block or shortly after, the window is small. But an indexer running on an RPC node sees all account writes in real-time.

**Impact:** Privacy degradation. An active observer can link deposits to claims during the credit note lifetime window. This undermines the core privacy proposition of the credit note model.

**Recommendation:**
- Store a *re-randomized* commitment in the CreditNote: `stored = Poseidon(commitment, random_salt)` where `salt` is included in the opening. This breaks the linkage while preserving the verification property. Requires a circuit or instruction change.
- Or accept this as a known limitation and document that users should withdraw immediately after claiming to minimize the exposure window.

---

### [M-02-NEW] `admin_sweep` emits no event — unmonitorable

**Severity:** MEDIUM  
**File:** `instructions/admin_sweep.rs:8-28`

**Description:**

The `admin_sweep` instruction uses `msg!()` for logging but does not emit an Anchor `#[event]`. Anchor events are indexed by RPC providers and can trigger alerts. Without an event, monitoring systems cannot detect sweep operations in real-time.

Combined with H-01-NEW (rug-pull vector), the lack of an event means users and monitoring services have no programmatic way to detect a sweep and rush to withdraw their credit notes.

**Impact:** Reduces the ability to detect and respond to malicious sweep operations.

**Recommendation:** Add an event:
```rust
#[event]
pub struct TreasurySweep {
    pub authority: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}
```

---

### [M-03-NEW] `DropCreated` event still emits `amount_commitment` — linkage source

**Severity:** MEDIUM  
**File:** `instructions/create_drop.rs:52-59`

**Description:**

The `DropCreated` event emits `amount_commitment` and `password_hash`:

```rust
emit!(DropCreated {
    leaf_index,
    leaf,
    amount_commitment,    // ← linkable to CreditNote.commitment
    password_hash,        // ← brute-forceable if weak password
    merkle_root: tree.current_root,
    timestamp: Clock::get()?.unix_timestamp,
});
```

This is the *source side* of the linkage described in M-01-NEW. Even if the CreditNote PDA were fixed, emitting `amount_commitment` in the deposit event provides one half of the correlation data.

Additionally, `password_hash` is a Poseidon hash of the password. If the password space is small (e.g., 4-6 digit PIN), the hash can be brute-forced offline. An attacker who recovers the password can front-run the intended recipient on the legacy `claim` path (the password is a public input in both V1 and V2 circuits).

**Impact:**
- `amount_commitment`: enables deposit→claim linkage (in combination with CreditNote PDA data).
- `password_hash`: enables password brute-forcing for weak passwords.

**Recommendation:**
- Remove `amount_commitment` from `DropCreated` event. The depositor already knows it (they computed it). Indexers don't need it.
- Remove `password_hash` from `DropCreated` event. Same reasoning.
- Keep `leaf_index`, `leaf`, `merkle_root`, and `timestamp` — these are needed for proof generation.

---

### [L-01-NEW] No validation on `drop_cap` in `initialize_vault`

**Severity:** LOW  
**File:** `instructions/initialize.rs:6-13`

**Description:**

Previously reported in Audit #2 as L-01. Still open. `drop_cap` has no minimum or maximum validation. `drop_cap = 0` makes the protocol unusable. `drop_cap = u64::MAX` disables the safety cap.

**Recommendation:** Add `require!(drop_cap > 0 && drop_cap <= 1_000_000_000_000, ...)` (cap at 1000 SOL or similar).

---

### [L-02-NEW] No authority rotation mechanism

**Severity:** LOW  
**File:** `state.rs:52`

**Description:**

Previously reported in Audit #2 as L-02. Still open. The vault authority is immutable after `initialize_vault`. If the authority key is compromised, the only option is program redeployment. Combined with H-01-NEW (`admin_sweep` rug-pull), a compromised authority key is catastrophic with no recovery path.

**Recommendation:** Add `update_authority` with a two-step propose/accept pattern.

---

### [L-03-NEW] Root history zero-initialized — 29 slots contain `[0; 32]`

**Severity:** LOW  
**File:** `instructions/initialize.rs:35`, `state.rs:99-111`

**Description:**

Previously reported in Audit #2 as M-03. Downgraded to LOW after re-analysis.

During `initialize_vault`, only `root_history[0]` is set to the empty-tree root. Slots 1-29 contain `[0; 32]` (zero bytes). The `is_known_root` function iterates all 30 slots on every claim, wasting compute units on zero-byte comparisons.

**Not exploitable:** Producing a valid Groth16 proof against root `[0; 32]` would require breaking Poseidon preimage resistance.

**Recommendation:** Initialize all 30 slots to `ZERO_HASHES[MERKLE_DEPTH]` for cleanliness:
```rust
for i in 0..ROOT_HISTORY_SIZE {
    tree.root_history[i] = ZERO_HASHES[MERKLE_DEPTH];
}
```

---

## Informational Notes

### [I-01] `create_drop` leaf is not verified against deposited amount (design limitation)

Previously reported in Audit #2 as H-02. Re-confirmed as a **design limitation inherent to commitment-scheme mixers**. The program cannot verify `leaf == Poseidon(secret, nullifier, amount, blinding)` because `secret` and `nullifier` are private values. A malicious depositor can construct a leaf committing to a higher amount than deposited, then claim that higher amount from other users' deposits.

This is mitigated by:
- The frontend being the practical deposit interface (constructs honest leaves).
- The treasury balance check preventing claims that exceed total deposits.
- This being a known property of Tornado Cash-style protocols.

**Status:** Accepted as design limitation. Document in user-facing materials.

---

### [I-02] `groth16-solana` crate is pre-release (v0.0.3)

Previously noted in Audit #2. The entire ZK verification depends on this crate. Pin version in `Cargo.lock` and consider vendoring.

---

### [I-03] `poseidon_hash` uses `unwrap()` — panics on failure

**File:** `poseidon.rs:6`

`Poseidon::hashv(&[left, right]).unwrap()` will panic if the hash fails. A Solana program panic causes transaction failure (no state corruption), but returning a proper `Result` would improve diagnostics. Low impact.

---

### [I-04] Redundant `fee_recipient` account after H-01/M-01 fixes

In both `claim.rs` and `withdraw_credit.rs`, the `fee_recipient` account is now constrained to equal `payer`. This makes `fee_recipient` a duplicate account reference. Consider removing it and crediting fees directly to `payer`, which simplifies the transaction and saves one account in the accounts list.

---

## Instruction-by-Instruction Review

### `initialize_vault`

| Check | Result |
|-------|--------|
| Authority is Signer | ✅ `authority: Signer<'info>` |
| Vault PDA derivation | ✅ `seeds = [b"vault"]` |
| Merkle tree PDA derivation | ✅ `seeds = [b"merkle_tree", vault.key()]` |
| Treasury PDA derivation | ✅ `seeds = [b"treasury"]` |
| All accounts use `init` | ✅ Cannot be called twice |
| drop_cap validated | ❌ No min/max check [L-01-NEW] |

### `create_drop`

| Check | Result |
|-------|--------|
| Amount > 0 | ✅ `require!(amount > 0)` |
| Amount <= drop_cap | ✅ `require!(amount <= vault.drop_cap)` |
| SOL transfer via CPI | ✅ `system_program::transfer` (sender → treasury) |
| Sender is Signer | ✅ `sender: Signer<'info>` |
| Vault PDA bump verified | ✅ `bump = vault.bump` |
| Treasury PDA bump verified | ✅ `bump = treasury.bump` |
| Merkle tree capacity check | ✅ `next_index < 2^20` in `merkle_tree_append` |
| total_drops overflow | ✅ `checked_add(1)` |
| Leaf verified against amount | ❌ Not possible (design limitation) [I-01] |
| Event leaks linkable data | ✅ amount_commitment + password_hash removed [M-03-NEW FIXED] |

### `claim` (legacy V1)

| Check | Result |
|-------|--------|
| Amount > 0 | ✅ |
| Amount <= drop_cap | ✅ |
| Fee capped at 5% | ✅ `fee_lamports <= amount / 20` |
| Merkle root in history | ✅ `is_known_root` |
| Groth16 proof verified (V1 VK) | ✅ `verify_proof` with 6 public inputs |
| Recipient bound by proof | ✅ `pubkey_to_field` → public input [3] |
| Nullifier PDA prevents double-spend | ✅ `init` constraint fails if exists |
| Treasury balance >= amount + rent | ✅ `checked_sub(min_balance)` |
| Lamport conservation | ✅ `treasury -= amount`, `recipient += recipient_amount`, `fee += fee_lamports` |
| Fee recipient bound to signer | ✅ `fee_recipient.key() == payer.key()` [H-01 FIXED] |
| Integer overflow in fee | ✅ `checked_sub` for recipient_amount |

### `claim_credit` (V2)

| Check | Result |
|-------|--------|
| Input length validated | ✅ `inputs.len() == 96` |
| Merkle root in history | ✅ `is_known_root` |
| Groth16 proof verified (V2 VK) | ✅ `verify_proof_v2` with 5 public inputs |
| Recipient bound by proof | ✅ `pubkey_to_field` → public input [2] |
| Nullifier PDA prevents double-spend | ✅ `init` constraint |
| CreditNote PDA uniquely derived | ✅ `seeds = [b"credit", nullifier_hash]` |
| Zero SOL moves | ✅ No lamport manipulation |
| Event does not leak commitment | ✅ [L-03 FIXED] |
| CreditNote account leaks commitment | ❌ [M-01-NEW] |
| total_claims overflow | ✅ `checked_add(1)` |

### `withdraw_credit`

| Check | Result |
|-------|--------|
| Opening length validated | ✅ `opening.len() == 40` |
| Recipient matches credit note | ✅ `recipient.key() == credit.recipient` |
| Commitment verified on-chain | ✅ `poseidon_hash == credit.commitment` |
| Amount > 0 | ✅ |
| Fee rate capped at 500 bps | ✅ `rate <= MAX_FEE_RATE` |
| Fee calculation overflow-safe | ✅ Upcast to u128, `checked_mul`, `checked_div` |
| Treasury balance >= amount + rent | ✅ `checked_sub(min_balance)` |
| Lamport conservation | ✅ `treasury -= amount`, `recipient += recipient_amount`, `fee += fee` |
| Fee recipient bound to signer | ✅ `fee_recipient.key() == payer.key()` [M-01 FIXED] |
| CreditNote closed after withdrawal | ✅ `close = payer` |
| CreditNote PDA derivation | ✅ `seeds = [b"credit", nullifier_hash]`, `bump = credit_note.bump` |

### `create_treasury`

| Check | Result |
|-------|--------|
| Authority is Signer | ✅ |
| Vault has_one = authority | ✅ |
| Treasury uses `init` | ✅ Cannot be called twice |
| Treasury PDA derivation | ✅ `seeds = [b"treasury"]` |

### `admin_sweep`

| Check | Result |
|-------|--------|
| Authority is Signer | ✅ |
| Vault has_one = authority | ✅ |
| Treasury PDA verified | ✅ `seeds + bump` |
| Rent-exempt preserved | ✅ `checked_sub(rent_exempt_min)` |
| Sweep amount > 0 | ✅ `require!(sweep_amount > 0)` |
| Lamport conservation | ✅ `treasury -= sweep_amount`, `authority += sweep_amount` |
| Outstanding credit notes checked | ✅ Sweep limited by `total_deposited - total_withdrawn` [H-01-NEW FIXED] |
| Event emitted | ✅ `TreasurySweep` event [M-02-NEW FIXED] |
| Timelock/multi-sig | ❌ None (mitigated by obligation tracking) |

---

## Attack Scenarios Tested

### 1. Rug-pull via admin_sweep + outstanding credit notes
**Result:** Not possible after H-01-NEW fix. `admin_sweep` now limits sweep to `treasury_balance - (total_deposited - total_withdrawn) - rent`. Outstanding credit note obligations are protected.

### 2. Double-spend via nullifier reuse (V1 → V2 or V2 → V1)
**Result:** Not possible. Both `claim` and `claim_credit` derive nullifier PDAs from `[b"nullifier", nullifier_hash]`. Cross-instruction double-spend is prevented.

### 3. Fee diversion by malicious relayer
**Result:** Not possible after H-01/M-01 fixes. `fee_recipient == payer` constraint enforced.

### 4. Frontrunning claim to steal funds
**Result:** Not possible. ZK proof binds to `Poseidon(pubkey_hi, pubkey_lo)`. Different recipient → proof fails.

### 5. Treasury drain via fabricated CreditNote
**Result:** Not possible without knowing `amount` and `blinding_factor`. Poseidon preimage resistance protects the commitment.

### 6. Deposit-to-claim linkage via on-chain data
**Result:** Partially mitigated. `amount_commitment` removed from `DropCreated` event (M-03-NEW fix). CreditNote PDA still stores commitment on-chain (M-01-NEW, open). Linkage now requires reading CreditNote account data and comparing against deposit leaves, which is harder but still possible for an active indexer.

### 7. Integer overflow in fee calculation
**Result:** Not possible. u128 upcast + checked arithmetic. Max product: `100_000_000_000 * 500 = 50_000_000_000_000` (fits u128).

### 8. Replay V1 proof as V2 (or vice versa)
**Result:** Not possible. Different VK, different IC array sizes (7 vs 6 elements).

### 9. PDA seed collision (credit vs nullifier)
**Result:** Not possible. Different prefixes (`b"credit"` vs `b"nullifier"`).

### 10. Drain treasury below rent-exempt minimum
**Result:** Not possible. All three withdrawal paths (`claim`, `withdraw_credit`, `admin_sweep`) subtract `rent.minimum_balance(Treasury::SIZE)` before computing available balance.

### 11. Manipulate `rate` to zero in gasless mode
**Result:** Technically possible — a user submitting directly (not via relayer) can set `rate=0`. This is by design. The relayer protects itself off-chain by refusing to relay low-rate transactions.

### 12. Brute-force password_hash from DropCreated event
**Result:** Not possible after M-03-NEW fix. `password_hash` removed from `DropCreated` event. An attacker would need to read raw Merkle leaves and reverse-engineer the hash, which is infeasible without the leaf preimage.

---

## Summary of All Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| **H-01** (Audit #2) | ~~HIGH~~ | Legacy claim fee_recipient unbound | ✅ **FIXED** — `fee_recipient == payer` constraint |
| **M-01** (Audit #2) | ~~MEDIUM~~ | withdraw_credit fee_recipient unbound | ✅ **FIXED** — `fee_recipient == payer` constraint |
| **L-03** (Audit #2) | ~~LOW~~ | Event commitment linkage | ✅ **FIXED** — commitment removed from CreditCreated |
| **H-01-NEW** | ~~HIGH~~ | admin_sweep drains treasury with outstanding credit notes | ✅ **FIXED** — sweep limited by `total_deposited - total_withdrawn` |
| **M-01-NEW** | MEDIUM | CreditNote PDA leaks commitment on-chain (L-03 incomplete) | **Open** |
| **M-02-NEW** | ~~MEDIUM~~ | admin_sweep emits no event | ✅ **FIXED** — `TreasurySweep` event added |
| **M-03-NEW** | ~~MEDIUM~~ | DropCreated event leaks amount_commitment + password_hash | ✅ **FIXED** — fields removed from event |
| **L-01-NEW** | LOW | No drop_cap validation | **Open** (from Audit #2) |
| **L-02-NEW** | LOW | No authority rotation | **Open** (from Audit #2) |
| **L-03-NEW** | LOW | Root history zero-initialized | **Open** (from Audit #2) |
| **I-01** | INFO | create_drop leaf unverified (design limitation) | Accepted |
| **I-02** | INFO | groth16-solana v0.0.3 pre-release | Noted |
| **I-03** | INFO | poseidon_hash unwrap() panics | Noted |
| **I-04** | INFO | Redundant fee_recipient after fixes | Noted |

---

## Recommendations Priority

### Before Mainnet (Blocking)

1. ~~**[H-01-NEW] Mitigate admin_sweep rug-pull.**~~ **FIXED** — Vault now tracks `total_deposited` and `total_withdrawn`. `admin_sweep` only allows sweeping excess balance beyond outstanding obligations.

2. ~~**[M-03-NEW] Remove `amount_commitment` and `password_hash` from `DropCreated` event.**~~ **FIXED** — Both fields removed. Event now contains only `leaf_index`, `leaf`, `merkle_root`, `timestamp`.

3. ~~**[M-02-NEW] Add event to `admin_sweep`.**~~ **FIXED** — `TreasurySweep` event emitted with `authority`, `amount`, `timestamp`.

### Short-Term

4. **[M-01-NEW] Address CreditNote commitment leakage.** Either re-randomize the stored commitment or document as a known limitation with guidance to withdraw immediately after claiming.

5. **[L-02-NEW] Add authority rotation.** Critical operational safety.

### Medium-Term

6. **[L-01-NEW] Validate drop_cap.** Simple defensive check.
7. **[L-03-NEW] Initialize root history properly.** Saves ~29 wasted comparisons per claim.
8. **[I-04] Remove redundant fee_recipient.** Simplifies transaction structure.

---

## Conclusion

The H-01, M-01, and L-03 fixes from Audit #2 are **correctly implemented**. The fee diversion attack is eliminated and event-level commitment linkage is resolved.

The three new findings from this audit (H-01-NEW, M-02-NEW, M-03-NEW) have also been **fixed and deployed**:

- **H-01-NEW (admin_sweep rug-pull):** Vault now tracks `total_deposited` and `total_withdrawn`. `admin_sweep` only allows sweeping `treasury_balance - (total_deposited - total_withdrawn) - rent_exempt_min`, protecting outstanding credit note obligations.
- **M-02-NEW (no sweep event):** `TreasurySweep` event added with authority, amount, and timestamp fields.
- **M-03-NEW (event leakage):** `amount_commitment` and `password_hash` removed from `DropCreated` event. Only `leaf_index`, `leaf`, `merkle_root`, and `timestamp` remain.

The remaining open finding is **M-01-NEW** (CreditNote PDA stores commitment on-chain, enabling deposit→claim linkage for active indexers during the credit note lifetime window). This is partially mitigated by the M-03-NEW fix (the deposit-side event no longer contains the commitment), but the commitment is still readable from the CreditNote PDA account data.

Overall, the program's core security properties — ZK proof verification, double-spend prevention, commitment binding, access control, and treasury obligation protection — are sound. The remaining open issues are in privacy leakage (commitment correlation via account data) and operational safety (authority rotation).

---

*End of audit report.*
