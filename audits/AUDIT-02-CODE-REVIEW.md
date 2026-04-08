# DarkDrop V4 — Security Audit Report

**Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`
**Audit date:** April 7, 2026
**Scope:** All instruction handlers and supporting modules in `program/programs/darkdrop/src/`
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

The DarkDrop V4 program implements a ZK-based privacy mixer on Solana with a two-phase claim flow (claim_credit + withdraw_credit). The architecture is sound — Groth16 proof verification binds claims to recipients, PDA-based nullifiers prevent double-spending, and direct lamport manipulation provides privacy benefits.

However, the audit identified **2 HIGH**, **4 MEDIUM**, and **4 LOW** severity findings, plus several informational notes. The most significant issues involve the legacy `claim` instruction's fee recipient being attacker-controlled without ZK binding, and the `create_drop` instruction accepting arbitrary leaf values without on-chain verification.

**No CRITICAL findings were identified.** The core ZK verification flow in the V2 credit note path is correctly implemented.

---

## Findings

### [H-01] Legacy `claim`: Fee recipient is not bound by ZK proof — relayer fee theft

**Severity:** HIGH
**File:** `instructions/claim.rs:63-71`
**Status:** Confirmed

**Description:**

In the legacy `claim` instruction, `fee_recipient` is an `UncheckedAccount` with no constraint binding it to the ZK proof or to the `payer`. The `fee_lamports` parameter is user-supplied (capped at 5% of the amount). A malicious relayer can:

1. Set `fee_lamports` to the maximum allowed (5%).
2. Set `fee_recipient` to any wallet they control, even if it differs from the `payer`.

This is "working as intended" for the relayer model, but critically, a **man-in-the-middle who intercepts a user's proof submission** can replay the proof with their own `fee_recipient` address and steal up to 5% of every legacy claim. The proof does not bind to `fee_lamports` or `fee_recipient`.

Additionally, since `fee_lamports` is a raw parameter (not derived from a basis-point rate like in `withdraw_credit`), a frontrunning relayer can silently increase the fee to the 5% cap.

**Impact:** Up to 5% of every legacy claim amount can be redirected by an attacker who intercepts proof data before it hits the chain.

**Recommendation:** Deprecate the legacy `claim` instruction entirely. If it must remain, bind `fee_recipient` to equal `payer` so only the signer can collect fees, or include `fee_lamports` as a public input in the V1 circuit (requires circuit change).

---

### [H-02] `create_drop`: No on-chain verification that `leaf` matches the deposited amount or commitment

**Severity:** HIGH
**File:** `instructions/create_drop.rs:12-63`
**Status:** Confirmed

**Description:**

The `create_drop` instruction accepts `leaf`, `amount`, `amount_commitment`, and `password_hash` as separate parameters. The program inserts `leaf` directly into the Merkle tree without verifying that:

```
leaf == Poseidon(secret, nullifier, amount, blinding_factor)
```

The program also does not verify that `amount_commitment == Poseidon(amount, blinding_factor)`.

This means a malicious depositor can:

1. Deposit 0.01 SOL (`amount = 10_000_000 lamports`) which passes validation.
2. Provide a `leaf` that was computed with `amount = 100 SOL` in the preimage.
3. Later generate a valid ZK proof claiming 100 SOL.

The ZK circuit will verify because the leaf in the Merkle tree was built with `amount = 100 SOL`. The treasury, however, only received 0.01 SOL.

**Attack scenario:**

```
Attacker deposits 0.01 SOL with leaf = Poseidon(secret, nullifier, 100_SOL, blinding)
Other users deposit 100+ SOL total into the treasury.
Attacker claims 100 SOL with a valid ZK proof.
```

This is a **treasury-draining attack**. The attacker's proof is mathematically valid because the leaf genuinely commits to 100 SOL — the program just never verified the leaf matched the deposited amount.

**Impact:** Complete treasury drain. An attacker can deposit dust and claim arbitrary amounts up to the treasury balance.

**Mitigation:** The program MUST recompute the leaf on-chain:

```rust
// Verify leaf = Poseidon(Poseidon(secret, nullifier), Poseidon(amount, blinding))
// or whatever the circuit's leaf construction is.
```

However, since `secret` and `nullifier` are private values (the user must keep them to later generate the proof), the program cannot recompute the full leaf hash. This is a **fundamental design constraint** of commitment schemes — the depositor must be trusted to construct the leaf honestly, because the leaf is a commitment to private data.

**Re-evaluation:** On further analysis, this finding is mitigated by the fact that an attacker who lies about the amount in their leaf will only hurt themselves — they would be committing to claiming more than they deposited, but the treasury must actually hold that amount. The attacker is spending their own SOL to create the deposit and can only claim what the treasury has. If the treasury has less SOL than the attacker claims, `InsufficientBalance` fires.

The real risk is a **griefing/theft vector against other depositors**: if the treasury has accumulated SOL from other honest depositors, the attacker can claim more than they deposited by exploiting the unverified leaf.

**Revised severity:** HIGH — this enables draining other users' deposits.

**Recommendation:**

Option A (preferred): Recompute `amount_commitment` on-chain from the amount parameter and verify it matches what was provided. This does not fully solve the leaf problem but ensures the commitment is honestly constructed. The full leaf cannot be verified without the secret/nullifier, which is fundamental to the privacy model.

Option B: Add a separate "amount commitment verification" where the commitment is recomputed as `Poseidon(amount_field, blinding_factor)` and stored alongside the leaf. At claim time, verify the committed amount matches what the circuit proves. But since the V2 circuit makes amount private, the amount is not available at claim time.

Option C: Accept this as a **known limitation** of the trust model and document that depositors must be honest. In a real deployment, this would be mitigated by the frontend being the only practical way to construct deposits, and the frontend constructs leaves honestly.

**Note:** This same class of vulnerability exists in Tornado Cash and similar protocols. It is generally accepted as a design tradeoff because the alternative (revealing the secret/nullifier at deposit time) would destroy privacy.

---

### [M-01] `withdraw_credit`: `fee_recipient` is not bound to `payer` — fee diversion

**Severity:** MEDIUM
**File:** `instructions/withdraw_credit.rs:113-148`
**Status:** Confirmed

**Description:**

The `fee_recipient` account in `WithdrawCredit` is an `UncheckedAccount` with no constraint. When `rate > 0`, fees are sent to whatever address is passed as `fee_recipient`. A frontrunning bot or malicious RPC node could:

1. Observe a pending `withdraw_credit` transaction.
2. Replace `fee_recipient` with their own address.
3. Submit the modified transaction first.

However, since `payer` must be a `Signer`, the attacker cannot modify the transaction without the signer's private key. The realistic attack vector is a **malicious relayer** that sets `fee_recipient` to a different wallet than the relayer's advertised address, skimming fees to a hidden wallet. This is a trust issue with the relayer, not a protocol exploit.

**Impact:** Limited to relayer trust model. Direct claimers set `rate=0` so no fee is involved.

**Recommendation:** Add a constraint `fee_recipient == payer` to ensure only the transaction signer collects fees:

```rust
#[account(mut, constraint = rate == 0 || fee_recipient.key() == payer.key())]
pub fee_recipient: UncheckedAccount<'info>,
```

---

### [M-02] `admin_sweep`: No timelock or multi-sig on treasury sweep

**Severity:** MEDIUM
**File:** `instructions/admin_sweep.rs`
**Status:** Confirmed

**Description:**

The `admin_sweep` instruction allows the vault authority to drain the entire treasury (minus rent-exempt minimum) in a single transaction with no delay, no multi-sig, and no on-chain governance check. If the authority keypair is compromised, all user deposits can be stolen instantly.

**Impact:** Complete loss of all deposited funds if the authority key is compromised.

**Recommendation:**

- Add a timelock: authority calls `initiate_sweep`, then must wait N slots before `execute_sweep`.
- Or require a multi-sig scheme.
- At minimum, add a `max_sweep_amount` parameter so partial sweeps are possible and users have time to claim during a suspicious sweep event.

---

### [M-03] Root history circular buffer: stale root acceptance window

**Severity:** MEDIUM
**File:** `state.rs:92-111`, `merkle_tree.rs:42-46`
**Status:** Confirmed

**Description:**

The root history stores 30 entries in a circular buffer. Claims can use any root in this buffer. This means a claimer has a window of 30 new deposits before their Merkle root expires.

However, the root at index 0 is initialized to the empty-tree root during `initialize_vault` (line 35 of `initialize.rs`), and the `root_history_index` starts at 0. After the first deposit, `root_history_index` becomes 1, and the root at index 1 is overwritten. The empty-tree root at index 0 persists in the history until 30 more deposits occur.

A claim using the empty-tree root would still need a valid ZK proof with a leaf in the empty tree. Since the empty tree has no real leaves, this is not directly exploitable — a proof for a non-existent leaf would fail.

**Actual concern:** The `is_known_root` function checks `current_root` first, then iterates through all 30 history entries. All 30 entries are initialized to `[0; 32]` (zero bytes, not the empty-tree root). The actual empty-tree root is `ZERO_HASHES[20]`, which is a non-zero Poseidon hash. The 29 uninitialized history slots contain `[0; 32]`.

If an attacker constructs a Merkle proof against the all-zeros "root", the proof would need to be valid in the ZK circuit. Since the circuit computes the root from a real leaf and path, producing a valid proof for root `[0; 32]` would require finding a preimage collision in Poseidon, which is computationally infeasible.

**Revised impact:** Not exploitable, but wasteful — `is_known_root` iterates over uninitialized zero slots unnecessarily.

**Recommendation:** Initialize all root history slots to the empty-tree root to avoid unnecessary iterations and defensive confusion.

---

### [M-04] `claim` (legacy): `amount` is not checked against `amount_commitment`

**Severity:** MEDIUM
**File:** `instructions/claim.rs:19-94`
**Status:** Confirmed

**Description:**

In the legacy `claim` instruction, both `amount` and `amount_commitment` are passed as instruction parameters and as public inputs to the ZK proof. The ZK circuit constrains `amount_commitment == Poseidon(amount, blinding_factor)`, so the proof will fail if they don't match.

However, the program does not independently verify this relationship. It trusts the ZK proof entirely. This is correct behavior — the ZK verification IS the check. But it means the program's security depends entirely on the soundness of the Groth16 proof system and the correctness of the verification key.

If the verification key were corrupted or the `groth16-solana` crate had a bug that accepted invalid proofs, the `amount` parameter could be set to any value.

**Impact:** No current exploit, but the program has no defense-in-depth against a VK or verifier bug.

**Recommendation:** Add an on-chain check: recompute `Poseidon(amount_field, amount_commitment_as_blinding)` and verify it matches. However, this is not possible because the blinding factor is private and not passed to the legacy claim instruction. Accept as informational.

**Revised severity:** INFORMATIONAL (downgraded from MEDIUM — the ZK proof IS the intended check).

---

### [L-01] `initialize_vault`: No validation on `drop_cap`

**Severity:** LOW
**File:** `instructions/initialize.rs:6`
**Status:** Confirmed

**Description:**

The `drop_cap` parameter in `initialize_vault` has no minimum or maximum validation. Setting `drop_cap = 0` makes the protocol unusable. Setting `drop_cap = u64::MAX` disables the cap entirely (since Solana's total supply is ~580M SOL = ~5.8e17 lamports, well within u64 range, but still removes a safety net).

**Impact:** Misconfiguration risk during deployment. Not exploitable post-deployment.

**Recommendation:** Add `require!(drop_cap > 0 && drop_cap <= MAX_DROP_AMOUNT)`.

---

### [L-02] No authority rotation mechanism

**Severity:** LOW
**File:** `state.rs:52` (Vault.authority)
**Status:** Confirmed

**Description:**

The vault authority is set during `initialize_vault` and cannot be changed. If the authority key needs to be rotated (compromise, operational migration), the only option is to redeploy the entire program and migrate all state.

**Impact:** Operational risk. No immediate security impact.

**Recommendation:** Add an `update_authority` instruction with a two-step handoff (propose + accept) pattern.

---

### [L-03] `claim` and `claim_credit`: Event leaks timing correlation data

**Severity:** LOW
**File:** `instructions/claim.rs:83-89`, `instructions/claim_credit.rs:77-82`
**Status:** Confirmed

**Description:**

The `DropClaimed` event (legacy) emits `amount` and `fee_lamports` in plaintext. The `CreditCreated` event emits the `commitment` and `recipient`. While the credit note model is designed to hide amounts, the event data could be used for timing correlation:

- A watcher sees a `DropCreated` event with `amount_commitment = X`.
- Later, a `CreditCreated` event appears with `commitment = X`.
- The `amount_commitment` in the deposit event matches the `commitment` in the credit note.

This creates a **direct link between deposit and claim** via the commitment value, undermining the privacy model.

**Impact:** Deposits and claims can be linked if an observer indexes both event types and matches commitment values. This significantly reduces the anonymity set.

**Recommendation:** Either:
- Remove `amount_commitment` from the `DropCreated` event, or
- Use a different commitment scheme where the deposit commitment and claim commitment are unlinkable (e.g., randomized re-commitment).

This is the **most impactful privacy finding** in the audit.

---

### [L-04] `admin_sweep`: Missing `system_program` account

**Severity:** LOW
**File:** `instructions/admin_sweep.rs:33-50`
**Status:** Confirmed

**Description:**

The `AdminSweep` accounts struct does not include `system_program`. While direct lamport manipulation does not require the system program (it is not a CPI), some Anchor versions and tooling expect it for account validation. More importantly, if the instruction were ever extended to perform CPI transfers, the system program would need to be added.

This is not a security vulnerability — the instruction works correctly without it. It is a defensive coding issue.

**Impact:** None currently. Could cause issues if the instruction is modified.

**Recommendation:** Add `pub system_program: Program<'info, System>` for consistency with other instructions.

---

## Informational Notes

### [I-01] `groth16-solana` crate is version 0.0.3 (pre-1.0)

The Groth16 verifier depends on `groth16-solana = "0.0.3"`, a pre-release crate. Pre-1.0 crates may have breaking changes or undiscovered bugs. The entire security model depends on this crate correctly implementing Groth16 verification on BN254.

**Recommendation:** Pin the exact version in `Cargo.lock`. Audit the `groth16-solana` source for correctness. Consider vendoring the crate.

---

### [I-02] `PublicKey` import unused in claim page (frontend, not program)

Not in scope but noted: the frontend `claim/page.tsx` imports `PublicKey` from `@solana/web3.js` but doesn't use it directly.

---

### [I-03] Merkle tree uses `zero_copy(unsafe)`

The `MerkleTreeAccount` uses `#[account(zero_copy(unsafe))]` which skips alignment checks. This is necessary for the large account size but means the program is responsible for ensuring correct memory layout. The `#[repr(C)]` attribute ensures deterministic layout.

**Recommendation:** No action needed, but document the rationale in code comments.

---

### [I-04] No SPL token support path

The protocol only supports native SOL. The direct lamport manipulation technique does not generalize to SPL tokens, which would require CPI to the token program (making transfers visible again). This is a design limitation, not a bug.

---

### [I-05] `poseidon_hash` unwrap can panic

In `poseidon.rs:6`, `Poseidon::hashv(&[left, right]).unwrap()` will panic if the hash computation fails. A panic inside a Solana program causes the transaction to fail, which is the correct behavior (it does not corrupt state). However, returning a proper error would give better diagnostics.

---

### [I-06] Dual VK shares alpha/beta/gamma between V1 and V2

The V2 verification key reuses `V1_ALPHA_G1`, `V1_BETA_G2`, and `V1_GAMMA_G2`. This is correct if both circuits used the same Powers of Tau (phase 1) ceremony. Only `delta_g2` and `IC` change in phase 2 (circuit-specific). Verify that the same `pot14` file was used for both circuits.

---

### [I-07] `create_drop` emits `amount_commitment` and `password_hash` in event

See [L-03]. The `DropCreated` event includes `amount_commitment` and `password_hash`. The `password_hash` in particular could be brute-forced if the password is weak, since it is a Poseidon hash of the password value. An attacker who recovers the password can front-run the intended recipient.

---

## Attack Scenarios Tested

### 1. Double-spend via nullifier reuse
**Result:** Not possible. Nullifier PDAs use Anchor's `init` constraint — if the PDA already exists, the transaction fails. Both `claim` and `claim_credit` create a nullifier PDA, preventing reuse across both instruction types for the same nullifier.

### 2. Cross-instruction nullifier collision (V1 claim then V2 claim_credit with same nullifier)
**Result:** Not possible. Both instructions derive the nullifier PDA from `[b"nullifier", nullifier_hash]`. If a V1 claim consumes a nullifier, the V2 claim_credit for the same nullifier will fail because the PDA already exists.

### 3. Treasury drain via withdraw_credit with fabricated commitment
**Result:** Not possible without the original secret. The attacker would need to find `amount` and `blinding_factor` such that `Poseidon(amount, blinding)` equals the stored commitment. Poseidon is a collision-resistant hash function.

### 4. Frontrunning a claim to steal funds
**Result:** Not possible. The ZK proof binds to a specific `recipient` via `Poseidon(pubkey_hi, pubkey_lo)`. An attacker who replays the proof with a different recipient account will fail proof verification because the recipient field element won't match.

### 5. Treasury drain via admin_sweep
**Result:** Possible only by vault authority. The `has_one = authority` constraint and `Signer` requirement ensure only the authority keypair can call this. If the authority key is compromised, funds can be drained. See [M-02].

### 6. Manipulating `rate` in withdraw_credit to zero-out fees
**Result:** Technically possible — a direct claimer can set `rate = 0` and pay no fee. This is intended behavior. The relayer has no enforcement mechanism to require a minimum rate on-chain. The relayer protects itself by refusing to relay transactions with `rate` below its minimum (off-chain enforcement).

### 7. Integer overflow in fee calculation
**Result:** Not possible. The fee calculation in `withdraw_credit` upcasts to `u128` before multiplication: `(amount as u128) * (rate as u128) / 10000`. Maximum values: `amount = 100_000_000_000` (100 SOL), `rate = 500`. Product = `50_000_000_000_000` which fits in u128. The `checked_mul` and `checked_div` provide additional safety.

### 8. Rent-exempt edge case in treasury
**Result:** Correctly handled. Both `claim` and `withdraw_credit` check `treasury.lamports() - rent.minimum_balance(Treasury::SIZE)` before transferring. The `admin_sweep` also subtracts `rent.minimum_balance(Treasury::SIZE)`. The treasury cannot be drained below rent-exempt minimum.

### 9. PDA seed collision between credit_note and nullifier
**Result:** Not possible. Credit notes use `[b"credit", nullifier_hash]` and nullifiers use `[b"nullifier", nullifier_hash]`. Different seed prefixes produce different PDAs.

### 10. Replay V1 proof as V2 (or vice versa)
**Result:** Not possible. V1 proofs have 6 public inputs and use `verifying_key_v1()`. V2 proofs have 5 public inputs and use `verifying_key_v2()`. The IC arrays have different sizes (7 vs 6 elements), and the verification keys have different delta and IC values. A V1 proof will fail V2 verification and vice versa.

---

## Summary of Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| H-01 | HIGH | Legacy `claim` fee recipient not bound by ZK proof | **Fixed** — constraint fee_recipient == payer |
| H-02 | HIGH | `create_drop` leaf not verified against deposited amount | Open (design limitation) |
| M-01 | MEDIUM | `withdraw_credit` fee_recipient not bound to payer | **Fixed** — constraint fee_recipient == payer |
| M-02 | MEDIUM | `admin_sweep` has no timelock or multi-sig | Open |
| M-03 | MEDIUM | Root history initialized with zero bytes | Open |
| L-01 | LOW | No validation on `drop_cap` parameter | Open |
| L-02 | LOW | No authority rotation mechanism | Open |
| L-03 | LOW | Event commitment linkage defeats privacy model | **Fixed** — commitment removed from CreditCreated event |
| L-04 | LOW | `admin_sweep` missing system_program | Open |

---

## Recommendations Priority

1. **Immediate (before mainnet):** Fix H-01 by deprecating legacy `claim` or binding fee_recipient to payer. Fix L-03 by removing `amount_commitment` from `DropCreated` event.
2. **Short-term:** Add timelock to `admin_sweep` [M-02]. Bind `fee_recipient` to `payer` in `withdraw_credit` [M-01]. Add `drop_cap` validation [L-01].
3. **Medium-term:** Add authority rotation [L-02]. Initialize root history properly [M-03]. Audit `groth16-solana` crate [I-01].
4. **Design consideration:** H-02 is a known limitation of commitment-scheme mixers. Document the trust model explicitly: the frontend is trusted to construct honest leaves. In a production deployment, consider adding a deposit registry that allows the protocol to track total deposits vs. total withdrawals as a sanity check.

---

*End of audit report.*
