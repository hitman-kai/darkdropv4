# DarkDrop V4 — Security Audit #6: Deep Scan, Post-SPL

**Program ID:** `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU`
**Audit date:** May 25, 2026
**Scope:** Fresh re-walk of the full repository at HEAD with no inherited findings. Focus on surfaces added or modified since Audit #5: the SPL/multi-mint extension (10 new instructions), relayer V3 proof handling, and the gasless trust boundary at `claim_credit`. Re-verification of audited surfaces was performed but only new, reproducible findings are listed below.
**Prior audits:** #1 (Apr 6), #2 (Apr 7), #3 (Apr 8), #4 (Apr 20), #5 (Apr 24, 2026)
**Framework:** Anchor 0.30.1, groth16-solana 0.0.3 (pinned), light-hasher 4.0.0, anchor-spl 0.30.1.
**Method:** Source-level adversarial review against the threat model in `SECURITY.md`. No fuzzing, no formal verification, no on-chain execution — pure static review of the working tree.

---

## Severity Scale

| Level | Definition |
|-------|-----------|
| **CRITICAL** | Funds can be drained or stolen. Immediate exploit path. |
| **HIGH** | Significant financial loss possible under realistic conditions. |
| **MEDIUM** | Unexpected behavior, fund availability impact, or trust-boundary erosion. Exploitable under specific conditions. |
| **LOW** | Best-practice violation or maintainability hazard. No direct exploit. |
| **INFORMATIONAL** | Code-quality, doc, or design note. No security impact. |

---

## Executive Summary

Audit #6 walked the full repository fresh and produced findings that are reproducible in the current source tree. None of the items below appear in Audits #1–#5 in the same form.

The SPL/multi-mint extension (lib.rs:188-294 — 10 new instructions) preserves the core invariants from the SOL flow: nullifier mutex, obligation-aware sweep, direct-CPI custody via the Vault PDA. The audit-credibility risk on this surface is not a fund-loss bug; it is **structural completeness**. The relayer cannot today verify the V3 proofs it relays — not because the call is missing, but because the verification key and verifier function for V3 do not exist in `relayer/src/verify.ts` at all. That is `M-01` below and supersedes any prior framing of the pool-claim-relay gap as a one-line fix.

A new fund-availability hazard appears on the gasless claim trust boundary: the user-supplied `salt` at `claim_credit` is not bound to the V2 proof. A malicious relayer can rewrite it freely, and the user's withdraw will fail unless their client reads `credit.salt` from on-chain rather than from local storage. This is `M-02` — recoverable via on-chain inspection, but the recovery path is not documented and the frontend does not appear to use it.

`initialize_vault` retains no constraint on who calls it. First-caller wins authority. On a fresh deploy this is a race condition between the deployer and any watcher of new program deployments; only mitigated by sequencing deploy and initialize in a single atomic context (`M-03`).

The Token program binding on the SPL extension excludes Token-2022 (`M-04`). Several maintainability hazards (`L-01` to `L-04`) materially raise the chance of a future regression: dead instruction parameters, an O(N) root scan, duplicated safety-critical helpers, and a hardcoded compute-unit budget.

**Findings:** 0 CRITICAL · 0 HIGH · **4 MEDIUM** · **4 LOW** · **3 INFORMATIONAL**.

---

## Findings

### [M-01] Relayer has no V3 verification key or verifier function — pool-claim path cannot be hardened without first building one

**Severity:** Medium
**Files:**
- `relayer/src/verify.ts:14-16` — only `VK_V1` and `VK_V2` loaded
- `relayer/src/verify.ts:166-183` — `verifyClaimProofV2` defined; no `verifyClaimProofV3`
- `relayer/src/routes/pool-claim.ts:51-122` — relays V3 proofs with no off-chain validation
- `circuits/build/note_pool/` — V3 verification key file exists but is never imported by the relayer

**Description.**

`relayer/src/verify.ts` loads exactly two verification keys at module init:

```ts
const VK_V1 = require("../../circuits/build/verification_key.json");
const VK_V2 = require("../../circuits/build/verification_key_v2.json");
```

It exports `verifyClaimProofV1` and `verifyClaimProofV2`. There is no `VK_V3` constant and no `verifyClaimProofV3` function. The note-pool relay endpoint at `relayer/src/routes/pool-claim.ts:51-122` accepts V3 proofs and submits them on-chain without any off-chain check. There is no path to add one without first wiring V3 support through `verify.ts` (load the V3 VK, expose a V3 verifier function, adapt the same proof-format conversions `g1NegFromBytes` / `g2FromBytes`).

**Impact.**

Gas-drain DoS against the relayer's keypair. Each junk V3 proof costs the relayer signature + compute-budget fees. Existing `express-rate-limit` middleware (`relayer/src/index.ts`) caps the rate per IP but does not protect against distributed sources. No user funds are at risk; the on-chain V3 verifier still rejects bad proofs.

The V2 endpoint (`relayer/src/routes/credit.ts:90-96`) does pre-verify, so this is a missed parallel, not a stylistic choice.

**Fix.**

1. Load `verification_key.json` from the V3 ceremony output into `relayer/src/verify.ts`:
   ```ts
   const VK_V3 = require("../../circuits/build/note_pool/verification_key.json");
   ```
2. Add `verifyClaimProofV3(proofA, proofB, proofC, publicInputs)` mirroring `verifyClaimProofV2`. Public-input order: `[pool_merkle_root, pool_nullifier_hash, new_stored_commitment, recipient_hash]`.
3. Call it from `pool-claim.ts` before TX construction; return HTTP 400 on failure.

**Status:** Open.

---

### [M-02] `claim_credit` salt parameter is not bound to the V2 proof — gasless relayer can substitute it and cause withdraw failure

**Severity:** Medium (fund-availability, recoverable only via on-chain inspection)
**Files:**
- `program/programs/darkdrop/src/instructions/claim_credit.rs:23,64-71` — handler takes `salt` as instruction data and stores it on `credit.salt`
- `program/programs/darkdrop/src/instructions/withdraw_credit.rs:33` — withdraw reads salt from the user-supplied `opening`, not from `credit.salt`
- `relayer/src/routes/credit.ts:67,120-122,124-133` — relayer reads salt from request body and forwards verbatim
- V2 circuit `circuits/darkdrop.circom` — public-input vector has 5 elements: merkle_root, nullifier_hash, recipient, amount_commitment, password_hash. Salt is absent.

**Description.**

At V2 claim time, the on-chain handler computes:

```rust
let stored_commitment = poseidon_hash(&amount_commitment, &salt);
```

where `salt` arrives as a standalone instruction argument. The V2 circuit does not include salt in its public inputs, so the relayer (who signs and submits the TX in gasless mode) can swap the user-supplied salt for any 32-byte value of their choosing before submission. The Groth16 verifier accepts.

At withdraw time, the user must supply `(amount, blinding, salt)` in their `opening`. The handler recomputes `Poseidon(Poseidon(amount, blinding), salt) == credit.commitment`. If the salt the user supplies differs from what's in `credit.commitment`, withdraw fails with `CommitmentMismatch`.

The on-chain credit account stores `credit.salt = salt` at claim time (claim_credit.rs:71), so the actual salt used is recoverable by reading the credit account. But `withdraw_credit.rs:33` deliberately reads the salt from the user's `opening` Vec — not from `credit.salt`. The on-chain field is purely advisory; the user must know the right salt.

The frontend's claim-code stores the salt the user generated locally. If a relayer substituted, the locally-stored salt is the wrong one. Withdraw fails. Recovery requires the user (or their client) to read `credit.salt` from chain and use that value in the opening.

**Impact.**

Two distinct concerns:

1. **Fund availability under malicious relayer.** A misbehaving or compromised relayer can break every claim it relays by emitting a fresh salt per TX. Users see a confirmed `claim_credit` on devnet but the subsequent `withdraw_credit` reverts. Recovery requires manual inspection of `credit.salt` — not documented, and the frontend's `vault.ts` / `proof.ts` flow does not consult it.
2. **Privacy regression.** A relayer that picks deterministic salts can correlate their relayed deposits to their relayed claims via the salt they chose, partially defeating the M-01-NEW (Audit 03) unlinkability property for relayer-mediated flows.

Neither leads to direct fund theft. Severity capped at Medium because the on-chain state is the source of truth and the salt is recoverable.

**Fix.**

Two options.

(A) **Make withdraw read from `credit.salt`.** Cleanest. Remove salt from the `opening` layout and read it from the loaded `credit_note` instead:

```rust
let amount = u64::from_le_bytes(opening[0..8].try_into().unwrap());
let blinding_factor: [u8; 32] = opening[8..40].try_into().unwrap();
// salt is now read from credit_note, not from caller
let original = poseidon_hash(&amount_bytes, &blinding_factor);
let computed = poseidon_hash(&original, &credit.salt);
```

This trusts the on-chain stored salt regardless of who set it. It removes the relayer's ability to brick the withdraw. Trade-off: opening shrinks from 72 to 40 bytes; this is a breaking client-API change.

(B) **Bind salt into the V2 proof.** Add `salt` as a 6th public input to the V2 circuit. The relayer can no longer substitute because that would break verification. Trade-off: V2 circuit redesign + new phase-2 ceremony + IDL bump.

Option A is the lower-risk fix; the salt's only job is to break commitment linkage at the indexer layer, which any honest relayer-chosen value also accomplishes.

**Status:** Open.

---

### [M-03] `initialize_vault` has no constraint on which signer becomes authority — first-caller-after-deploy wins

**Severity:** Medium (deployment-process hazard; mitigated by atomic deploy+init in practice)
**File:** `program/programs/darkdrop/src/instructions/initialize.rs:7-49, 51-88`

**Description.**

```rust
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(init, payer = authority, space = Vault::SIZE, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    // ...
    #[account(mut)]
    pub authority: Signer<'info>,
    // ...
}
```

The handler then assigns:

```rust
vault.authority = ctx.accounts.authority.key();
```

There is no whitelist, no upgrade-authority check, no "deployer is recorded in a sidecar" pattern. Any signer that lands the first successful `initialize_vault` TX on a freshly deployed program owns the vault forever (modulo the new rotation path in Audit 05).

**Impact.**

On a clean program deploy, if the deployer does not initialize in the same transaction context (or in a tightly-sequenced follow-up TX they alone can win), a watcher monitoring `BPFLoaderUpgradeable` program-creation events can race the `initialize_vault` call. The winner becomes `vault.authority` and gains `admin_sweep`, `pause_deposits`, and (after the 24h time-lock) authority rotation rights.

The deployed `GSig1...kfAgkU` program has long since been initialized, so this is not exploitable today. It is a hazard on every future fresh deploy (devnet redeploy, mainnet bring-up). The 24-hour `ROTATION_DELAY` added in Audit 05 mitigates the recovery window if it does happen — but only if the legitimate deployer still holds the upgrade authority for the program itself, which they would.

**Fix.**

Either:

1. **Constrain `authority` to a hardcoded pubkey at the program level.** Brittle (changes on each redeploy).
2. **Require `initialize_vault` to be CPI'd from a trusted bootstrap program.** Heavy.
3. **Accept the risk and document the requirement** that deploy + initialize must be atomic, with a runbook in `CONTRIBUTING.md` and a `scripts/initialize.js` that fires immediately after deploy.

Option 3 is the proportionate fix. The existing `Anchor.toml` and migration scripts arguably already imply this, but it is not stated as a security invariant anywhere.

**Status:** Open.

---

### [M-04] SPL extension is bound to legacy SPL Token; Token-2022 mints fail at account validation with a non-informative error

**Severity:** Medium (functional gap that will increasingly bite as Token-2022 adoption grows; not a vulnerability)
**Files:**
- `program/programs/darkdrop/src/instructions/create_drop_spl.rs:2,192` — `use anchor_spl::token::{...Token...}; pub token_program: Program<'info, Token>`
- `program/programs/darkdrop/src/instructions/withdraw_credit_spl.rs:2,225`
- `program/programs/darkdrop/src/instructions/admin_sweep_spl.rs:2,139`
- `program/programs/darkdrop/src/instructions/initialize_mint_vault.rs` (constrains `mint: Account<'info, Mint>` to legacy Mint deserialization)
- `program/programs/darkdrop/src/instructions/create_drop_to_pool_spl.rs` (same)

**Description.**

Every SPL instruction imports `anchor_spl::token::{Mint, Token, TokenAccount, Transfer}`. The `Program<'info, Token>` constraint locks the token program id to `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (legacy SPL Token). The `Account<'info, Mint>` and `Account<'info, TokenAccount>` constraints additionally lock to the legacy account schema.

A Token-2022 mint (program id `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`) deserialized as `Mint` will fail because Token-2022 accounts carry extensions appended past the base Mint layout, and the owner field will not match the legacy program id. The Anchor failure is `AccountOwnedByWrongProgram` or `ConstraintTokenMint` — neither of which tells an integrator "your mint uses Token-2022."

**Impact.**

Two compounding effects:

1. **Functional exclusion.** A growing share of mainstream SPL mints (interest-bearing stablecoins, transfer-fee variants of USDC, future stablecoin issuance using Token-2022 extensions) cannot be registered with the program at all. As Token-2022 adoption grows, more candidate mints fail.
2. **Latent privacy hazard if the binding ever changes.** Token-2022's `TransferFeeConfig` extension reduces the amount delivered relative to the amount transferred. The current pool-leaf construction in `create_drop_to_pool_spl` uses the CPI-supplied `amount` to build the leaf. If a future commit relaxes the Token constraint to also accept Token-2022 without auditing the transfer-fee interaction, the on-chain leaf would commit to the pre-fee amount while the vault would receive the post-fee amount — creating a real dishonest-leaf reintroduction on the pool layer that Audit 04 I-01 had closed for the legacy path.

The first effect is a feature gap. The second is a latent regression risk that should be locked down explicitly even if Token-2022 support is never added.

**Fix.**

If Token-2022 support is not planned: leave the binding as-is but add a tiny `require!(mint_info.owner == &spl_token::ID, MintNotRegistered)` style guard with a clearer error (or rename the existing `MintNotRegistered` variant message to mention Token-2022 explicitly). Update `ARCHITECTURE.md` to state the binding decision.

If Token-2022 support is planned: this becomes a separate design-and-audit effort. Use `anchor_spl::token_interface` types instead, and add explicit Token-2022 transfer-fee accounting on every ingress path so the pool leaf reflects the amount actually credited to the vault.

**Status:** Open (functional gap; no immediate action required if scope stays legacy-only).

---

### [L-01] `create_drop` accepts `_amount_commitment` and `_password_hash` parameters that are completely ignored

**Severity:** Low (maintainability; misleads the threat-model reader)
**File:** `program/programs/darkdrop/src/instructions/create_drop.rs:19-25`

**Description.**

```rust
pub fn handle_create_drop<'info>(
    ctx: Context<'_, '_, '_, 'info, CreateDrop<'info>>,
    leaf: [u8; 32],
    amount: u64,
    _amount_commitment: [u8; 32],
    _password_hash: [u8; 32],
) -> Result<()>
```

Both `_amount_commitment` and `_password_hash` are received in instruction data, occupy 64 bytes per call, and are then thrown away. The Merkle leaf is what binds them indirectly — the V2 circuit's leaf preimage includes the amount/password — but the program never validates the supplied bytes against anything.

A reader auditing the instruction surface naturally asks: "what protects against a mismatch between supplied `_amount_commitment` and the leaf's encoded commitment?" The answer is "nothing, because the program never reads it." That answer is correct but not visible from the handler signature, which actively misleads.

**Impact.**

No security impact (the V2 proof binds the real commitment at claim time). Real impact is on future modifications: an engineer adding amount validation in `create_drop` would naturally reach for these existing parameters and add a `require!` against the supplied bytes — but those bytes are caller-controlled and unbound, so any such check is a no-op. The shape of the API invites incorrect tightening.

**Fix.**

Drop both parameters from the handler signature and from the IDL. They are pure noise.

If keeping them is required for IDL stability with old clients (unlikely — they're already `_`-prefixed and ignored), add a one-line comment block explaining why they exist and why no validation against them is meaningful.

**Status:** Open.

---

### [L-02] `is_known_root` is an O(ROOT_HISTORY_SIZE) linear scan on every claim and revoke

**Severity:** Low (performance / future-scaling hazard)
**Files:**
- `program/programs/darkdrop/src/state.rs:137-147` (`MerkleTreeAccount::is_known_root`)
- `state.rs:258-268` (`NotePoolTree::is_known_root`)
- `state.rs:426-438` (`MerkleTreeSpl::is_known_root`)
- `state.rs:463-475` (`NotePoolTreeSpl::is_known_root`)

**Description.**

Every root-validating instruction (`claim`, `claim_credit`, `claim_from_note_pool`, `revoke_drop`, and their SPL parallels) walks the entire 256-entry `root_history` array linearly:

```rust
pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
    if *root == self.current_root {
        return true;
    }
    for i in 0..ROOT_HISTORY_SIZE {
        if self.root_history[i] == *root {
            return true;
        }
    }
    false
}
```

At ROOT_HISTORY_SIZE = 256, this is 256 × 32-byte comparisons. The schema v2 bump from 30 → 256 (Audit 05) increased this by 8.5x. Compute-unit budget is fine today, but the cost grows linearly if the history is ever extended further (e.g., to handle higher devnet throughput or longer claim-code lifespans).

**Impact.**

Today: negligible. ~5–10k CU per is_known_root call; well within the 400k budget.

Future: if you ever want claim codes that remain verifiable for months rather than weeks (the obvious next ask), you bump ROOT_HISTORY_SIZE again. At, say, 4096, this becomes meaningful (~80–160k CU). It also competes for the same budget as Groth16 verification.

The same structure also costs read I/O — 256 entries × 32 bytes = 8 KiB read per claim. With four trees on a SPL-multi-mint deployment, this is non-trivial pressure on the SVM's account-loading paths.

**Fix.**

Two options.

1. **Early exit on first ZERO_HASHES sentinel.** After initialization, every unused slot holds `ZERO_HASHES[MERKLE_DEPTH]`. The handler could short-circuit if it encounters that sentinel before finding a match. Saves work in the steady-state but doesn't bound worst-case.
2. **Switch to a tree-indexed-position lookup.** `root_history_index` tells you where the most recent root was written; walk backward from there for at most `ROOT_HISTORY_SIZE` slots and stop at the first wrap or sentinel. Same worst case but better average case.

A real fix (constant-time set membership via Bloom filter or per-root account) is overkill; option 1 is the pragmatic move.

**Status:** Open.

---

### [L-03] Safety-critical helpers `pubkey_to_field` and `u64_to_field_be` are duplicated inline across 5+ instruction files instead of being shared

**Severity:** Low (drift risk on the Poseidon binding and amount encoding — the two most security-critical reductions in the program)
**Files:**
- `pubkey_to_field`: `claim.rs:104-111`, `claim_credit.rs:96-103`, `claim_credit_spl.rs:122-129`, `claim_from_note_pool.rs:98-105` — four byte-for-byte copies
- `u64_to_field_be`: `withdraw_credit.rs:121-125`, `revoke_drop.rs:118-122`, `claim.rs:114-118`, `deposit_to_note_pool.rs:96-100`, `create_drop_to_pool.rs:103-107`, `withdraw_credit_spl.rs:148-152` — six byte-for-byte copies

**Description.**

Both helpers implement load-bearing reductions:
- `pubkey_to_field` is the on-chain mirror of the V2/V3 circuit's recipient binding (`Poseidon(hi_128, lo_128)`).
- `u64_to_field_be` is the on-chain mirror of the JS `amountToFieldBE` and the circuit's amount encoding.

If they diverge from the circuit's encoding, every claim flow fails with `InvalidProof`. Worse, a bug introduced in one copy but not another can create asymmetric behavior where some ingress paths verify and others do not — extremely confusing to debug.

The justification comments in `claim_credit_spl.rs` and `withdraw_credit_spl.rs` explicitly state the duplication is intentional ("file does not depend on internal items of claim_credit.rs (which is audited code we choose not to touch)"). This decision optimizes for short-term audit isolation at the cost of a long-term divergence hazard. Six copies of a 5-line function is a high enough count that even disciplined maintenance is fragile.

**Impact.**

No current bug. Real impact is the next edit. A future change to `pubkey_to_field` (e.g., adding a domain-separation tag — see I-01 below) requires synchronizing five files. Forgetting one silently breaks one of the five claim paths.

**Fix.**

Move both helpers into `program/programs/darkdrop/src/poseidon.rs` (or a `program/programs/darkdrop/src/util.rs`). Replace all six call sites. The implementation is identical; this is a mechanical refactor.

**Status:** Open.

---

### [L-04] Hardcoded 400_000 CU budget in `pool-claim.ts` — no headroom for verifier or runtime regressions

**Severity:** Low
**File:** `relayer/src/routes/pool-claim.ts:108-110`

**Description.**

```ts
const tx = new Transaction().add(
  ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
  ix,
);
```

The compute-unit limit is hardcoded. V3 Groth16 verification on Solana sits around 200–300k CU today; 400k is reasonable headroom. But this is the only operational knob on the relayer side, and it is buried in route code rather than `config.ts`.

A future upgrade to `groth16-solana`, a Solana runtime CU repricing, or any pre-verifier work the relayer adds (e.g., when M-01 is fixed) could push the V3 verification cost over 400k. The next signal would be on-chain TX failures with `ComputeBudgetExceeded`, with the relayer still paying the failed-TX fee.

**Impact.**

Operational brittleness. No security exposure.

**Fix.**

Move to `relayer/src/config.ts`:

```ts
poolClaimComputeBudget: parseInt(process.env.POOL_CLAIM_CU || "400000", 10),
```

Apply same treatment to `relayer/src/routes/credit.ts` where the same hardcoded value appears for V2 verification (line 150).

**Status:** Open.

---

### [I-01] No domain separation on Poseidon usage; recipient/amount/commitment hashes share the same Poseidon parameters

**Severity:** Informational
**Files:**
- `program/programs/darkdrop/src/poseidon.rs:5-19` — `poseidon_hash`, `poseidon_hash_1`, `poseidon_hash_4` all dispatch to `Poseidon::hashv(...)` with no tag
- All call sites (recipient binding, commitment construction, pool-leaf construction, nullifier hashing)

**Description.**

The on-chain Poseidon helpers do not include a domain-separation tag. `Poseidon::hashv(&[hi, lo])` is used for `Poseidon(pubkey_hi, pubkey_lo)` (recipient), `Poseidon(amount, blinding)` (commitment), and `Poseidon(commitment, salt)` (re-randomization) — all with the same parameters and arity.

Concretely: if an attacker can ever choose an `amount_commitment` value `c` and a `salt` value `s` such that `Poseidon(c, s) == Poseidon(hi, lo)` for some valid `(hi, lo)` corresponding to a pubkey of theirs, they could swap roles between contexts. The probability of this happening at random is 2^-254 (negligible), and the structured construction (commitments come from circuit-produced values; salts come from CSPRNG) makes deliberate construction very hard. So the practical risk is zero. But it is the kind of decision that benefits from being explicit rather than implicit.

Other Solana-deployed mixers (Light Protocol's compressed-token primitives, for example) prefix each hash domain with a tagged constant.

**Impact.**

None today. Documentation / hardening only.

**Fix recommendation.**

If you ever revisit the V2/V3 circuits for another reason (e.g., L-07 ceremony in a future audit), consider adding a 1-element domain prefix to each Poseidon call:

```rust
pub fn poseidon_recipient(hi: &[u8; 32], lo: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[&DOMAIN_RECIPIENT, hi, lo]).unwrap()
}
```

with matching circuit changes. Not worth a ceremony rotation on its own.

**Status:** Open (advisory).

---

### [I-02] `migrate_vault.rs` reads authority via a hardcoded byte offset; `unwrap()` will panic if the account is too small

**Severity:** Informational (one-shot migration; effectively non-reachable on the deployed devnet program)
**File:** `program/programs/darkdrop/src/instructions/migrate_vault.rs:21-25`

**Description.**

```rust
let vault_data = vault_info.try_borrow_data()?;
let stored_authority = Pubkey::try_from(&vault_data[9..41]).unwrap();
```

The offset `9` assumes Anchor's account layout is `[8-byte discriminator | 1-byte bump | 32-byte authority | ...]`. That assumption is correct for the current Vault struct, but it is pinned only by audit memory — there is no compile-time check that `bump` is the first field after the discriminator.

If `vault_info.data.len() < 41`, the slice `&vault_data[9..41]` panics with index out of bounds. The migration is gated by `vault_data.len() < Vault::SIZE` later (line 30), but that check happens after the slice, so a vault with `len() < 41` panics before reaching the size check.

**Impact.**

The deployed vault has been migrated since well before Audit 05; this instruction is now effectively dead code. Re-execution returns `AlreadyMigrated`. No live program state can trigger the panic path.

Risk is purely on a future fresh devnet redeploy that re-runs `migrate_vault` against an undersized vault account. That requires either a hand-crafted migration order or a deploy bug — neither realistic.

**Fix.**

If `migrate_vault.rs` is being kept in the source tree at all, replace the panicking `unwrap()` with a fallible `ok_or(DarkDropError::InvalidAccountSize)?` and add an explicit `require!(vault_data.len() >= 41, ...)` ahead of the slice.

Alternatively, since this is one-shot legacy code, mark it `#[deprecated]` and consider removing it in the next breaking program upgrade.

**Status:** Open.

---

### [I-03] `processed-txs.ts` dedup is keyed on transaction signature, not on nullifier hash — does not protect against junk-proof gas drain

**Severity:** Informational (documents a limitation; not a new bug)
**File:** `relayer/src/processed-txs.ts:54-65`

**Description.**

The dedup store keys on TX signature:

```ts
export function hasProcessedTx(sig: string): boolean { return sig in cache; }
export function markProcessed(sig: string) { ... }
```

It is used by `relayer/src/routes/deposit.ts` to prevent the relayer from being charged twice when a user retries a signed deposit transaction. It is not a defense against attackers spamming the same nullifier_hash with different proofs (which is what off-chain proof pre-verification handles — see M-01), and it does not deduplicate at the nullifier layer.

The naming and 24-hour TTL imply broader applicability than the store actually delivers.

**Impact.**

None. Worth flagging because future engineers reading "we have a dedup layer" might over-attribute its protection.

**Fix recommendation.**

Comment block above the exported API stating: "this dedups deposit-TX retries by signature. It does not dedupe claims by nullifier; on-chain nullifier PDA is the source of truth for double-spend prevention."

**Status:** Open (advisory).

---

## Cross-Layer Verification Sweep

The following were re-walked from source. No findings beyond what is listed above.

| Surface | Verification |
|---|---|
| Nullifier mutex (`claim_credit` ↔ `revoke_drop`) | Both `init` `[b"nullifier", hash]`; first to land wins. ✓ |
| Per-mint nullifier namespace | `[b"nullifier_spl", mint, hash]` distinct prefix from SOL. ✓ |
| Treasury direct-lamport debit | Vault PDA owns treasury account; lamport math via `checked_sub`. ✓ |
| Obligation accounting on `admin_sweep` | `treasury_balance − (total_deposited − total_withdrawn) − rent`. ✓ |
| Obligation accounting on `admin_sweep_spl` | Per-mint via `MintConfig.total_deposited − total_withdrawn`; no global cross-leak. ✓ |
| Pause kill-switch | Only checked at SPL deposit paths; never gates exits. ✓ |
| Authority rotation time-lock | 24-hour `ROTATION_DELAY` enforced in `accept`. ✓ (Audit 05 fix) |
| Mint vault custody | `token::authority = vault` set at `initialize_mint_vault`; Vault PDA signs all outbound transfers. ✓ |
| Fee cap | `MAX_FEE_RATE = 500` in withdraw paths; `amount / 20` in legacy claim. ✓ |
| Direct lamport credit on `recipient` `UncheckedAccount` | Bound by ZK proof's `recipient_hash`; substitution by relayer breaks verification. ✓ |
| Receipt close auth | Explicit `require_keys_eq!` (does not rely on Anchor `close =`). ✓ |
| `processed-txs.ts` retry semantics | Confirmed (see I-03). |
| Frontend claim-code transmission | Pasted via textarea; not URL-encoded; not transmitted to any server during decode. ✓ |
| Committed secrets | None; `.gitignore` covers `.env*`, `*.keypair.json`, `target/`, `node_modules/`. ✓ |

---

## Re-verification of Audit #5 Open Items

| Item | Status |
|---|---|
| Audit 05 L-02 (`migrate_schema_v2` emits no event) | Still open. Not re-flagged here — same finding. |
| Audit 05 L-03 (`create_drop_to_pool` no revoke option) | Still open by design. Note pool's revoke gap is a deliberate scope decision; documented in SECURITY.md. |
| Audit 05 I-01 (`deposit_to_note_pool` doc-comment misdescribes leaf hash) | Still open. The comment at `deposit_to_note_pool.rs:12-14` still says "2-level hash tree"; the code is a single `poseidon_hash_4`. |
| Audit 05 I-02 (`migrate_schema_v2` invariant comment) | Still open. |
| Audit 05 I-03 (`groth16-solana 0.0.3` pin) | Still pinned. No upstream 0.0.4. |

These are tracked in `audits/AUDIT-05-SCHEMA-V2-AND-POOL-DEPOSIT.md` and `audits/README.md`. Audit #6 does not re-file them.

---

## Recommendations Priority

1. **M-02** — fix `withdraw_credit` to read salt from `credit.salt` instead of from caller-supplied `opening`. Removes a class of relayer-side fund-availability attack, single-file change, no ceremony required.
2. **M-01** — wire V3 verification into `relayer/src/verify.ts` and call it from `pool-claim.ts`. Eliminates the gas-drain DoS on the only un-pre-verified relay endpoint.
3. **M-03** — document the deploy+init atomicity requirement in `CONTRIBUTING.md` (`scripts/initialize.js` already exists if this can be wrapped). One paragraph + a one-line check at the top of the script that exits if the vault PDA is already initialized by someone unexpected.
4. **L-03** — factor `pubkey_to_field` and `u64_to_field_be` to `poseidon.rs` / `util.rs`. Mechanical refactor; closes a drift hazard before it bites.
5. **L-01** — drop the dead `_amount_commitment` / `_password_hash` parameters from `create_drop`. IDL touchup.
6. **L-04** — move the relayer's CU budgets to `config.ts`.
7. **M-04** — decide explicitly whether Token-2022 is in scope and document. Either tighten the error message or plan a Token-2022 design pass.
8. **L-02** — `is_known_root` micro-optimization. Defer until ROOT_HISTORY_SIZE is bumped further.
9. **I-01, I-02, I-03** — advisory; batch into a docs-and-hardening commit.

---

## Deployment Recommendation

No findings block continued devnet operation. The deployed program at `GSig1...kfAgkU` is sound as of this audit.

**M-02** is the highest-leverage fix because it changes a real user-visible failure mode under realistic gasless-relayer conditions, and the fix is small. Land it before next devnet promotion.

**M-03** is a deployment-runbook fix, not a code fix. Address it before any redeploy or mainnet bring-up.

**L-07 from prior audit framing (multi-party trusted setup ceremony)** is still the mainnet-blocking item. Audit #6 does not re-walk it; the README's ceremony documentation is unchanged.

---

*End of Audit #6.*
