# DarkDrop V4 — Audit Findings

Date: April 6, 2026
Scope: claim_credit, withdraw_credit, create_drop, deposit relay, fee system

---

## Finding 1: Fee rate uncapped — relayer could steal up to 99.99% of withdrawal

**Severity: HIGH (fixed)**
**Status: FIXED — deployed to devnet**

### The bug

`withdraw_credit` accepts `rate: u16` as a fee in basis points. Before the fix, any value from 0 to 9999 was accepted. The only check was `fee < amount`, which passes for rate=9999 (`fee = amount * 9999 / 10000`).

A malicious relayer could set `rate=9999` in the `withdraw_credit` TX, taking 99.99% of the withdrawal. The recipient would receive only 0.01% — for a 0.1 SOL withdrawal, that's 10 lamports (0.00000001 SOL).

The same issue existed in legacy `claim`: `fee_lamports` could be set to `amount - 1`.

### The fix

**withdraw_credit**: Added `MAX_FEE_RATE = 500` (5%) constant. `rate > MAX_FEE_RATE` now returns `FeeTooHigh`.

**legacy claim**: Changed `fee_lamports < amount` to `fee_lamports <= amount / 20` (5% cap).

### Verification

Deployed to devnet. Security tests (7/7) still pass. Rate=501 rejected, rate=500 accepted.

### Residual risk

The 5% cap is a protocol-level enforcement. A relayer advertising 0.5% that secretly submits rate=500 (5%) would overcharge by 10x. Users should verify the fee in the frontend before approving. In gasless mode, the user doesn't sign — they trust the relayer. But the relayer can only take up to 5% now, not 99.99%.

---

## Finding 2: Treasury rent-exempt minimum is correctly protected

**Severity: N/A (no bug)**
**Status: Already correct**

### Analysis

`withdraw_credit` computes available balance as:
```rust
let min_balance = rent.minimum_balance(Treasury::SIZE);  // ~953,520 lamports
let available = treasury.lamports() - min_balance;
require!(amount <= available, ...);
```

This correctly prevents draining the treasury below rent-exempt minimum. The account cannot be bricked.

However, the rent-exempt minimum (~0.00095 SOL) is permanently locked in the treasury. This is expected — all program-owned accounts on Solana have this property. The amount is negligible.

### Edge case checked

If a user deposits exactly X lamports and then withdraws X lamports, does the rent math work? Yes:
- After deposit: `treasury = rent_min + X`
- Available: `rent_min + X - rent_min = X`
- `X <= X` → passes

No off-by-one.

---

## Finding 3: Claim_credit succeeds but withdraw fails — stuck credit note

**Severity: MEDIUM (known limitation, not fixable without escrow)**
**Status: Documented, accepted**

### The scenario

1. Alice deposits 1 SOL → treasury has `rent + 1 SOL`
2. Alice does `claim_credit` → credit note created, nullifier spent, treasury unchanged
3. Bob deposits 0.5 SOL → treasury has `rent + 1.5 SOL`
4. Bob does legacy `claim` for 0.5 SOL → treasury has `rent + 1.0 SOL`
5. Charlie deposits 0.5 SOL → treasury has `rent + 1.5 SOL`
6. Charlie does `claim_credit` → credit note for 0.5 SOL
7. Alice does `withdraw_credit` for 1.0 SOL → treasury has `rent + 0.5 SOL`
8. Charlie does `withdraw_credit` for 0.5 SOL → treasury has `rent` → succeeds

This works because total deposits (2.0 SOL) >= total withdrawals (2.0 SOL). The Merkle tree + nullifier system ensures each leaf is claimed exactly once, so total claims can never exceed total deposits.

### When it breaks

If the treasury loses funds through a mechanism outside the normal flow (e.g., a bug in a future instruction, or if rent-exempt minimums change), a credit note holder could be stuck. But under normal operation, the math is sound.

### Why not escrow?

Escrowing funds at `claim_credit` time would require moving SOL during the claim — which defeats the purpose (the claim TX would show SOL movement). The credit note model's entire value proposition is that zero SOL moves at claim time.

### Mitigation

The frontend should check `treasury.lamports() - rent_min >= amount` before submitting `withdraw_credit` and warn the user if funds are insufficient. The user can retry later after more deposits.

---

## Finding 4: Merkle tree griefing — filling 1M leaves

**Severity: LOW (economically expensive)**
**Status: Documented, no fix needed**

### The attack

The Merkle tree supports 2^20 = 1,048,576 leaves. An attacker could fill it by calling `create_drop` 1M times with 1 lamport each.

### Cost analysis

- Deposit cost: 1M × 1 lamport = 0.001 SOL (negligible)
- Transaction fees: 1M × ~5,000 lamports = ~5 SOL
- Time: 1M TXs at ~400ms each = ~4.6 days of continuous sending
- Rate limit: Solana's TPS (~400 for a single sender) limits this to ~34M seconds

On devnet this is feasible (airdrop SOL). On mainnet it costs ~5 SOL in fees but would take days and be obvious from the tree growth.

### Mitigation options (not implemented)

1. **Minimum deposit**: Add `require!(amount >= MIN_DEPOSIT, ...)` where MIN_DEPOSIT = 10,000 lamports (0.00001 SOL). Makes filling the tree cost 10 SOL in deposits.
2. **Larger tree**: Increase MERKLE_DEPTH from 20 to 25 (32M leaves). Costs ~160 bytes more in `filled_subtrees` and 5 more Poseidon hashes per insertion.
3. **Dynamic tree**: Create new Merkle trees when full. Adds complexity.

Not fixing because: the current tree handles 1M drops, the attack is expensive on mainnet, and the tree can be upgraded later if needed.

---

## Finding 5: Relayer down — users can do everything directly

**Severity: N/A (by design)**
**Status: Correct**

### Analysis

| Action | With relayer | Without relayer |
|--------|-------------|-----------------|
| create_drop | Relayer calls program | User calls program directly |
| claim_credit | Relayer signs + pays gas | User signs + pays gas |
| withdraw_credit | Relayer signs + pays gas | User signs + pays gas |

The only features that require the relayer are:
- **Gasless claims**: recipient wallet never appears as signer
- **Private deposits**: user wallet never appears in DarkDrop TX

Both are privacy features. Without the relayer, the protocol still functions — users just lose the gasless/private-deposit convenience.

The frontend supports both modes ("Gasless" / "Direct" toggle on claim page, "Direct" / "Private Deposit" toggle on create page). If the relayer is unreachable, the frontend should auto-fallback to direct mode. Currently it does not — **this is a UX improvement to make**, not a security issue.

---

## Finding 6: Deposit relay — SOL at risk if relayer crashes

**Severity: MEDIUM (trust assumption, documented)**
**Status: Documented, accepted**

### The scenario

1. User sends 1 SOL to relayer wallet via `system_program::transfer`
2. Relayer crashes/reboots before calling `create_drop`
3. The 1 SOL is in the relayer's wallet — a normal system-owned account
4. There is no on-chain mechanism to recover it

### Why this is hard to fix on-chain

The deposit relay flow works by having the user send SOL to the relayer's wallet (a normal transfer), then the relayer forwards it to the treasury. This two-step approach is intentional — it makes the deposit TX look like a normal wallet-to-wallet transfer, hiding the user's connection to DarkDrop.

An escrow PDA approach would:
- Create a visible link between the user and DarkDrop (defeating the purpose)
- Require the user to interact with the DarkDrop program (which is what we're trying to avoid)

### Mitigations

1. **Relayer-side idempotency**: Store pending deposit requests in a database. On restart, check for unprocessed deposits and complete them. This is a relayer implementation detail, not a program change.
2. **Confirmation before deposit**: The frontend should wait for the relayer to confirm receipt of the deposit request before sending the SOL transfer. Currently the flow is: send SOL → tell relayer. It should be: tell relayer → relayer says "ready" → send SOL → relayer completes.
3. **Operator recovery**: The relayer operator can always manually call `create_drop` with the lost deposit parameters (stored in server logs).
4. **Small amounts first**: Users trying the private deposit mode for the first time should use small amounts to build trust.

### Honest assessment

This is a trust assumption. The user trusts the relayer operator not to steal the deposit and to complete the flow. This is the same trust model as any custodial bridge or exchange deposit. The risk is mitigated by:
- The deposit relay being optional (direct deposit always works)
- The relayer being open-source (operators can be verified)
- The relayer handling small amounts (drop cap = 100 SOL)

---

## Finding 7: Fee rate of exactly 10000 (100%) — already prevented

**Severity: N/A (already handled pre-fix, now doubly handled)**
**Status: Not a bug**

### Analysis

`rate = 10000` → `fee = amount * 10000 / 10000 = amount` → old check `fee < amount` would have caught it (amount < amount = false). The new `rate <= 500` check catches it much earlier. Both before and after the fix, rate=10000 was rejected.

---

## Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Fee rate uncapped (99.99% steal) | HIGH | **FIXED** — capped at 500 bps (5%) |
| 2 | Treasury rent-exempt correctly protected | N/A | No bug |
| 3 | Stuck credit note if treasury drained | MEDIUM | Documented, inherent to non-escrow design |
| 4 | Merkle tree griefing (1M leaves) | LOW | Economically expensive, documented |
| 5 | Relayer down, direct mode works | N/A | By design |
| 6 | Deposit relay crash loses SOL | MEDIUM | Trust assumption, documented |
| 7 | Rate=10000 already rejected | N/A | No bug |

### Code changes made

1. `withdraw_credit.rs`: Added `const MAX_FEE_RATE: u16 = 500` and `require!(rate <= MAX_FEE_RATE, DarkDropError::FeeTooHigh)`
2. `claim.rs`: Changed `fee_lamports < amount` to `fee_lamports <= amount / 20` (5% cap)
3. Rebuilt and redeployed to devnet
4. All 7/7 security tests still passing
