# Observer Response — On-Chain Amount Visibility

**Date:** 2026-05-04
**Subject:** On-chain balance-delta visibility flagged on 2026-05-01

---

## What you observed

You pointed out that DarkDrop's deposit and withdrawal transactions reveal SOL amounts via the standard `preBalances` / `postBalances` fields in transaction metadata. With matching amounts and timing, an outside observer can correlate a deposit with a subsequent withdrawal, partially defeating sender↔recipient unlinkability for variable-amount drops.

You are correct.

## What's actually happening on Solana

The leak is at the runtime layer, not the program layer. Solana's transaction metadata exposes `preBalances` and `postBalances` for every account in every transaction. Solscan and other explorers compute their "SOL Balance Change" panels directly from these fields. No program — including DarkDrop — can suppress them. Direct lamport manipulation (which we already use to avoid the inner-`system_program::transfer` decode) hides the *instruction-level* "Transfer" decode but leaves the balance delta visible.

This is not a DarkDrop-specific weakness:

- **Privacy Cash** ($190M+ historical volume, four audits) has the exact same leak. From their public docs: *"observers may still make educated guesses by analyzing on-chain activity (for example, via SolScan) if a unique amount is deposited and the same amount is withdrawn shortly afterward."*
- **Tornado-Nova / Railgun** architectures on Ethereum hide more because Ethereum doesn't surface per-account balance deltas the same way. On Solana with native SOL, the platform reveals them.
- **Token-2022 Confidential Transfers** would hide amounts between confidential SPL accounts but still leak at the wrap/unwrap boundaries to native SOL. The underlying ZK ElGamal Proof Program has been disabled on mainnet since June 2025; we don't depend on it.

For variable-amount **native SOL** drops on Solana, the only way to hide amounts at the explorer level is to route through an MPC-shielded layer (Arcium / Umbra) — a different security model than DarkDrop's pure-ZK approach, with months-long integration effort.

## What we changed in response

We did **not** ship a "fix" that pretends to hide amounts — that would be privacy theater. We did three things:

### 1. Privacy claim reframe

Documentation across `README.md`, `ARCHITECTURE.md`, and the in-app `/docs` page has been rewritten to match what we actually deliver: **deposit↔claim graph unlinkability via mixing**, not amount-privacy at boundaries. We explicitly acknowledge the boundary leak as a Solana platform constraint. The previous wording overstated the property; we own that and corrected it.

### 2. Stealth-recipient pattern at claim (new code, this branch)

The claim flow now defaults to landing SOL at a fresh single-use stealth address rather than the recipient's main wallet. The recipient's main wallet pays gas and signs the claim, but the on-chain claim TX names the stealth pubkey as the recipient. The recipient sweeps the stealth address to their main wallet from `/drop/manage` at a time of their choosing.

Effect on outside observers:
- Recipient's main wallet is **not** publicly tagged as the recipient on the claim TX itself.
- The sweep TX (stealth → main) is a separate, timing-decoupled transaction the recipient can mix with other wallet activity.
- The deposit→withdraw amount correlation still survives at the global level, but the per-wallet identity correlation at the claim moment is broken.

### 3. Anonymity-set indicator in the UI

Both `/drop/create` and `/drop/claim` now show the current size of the deposit + pool anonymity set (Tornado-style: weak / moderate / reasonable). Users can make informed decisions about whether the set is large enough for their threat model before depositing or claiming. We say plainly: *sender↔recipient unlinkability scales with this count. Boundary amounts remain visible — Solana platform constraint.*

## What's on the roadmap, not in this fix

A true UTXO-shielded-pool architecture (Privacy-Cash-style, BN254/Groth16/Poseidon, on our own crypto stack) is the right long-term direction for amount unlinkability via graph mixing. This is approximately 6–8 weeks of circuit + program + ceremony + audit work. It is post-Colosseum-Frontier work, not part of this response. We are not waiting on any third-party Solana primitive (ZK ElGamal Proof Program, Confidential Balances, etc.) — the entire architecture stays under our own control.

## Honest scope of current claims

- ✅ **Sender↔claim graph unlinkability** via Groth16 + Poseidon-commitment Merkle mixing.
- ✅ **Recipient identity decoupling** at claim via stealth-recipient pattern (default ON).
- ✅ **Anonymity-set transparency** in the UI.
- ❌ **Not claimed:** amount privacy at deposit boundary.
- ❌ **Not claimed:** amount privacy at withdrawal boundary.
- ❌ **Not claimed:** protection against an observer with full chain analysis when the anonymity set is small.

If you find anything misstated above, or any remaining piece of UI or docs that overstates beyond this list, please flag it. The intent of this branch is to close the gap between what we say and what we deliver, not to patch over it.
