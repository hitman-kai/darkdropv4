# Security Policy

## Supported Versions

| Version | Cluster | Status |
|---------|---------|--------|
| V4 (current) | Devnet | Active development — security reports welcome |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in DarkDrop, please report it responsibly:

1. **Contact:** Reach the repository maintainer via GitHub private messaging or the contact method listed in the repository profile.
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce or proof of concept
   - Affected instruction(s) and file(s)
   - Suggested severity (Critical / High / Medium / Low)
   - Suggested fix (if any)
3. **Response time:** We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

---

## Scope

The following components are in scope for security reports:

| Component | Location | In Scope |
|-----------|----------|----------|
| Solana program | `program/programs/darkdrop/src/` | Yes |
| Circom circuits (V2 credit note + V3 note pool) | `circuits/darkdrop.circom`, `circuits/note_pool.circom` | Yes |
| Relayer server | `relayer/src/` | Yes |
| Frontend | `frontend/` | Limited (XSS, key exposure) |
| Scripts | `scripts/` | No (test utilities only) |

---

## Known Limitations

The following are **known design limitations**, not vulnerabilities. They are documented in the [audit reports](audits/README.md):

1. **Unverified leaf in `create_drop`:** The program cannot verify that the Merkle leaf matches the deposited amount because the leaf commits to private data (secret, nullifier). This is inherent to commitment-scheme mixers (same class as Tornado Cash). A malicious depositor can construct a dishonest leaf, but exploiting it requires other users' deposits to be in the treasury. The Note Pool (V3) layer eliminates this for pool-deposited credit notes by constructing pool leaves on-chain with a program-verified amount.

2. **Deposit amount is visible:** The `create_drop` instruction uses CPI `system_program::transfer`, which makes the deposit amount visible on-chain. The credit note model hides the amount at claim time and decorrelates at withdraw time, but the deposit itself is public.

3. **Anonymity set grows over time.** Privacy improves as the Merkle tree fills with more deposits. A seeder running on devnet adds 15–30 drops/day; the current leaf count is visible on Solscan for the Merkle Tree PDA.

4. **Deposit relay trust assumption:** Users who use the private deposit relay trust the relayer to complete the `create_drop` call after receiving SOL. If the relayer crashes, the SOL is in the relayer's wallet with no on-chain recovery mechanism.

5. **Deposit-side privacy leak on the revoke path:** Creating a `DepositReceipt` at deposit time establishes a permanent on-chain linkage between the depositor wallet, the leaf, and the amount. This is observable from the moment of deposit, regardless of whether revoke is later exercised or the receipt is closed. Users who prioritize claim privacy should use the legacy 5-account `create_drop` call (no receipt, no revoke). See Audit 04 L-04 for the full analysis.

---

## Security Audits

All audit reports are available in the [`audits/`](audits/) directory. See [`audits/README.md`](audits/README.md) for the full summary table and fix tracker.

| Audit | Date | Scope | Status |
|-------|------|-------|--------|
| [#1 Manual Review](audits/AUDIT-01-MANUAL-REVIEW.md) | 2026-04-06 | Fee system, credit notes, treasury, relay trust | 1 HIGH fixed, 2 MEDIUM accepted, 1 LOW |
| [#2 Code Review](audits/AUDIT-02-CODE-REVIEW.md) | 2026-04-07 | Full instruction-level review, all modules | 2 HIGH fixed, 4 MEDIUM, 4 LOW, 7 INFO |
| [#3 Post-Fix Review](audits/AUDIT-03-POST-FIX-REVIEW.md) | 2026-04-08 | Fix verification + `admin_sweep` + full re-audit | 1 HIGH fixed in-cycle (admin_sweep rug-pull), 3 MEDIUM fixed in-cycle, 3 LOW, 4 INFO |
| [#4 Post-Revoke Review](audits/AUDIT-04-POST-REVOKE.md) | 2026-04-20 | V3 Note Pool + `revoke_drop` + `DepositReceipt` + counter invariants + privacy | 0 CRITICAL, 0 HIGH, 1 MEDIUM fixed in-cycle (orphan receipt), 4 LOW, 4 INFO |

No open HIGH or CRITICAL findings as of Audit 04. DarkDrop has not yet commissioned a third-party firm review — deployment is restricted to Solana devnet.

---

## Security Properties

DarkDrop's security model provides the following guarantees:

| Property | Mechanism | Verified |
|----------|-----------|----------|
| No double-spend | Nullifier PDAs (Anchor `init` fails if exists); shared namespace across `claim_credit` and `revoke_drop` gives mutual exclusion | Audit #1–#4 |
| Recipient binding | ZK proof commits to `Poseidon(pubkey_hi, pubkey_lo)` | Audit #2, #3 |
| Amount integrity | Poseidon commitment verified on-chain at withdrawal | Audit #2, #3 |
| Stored-commitment unlinkability | Re-randomized with caller-supplied salt: `Poseidon(amount_commitment, salt)` | Audit #3 (M-01-NEW) |
| Treasury solvency | Balance check minus rent-exempt minimum on every withdrawal | Audit #1–#3 |
| Obligation-aware admin sweep | Sweep ≤ `treasury − (total_deposited − total_withdrawn) − rent` | Audit #3 (H-01-NEW) |
| Fee cap | 5% maximum enforced on-chain (500 bps) | Audit #1, #3 |
| Proof soundness | Groth16 verification via `groth16-solana` crate (V1/V2/V3 circuits) | Audit #2, #4 |
| Revoke authorization | Preimage-verified leaf reconstruction; 30-day time-lock; depositor-signed; shares nullifier namespace with claim | Audit #4 |
