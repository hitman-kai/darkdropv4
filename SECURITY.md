# Security Policy

## Supported Versions

| Version | Cluster | Status |
|---------|---------|--------|
| V4 (current) | Devnet | Active development — security reports welcome |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in DarkDrop, please report it responsibly:

1. **Email:** Send details to the repository maintainer via GitHub private messaging or the contact method listed in the repository profile.
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
| Circom circuits | `circuits/darkdrop.circom` | Yes |
| Relayer server | `relayer/src/` | Yes |
| Frontend | `frontend/` | Limited (XSS, key exposure) |
| Scripts | `scripts/` | No (test utilities only) |

---

## Known Limitations

The following are **known design limitations**, not vulnerabilities. They are documented in the [audit reports](audits/README.md):

1. **Unverified leaf in `create_drop`:** The program cannot verify that the Merkle leaf matches the deposited amount because the leaf commits to private data (secret, nullifier). This is inherent to commitment-scheme mixers (same class as Tornado Cash). A malicious depositor can construct a dishonest leaf, but exploiting it requires other users' deposits to be in the treasury.

2. **Deposit amount is visible:** The `create_drop` instruction uses CPI `system_program::transfer`, which makes the deposit amount visible on-chain. The credit note model hides the amount at claim time and decorrelates at withdraw time, but the deposit itself is public.

3. **Small anonymity set:** The Merkle tree currently has ~22 leaves on devnet. Privacy improves as the tree grows with more deposits.

4. **Deposit relay trust assumption:** Users who use the private deposit relay trust the relayer to complete the `create_drop` call after receiving SOL. If the relayer crashes, the SOL is in the relayer's wallet with no on-chain recovery mechanism.

---

## Security Audits

All audit reports are available in the [`audits/`](audits/) directory:

| Audit | Date | Key Findings |
|-------|------|-------------|
| [#1 Manual Review](audits/AUDIT-01-MANUAL-REVIEW.md) | April 6, 2026 | Fee rate uncapped (FIXED) |
| [#2 Code Review](audits/AUDIT-02-CODE-REVIEW.md) | April 7, 2026 | Fee recipient unbound (FIXED), event linkage (FIXED) |
| [#3 Post-Fix Review](audits/AUDIT-03-POST-FIX-REVIEW.md) | April 8, 2026 | admin_sweep rug-pull vector (OPEN) |

---

## Security Properties

DarkDrop's security model provides the following guarantees:

| Property | Mechanism | Verified |
|----------|-----------|----------|
| No double-spend | Nullifier PDAs (Anchor `init` fails if exists) | Audit #1, #2, #3 |
| Recipient binding | ZK proof commits to `Poseidon(pubkey_hi, pubkey_lo)` | Audit #2, #3 |
| Amount integrity | Poseidon commitment verified on-chain at withdrawal | Audit #2, #3 |
| Treasury solvency | Balance check minus rent-exempt minimum on every withdrawal | Audit #1, #2, #3 |
| Fee cap | 5% maximum enforced on-chain (500 bps) | Audit #1, #3 |
| Proof soundness | Groth16 verification via `groth16-solana` crate | Audit #2 |
