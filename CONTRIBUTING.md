# Contributing to DarkDrop V4

Thank you for your interest in contributing to DarkDrop. This document covers how to get started, the development workflow, and contribution guidelines.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | 1.87.0+ (stable) | |
| Solana CLI | 1.18+ | Uses `cargo build-sbf` from the SBF toolchain |
| Anchor CLI | 0.30.1 | `anchor build` is broken — see Build section |
| Node.js | 20+ | For scripts, circuits, frontend |
| Circom | 2.2.2 | Only needed for circuit changes |
| snarkjs | 0.7+ | Only needed for circuit changes |

---

## Repository Structure

```
program/          Solana program (Anchor/Rust) — 18 instructions, triple VK (V1/V2/V3)
circuits/         Circom ZK circuits (V2 credit note + V3 note pool) + build artifacts
scripts/          E2E tests, security tests, stress test, migration runbooks
frontend/         Next.js web application (/drop/create, /drop/claim, /drop/manage)
relayer/          Express.js gasless relay server
audits/           4 security audit reports + fix tracker
```

---

## Building the Program

`anchor build` is currently broken due to toolchain issues. Use the `cargo build-sbf` workaround:

```bash
cd program
cargo build-sbf
cp target/sbpf-solana-solana/release/darkdrop.so target/deploy/darkdrop.so
```

For localnet tests that exercise the revoke time-lock, build with the `short-revoke-timeout` feature so the 30-day wait becomes 5 seconds:

```bash
cargo build-sbf --features short-revoke-timeout
```

---

## Running Tests

All test scripts accept `RPC_URL` (defaults to devnet) and `PROGRAM_ID` (defaults to the deployed devnet address).

### Core flow (devnet)

```bash
# Legacy flow (V1 circuit)
node scripts/e2e-test.js

# Credit note flow (V2 circuit) — amount hidden at claim, decorrelated at withdraw
node scripts/e2e-credit-test.js

# Relayer gasless flow
node scripts/relayer-test.js
```

### Security tests (devnet)

```bash
# 6 legacy attack vectors (V1 circuit)
node scripts/security-tests.js

# 7 credit note attack vectors (V2 circuit)
node scripts/security-credit-tests.js

# 4 note pool attack vectors (V3 circuit)
node scripts/note-pool-security-tests.js
```

### Revoke and close_receipt (localnet with short-timeout build)

```bash
# E2E: deposit → wait 5s → revoke → refund
node scripts/revoke-test.js

# 11 attack vectors (6 revoke + 5 close_receipt)
node scripts/security-revoke-tests.js

# E2E: deposit → claim normally → close receipt → rent refunded
node scripts/close-receipt-test.js

# Cross-implementation parity (JS amountToFieldBE ↔ circuit ↔ program u64_to_field_be)
node scripts/revoke-crossimpl-test.js

# Backward compat: 5-account create_drop still works, produces no receipt
node scripts/legacy-create-drop-test.js
```

### Note Pool (recursive privacy)

```bash
# E2E: credit note → deposit to pool → claim fresh note → withdraw
node scripts/note-pool-test.js

# E2E: create_drop_to_pool (one-TX deposit) → claim_from_note_pool → withdraw_credit
node scripts/e2e-pool-deposit-test.js
```

### Schema v2 migration (one-off deploy tooling)

```bash
# Snapshot current on-chain account sizes (MerkleTree, NotePoolTree, Vault)
# and write scripts/migration-baseline.json as a known-good pre-migration reference.
RPC_URL=https://api.devnet.solana.com node scripts/dump-account-sizes.js

# Idempotent runner that reallocates both trees to the new 8912-byte layout
# (ROOT_HISTORY_SIZE=256). Safe to re-run; no-op once already migrated.
RPC_URL=https://api.devnet.solana.com node scripts/migrate-schema-v2.js
```

### Stress and parity

```bash
# 10 deposits, 10 claims, 5 wallets each side
node scripts/stress-test.js

# JS ↔ Rust Poseidon parity check
node scripts/test_poseidon_compat.js
```

---

## Development Workflow

1. **Create a branch** from `main`.
2. **Make changes** to the relevant module.
3. **Build** using `cargo build-sbf` (see above).
4. **Test** against devnet (or localnet for revoke) using the test scripts.
5. **Open a pull request** with a clear description of what changed and why.

### If you change the program

- Rebuild with `cargo build-sbf`.
- Deploy to devnet: `solana program deploy target/deploy/darkdrop.so --program-id <KEYPAIR>`.
- Run all security tests to verify no regressions.
- If you added, removed, or changed an instruction's accounts or arguments, update the hand-written IDL at `program/idl/darkdrop.json` (see IDL Management below).

### If you change the circuit

- Recompile: `circom circuits/darkdrop.circom --r1cs --wasm --sym -o circuits/build/` (or `circuits/note_pool.circom` for V3).
- Run trusted setup (phase 2): `snarkjs groth16 setup build/<name>.r1cs build/pot14_final.ptau build/<name>_final.zkey`.
- Export verification key: `snarkjs zkey export verificationkey build/<name>_final.zkey build/verification_key_<name>.json`.
- Convert to Rust: `node scripts/export_vk_rust.js circuits/build/verification_key_<name>.json`.
- Update `program/programs/darkdrop/src/vk.rs` with the new constants for the corresponding VK (`verifying_key_v1` / `verifying_key_v2` / `verifying_key_v3`).
- Run `scripts/test_poseidon_compat.js` and the relevant E2E script.

### If you change the frontend

- Dev server: `cd frontend && npx next dev`.
- Build: `npx next build`.
- Circuit artifacts must be in `frontend/public/circuits/`:
  - `darkdrop.wasm` (V1/V2 prover, ~2.5 MB)
  - `darkdrop_final.zkey` (V1 proving key, legacy)
  - `darkdrop_v2_final.zkey` (V2 proving key, credit note)
  - `note_pool.wasm` (V3 prover, ~2.5 MB)
  - `note_pool_final.zkey` (V3 proving key, ~5.8 MB)
  The V3 artifacts must be present for MAX PRIVACY (pool) deposits to claim — the browser loads them when it detects a pool-flavored claim code.

---

## Code Style

- **Rust:** Follow standard Rust conventions. Use `cargo fmt` and `cargo clippy`.
- **TypeScript/JavaScript:** Use the existing style in `scripts/` and `relayer/`.
- **Commit messages:** Use imperative mood. Prefix with scope: `program:`, `frontend:`, `circuit:`, `relayer:`, `scripts:`, `docs:`.

---

## Security

- **Do not commit private keys, keypairs, or secrets.** The `.gitignore` excludes common patterns, but double-check before committing.
- **Do not weaken security checks** (remove `require!` statements, relax constraints, etc.) without explicit discussion.
- **If you find a vulnerability**, see [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## IDL Management

The IDL is hand-written with deliberately obfuscated field names (privacy feature). Do not auto-generate it with Anchor — the generated output would restore descriptive names like `amount` and `fee` and defeat the obfuscation.

Source of truth: `program/idl/darkdrop.json` (currently **v0.3.0**).

**Current staleness:** The hand-written IDL (v0.3.0) declares **13 instructions**, but the deployed program binary exposes **18**. The 5 instructions present in the binary but missing from the IDL are pre-existing: `create_treasury`, `admin_sweep`, `migrate_vault`, `revoke_drop`, `close_receipt`. The schema v2 and note-pool sessions added `migrate_schema_v2`, `propose_authority_rotation`, `revoke_authority_rotation`, `accept_authority_rotation`, and `create_drop_to_pool` to the IDL. Block explorers and Anchor-based SDK clients still cannot decode calls to the 5 missing instructions; the frontend hardcodes discriminators instead. See KNOWN ISSUES #9 in [ARCHITECTURE.md](ARCHITECTURE.md).

Fixing this is a deploy-time action: add the missing instructions to `program/idl/darkdrop.json` (preserving obfuscated field names) and upload with `anchor idl upgrade`. If you change any existing instruction's accounts or arguments, you must also manually update the hand-written IDL.

```bash
anchor idl upgrade GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU \
  --filepath program/idl/darkdrop.json \
  --provider.cluster devnet \
  --provider.wallet ~/.config/solana/id.json
```

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
