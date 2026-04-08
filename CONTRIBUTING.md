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
program/          Solana program (Anchor/Rust)
circuits/         Circom ZK circuits + build artifacts
scripts/          E2E tests, security tests, utilities
frontend/         Next.js web application
relayer/          Express.js gasless relay server
audits/           Security audit reports
```

---

## Building the Program

`anchor build` is currently broken due to toolchain issues. Use the `cargo build-sbf` workaround:

```bash
cd program
cargo build-sbf
cp target/sbpf-solana-solana/release/darkdrop.so target/deploy/darkdrop.so
```

---

## Running Tests

### Security tests (devnet)

```bash
# Legacy security tests (6 tests)
node scripts/security-tests.js

# Credit note security tests (7 tests)
node scripts/security-credit-tests.js
```

### E2E tests (devnet)

```bash
# Legacy flow
node scripts/e2e-test.js

# Credit note flow (V2 circuit)
node scripts/e2e-credit-test.js

# Relayer flow
node scripts/relayer-test.js
```

All test scripts require `RPC_URL` environment variable (defaults to devnet).

---

## Development Workflow

1. **Create a branch** from `main`.
2. **Make changes** to the relevant module.
3. **Build** using `cargo build-sbf` (see above).
4. **Test** against devnet using the test scripts.
5. **Open a pull request** with a clear description of what changed and why.

### If you change the program

- Rebuild with `cargo build-sbf`.
- Deploy to devnet: `solana program deploy target/deploy/darkdrop.so --program-id <KEYPAIR>`.
- Run all security tests to verify no regressions.
- If you changed instruction accounts or arguments, update the hand-written IDL at `program/target/idl/darkdrop.json`.

### If you change the circuit

- Recompile: `circom darkdrop.circom --r1cs --wasm --sym`.
- Run trusted setup (phase 2): `snarkjs groth16 setup darkdrop.r1cs pot14_final.ptau darkdrop_v2.zkey`.
- Export verification key: `snarkjs zkey export verificationkey darkdrop_v2.zkey verification_key_v2.json`.
- Convert to Rust: `node scripts/export_vk_rust.js`.
- Update `program/programs/darkdrop/src/vk.rs` with the new constants.
- Run circuit tests: `cd circuits && npm test`.

### If you change the frontend

- Dev server: `cd frontend && npx next dev`.
- Build: `npx next build`.
- Circuit artifacts must be in `frontend/public/circuits/`.

---

## Code Style

- **Rust:** Follow standard Rust conventions. Use `cargo fmt` and `cargo clippy`.
- **TypeScript/JavaScript:** Use the existing style in `scripts/` and `relayer/`.
- **Commit messages:** Use imperative mood. Prefix with scope: `program:`, `frontend:`, `circuit:`, `relayer:`, `scripts:`, `docs:`.

---

## Security

- **Do not commit private keys, keypairs, or secrets.** The `.gitignore` excludes common patterns, but double-check before committing.
- **Do not weaken security checks** (remove require! statements, relax constraints, etc.) without explicit discussion.
- **If you find a vulnerability**, see [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## IDL Management

The IDL is hand-written with deliberately obfuscated field names (privacy feature). Do not auto-generate the IDL with Anchor. If you change instruction parameters, manually update `program/target/idl/darkdrop.json` and redeploy with:

```bash
anchor idl upgrade GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU \
  --filepath target/idl/darkdrop.json \
  --provider.cluster devnet \
  --provider.wallet ~/.config/solana/id.json
```

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
