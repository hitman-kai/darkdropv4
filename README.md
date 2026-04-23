# DarkDrop V4

Unlinkable value transfer on Solana. DarkDrop uses Groth16 zero-knowledge proofs and an incremental Merkle tree to break every on-chain link between sender and receiver. The claim transaction contains zero decoded amounts and zero SOL movement. The withdrawal uses direct lamport manipulation -- no Transfer inner instruction, no CPI. The IDL reveals no amount-related field names to block explorers.

## Architecture

DarkDrop splits the claim into two steps via a **credit note model**:

1. **Deposit** (`create_drop`) -- SOL enters a program-owned treasury via CPI. Leaf inserted into Merkle tree. Claim code generated client-side. Optionally, a `DepositReceipt` PDA is created so the depositor can revoke if the claim code is lost.
2. **Claim** (`claim_credit`) -- Groth16 proof verified on-chain (V2 circuit, amount is a private input). CreditNote PDA created storing a re-randomized Poseidon commitment (salted to break deposit→claim linkage). Nullifier marked spent. Zero SOL moves. Zero amounts in instruction data.
3. **Withdraw** (`withdraw_credit`) -- User opens the Poseidon commitment. Program verifies via on-chain recomputation. SOL transferred via direct lamport manipulation on the program-owned treasury. No CPI, no inner instruction. CreditNote PDA closed.

Three additional paths layer on top of the core flow:

- **Note Pool (V3)** -- second-layer Merkle mixer. Two entry paths: `deposit_to_note_pool` opens an existing credit note and inserts a fresh pool leaf; `create_drop_to_pool` goes straight from SOL → pool leaf in one TX (MAX PRIVACY on the frontend). Both construct the pool leaf on-chain with a program-verified amount, eliminating the dishonest-leaf problem at the pool layer. `claim_from_note_pool` verifies a V3 Groth16 proof and issues a brand-new credit note. An observer must break both ZK layers to deanonymize.
- **Revoke (30-day time-lock)** -- `revoke_drop` lets the depositor reclaim SOL from an unclaimed drop by submitting the full leaf preimage. The program reconstructs the leaf on-chain, derives the nullifier, and refunds via direct lamport manipulation. Claim and revoke share the nullifier PDA namespace, so a drop can only resolve one way. `close_receipt` recovers receipt rent for drops that were claimed normally. The frontend's `/drop/manage` page surfaces stored receipts per-wallet with revoke / close_receipt actions and a staleness badge warning when a claim-code snapshot is near root-history rotation.
- **Authority rotation** -- `propose_authority_rotation` / `revoke_authority_rotation` / `accept_authority_rotation` implement a single-proposal sidecar pattern for rotating the vault authority without touching Vault state. Closes Audit 04 L-03.

The treasury PDA is owned by the DarkDrop program (not the system program), enabling direct lamport debit without `system_program::transfer`. The program stores triple verification keys (V1 for backward compatibility, V2 for credit notes, V3 for note pool claims). The IDL uses obfuscated field names (`data`, `inputs`, `opening`, `rate`) -- no field is named "amount", "fee", or "lamports".

See [ARCHITECTURE.md](ARCHITECTURE.md) for full technical details, deployed addresses, test results, and proof TX signatures.

## Deployed (Devnet)

| Component | Address |
|-----------|---------|
| Program | `GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU` |
| Vault PDA | `3ioMEKQvKnLaR8JFQUgsNFDby9Xi89M5MWZXNzdUJZoG` |
| Merkle Tree PDA | `2rvpifNShofeGz1BqJHeVPHoyvm43fYpcU5vtgozLrA2` |
| Treasury PDA | `1427qYPVC3ghVifCtg45yDtoSvdzNKQ3TEce5kK3c6Wr` |
| IDL Account | `Ga5PRgbVxhh9ek39BRHCXgsb5obHqYooq4qV2ebJ8tKG` |

## Build

### Circuit

Requires [circom](https://docs.circom.io/) v2.2+ and [snarkjs](https://github.com/iden3/snarkjs).

```bash
cd circuits
circom darkdrop.circom --r1cs --wasm --sym -o build/

# Trusted setup (phase 2)
snarkjs groth16 setup build/darkdrop.r1cs build/pot14_final.ptau build/darkdrop_v2_0000.zkey
snarkjs zkey contribute build/darkdrop_v2_0000.zkey build/darkdrop_v2_final.zkey --name="phase2"
snarkjs zkey export verificationkey build/darkdrop_v2_final.zkey build/verification_key_v2.json

# Export VK to Rust constants
node scripts/export_vk_rust.js circuits/build/verification_key_v2.json > program/programs/darkdrop/src/vk_new.rs
```

### Program

Requires Solana CLI with `cargo-build-sbf`. `anchor build` is broken -- use the workaround:

```bash
cd program
cargo build-sbf
cp target/sbpf-solana-solana/release/darkdrop.so target/deploy/darkdrop.so

# Deploy
solana program deploy target/deploy/darkdrop.so --program-id <KEYPAIR> -u devnet
```

### Frontend

Requires Node.js v20+. Build from Linux filesystem (WSL2 performance):

```bash
# Copy circuit artifacts (V1 legacy + V2 credit note + V3 note pool)
cp circuits/build/darkdrop_js/darkdrop.wasm frontend/public/circuits/
cp circuits/build/darkdrop_final.zkey frontend/public/circuits/           # V1 legacy
cp circuits/build/darkdrop_v2_final.zkey frontend/public/circuits/        # V2 credit note
cp circuits/build/note_pool/note_pool_js/note_pool.wasm frontend/public/circuits/
cp circuits/build/note_pool/note_pool_final.zkey frontend/public/circuits/ # V3 note pool

# Build
cd frontend
npm install
npx next build
npx next dev  # development server
```

### Relayer

```bash
cd relayer
npm install
npx ts-node src/index.ts
```

Endpoints: `GET /health`, `POST /api/relay/claim` (legacy V1), `POST /api/relay/create-drop` (private deposit), `POST /api/relay/credit/claim` (V2 claim), `POST /api/relay/credit/withdraw` (V2 withdraw), `POST /api/relay/create-drop-to-pool` (MAX PRIVACY deposit), `POST /api/relay/pool/claim` (gasless V3 claim).

## Tests

```bash
# E2E credit note flow (devnet or localnet)
RPC_URL=https://api.devnet.solana.com node scripts/e2e-credit-test.js

# Security tests (7 attack vectors)
RPC_URL=https://api.devnet.solana.com node scripts/security-credit-tests.js

# Multi-wallet stress test (10 deposits, 10 claims, 5 wallets each side)
RPC_URL=https://api.devnet.solana.com node scripts/stress-test.js

# Pool direct-deposit E2E (localnet or devnet)
node scripts/e2e-pool-deposit-test.js

# Legacy tests
node scripts/e2e-test.js
node scripts/security-tests.js
```

## Project Structure

```
circuits/           Circom circuits (V2 credit note + V3 note pool)
program/            Anchor program (18 instructions, triple VK — V1/V2/V3)
frontend/           Next.js 16 frontend (/drop/create, /drop/claim, /drop/manage)
relayer/            Express relay server (7 endpoints: deposit + pool deposit + legacy claim + credit claim/withdraw + pool claim + health)
scripts/            E2E tests, security tests, stress test, migration runbooks, VK export
audits/             4 security audit reports + fix tracker
```

## Security

- Fee rate capped at 500 bps (5%) on-chain
- Nullifier PDA prevents double-spend (shared namespace across `claim_credit` and `revoke_drop` gives mutual exclusion)
- Poseidon commitment binding verified on-chain at withdrawal
- Stored commitments re-randomized with a caller-supplied salt (breaks deposit→claim linkage)
- Recipient bound to proof via Poseidon(pubkey)
- `admin_sweep` obligation-aware: cannot drain SOL backing outstanding credit notes
- Revoke is sender-keyed and time-locked (30 days), preimage-verified on-chain
- Authority rotation via propose/accept sidecar (no Vault realloc, single-proposal invariant)
- Root history 256 slots (schema v2) — claim-code snapshots remain verifiable for ~1–2 weeks of devnet activity
- `create_drop_to_pool` takes the dishonest-leaf problem off the table for pool-bound deposits: the pool leaf is constructed on-chain from the literal CPI amount
- Test matrix: 6/6 legacy, 7/7 credit note, 4/4 note pool, 11/11 revoke + close_receipt, plus pool-direct-deposit E2E — all passing

## Audits

Four audit reports cover the program, circuits, fee/treasury logic, and the revoke + note-pool layer. See the [audit README](audits/README.md) for the summary table and fix tracker.

| # | Report | Date | Scope |
|---|--------|------|-------|
| 1 | [Manual Review](audits/AUDIT-01-MANUAL-REVIEW.md) | 2026-04-06 | Fee system, credit notes, treasury, relay trust |
| 2 | [Code Review](audits/AUDIT-02-CODE-REVIEW.md) | 2026-04-07 | Full instruction-level review |
| 3 | [Post-Fix Review](audits/AUDIT-03-POST-FIX-REVIEW.md) | 2026-04-08 | Fix verification + `admin_sweep` + re-audit |
| 4 | [Post-Revoke Review](audits/AUDIT-04-POST-REVOKE.md) | 2026-04-20 | V3 Note Pool + `revoke_drop` + `DepositReceipt` + privacy |

No open HIGH or CRITICAL findings as of Audit 04. No third-party firm review yet — deployment restricted to Solana devnet.

## License

MIT
