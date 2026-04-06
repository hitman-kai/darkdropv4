# DarkDrop V4

Unlinkable value transfer on Solana. DarkDrop uses Groth16 zero-knowledge proofs and an incremental Merkle tree to break every on-chain link between sender and receiver. The claim transaction contains zero decoded amounts and zero SOL movement. The withdrawal uses direct lamport manipulation -- no Transfer inner instruction, no CPI. The IDL reveals no amount-related field names to block explorers.

## Architecture

DarkDrop splits the claim into two steps via a **credit note model**:

1. **Deposit** (`create_drop`) -- SOL enters a program-owned treasury via CPI. Leaf inserted into Merkle tree. Claim code generated client-side.
2. **Claim** (`claim_credit`) -- Groth16 proof verified on-chain (V2 circuit, amount is a private input). CreditNote PDA created storing a Poseidon commitment. Nullifier marked spent. Zero SOL moves. Zero amounts in instruction data.
3. **Withdraw** (`withdraw_credit`) -- User opens the Poseidon commitment. Program verifies via on-chain recomputation. SOL transferred via direct lamport manipulation on the program-owned treasury. No CPI, no inner instruction. CreditNote PDA closed.

The treasury PDA is owned by the DarkDrop program (not the system program), enabling direct lamport debit without `system_program::transfer`. The program stores dual verification keys (V1 for backward compatibility, V2 for credit notes). The IDL uses obfuscated field names (`data`, `inputs`, `opening`, `rate`) -- no field is named "amount", "fee", or "lamports".

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
# Copy circuit artifacts
cp circuits/build/darkdrop_js/darkdrop.wasm frontend/public/circuits/
cp circuits/build/darkdrop_v2_final.zkey frontend/public/circuits/

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

Endpoints: `POST /api/relay/claim`, `POST /api/relay/create-drop`, `POST /api/relay/credit/claim`, `POST /api/relay/credit/withdraw`.

## Tests

```bash
# E2E credit note flow (devnet or localnet)
RPC_URL=https://api.devnet.solana.com node scripts/e2e-credit-test.js

# Security tests (7 attack vectors)
RPC_URL=https://api.devnet.solana.com node scripts/security-credit-tests.js

# Multi-wallet stress test (10 deposits, 10 claims, 5 wallets each side)
RPC_URL=https://api.devnet.solana.com node scripts/stress-test.js

# Legacy tests
node scripts/e2e-test.js
node scripts/security-tests.js
```

## Project Structure

```
circuits/           Circom circuit (V2, amount private)
program/            Anchor program (6 instructions, dual VK)
frontend/           Next.js 16 frontend (V3 design)
relayer/            Express relay server (deposit + claim + withdraw)
scripts/            E2E tests, security tests, stress test, VK export
```

## Security

- Fee rate capped at 500 bps (5%) on-chain
- Nullifier PDA prevents double-spend
- Poseidon commitment binding verified on-chain at withdrawal
- Recipient bound to proof via Poseidon(pubkey)
- 7/7 credit note security tests passing
- 6/6 legacy security tests passing
- Unaudited -- use at your own risk

## License

MIT
