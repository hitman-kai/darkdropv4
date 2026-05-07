# DarkDrop Trusted Setup Ceremony

Phase-2 multi-party computation for DarkDrop's two production Groth16 circuits:

- **`darkdrop_v2`** — V2 credit note ([circuits/darkdrop.circom](../circuits/darkdrop.circom))
- **`note_pool`** — V3 note pool ([circuits/note_pool.circom](../circuits/note_pool.circom))

## What is a trusted setup?

Groth16 zk-SNARKs require a one-time setup that produces secret randomness ("toxic waste"). Anyone who knows that randomness can forge proofs. Multi-party computation (MPC) splits the secret across many contributors — as long as **at least one contributor is honest** and discards their share, the ceremony is secure.

## Layered structure

| Phase | What | Source |
|---|---|---|
| **Phase 1 (universal)** | Powers of Tau, supports any circuit up to 2^14 constraints | Hermez Network ceremony, 54 contributors. File: `powersOfTau28_hez_final_14.ptau` (~45MB, fetched from `hermez.s3-eu-west-1.amazonaws.com`, gitignored). |
| **Phase 2 (circuit-specific)** | Per-circuit randomness for V2 + V3 | This ceremony — DarkDrop community contributions. |
| **Final beacon** | Public, unpredictable randomness applied at finalisation | `drand.cloudflare.com` — public verifiable random function. |

## Status

See [`state.json`](state.json) for the live state machine: current contribution index, finalisation status, beacon value once applied.

## How to contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full flow. Short version:

```bash
./scripts/ceremony.sh contribute "Your Name"
```

Pre-requisites: `circom` 2.2+, `snarkjs` 0.7+, Node.js 20+, `jq`, `curl`, `openssl`.

## Verifying the ceremony

Anyone can independently verify the ceremony at any time:

```bash
./scripts/ceremony.sh verify
```

This re-runs `snarkjs zkey verify` against every contribution using the original r1cs and the Hermez ptau.

## Production promotion

Finalised zkeys live in [`zkeys/`](zkeys/). They are intentionally **not copied** into production paths (`circuits/build/`, `frontend/public/circuits/`, [program/programs/darkdrop/src/vk_new.rs](../program/programs/darkdrop/src/vk_new.rs)) by the ceremony script. Promotion is a separate, deliberate PR so the maintainers can review the final beacon, the contributor list, and the verification key diff before swapping production keys.

## Threat model

- **At least one honest contributor** → security holds.
- **Beacon manipulation** → mitigated by drand: a public, distributed, externally verifiable randomness source whose value is unknown until ceremony finalisation time.
- **Server compromise** → not relevant: this ceremony runs locally, all artefacts are committed to the repo, and verification is independent of any server.
- **Toxic waste leakage from a contributor's machine** → covered by the "one honest contributor" assumption; we recommend air-gapped or freshly booted environments for sensitive contributors.

## Provenance

The ceremony framework is adapted from [zkRune's ceremony](https://github.com/louisstein94/zkrune) (finalised 2026-01-15, 5 contributors, drand beacon). zkRune's framework is reused under the same MIT license; circuit-specific zkeys are produced fresh for DarkDrop.
