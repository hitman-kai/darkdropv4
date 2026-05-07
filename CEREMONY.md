# DarkDrop Trusted Setup Ceremony

DarkDrop's V2 (credit note) and V3 (note pool) Groth16 circuits require a one-time phase-2 multi-party computation ceremony before mainnet. The ceremony framework lives under [`ceremony/`](ceremony/) and is invoked via [`scripts/ceremony.sh`](scripts/ceremony.sh).

## Quick links

- **How it works:** [ceremony/README.md](ceremony/README.md)
- **How to contribute:** [ceremony/CONTRIBUTING.md](ceremony/CONTRIBUTING.md)
- **Live state:** [ceremony/state.json](ceremony/state.json)
- **Contribution receipts:** [ceremony/contributions/](ceremony/contributions/)

## Why a ceremony

Groth16 trusted setup produces randomness that, if known, allows forging proofs. A community phase-2 MPC ensures that no single party — not the DarkDrop maintainers, not any one contributor — can reconstruct the secret, as long as **at least one contributor was honest**. The final beacon (drand.cloudflare.com) adds public, externally verifiable randomness as a final hedge.

## Status

The ceremony is **bootstrapped but not yet started.** Initialisation runs once the maintainers approve this PR; community contributions open after that, with a 7-day finalisation window.

## Provenance and acknowledgements

The ceremony framework is adapted from the [zkRune ceremony](https://github.com/louisstein94/zkrune) which finalised on 2026-01-15 with 5 contributors. zkRune contributed this scaffolding to DarkDrop as part of the partnership; circuit-specific zkeys are produced fresh for DarkDrop's V2 + V3 circuits.

## Production promotion

Finalised zkeys produced under [`ceremony/zkeys/`](ceremony/zkeys/) are intentionally kept out of production paths. A separate, deliberate PR (after maintainer review of the final beacon and contributor list) promotes them to:

- `circuits/build/darkdrop_v2_final.zkey`
- `circuits/build/note_pool/note_pool_final.zkey`
- `frontend/public/circuits/darkdrop_v2_final.zkey`
- `frontend/public/circuits/note_pool_final.zkey`
- `program/programs/darkdrop/src/vk_new.rs` (regenerated via `node scripts/export_vk_rust.js`)

This two-PR design is deliberate: the bootstrap PR carries no production risk; the promotion PR is the auditable security boundary.
