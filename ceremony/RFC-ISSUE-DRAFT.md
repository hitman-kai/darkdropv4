<!--
This file is the draft body for an RFC issue to be opened on the darkdrop
upstream (hitman-kai/darkdropv4). It is NOT meant to live in the repo long-term —
delete this file from the PR if maintainers prefer.
Title to use when opening: RFC: Phase-2 community trusted setup ceremony, sponsored by zkRune
-->

# RFC: Phase-2 community trusted setup ceremony, sponsored by zkRune

## Summary

Bootstrap a community phase-2 multi-party computation (MPC) ceremony for DarkDrop's V2 (credit note) and V3 (note pool) Groth16 circuits, using the same ceremony framework that produced [zkRune's finalised ceremony](https://github.com/louisstein94/zkrune) on 2026-01-15. zkRune offers to sponsor the framework, contribute the first phase-2 share, and coordinate community contributors.

## Motivation

DarkDrop's V2 and V3 zkeys (`darkdrop_v2_final.zkey`, `note_pool_final.zkey`) are currently produced by single-developer phase-2 setup. Hermez Phase-1 (`pot14_final.ptau`) covers the universal portion, but the per-circuit phase-2 was not run as a community MPC. This is the largest cryptographic gap remaining before mainnet:

- A single-party phase-2 means **one entity** holds the toxic waste and could forge proofs.
- Once on mainnet, the trusted setup cannot be retroactively strengthened without a hard fork that invalidates outstanding credit notes and pool leaves.
- Independent firms typically flag single-party phase-2 as a HIGH finding for any production privacy protocol.

A community phase-2 ceremony with ≥5 contributors, drand-beaconed finalisation, and public attestations brings DarkDrop in line with industry-standard practices (Tornado Cash, Semaphore, Aztec, zkRune).

## Proposal

### Two-PR rollout

**PR #1 — Ceremony bootstrap** (this proposal):
- Add `ceremony/` directory with adapted MPC framework.
- Add `scripts/ceremony.sh` (init / contribute / verify / finalize / status).
- Add `.github/workflows/ceremony-verify.yml` to verify any new contribution PR.
- Add `CEREMONY.md` and a one-line entry in `README.md > Security`.
- **Touches no production paths** (no changes to `circuits/build/`, `frontend/public/circuits/`, `program/programs/darkdrop/src/vk_new.rs`). The CI workflow explicitly fails any PR that does, so this invariant is enforced.

**PR #2 — Production promotion** (after ceremony finalises):
- Replace production zkeys with finalised ceremony output.
- Regenerate `vk_new.rs` via `node scripts/export_vk_rust.js`.
- Update audit fixtures and re-run the full test matrix.
- Bump program version + redeploy to devnet for fresh end-to-end validation.

### Ceremony parameters

| Parameter | Value |
|---|---|
| Phase 1 | Hermez Powers of Tau, `powersOfTau28_hez_final_14.ptau` (already in use by DarkDrop) |
| Circuits | `darkdrop_v2`, `note_pool` |
| Minimum contributors | 5 (zkRune ceremony precedent) |
| Beacon | `drand.cloudflare.com` (public, externally verifiable) |
| Open contribution window | 14–21 days from go-ahead |
| Finalisation | Maintainer-triggered after window + ≥5 contributions |

### zkRune's first contribution

If approved, zkRune will contribute the first phase-2 share — same flow we ran for our own 13 production circuits. We commit to:
- Running the contribution on a freshly booted, network-isolated machine.
- Publishing a GPG-signed attestation under `ceremony/attestations/0001-zkrune.txt.asc`.
- Promoting the call for community contributors via @rune_zk and @legelsteinn.

## Non-goals

- This RFC does **not** propose changing any DarkDrop circuit, on-chain program, frontend, or relayer code.
- This RFC does **not** propose touching production zkeys or VKs in any way during PR #1.
- This RFC does **not** propose a hosted contribution server / API. Local-only contribution is sufficient and reduces surface area; we can add a hosted UI later if maintainers want it.

## Open questions for maintainers

1. **Approval to proceed with PR #1?** The bootstrap PR is written and ready (see `feat/ceremony-bootstrap` on louisstein94's fork).
2. **Beacon round selection** — should the beacon round be drand-pinned at PR #1 merge time, or chosen at finalisation time?
3. **Minimum contributor count** — happy with 5, or do you want more (e.g. matching the contributor count of recent comparable projects)?
4. **Air-gap requirements for the genesis (zkRune) contribution** — any hardware or process you want us to follow beyond a freshly booted clean machine?
5. **Finalisation announcement channel** — pinned issue, README banner, both?

## Security analysis

- **Trust model:** Soundness holds if **at least one** contributor is honest and discards their toxic waste. Beacon adds public unpredictable randomness.
- **Bootstrap PR risk:** Zero — no production keys, no on-chain code, no circuit logic touched. CI enforces the invariant.
- **Promotion PR risk:** Standard zkey swap; verified by `snarkjs zkey verify`, audit re-run, fresh devnet deployment.
- **Reorg / cross-implementation risk:** Beacon value is committed in `state.json` and reproducible; verifiers don't depend on ceremony state.

## References

- zkRune ceremony report: https://github.com/louisstein94/zkrune/blob/main/ceremony/CEREMONY_REPORT.md
- snarkjs MPC docs: https://github.com/iden3/snarkjs#groth16
- drand: https://drand.love/
- Hermez Powers of Tau: https://github.com/iden3/snarkjs#7-prepare-phase-2

## Filed by

zkRune team (zkruneprotocol@gmail.com / @rune_zk) under the existing zkRune ↔ DarkDrop partnership.
