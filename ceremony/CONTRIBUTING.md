# Contributing to the DarkDrop Trusted Setup Ceremony

Thank you for adding entropy to the DarkDrop ceremony. Every honest contributor strengthens the security of every future proof.

## **Important: run on a freshly booted, ephemeral environment**

Phase-2 contributions produce *toxic waste* — a secret value that must never leave your machine. If a single honest contributor discards their share, the ceremony is sound; if every contributor leaks, anyone can forge proofs against the resulting zkey.

Before you run the contribute script:

- **Use a fresh environment.** A live USB, a freshly created VM with no other workloads, or a brand-new container is ideal. Avoid your daily-driver shell.
- **Disable shell history** (`export HISTFILE=/dev/null`) and persistent clipboard sync.
- **Disconnect from the network for the duration of the contribute call.** snarkjs does not need the network mid-contribution.
- **Reboot or destroy the environment afterward.** Do not back it up.

The contribute script generates entropy directly from `/dev/urandom`, pipes it to snarkjs via stdin (never argv), and unsets it immediately. These mitigations only matter if your runtime environment is clean.

## Contribution model

DarkDrop runs a **permissionless** phase-2 ceremony: anyone can submit a contribution PR within the announced window, subject to the gates below. We chose permissionless over a curated roster because Groth16 phase-2 soundness only requires *one* honest contributor, and a broader contributor set gives better odds than a smaller permissioned one.

Gates (enforced by CI):

| Gate | Purpose |
|---|---|
| GitHub account age ≥ 90 days at PR open time | Raises the cost of opportunistic same-day sock-puppets. Easy to defeat at scale, useful against drive-by bad actors. |
| Pre-committed drand beacon round (see [CEREMONY.md](CEREMONY.md)) | Removes finalization-timing grinding. The beacon round is fixed publicly ≥7 days before finalize; no maintainer can shop for a favorable randomness value. |
| Public announcement window | The contribution phase is open only between the dated entries in [CEREMONY.md](CEREMONY.md). PRs before/after the window are out of scope. |

## Prerequisites — pinned versions

These versions are pinned in CI; using anything else can produce zkeys that pass locally but fail CI verification.

| Tool | Pinned version |
|---|---|
| Node.js | 20.x |
| circom | `v2.2.2` |
| snarkjs | `0.7.6` |
| jq | any recent |
| curl | any recent |

```bash
# circom — pin the exact tag
cargo install --git https://github.com/iden3/circom.git --tag v2.2.2 --locked

# snarkjs — exact version
npm install -g snarkjs@0.7.6
```

The contribute script also uses `drand-client` to verify the finalization beacon. It is pulled in via `scripts/package.json` automatically the first time finalize is invoked.

## Flow

1. **Confirm the contribution window is open** — see the latest dated entry in [CEREMONY.md](CEREMONY.md). If we're outside the window, your PR will be closed.
2. **Fork + clone darkdropv4** and `cd` into the repo.
3. **Pull latest** so you contribute on top of the most recent zkey:
   ```bash
   git fetch origin && git checkout main && git pull
   ```
4. **Run the contribute script in a fresh environment:**
   ```bash
   ./scripts/ceremony.sh contribute "Your Name or Pseudonym"
   ```
   - Move your mouse and type randomly while the script runs (~30s–2min per circuit).
   - The script re-verifies the ptau SHA256, generates fresh entropy from `/dev/urandom`, pipes it to snarkjs via stdin, and never echoes it to the terminal.
   - If snarkjs verification fails or its output format unexpectedly changes, the script aborts — it will never fall back to recording a fabricated hash.
5. **Confirm your receipt** — `ceremony/contributions/contribution_<N>_<your-name>.json` is your attestation. Inspect it; the `circuitHashes` field must contain non-empty 64-char hex values for every circuit.
6. **Open a PR titled** `ceremony: contribution #<N> by <your-name>`. The PR should add:
   - `ceremony/contributions/contribution_<N>_<your-name>.json`
   - Updated `ceremony/state.json`
   - Updated zkeys in `ceremony/zkeys/`

## Optional attestation — bind your contribution to an identity

Attestation is optional but recommended for contributors who want their share to be cryptographically attributable. Pick one (or both):

### Option A — Solana key signature

Sign the contents of your contribution receipt with a Solana key you publicly announced ≥3 days ago in the contribution-window discussion thread.

```bash
# Sign the receipt
solana sign-offchain-message "$(cat ceremony/contributions/contribution_<N>_<your-name>.json)" \
  --keypair ~/.config/solana/your-attestation-keypair.json \
  > ceremony/attestations/<N>_<your-name>.sig

# Add the Solana public key to the attestation alongside the signature
echo "pubkey: $(solana address --keypair ~/.config/solana/your-attestation-keypair.json)" \
  >> ceremony/attestations/<N>_<your-name>.sig
```

This attests that the same Solana identity who announced the key is the one who produced the contribution. It is a *soft trust signal*, not a gate.

### Option B — GPG signature

If you have an existing GPG identity tied to your real-world or pseudonymous identity:

```bash
gpg --armor --detach-sign --output ceremony/attestations/<N>_<your-name>.txt.asc \
    ceremony/contributions/contribution_<N>_<your-name>.json
```

Same caveat: optional, treated as a soft trust signal. We deliberately do not require GPG because in a permissionless flow an attacker can generate their own key and sign their own malicious contribution — required-GPG-without-pre-published-roster creates an illusion of attribution rather than real attribution.

## Verifying someone else's contribution

```bash
./scripts/ceremony.sh verify
```

Checks every contribution in `ceremony/zkeys/` against the source r1cs and the Hermez ptau. CI also runs an *independent* verification path that does not invoke `scripts/ceremony.sh` — see `.github/workflows/ceremony-verify.yml`.

If you suspect a contribution is invalid, open a comment on its PR rather than opening a sabotage PR.

## Finalisation

Finalisation is maintainer-triggered after the contribution window closes and the pre-committed drand beacon round resolves. See [CEREMONY.md](CEREMONY.md) for the committed round number, the expected drand time, and the public announcement.

## Code of conduct

- Use a name or pseudonym you're comfortable being permanently attached to a contribution.
- Don't sabotage another contributor's PR — open a verify-only review or a comment instead.
- If you suspect your machine was compromised during contribution, mark your contribution as untrusted in your PR description and let later contributors override it.
