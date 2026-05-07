# Contributing to the DarkDrop Trusted Setup Ceremony

Thank you for adding entropy to the DarkDrop ceremony. Every honest contributor strengthens the security of every future proof.

## Prerequisites

| Tool | Version |
|---|---|
| Node.js | 20+ |
| circom | 2.2+ |
| snarkjs | 0.7+ |
| jq | any recent |
| curl | any recent |
| openssl | any recent |

```bash
# circom
cargo install --git https://github.com/iden3/circom.git
# snarkjs
npm install -g snarkjs
```

## Flow

1. **Fork + clone darkdropv4** and `cd` into the repo.
2. **Pull latest** so you contribute on top of the most recent zkey:
   ```bash
   git fetch origin && git checkout main && git pull
   ```
3. **Run the contribute script:**
   ```bash
   ./scripts/ceremony.sh contribute "Your Name or Pseudonym"
   ```
   - Move your mouse, type randomly, and let the script finish (~30s–2min).
   - The script generates fresh entropy via `openssl rand` and `snarkjs zkey contribute`.
4. **Confirm your receipt** — `ceremony/contributions/contribution_<N>_<your-name>.json` is your attestation.
5. **Open a PR** titled `ceremony: contribution #<N> by <your-name>`. The PR should add:
   - `ceremony/contributions/contribution_<N>_<your-name>.json`
   - Updated `ceremony/state.json`
   - Updated zkeys in `ceremony/zkeys/`
6. **Optional: GPG-sign your attestation.** Add `ceremony/attestations/<N>_<your-name>.txt.asc` with a signature over the contents of your contribution receipt. This makes your attestation cryptographically attributable to you.

## What "one honest contributor" means in practice

- Run on a freshly booted machine if you can. A live USB or fresh container is ideal.
- After running the script, **wipe the entropy** — close the shell, delete the temp files, reboot.
- Do **not** publish or back up the entropy variable used during contribution. The script never persists it; just don't paste your shell history anywhere.
- After your contribution is merged, you don't need to keep anything. The zkey + receipt are public.

## Verifying someone else's contribution

```bash
./scripts/ceremony.sh verify
```

Checks every contribution in `ceremony/zkeys/` against the source r1cs and the Hermez ptau. If verification fails, the PR is rejected.

## Schedule

Phase-2 contributions are open until **finalisation**, which the maintainers schedule with at least 7 days notice in `ceremony/state.json` and pinned issues. The beacon round is announced at finalisation time.

## Code of conduct

- Use a name or pseudonym you're comfortable being permanently attached to a contribution.
- Don't sabotage another contributor's PR — open a verify-only review instead.
- If you suspect your machine was compromised during contribution, mark your contribution as untrusted in your PR and let later contributors override it.
