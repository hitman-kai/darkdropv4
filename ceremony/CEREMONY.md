# DarkDrop Ceremony — Public Schedule & Beacon Commitment

This document is the **authoritative public record** of the ceremony's timing and the drand beacon round committed for finalisation. Maintainers update it at each phase transition; contributors and external verifiers read it to confirm a contribution falls inside the announced window.

Schema-machine-readable state lives in [`state.json`](state.json). This file is the human-readable mirror, plus the public commitments required to remove finalization-timing attacks.

## Why this file exists

Without a pre-committed beacon round, a maintainer could:

1. Wait until finalisation time, fetch `drand /public/latest`, and apply whatever randomness happens to be current.
2. By varying *when* they hit finalize, shop for a round whose randomness biases the final zkey favorably.

The standard fix used by every recent production phase-2 ceremony (Aztec, Tornado, Semaphore, zkRune) is:

1. Pick a future drand round `N`.
2. Commit it publicly ≥7 days before finalise.
3. At finalise time, fetch round `N` exactly and verify its BLS signature against the drand chain's pinned group public key.

This file is where the commitment lives.

## Beacon parameters

| Field | Value |
|---|---|
| Drand network | Mainnet ("League of Entropy") |
| Chain hash | `8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce` |
| Group public key (G1, 48 bytes) | `868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31` |
| Chain type | Chained, 30 s period |
| Genesis time (unix) | 1595431050 (2020-08-22 17:57:30 UTC) |
| Verification | BLS signature against the pinned group public key. `drand-client` refuses to proceed unless `/info` returns matching `hash` and `public_key`. Performed client-side by `scripts/verify-drand.js`. |

Round-to-time formula: `roundTime = 1595431050 + (round - 1) * 30`.

## Phase timeline

> **Status before first announcement:** No round committed yet. `state.json.beaconRound` is `null`. The contribution phase will not open until a maintainer runs `./scripts/ceremony.sh announce-beacon <round>` and commits the result.

| Phase | Status | Window |
|---|---|---|
| Bootstrap | merged | n/a — this is the framework PR |
| Beacon announcement | _pending_ | maintainer commits round in `state.json`, updates this file with the dated entry |
| Contribution window | _not yet open_ | opens with the dated entry below, closes ≥7 days before beacon round resolves |
| Finalisation | _not yet open_ | runs after the committed drand round produces its signature |
| Promotion to production | _separate PR_ | maintainers review final beacon and verification key diff before swapping production keys |

## Announcements (chronological)

<!--
Maintainers: append a new entry each time a phase boundary is crossed. Format:

### YYYY-MM-DD — <event title>

- Field: value
- Field: value

Do NOT edit or remove past entries. The chronological record IS the public attestation.
-->

_No announcements yet. The first entry will be posted when the beacon round is committed._

## How to verify the beacon at finalise time

Anyone, including non-contributors, can independently re-fetch and verify the beacon used at finalise:

```bash
# Reads pinned chain + key + round from state.json, fetches and BLS-verifies.
ROUND=$(jq -r .beaconRound ceremony/state.json)
CHAIN=$(jq -r .beaconChainHash ceremony/state.json)
PK=$(jq -r .beaconPublicKey ceremony/state.json)
node scripts/verify-drand.js "$CHAIN" "$PK" "$ROUND"
# Output should be a 64-char hex randomness equal to state.json.beacon
```

If the output does not match `state.json.beacon`, the finalisation was not performed against the committed round and the ceremony must be rejected.

## How a contributor confirms a window is open

1. Check the latest dated entry under **Announcements**. If it says "contribution window open" and gives a closing date in the future, you're in.
2. Cross-check `state.json.beaconRound` is non-null and `beaconExpectedAt` is ≥7 days from today.
3. Verify the chain hash in `state.json` matches the value in the **Beacon parameters** table above.

If any of those fail, **do not submit a contribution PR**. Open an issue asking the maintainer to clarify the schedule first.
