#!/bin/bash

# DarkDrop Trusted Setup Ceremony Script
# Phase-2 Multi-Party Computation for Groth16 zk-SNARKs (V2 credit note + V3 note pool)
# Adapted from the zkRune ceremony framework (https://github.com/louisstein94/zkrune).
#
# Usage:
#   ./scripts/ceremony.sh init                       Initialize ceremony (download ptau, build r1cs, create _0000 zkeys)
#   ./scripts/ceremony.sh announce-beacon <round>    Commit a future drand round for finalization (≥7 days out)
#   ./scripts/ceremony.sh contribute <name>          Add a phase-2 contribution
#   ./scripts/ceremony.sh verify                     Verify every contribution against the r1cs + ptau
#   ./scripts/ceremony.sh finalize                   Apply pre-committed drand beacon, export final VKs
#   ./scripts/ceremony.sh status                     Show current ceremony state
#
# A separate, deliberate PR promotes the finalized zkeys to production paths
# (circuits/build/, frontend/public/circuits/, program/.../vk_new.rs).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS_DIR="$REPO_ROOT/circuits"
CEREMONY_DIR="$REPO_ROOT/ceremony"
SCRIPTS_DIR="$REPO_ROOT/scripts"
PTAU_FILE="powersOfTau28_hez_final_14.ptau"
PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/$PTAU_FILE"
PTAU_PATH="$CEREMONY_DIR/$PTAU_FILE"

# SHA256 of powersOfTau28_hez_final_14.ptau. Published by iden3/snarkjs and used by
# every ceremony that builds on the Hermez Phase-1 trusted setup. If this hash ever
# fails to match, treat the download as adversarial — do NOT use the file.
# Cross-checked against the zkRune ceremony's committed copy (finalised 2026-01-15).
PTAU_SHA256="489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d"

# drand "League of Entropy" mainnet chain (chained, 30s period).
# We pin BOTH the chain hash and the BLS group public key. drand-client refuses
# to proceed unless the chain_info served at /info matches both pins — this
# defends against a substituted /info response that would otherwise let a
# tampered endpoint accept forged round signatures. The 30s period and 2020
# genesis match the LoE mainchain that has been continuously producing rounds
# since chain hash 8990e7a9... was published.
DRAND_CHAIN_HASH="8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
DRAND_PUBLIC_KEY="868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"
DRAND_GENESIS_TIME=1595431050
DRAND_PERIOD=30

# DarkDrop has two phase-2 circuits.
# Each tuple is: <id>|<circom source>|<r1cs path>|<final-zkey filename>
CIRCUITS=(
    "darkdrop_v2|$CIRCUITS_DIR/darkdrop.circom|$CIRCUITS_DIR/build/darkdrop.r1cs|darkdrop_v2_final.zkey"
    "note_pool|$CIRCUITS_DIR/note_pool.circom|$CIRCUITS_DIR/build/note_pool/note_pool.r1cs|note_pool_final.zkey"
)

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

banner() {
    echo
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}     ${YELLOW}DarkDrop Trusted Setup Ceremony${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     ${GREEN}Phase-2 MPC for V2 credit note + V3 note pool${NC}         ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
}

require() {
    command -v "$1" >/dev/null 2>&1 || { echo -e "${RED}Missing dependency: $1${NC}"; exit 1; }
}

check_deps() {
    require circom
    require snarkjs
    require node
    require jq
    require curl
    require openssl
    require shasum
    require xxd
}

field() { echo "$1" | cut -d'|' -f"$2"; }

# Cross-platform sha256 (-c style) — macOS shasum and Linux sha256sum agree on the
# "<hash>  <path>" format. We compare hashes directly rather than relying on -c.
sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

verify_ptau_hash() {
    local actual
    actual=$(sha256_of "$PTAU_PATH")
    if [ "$actual" != "$PTAU_SHA256" ]; then
        echo -e "${RED}FATAL: ptau hash mismatch.${NC}" >&2
        echo -e "${RED}  expected: $PTAU_SHA256${NC}" >&2
        echo -e "${RED}  actual:   $actual${NC}" >&2
        echo -e "${RED}  path:     $PTAU_PATH${NC}" >&2
        echo -e "${RED}Refusing to proceed. The ptau may have been tampered with in transit, or${NC}" >&2
        echo -e "${RED}the local copy modified. Delete and re-download, or investigate.${NC}" >&2
        exit 1
    fi
}

ensure_ptau() {
    if [ ! -f "$PTAU_PATH" ]; then
        mkdir -p "$CEREMONY_DIR"
        echo -e "${BLUE}Downloading Hermez Powers of Tau (Phase 1, ~18MB)...${NC}"
        curl -L --fail -o "$PTAU_PATH" "$PTAU_URL"
    fi
    # Always verify, even when the file was already on disk — catches local tampering.
    echo -e "${BLUE}Verifying ptau SHA256...${NC}"
    verify_ptau_hash
    echo -e "${GREEN}  ✓ ptau hash matches $PTAU_SHA256${NC}"
}

ensure_r1cs() {
    local circom_src="$1" r1cs_path="$2"
    if [ -f "$r1cs_path" ]; then return; fi
    local out_dir
    out_dir=$(dirname "$r1cs_path")
    mkdir -p "$out_dir"
    echo -e "${BLUE}Compiling $(basename "$circom_src")...${NC}"
    (cd "$CIRCUITS_DIR" && circom "$circom_src" --r1cs --wasm --sym -o "$out_dir")
}

ensure_drand_deps() {
    # scripts/package.json pins the drand-client library used by verify-drand.js.
    # We install once into scripts/node_modules and reuse it across invocations.
    if [ ! -d "$SCRIPTS_DIR/node_modules/drand-client" ]; then
        echo -e "${BLUE}Installing drand-client...${NC}"
        (cd "$SCRIPTS_DIR" && npm install --no-audit --no-fund --silent 2>&1 | tail -5)
    fi
}

cmd_init() {
    banner
    check_deps
    ensure_ptau
    mkdir -p "$CEREMONY_DIR/zkeys" "$CEREMONY_DIR/contributions" "$CEREMONY_DIR/attestations"

    for entry in "${CIRCUITS[@]}"; do
        local id circom_src r1cs
        id=$(field "$entry" 1)
        circom_src=$(field "$entry" 2)
        r1cs=$(field "$entry" 3)
        ensure_r1cs "$circom_src" "$r1cs"
        echo -e "${BLUE}Initialising phase-2 zkey for ${CYAN}$id${NC}..."
        snarkjs groth16 setup "$r1cs" "$PTAU_PATH" "$CEREMONY_DIR/zkeys/${id}_0000.zkey"
        echo -e "${GREEN}  ✓ ${id}_0000.zkey${NC}"
    done

    cat > "$CEREMONY_DIR/state.json" <<EOF
{
    "phase": "contribution",
    "startedAt": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "contributions": [],
    "circuits": ["darkdrop_v2", "note_pool"],
    "ptauFile": "$PTAU_FILE",
    "ptauSha256": "$PTAU_SHA256",
    "currentContributionIndex": 0,
    "beaconSource": "drand mainnet (League of Entropy)",
    "beaconChainHash": "$DRAND_CHAIN_HASH",
    "beaconPublicKey": "$DRAND_PUBLIC_KEY",
    "beaconRound": null,
    "beaconAnnouncedAt": null,
    "beaconExpectedAt": null,
    "beacon": null,
    "finalizedAt": null
}
EOF

    echo
    echo -e "${GREEN}Ceremony initialised.${NC}"
    echo -e "Next steps:"
    echo -e "  1. ${YELLOW}./scripts/ceremony.sh announce-beacon <round>${NC}  (commits a future drand round ≥7d out)"
    echo -e "  2. ${YELLOW}./scripts/ceremony.sh contribute \"Your Name\"${NC}  (first contribution)"
}

cmd_announce_beacon() {
    # Pre-commit a specific drand round for finalize. Mitigates beacon-timing
    # grinding: at finalize time the round is fixed, the maintainer can't shop
    # for a favorable randomness value by varying when they hit /public/latest.
    local round="${1:-}"
    [ -n "$round" ] || { echo -e "${RED}Usage: ./scripts/ceremony.sh announce-beacon <round>${NC}"; exit 1; }
    [[ "$round" =~ ^[0-9]+$ ]] || { echo -e "${RED}FATAL: round must be a positive integer${NC}"; exit 1; }
    [ -f "$CEREMONY_DIR/state.json" ] || { echo -e "${RED}Run init first.${NC}"; exit 1; }

    local now_unix round_time delta seven_days
    now_unix=$(date +%s)
    round_time=$((DRAND_GENESIS_TIME + (round - 1) * DRAND_PERIOD))
    delta=$((round_time - now_unix))
    seven_days=604800
    if [ "$delta" -lt "$seven_days" ]; then
        echo -e "${RED}FATAL: round $round resolves to $(date -u -r "$round_time" 2>/dev/null || date -u -d "@$round_time")${NC}" >&2
        echo -e "${RED}  That is only ${delta}s away (need ≥${seven_days}s / 7 days).${NC}" >&2
        echo -e "${RED}  Pick a round further in the future so the announcement has real lead time.${NC}" >&2
        exit 1
    fi

    local round_iso announced_iso
    round_iso=$(date -u -r "$round_time" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
                || date -u -d "@$round_time" +"%Y-%m-%dT%H:%M:%SZ")
    announced_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    jq --argjson round "$round" --arg announced "$announced_iso" --arg expected "$round_iso" \
        '.beaconRound = $round | .beaconAnnouncedAt = $announced | .beaconExpectedAt = $expected' \
        "$CEREMONY_DIR/state.json" > "$CEREMONY_DIR/state.tmp" && mv "$CEREMONY_DIR/state.tmp" "$CEREMONY_DIR/state.json"

    echo -e "${GREEN}Beacon round $round committed.${NC}"
    echo -e "Expected drand time: ${CYAN}$round_iso${NC}"
    echo -e "Commit ${YELLOW}ceremony/state.json${NC} and update ${YELLOW}ceremony/CEREMONY.md${NC} to publicly announce the round."
    echo -e "Finalize will refuse to run before $round_iso."
}

cmd_contribute() {
    # Prevent zsh/bash from persisting any command we run during contribution into
    # a history file. Inside this script the shell is non-interactive so HISTFILE
    # is usually inert, but defense-in-depth in case anyone source's this file.
    unset HISTFILE
    export HISTFILE=/dev/null
    set +o history 2>/dev/null || true

    local name="${1:-}"
    if [ -z "$name" ]; then
        echo -e "${RED}Usage: ./scripts/ceremony.sh contribute \"Your Name\"${NC}"
        exit 1
    fi
    [ -f "$CEREMONY_DIR/state.json" ] || { echo -e "${RED}Run init first.${NC}"; exit 1; }
    banner
    ensure_ptau

    local current next timestamp safe_name
    current=$(jq -r '.currentContributionIndex' "$CEREMONY_DIR/state.json")
    next=$((current + 1))
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    safe_name="${name//[^a-zA-Z0-9]/_}"

    echo -e "${YELLOW}Move your mouse and type randomly while contributing.${NC}"
    echo

    local hashes_json="["
    local first=1
    for entry in "${CIRCUITS[@]}"; do
        local id r1cs
        id=$(field "$entry" 1)
        r1cs=$(field "$entry" 3)
        local prev="$CEREMONY_DIR/zkeys/${id}_$(printf '%04d' "$current").zkey"
        local nxt="$CEREMONY_DIR/zkeys/${id}_$(printf '%04d' "$next").zkey"
        [ -f "$prev" ] || { echo -e "${RED}Missing $prev${NC}"; exit 1; }
        echo -e "${BLUE}Contributing to ${CYAN}$id${NC}..."

        # Entropy lifecycle, three things working together:
        #
        #   (a) Pure CSPRNG from /dev/urandom. Do NOT mix in name/timestamp/etc.
        #       Structured prefixes don't reduce effective entropy, but they look
        #       like derivable randomness, which is the wrong signal to send
        #       around toxic waste. If a future contributor wants to "helpfully"
        #       reintroduce a debug prefix here: don't.
        #
        #   (b) Piped to snarkjs via stdin instead of -e=<value>. Anything passed
        #       on argv is visible to any same-uid process via /proc/$pid/cmdline
        #       and may also be captured by audit/exec logging. stdin is read once
        #       and discarded.
        #
        #   (c) The HISTFILE guard at the top of cmd_contribute prevents the
        #       containing shell from persisting any command into a history file.
        local entropy
        entropy=$(head -c 64 /dev/urandom | xxd -p -c 128)
        printf '%s\n' "$entropy" | snarkjs zkey contribute "$prev" "$nxt" --name="$name"
        unset entropy

        # Verify the produced zkey before we record a hash for it. Two layers:
        #   1. Exit code: snarkjs zkey verify exits non-zero on failure. If we
        #      didn't check it, a malformed verify output could still contain a
        #      64-char hex string somewhere (a hash echoed in an error message)
        #      that the grep would happily accept.
        #   2. Parse fail-loud: if exit is 0 but we can't find the contribution
        #      hash, treat that as fatal rather than silently substituting a
        #      random value into the receipt. Receipts must be truthful.
        local verify_out
        verify_out=$(snarkjs zkey verify "$r1cs" "$PTAU_PATH" "$nxt" 2>&1) || {
            echo -e "${RED}FATAL: snarkjs verify failed for $id${NC}" >&2
            echo "$verify_out" >&2
            exit 1
        }
        local h
        h=$(printf '%s' "$verify_out" | grep -Eo '[0-9a-f]{64}' | tail -n1)
        [ -n "$h" ] || {
            echo -e "${RED}FATAL: could not parse contribution hash from snarkjs verify output for $id${NC}" >&2
            echo -e "${RED}This usually means snarkjs's output format changed. Do NOT record a fabricated hash — investigate.${NC}" >&2
            echo "$verify_out" >&2
            exit 1
        }
        if [ $first -eq 0 ]; then hashes_json+=","; fi
        hashes_json+="{\"circuit\":\"$id\",\"hash\":\"$h\"}"
        first=0
    done
    hashes_json+="]"

    jq --arg name "$name" --arg time "$timestamp" --argjson hashes "$hashes_json" --argjson idx "$next" \
        '.contributions += [{"index": $idx, "name": $name, "timestamp": $time, "circuitHashes": $hashes}] | .currentContributionIndex = $idx' \
        "$CEREMONY_DIR/state.json" > "$CEREMONY_DIR/state.tmp" && mv "$CEREMONY_DIR/state.tmp" "$CEREMONY_DIR/state.json"

    local receipt="$CEREMONY_DIR/contributions/contribution_${next}_${safe_name}.json"
    cat > "$receipt" <<EOF
{
    "contributionIndex": $next,
    "contributorName": "$name",
    "timestamp": "$timestamp",
    "circuitHashes": $hashes_json,
    "verification": "Run './scripts/ceremony.sh verify' to verify this contribution."
}
EOF

    echo
    echo -e "${GREEN}Contribution #$next saved.${NC} Receipt: $receipt"
}

cmd_verify() {
    banner
    [ -f "$CEREMONY_DIR/state.json" ] || { echo -e "${RED}Run init first.${NC}"; exit 1; }
    ensure_ptau
    local current; current=$(jq -r '.currentContributionIndex' "$CEREMONY_DIR/state.json")
    if [ "$current" -eq 0 ]; then echo -e "${YELLOW}No contributions yet.${NC}"; exit 0; fi

    local ok=1
    for entry in "${CIRCUITS[@]}"; do
        local id r1cs; id=$(field "$entry" 1); r1cs=$(field "$entry" 3)
        local final="$CEREMONY_DIR/zkeys/${id}_$(printf '%04d' "$current").zkey"
        echo -e "${BLUE}Verifying ${CYAN}$id${NC}..."
        if snarkjs zkey verify "$r1cs" "$PTAU_PATH" "$final"; then
            echo -e "${GREEN}  ✓ $id verified${NC}"
        else
            echo -e "${RED}  ✗ $id verification failed${NC}"; ok=0
        fi
    done
    [ $ok -eq 1 ] && echo -e "${GREEN}All contributions verified.${NC}" || { echo -e "${RED}Verification failed.${NC}"; exit 1; }

    echo; echo -e "${BLUE}Contribution history:${NC}"
    jq -r '.contributions[] | "  #\(.index) — \(.name) @ \(.timestamp)"' "$CEREMONY_DIR/state.json"
}

cmd_finalize() {
    banner
    [ -f "$CEREMONY_DIR/state.json" ] || { echo -e "${RED}Run init first.${NC}"; exit 1; }
    ensure_ptau
    local current; current=$(jq -r '.currentContributionIndex' "$CEREMONY_DIR/state.json")
    if [ "$current" -lt 2 ]; then
        echo -e "${YELLOW}Only $current contribution(s). Production-grade ceremonies need ≥2.${NC}"
        read -p "Continue anyway? (y/n): " confirm
        [ "$confirm" = "y" ] || exit 0
    fi

    # Pre-committed beacon round — required. If beaconRound is null we refuse to
    # finalize, because that would mean falling back to "latest at finalize time"
    # which is the grinding-attack surface we eliminated.
    local round chain_hash pub_key expected_at now_unix expected_unix
    round=$(jq -r '.beaconRound' "$CEREMONY_DIR/state.json")
    chain_hash=$(jq -r '.beaconChainHash' "$CEREMONY_DIR/state.json")
    pub_key=$(jq -r '.beaconPublicKey' "$CEREMONY_DIR/state.json")
    expected_at=$(jq -r '.beaconExpectedAt' "$CEREMONY_DIR/state.json")
    if [ "$round" = "null" ] || [ -z "$round" ]; then
        echo -e "${RED}FATAL: no beacon round committed.${NC}" >&2
        echo -e "${RED}Run: ./scripts/ceremony.sh announce-beacon <round>  (≥7 days before finalize)${NC}" >&2
        exit 1
    fi
    if [ "$chain_hash" != "$DRAND_CHAIN_HASH" ]; then
        echo -e "${RED}FATAL: state.json beaconChainHash ($chain_hash) does not match script constant ($DRAND_CHAIN_HASH).${NC}" >&2
        echo -e "${RED}Either state.json was tampered with, or the script's pinned chain was changed without re-init.${NC}" >&2
        exit 1
    fi
    if [ "$pub_key" != "$DRAND_PUBLIC_KEY" ]; then
        echo -e "${RED}FATAL: state.json beaconPublicKey does not match script constant.${NC}" >&2
        echo -e "${RED}  state.json: $pub_key${NC}" >&2
        echo -e "${RED}  script:     $DRAND_PUBLIC_KEY${NC}" >&2
        exit 1
    fi

    # Don't try to fetch the round before its target time.
    expected_unix=$((DRAND_GENESIS_TIME + (round - 1) * DRAND_PERIOD))
    now_unix=$(date +%s)
    if [ "$now_unix" -lt "$expected_unix" ]; then
        echo -e "${RED}FATAL: too early to finalize. Beacon round $round expected at $expected_at.${NC}" >&2
        echo -e "${RED}Wait $((expected_unix - now_unix))s and retry.${NC}" >&2
        exit 1
    fi

    ensure_drand_deps
    echo -e "${BLUE}Fetching and verifying drand round $round on chain $chain_hash...${NC}"
    local beacon
    beacon=$(node "$SCRIPTS_DIR/verify-drand.js" "$chain_hash" "$pub_key" "$round")
    [ -n "$beacon" ] && [[ "$beacon" =~ ^[0-9a-f]{64}$ ]] || {
        echo -e "${RED}FATAL: verify-drand.js did not return a 64-char hex randomness.${NC}" >&2
        echo -e "${RED}Output was: $beacon${NC}" >&2
        exit 1
    }
    echo -e "${GREEN}  ✓ drand round $round verified, randomness = $beacon${NC}"

    for entry in "${CIRCUITS[@]}"; do
        local id final_name; id=$(field "$entry" 1); final_name=$(field "$entry" 4)
        local in="$CEREMONY_DIR/zkeys/${id}_$(printf '%04d' "$current").zkey"
        local out="$CEREMONY_DIR/zkeys/$final_name"
        echo -e "${BLUE}Applying drand beacon to ${CYAN}$id${NC}..."
        snarkjs zkey beacon "$in" "$out" "$beacon" 10 --name="DarkDrop final beacon (drand round $round)"
        snarkjs zkey export verificationkey "$out" "$CEREMONY_DIR/zkeys/${id%_v2}_verification_key.json"
    done

    jq --arg b "$beacon" --arg t "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        '.phase = "finalized" | .beacon = $b | .finalizedAt = $t' \
        "$CEREMONY_DIR/state.json" > "$CEREMONY_DIR/state.tmp" && mv "$CEREMONY_DIR/state.tmp" "$CEREMONY_DIR/state.json"

    cat <<EOF

${GREEN}Ceremony finalised.${NC}
Final zkeys are in: $CEREMONY_DIR/zkeys/
Verification keys: $CEREMONY_DIR/zkeys/*_verification_key.json
Beacon: $beacon (drand mainnet, round $round)

Production promotion is a separate, deliberate PR — do NOT copy these files into
circuits/build/, frontend/public/circuits/, or program/.../vk_new.rs from this script.
EOF
}

cmd_status() {
    banner
    [ -f "$CEREMONY_DIR/state.json" ] || { echo -e "${YELLOW}Ceremony not initialised. Run: ./scripts/ceremony.sh init${NC}"; exit 0; }
    jq . "$CEREMONY_DIR/state.json"
}

case "${1:-}" in
    init) cmd_init ;;
    announce-beacon) cmd_announce_beacon "${2:-}" ;;
    contribute) cmd_contribute "${2:-}" ;;
    verify) cmd_verify ;;
    finalize) cmd_finalize ;;
    status) cmd_status ;;
    *)
        banner
        cat <<EOF
Usage: ./scripts/ceremony.sh <command>

Commands:
  init                          Initialise ceremony (admin)
  announce-beacon <round>       Commit a future drand round (≥7d out) for finalize
  contribute "Your Name"        Add a phase-2 contribution
  verify                        Verify all contributions
  finalize                      Apply the pre-committed drand beacon, export final zkeys
  status                        Show ceremony state

Production promotion (copying final zkeys into circuits/build/, frontend/public/,
and regenerating program/.../vk_new.rs) is intentionally a separate PR — never
mutates source-controlled production paths from this script.
EOF
        ;;
esac
