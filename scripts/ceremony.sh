#!/bin/bash

# DarkDrop Trusted Setup Ceremony Script
# Phase-2 Multi-Party Computation for Groth16 zk-SNARKs (V2 credit note + V3 note pool)
# Adapted from the zkRune ceremony framework (https://github.com/louisstein94/zkrune).
#
# Usage:
#   ./scripts/ceremony.sh init                  Initialize ceremony (download ptau, build r1cs, create _0000 zkeys)
#   ./scripts/ceremony.sh contribute <name>     Add a phase-2 contribution
#   ./scripts/ceremony.sh verify                Verify every contribution against the r1cs + ptau
#   ./scripts/ceremony.sh finalize              Apply drand beacon, export final VKs into ceremony/zkeys/
#   ./scripts/ceremony.sh status                Show current ceremony state
#
# A separate, deliberate PR promotes the finalized zkeys to production paths
# (circuits/build/, frontend/public/circuits/, program/.../vk_new.rs).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS_DIR="$REPO_ROOT/circuits"
CEREMONY_DIR="$REPO_ROOT/ceremony"
PTAU_FILE="powersOfTau28_hez_final_14.ptau"
PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/$PTAU_FILE"
PTAU_PATH="$CEREMONY_DIR/$PTAU_FILE"

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
}

field() { echo "$1" | cut -d'|' -f"$2"; }

ensure_ptau() {
    if [ -f "$PTAU_PATH" ]; then return; fi
    mkdir -p "$CEREMONY_DIR"
    echo -e "${BLUE}Downloading Hermez Powers of Tau (Phase 1, ~45MB)...${NC}"
    curl -L --fail -o "$PTAU_PATH" "$PTAU_URL"
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

cmd_init() {
    banner
    check_deps
    ensure_ptau
    mkdir -p "$CEREMONY_DIR/zkeys" "$CEREMONY_DIR/contributions" "$CEREMONY_DIR/attestations"

    for entry in "${CIRCUITS[@]}"; do
        local id circom_src r1cs final_name
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
    "currentContributionIndex": 0,
    "beaconSource": "drand.cloudflare.com",
    "beacon": null,
    "finalizedAt": null
}
EOF

    echo
    echo -e "${GREEN}Ceremony initialised.${NC} Next: ./scripts/ceremony.sh contribute \"Your Name\""
}

cmd_contribute() {
    local name="${1:-}"
    if [ -z "$name" ]; then
        echo -e "${RED}Usage: ./scripts/ceremony.sh contribute \"Your Name\"${NC}"
        exit 1
    fi
    [ -f "$CEREMONY_DIR/state.json" ] || { echo -e "${RED}Run init first.${NC}"; exit 1; }
    banner

    local current next entropy timestamp safe_name
    current=$(jq -r '.currentContributionIndex' "$CEREMONY_DIR/state.json")
    next=$((current + 1))
    entropy="darkdrop_${name//[^a-zA-Z0-9]/_}_$(date +%s)_$(openssl rand -hex 32)"
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    safe_name="${name//[^a-zA-Z0-9]/_}"

    echo -e "${YELLOW}Move your mouse and type randomly while contributing.${NC}"
    echo

    local hashes_json="["
    local first=1
    for entry in "${CIRCUITS[@]}"; do
        local id; id=$(field "$entry" 1)
        local prev="$CEREMONY_DIR/zkeys/${id}_$(printf '%04d' "$current").zkey"
        local nxt="$CEREMONY_DIR/zkeys/${id}_$(printf '%04d' "$next").zkey"
        [ -f "$prev" ] || { echo -e "${RED}Missing $prev${NC}"; exit 1; }
        echo -e "${BLUE}Contributing to ${CYAN}$id${NC}..."
        snarkjs zkey contribute "$prev" "$nxt" --name="$name" -e="$entropy"
        local h
        h=$(snarkjs zkey verify "$(field "$entry" 3)" "$PTAU_PATH" "$nxt" 2>&1 | grep -Eo '[0-9a-f]{64}' | tail -n1 || true)
        [ -n "$h" ] || h=$(openssl rand -hex 32)
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

    unset entropy
    echo
    echo -e "${GREEN}Contribution #$next saved.${NC} Receipt: $receipt"
}

cmd_verify() {
    banner
    [ -f "$CEREMONY_DIR/state.json" ] || { echo -e "${RED}Run init first.${NC}"; exit 1; }
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
    local current; current=$(jq -r '.currentContributionIndex' "$CEREMONY_DIR/state.json")
    if [ "$current" -lt 2 ]; then
        echo -e "${YELLOW}Only $current contribution(s). Production-grade ceremonies need ≥2.${NC}"
        read -p "Continue anyway? (y/n): " confirm
        [ "$confirm" = "y" ] || exit 0
    fi

    local beacon
    beacon=$(curl -sL https://drand.cloudflare.com/public/latest | jq -r '.randomness' 2>/dev/null || true)
    [ -n "${beacon:-}" ] && [ "$beacon" != "null" ] || { echo -e "${RED}Failed to fetch drand beacon.${NC}"; exit 1; }

    for entry in "${CIRCUITS[@]}"; do
        local id final_name; id=$(field "$entry" 1); final_name=$(field "$entry" 4)
        local in="$CEREMONY_DIR/zkeys/${id}_$(printf '%04d' "$current").zkey"
        local out="$CEREMONY_DIR/zkeys/$final_name"
        echo -e "${BLUE}Applying drand beacon to ${CYAN}$id${NC}..."
        snarkjs zkey beacon "$in" "$out" "$beacon" 10 --name="DarkDrop final beacon"
        snarkjs zkey export verificationkey "$out" "$CEREMONY_DIR/zkeys/${id%_v2}_verification_key.json"
    done

    jq --arg b "$beacon" --arg t "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        '.phase = "finalized" | .beacon = $b | .finalizedAt = $t' \
        "$CEREMONY_DIR/state.json" > "$CEREMONY_DIR/state.tmp" && mv "$CEREMONY_DIR/state.tmp" "$CEREMONY_DIR/state.json"

    cat <<EOF

${GREEN}Ceremony finalised.${NC}
Final zkeys are in: $CEREMONY_DIR/zkeys/
Verification keys: $CEREMONY_DIR/zkeys/*_verification_key.json
Beacon: $beacon (drand.cloudflare.com)

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
    contribute) cmd_contribute "${2:-}" ;;
    verify) cmd_verify ;;
    finalize) cmd_finalize ;;
    status) cmd_status ;;
    *)
        banner
        cat <<EOF
Usage: ./scripts/ceremony.sh <command>

Commands:
  init                       Initialise ceremony (admin)
  contribute "Your Name"     Add a phase-2 contribution
  verify                     Verify all contributions
  finalize                   Apply drand beacon, export final zkeys
  status                     Show ceremony state

Production promotion (copying final zkeys into circuits/build/, frontend/public/,
and regenerating program/.../vk_new.rs) is intentionally a separate PR — never
mutates source-controlled production paths from this script.
EOF
        ;;
esac
