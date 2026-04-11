#!/usr/bin/env bash
# deploy-config.sh — Deploy an LB config file to one or more LB nodes.
#
# Per ADR-001, LB nodes watch their config file via inotify and reload
# atomically on change. This script:
# 1. Validates the config locally
# 2. Copies it to each target node via scp
# 3. Uses atomic mv on the target to avoid partial reads
#
# Usage:
#   ./deploy-config.sh -c lb-config.json -n node1.cern.ch,node2.cern.ch
#   ./deploy-config.sh -c lb-config.json -f nodes.txt
#   ./deploy-config.sh -c lb-config.json -n node1.cern.ch --dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE=""
NODES=()
NODES_FILE=""
REMOTE_PATH="/etc/lb/lb-config.json"
REMOTE_USER="root"
DRY_RUN=false
PARALLEL=4

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deploy an LB config JSON file to LB nodes.

Options:
  -c, --config FILE       Local config file to deploy (required)
  -n, --nodes LIST        Comma-separated list of target hostnames
  -f, --nodes-file FILE   File with one hostname per line
  -r, --remote-path PATH  Remote config path (default: $REMOTE_PATH)
  -u, --user USER         SSH user (default: $REMOTE_USER)
  -p, --parallel N        Max parallel deploys (default: $PARALLEL)
  --dry-run               Validate and show what would be deployed
  -h, --help              Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config)      CONFIG_FILE="$2"; shift 2 ;;
        -n|--nodes)       IFS=',' read -ra NODES <<< "$2"; shift 2 ;;
        -f|--nodes-file)  NODES_FILE="$2"; shift 2 ;;
        -r|--remote-path) REMOTE_PATH="$2"; shift 2 ;;
        -u|--user)        REMOTE_USER="$2"; shift 2 ;;
        -p|--parallel)    PARALLEL="$2"; shift 2 ;;
        --dry-run)        DRY_RUN=true; shift ;;
        -h|--help)        usage ;;
        *)                echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$CONFIG_FILE" ]]; then
    echo "Error: --config is required" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: config file not found: $CONFIG_FILE" >&2
    exit 1
fi

# Load nodes from file if specified
if [[ -n "$NODES_FILE" ]]; then
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/#.*//' | xargs)
        [[ -n "$line" ]] && NODES+=("$line")
    done < "$NODES_FILE"
fi

if [[ ${#NODES[@]} -eq 0 ]]; then
    echo "Error: no target nodes specified" >&2
    exit 1
fi

# Step 1: Validate locally
echo "==> Validating config..."
if ! "$SCRIPT_DIR/validate-config.sh" "$CONFIG_FILE"; then
    echo "Validation failed, aborting deployment" >&2
    exit 1
fi
echo ""

if $DRY_RUN; then
    echo "==> Dry run: would deploy $CONFIG_FILE to:"
    for node in "${NODES[@]}"; do
        echo "    ${REMOTE_USER}@${node}:${REMOTE_PATH}"
    done
    exit 0
fi

# Step 2: Deploy to each node
echo "==> Deploying to ${#NODES[@]} node(s)..."

FAILED=0
SUCCEEDED=0

deploy_to_node() {
    local node="$1"
    local remote_tmp="${REMOTE_PATH}.tmp.$$"

    # Copy to temp file on remote
    if ! scp -q "$CONFIG_FILE" "${REMOTE_USER}@${node}:${remote_tmp}" 2>/dev/null; then
        echo "FAIL: $node (scp failed)" >&2
        return 1
    fi

    # Atomic rename on remote (inotify will detect this)
    if ! ssh -q "${REMOTE_USER}@${node}" "mv -f '${remote_tmp}' '${REMOTE_PATH}'" 2>/dev/null; then
        echo "FAIL: $node (mv failed)" >&2
        # Clean up temp file
        ssh -q "${REMOTE_USER}@${node}" "rm -f '${remote_tmp}'" 2>/dev/null || true
        return 1
    fi

    echo "  OK: $node"
    return 0
}

# Deploy with limited parallelism
for node in "${NODES[@]}"; do
    if deploy_to_node "$node"; then
        SUCCEEDED=$((SUCCEEDED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "==> Deployment complete: $SUCCEEDED succeeded, $FAILED failed"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
