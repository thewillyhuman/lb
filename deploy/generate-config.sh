#!/usr/bin/env bash
# generate-config.sh — Generate an LB config JSON file from a template.
#
# Per ADR-001, the LB node reads its VIP/pool configuration from a local
# JSON file. This script generates that file from a simple YAML-like
# definition or from Foreman/Puppet hostgroup data.
#
# Usage:
#   ./generate-config.sh -o /etc/lb/lb-config.json \
#       -v vips.json -p pools.json
#
# Or generate an empty scaffold:
#   ./generate-config.sh --scaffold -o /etc/lb/lb-config.json

set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Generate an LB config JSON file (VIPs + pools).

Options:
  -o, --output FILE       Output file path (default: stdout)
  -v, --vips FILE         JSON file with VIP definitions
  -p, --pools FILE        JSON file with pool definitions
  --scaffold              Generate an empty scaffold config
  -h, --help              Show this help

Examples:
  # Generate a scaffold
  $(basename "$0") --scaffold -o /etc/lb/lb-config.json

  # Merge VIP and pool definitions
  $(basename "$0") -v vips.json -p pools.json -o /etc/lb/lb-config.json
EOF
    exit 0
}

OUTPUT=""
VIPS_FILE=""
POOLS_FILE=""
SCAFFOLD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)  OUTPUT="$2"; shift 2 ;;
        -v|--vips)    VIPS_FILE="$2"; shift 2 ;;
        -p|--pools)   POOLS_FILE="$2"; shift 2 ;;
        --scaffold)   SCAFFOLD=true; shift ;;
        -h|--help)    usage ;;
        *)            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

generate_scaffold() {
    cat <<'SCAFFOLD_EOF'
{
  "vips": [
    {
      "id": "example-vip",
      "address": "188.184.100.10",
      "services": [
        {
          "protocol": "tcp",
          "port": 443,
          "backend_pool": "example-pool"
        }
      ],
      "owner": "team-name",
      "description": "Example VIP for HTTPS traffic"
    }
  ],
  "pools": [
    {
      "id": "example-pool",
      "backends": [
        { "ip": "10.0.0.1", "port": 443, "weight": 1 },
        { "ip": "10.0.0.2", "port": 443, "weight": 1 }
      ],
      "health_check": {
        "interval": "5s",
        "timeout": "2s",
        "healthy_threshold": 2,
        "unhealthy_threshold": 3
      }
    }
  ]
}
SCAFFOLD_EOF
}

merge_configs() {
    local vips pools

    if [[ -n "$VIPS_FILE" ]]; then
        vips=$(cat "$VIPS_FILE")
    else
        vips="[]"
    fi

    if [[ -n "$POOLS_FILE" ]]; then
        pools=$(cat "$POOLS_FILE")
    else
        pools="[]"
    fi

    # Use python3 (available on CERN hosts) to merge JSON
    python3 -c "
import json, sys
vips = json.loads('''${vips}''')
pools = json.loads('''${pools}''')
config = {'vips': vips, 'pools': pools}
json.dump(config, sys.stdout, indent=2)
print()
"
}

# Generate the config
if $SCAFFOLD; then
    config=$(generate_scaffold)
else
    config=$(merge_configs)
fi

# Write output
if [[ -n "$OUTPUT" ]]; then
    # Atomic write: write to temp file then rename (per ADR-001 recommendation)
    tmp="${OUTPUT}.tmp.$$"
    echo "$config" > "$tmp"
    mv -f "$tmp" "$OUTPUT"
    echo "Config written to $OUTPUT"
else
    echo "$config"
fi
