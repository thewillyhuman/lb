#!/usr/bin/env bash
# validate-config.sh — Validate an LB config JSON file before deployment.
#
# Checks:
# 1. JSON is well-formed
# 2. Required fields are present
# 3. No dangling pool references (VIP → pool)
# 4. No empty backend pools
# 5. IP addresses are valid
#
# Usage:
#   ./validate-config.sh /etc/lb/lb-config.json
#   ./validate-config.sh --strict /etc/lb/lb-config.json

set -euo pipefail

STRICT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict)  STRICT=true; shift ;;
        -h|--help)
            echo "Usage: $(basename "$0") [--strict] <config-file>"
            echo ""
            echo "Validate an LB config JSON file."
            echo ""
            echo "Options:"
            echo "  --strict    Treat warnings as errors"
            exit 0
            ;;
        *)
            CONFIG_FILE="$1"; shift ;;
    esac
done

if [[ -z "${CONFIG_FILE:-}" ]]; then
    echo "Error: config file path required" >&2
    echo "Usage: $(basename "$0") [--strict] <config-file>" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "FAIL: file not found: $CONFIG_FILE" >&2
    exit 1
fi

ERRORS=0
WARNINGS=0

error() {
    echo "ERROR: $1" >&2
    ERRORS=$((ERRORS + 1))
}

warn() {
    echo "WARN:  $1" >&2
    WARNINGS=$((WARNINGS + 1))
}

ok() {
    echo "OK:    $1"
}

# 1. Check JSON is valid
if ! python3 -c "import json; json.load(open('$CONFIG_FILE'))" 2>/dev/null; then
    error "invalid JSON"
    echo ""
    echo "Validation failed: $ERRORS error(s)" >&2
    exit 1
fi
ok "valid JSON"

# 2. Structural validation using python3
python3 - "$CONFIG_FILE" "$STRICT" <<'PYEOF'
import json
import sys
import ipaddress

config_file = sys.argv[1]
strict = sys.argv[2] == "True"

with open(config_file) as f:
    config = json.load(f)

errors = 0
warnings = 0

def error(msg):
    global errors
    print(f"ERROR: {msg}", file=sys.stderr)
    errors += 1

def warn(msg):
    global warnings
    print(f"WARN:  {msg}", file=sys.stderr)
    warnings += 1

def ok(msg):
    print(f"OK:    {msg}")

# Check top-level structure
if "vips" not in config:
    error("missing 'vips' array")
if "pools" not in config:
    error("missing 'pools' array")

vips = config.get("vips", [])
pools = config.get("pools", [])

ok(f"found {len(vips)} VIP(s) and {len(pools)} pool(s)")

# Build pool index
pool_ids = set()
for pool in pools:
    pid = pool.get("id", "")
    if not pid:
        error("pool missing 'id' field")
        continue
    if pid in pool_ids:
        error(f"duplicate pool ID: '{pid}'")
    pool_ids.add(pid)

    backends = pool.get("backends", [])
    if not backends:
        error(f"pool '{pid}' has no backends")

    for i, b in enumerate(backends):
        ip = b.get("ip", "")
        if not ip:
            error(f"pool '{pid}' backend {i}: missing 'ip'")
        else:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                error(f"pool '{pid}' backend {i}: invalid IP '{ip}'")

        if "port" not in b:
            error(f"pool '{pid}' backend {i}: missing 'port'")

# Validate VIPs
vip_ids = set()
for vip in vips:
    vid = vip.get("id", "")
    if not vid:
        error("VIP missing 'id' field")
        continue
    if vid in vip_ids:
        error(f"duplicate VIP ID: '{vid}'")
    vip_ids.add(vid)

    addr = vip.get("address", "")
    if not addr:
        error(f"VIP '{vid}': missing 'address'")
    else:
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            error(f"VIP '{vid}': invalid address '{addr}'")

    services = vip.get("services", [])
    if not services:
        warn(f"VIP '{vid}' has no services")

    for svc in services:
        pool_ref = svc.get("backend_pool", "")
        if pool_ref and pool_ref not in pool_ids:
            error(f"VIP '{vid}' references pool '{pool_ref}' which does not exist")

        if "port" not in svc:
            error(f"VIP '{vid}' service: missing 'port'")

# Summary
print()
if errors > 0:
    print(f"Validation FAILED: {errors} error(s), {warnings} warning(s)", file=sys.stderr)
    sys.exit(1)
elif strict and warnings > 0:
    print(f"Validation FAILED (strict): {warnings} warning(s)", file=sys.stderr)
    sys.exit(1)
else:
    print(f"Validation PASSED: {errors} error(s), {warnings} warning(s)")
    sys.exit(0)
PYEOF
