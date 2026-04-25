#!/usr/bin/env bash
# unload.sh — detach the XDP redirect program and clean up pinned maps.
#
# Usage:
#   sudo ./unload.sh <iface>
#
# Safe to run multiple times. Leaves the bpffs mount in place — that's
# host-wide state, not ours to tear down.

set -euo pipefail

IFACE="${1:-}"
PIN_DIR="/sys/fs/bpf/lb"

if [[ -z "$IFACE" ]]; then
    echo "usage: $0 <iface>" >&2
    exit 2
fi

# Detach in all three modes; whichever was attached takes effect, the
# others are no-ops.
ip link set dev "$IFACE" xdpnative off 2>/dev/null || true
ip link set dev "$IFACE" xdpskb off 2>/dev/null || true
ip link set dev "$IFACE" xdphw off 2>/dev/null || true

# Drop the pinned program + map.
if [[ -d "$PIN_DIR" ]]; then
    rm -rf "$PIN_DIR"
fi

echo "✓ detached XDP from $IFACE and removed $PIN_DIR"
