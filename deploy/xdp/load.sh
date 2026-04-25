#!/usr/bin/env bash
# load.sh — attach the XDP redirect program for lb-node and pin the
# XSKMAP at a known path so lb-node can populate it at startup.
#
# Run **once on the host**, before `systemctl start lb-node`. The
# program stays attached across lb-node restarts; only re-run this if
# you changed `redirect.bpf.c` or rebooted the host.
#
# Usage:
#   sudo ./load.sh <iface> [mode]
#
#   <iface>  Data interface (matches `[node].data_iface` in lb-node.toml).
#   [mode]   xdp attach mode: `native` (default), `skb`, or `hw`.
#            Use `native` on supported NICs (Intel ixgbe/i40e/ice,
#            Mellanox CX-4+, AWS ENA). `skb` is the kernel fallback —
#            slower but works everywhere. `hw` requires NIC offload
#            support (most don't).
#
# Effect:
#   * Compiles redirect.bpf.o if missing (`make`).
#   * Attaches the program to <iface> in the chosen mode.
#   * Pins the XSKMAP at /sys/fs/bpf/lb/xsks_map so lb-node can
#     locate it via BPF_OBJ_GET (todo: in-process).
#
# To unload:
#   sudo ./unload.sh <iface>

set -euo pipefail

IFACE="${1:-}"
MODE="${2:-native}"

if [[ -z "$IFACE" ]]; then
    echo "usage: $0 <iface> [native|skb|hw]" >&2
    exit 2
fi

case "$MODE" in
    native|skb|hw) ;;
    *) echo "mode must be one of: native, skb, hw" >&2; exit 2 ;;
esac

cd "$(dirname "$0")"

# Build the object file if it isn't already present.
if [[ ! -f redirect.bpf.o ]]; then
    echo "redirect.bpf.o not present, building..."
    make
fi

# Make sure the bpffs is mounted; some minimal images don't have it.
if ! mountpoint -q /sys/fs/bpf; then
    echo "mounting bpffs at /sys/fs/bpf"
    mount -t bpf bpf /sys/fs/bpf
fi

# Pin path for the XSKMAP. lb-node will look here at startup (in-process
# load is a follow-up; for now an operator script populates the map).
PIN_DIR="/sys/fs/bpf/lb"
mkdir -p "$PIN_DIR"

# Detach any prior program — re-running load.sh shouldn't fail because
# something is already attached.
ip link set dev "$IFACE" xdp${MODE} off 2>/dev/null || true

# Load the program with bpftool. `pinmaps` parks every map (here just
# `xsks_map`) under PIN_DIR.
bpftool prog loadall redirect.bpf.o "$PIN_DIR/prog" \
    type xdp pinmaps "$PIN_DIR"

# Attach the program to the interface.
ip link set dev "$IFACE" xdp${MODE} pinned "$PIN_DIR/prog/lb_redirect"

echo "✓ XDP redirect program attached to $IFACE ($MODE mode)"
echo "  XSKMAP pinned at $PIN_DIR/xsks_map"
echo
echo "Next: start lb-node. To populate xsks_map manually for queue 0:"
echo "  bpftool map update pinned $PIN_DIR/xsks_map key 0 0 0 0 \\"
echo "                          value 0 0 0 0  # replace with XSK fd"
echo
echo "(in-process map population lands in a follow-up commit —"
echo " until then, lb-node logs the XSK fd at startup and the operator"
echo " runs the bpftool map update once.)"
