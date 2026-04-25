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
#   [mode]   xdp attach mode:
#            `auto`   (default) — try `native` first, fall back to `skb`
#                     if the driver doesn't support it. This honours the
#                     project's commodity-hardware constraint: no NIC is
#                     too old to run lb-node. Throughput on `skb` is
#                     ~30–40% lower than `native`, but every kernel
#                     ≥ 5.10 supports it.
#            `native` — driver-attached XDP (Intel ixgbe/i40e/ice,
#                     Mellanox CX-4+, AWS ENA, virtio-net 5.13+, …).
#                     Higher throughput; fails fast if the driver
#                     doesn't support it.
#            `skb`    — generic kernel-side XDP. Works everywhere,
#                     including veth/tun/loopback for tests. Slower.
#            `hw`     — full NIC offload. Requires SmartNIC support
#                     (Netronome/Corigine and a few others). Out of
#                     scope for the commodity-hardware deployment
#                     target — pass explicitly only if you know your
#                     NIC supports it.
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
MODE="${2:-auto}"

if [[ -z "$IFACE" ]]; then
    echo "usage: $0 <iface> [auto|native|skb|hw]" >&2
    exit 2
fi

case "$MODE" in
    auto|native|skb|hw) ;;
    *) echo "mode must be one of: auto, native, skb, hw" >&2; exit 2 ;;
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

# Detach any prior program in any mode — re-running load.sh shouldn't
# fail because something is already attached.
for m in native skb hw; do
    ip link set dev "$IFACE" xdp${m} off 2>/dev/null || true
done

# Load the program with bpftool. `pinmaps` parks every map (here just
# `xsks_map`) under PIN_DIR.
bpftool prog loadall redirect.bpf.o "$PIN_DIR/prog" \
    type xdp pinmaps "$PIN_DIR"

# Attach. In `auto` mode, try native first and fall back to skb when the
# driver doesn't support it — this is the commodity-hardware path: every
# kernel ≥ 5.10 supports skb mode regardless of NIC vendor or vintage.
attach() {
    local m="$1"
    ip link set dev "$IFACE" xdp${m} pinned "$PIN_DIR/prog/lb_redirect" 2>&1
}

ATTACHED=""
case "$MODE" in
    auto)
        if attach native >/dev/null 2>&1; then
            ATTACHED="native"
        else
            echo "  driver does not support native XDP on $IFACE, falling back to skb"
            if attach skb >/dev/null 2>&1; then
                ATTACHED="skb"
            else
                echo "FAIL: could not attach in either native or skb mode" >&2
                attach skb >&2
                exit 1
            fi
        fi
        ;;
    *)
        if ! attach "$MODE" >&2; then
            echo "FAIL: could not attach in $MODE mode" >&2
            exit 1
        fi
        ATTACHED="$MODE"
        ;;
esac

echo "✓ XDP redirect program attached to $IFACE ($ATTACHED mode)"
echo "  XSKMAP pinned at $PIN_DIR/xsks_map"
echo
echo "Next: start lb-node. To populate xsks_map manually for queue 0:"
echo "  bpftool map update pinned $PIN_DIR/xsks_map key 0 0 0 0 \\"
echo "                          value 0 0 0 0  # replace with XSK fd"
echo
echo "(in-process map population lands in a follow-up commit —"
echo " until then, lb-node logs the XSK fd at startup and the operator"
echo " runs the bpftool map update once.)"
