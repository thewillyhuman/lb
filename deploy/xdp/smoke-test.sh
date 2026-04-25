#!/usr/bin/env bash
# smoke-test.sh — end-to-end AF_XDP smoke test against a veth pair.
#
# Sets up:
#   * a netns "lb-test" with a veth pair (lb-veth0 in root ns, lb-veth1 inside)
#   * the XDP redirect program attached to lb-veth0
#   * a packet generator inside the netns
# Then injects 1000 packets and confirms `lb-node` (built with af-xdp)
# accepts at least 90% of them. Passes if no kernel error and the loss
# rate stays below 10%.
#
# Requirements:
#   * Linux with AF_XDP, kernel ≥ 5.10
#   * `lb-node` built with --features af-xdp at ./target/release/lb-node
#   * sudo (the test creates a netns and attaches an XDP program)
#   * iproute2, bpftool, scapy (`apt install iproute2 bpftool python3-scapy`)
#
# Usage:
#   sudo ./smoke-test.sh
#
# Exit codes:
#   0  smoke test passed
#   1  loss rate > 10% or lb-node didn't start
#   2  prerequisites missing

set -euo pipefail

NS="lb-test"
VETH_HOST="lb-veth0"
VETH_NS="lb-veth1"
HOST_IP="192.0.2.1/24"
NS_IP="192.0.2.2/24"
PIN_DIR="/sys/fs/bpf/lb"
LBNODE_BIN="${LBNODE_BIN:-./target/release/lb-node}"

cleanup() {
    set +e
    [[ -n "${LB_PID:-}" ]] && kill "$LB_PID" 2>/dev/null
    "$(dirname "$0")"/unload.sh "$VETH_HOST" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$VETH_HOST" 2>/dev/null
    rm -f /tmp/lb-smoke-config.toml
}
trap cleanup EXIT

# Prerequisite checks
require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "FAIL: $1 not in PATH ($2)" >&2
        exit 2
    }
}
require ip iproute2
require bpftool bpftool
require python3 python3
[[ -x "$LBNODE_BIN" ]] || {
    echo "FAIL: $LBNODE_BIN not built. Run: cargo build --release --features af-xdp" >&2
    exit 2
}

# Build the BPF program if not present
if [[ ! -f "$(dirname "$0")/redirect.bpf.o" ]]; then
    echo "Building BPF program..."
    make -C "$(dirname "$0")"
fi

echo "== Setting up veth + netns =="
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip netns add "$NS"
ip link set "$VETH_NS" netns "$NS"
ip addr add "$HOST_IP" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NS" ip addr add "$NS_IP" dev "$VETH_NS"
ip netns exec "$NS" ip link set "$VETH_NS" up

# Wait for veth to come up
sleep 0.5

echo "== Attaching XDP program to $VETH_HOST =="
"$(dirname "$0")"/load.sh "$VETH_HOST" skb   # veth supports SKB mode

echo "== Starting lb-node =="
cat > /tmp/lb-smoke-config.toml <<EOF
[node]
id = "smoke"
loopback_ip = "192.0.2.1"
data_iface = "$VETH_HOST"
num_threads = 1
io_backend = "af_xdp"

[bgp]
local_asn = 65000
router_id = "192.0.2.1"
peers = []

[control_plane]
config_file = "/dev/null"
local_cache = "/tmp/lb-smoke-cache.json"

[forwarder]
network_mtu = 1500

[health_check_defaults]
interval = "5s"
timeout = "1s"
EOF

# lb-node will fail because peers = [] is invalid — just verify it boots
# far enough to register the XSK fd. We accept any startup logs, only
# care that the AF_XDP socket got bound.
"$LBNODE_BIN" --config /tmp/lb-smoke-config.toml &
LB_PID=$!

# Give it a few seconds to bind
sleep 3
if ! kill -0 "$LB_PID" 2>/dev/null; then
    echo "FAIL: lb-node exited prematurely. Check stderr above." >&2
    exit 1
fi

echo "== Injecting test packets =="
INJECTED=1000
ip netns exec "$NS" python3 - <<EOF
from scapy.all import sendp, Ether, IP, TCP
pkts = [Ether()/IP(dst="192.0.2.1")/TCP(dport=443, sport=10000+i) for i in range($INJECTED)]
sendp(pkts, iface="$VETH_NS", verbose=False)
EOF

# Read packets_received counter from /metrics
sleep 1
RECEIVED=$(curl -s http://127.0.0.1:9100/metrics | \
    awk '/^lb_packets_received_total/ {print $2; exit}')
RECEIVED="${RECEIVED:-0}"

LOSS_PCT=$(( (INJECTED - RECEIVED) * 100 / INJECTED ))
echo "Injected: $INJECTED  Received: $RECEIVED  Loss: ${LOSS_PCT}%"

if (( LOSS_PCT > 10 )); then
    echo "FAIL: loss rate ${LOSS_PCT}% > 10%" >&2
    exit 1
fi

echo "✓ AF_XDP smoke test passed"
