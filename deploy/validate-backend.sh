#!/usr/bin/env bash
# validate-backend.sh — sanity-check a backend's DSR plumbing.
#
# Maglev does direct server return: clients send packets to a VIP, the LB
# rewrites only the destination IP (GRE-encapped), and the *backend*
# de-encapsulates and replies *directly to the client* — bypassing the LB
# on the return path. For this to work, every backend has to be configured
# with the right kernel knobs:
#
#   1. The VIP must be bound on the loopback interface (so the kernel
#      accepts packets addressed to the VIP after GRE decap), but NOT
#      ARP-advertised on the data interface (or both the LB and the
#      backend would respond, and the upstream router would send half
#      the traffic to the wrong host).
#   2. `rp_filter` must be relaxed on the data interface so the kernel
#      doesn't drop reply-path packets whose source IP doesn't match a
#      route through the same interface.
#   3. A GRE tunnel device must exist that knows to decap incoming GRE
#      packets and surface the inner payload to the kernel.
#   4. ARP behaviour on `lo` must be set to "don't reply on other ifaces"
#      (`arp_ignore=1`, `arp_announce=2`) so the VIP advertised by the
#      LB stays addressable.
#
# This script checks (1)–(4) for a given VIP and data interface. It is
# read-only by default — it neither configures nor fixes anything; it
# just reports each check as PASS / WARN / FAIL with the matching
# remediation command.
#
# Usage:
#   sudo ./validate-backend.sh <vip> [iface]
#
# Example:
#   sudo ./validate-backend.sh 188.184.100.10 eth0
#
# Exit codes:
#   0  every check passed (DSR backend is well-configured)
#   1  one or more FAILs — DSR will not work
#   2  warnings only — DSR will probably work but is fragile

set -euo pipefail

VIP="${1:-}"
IFACE="${2:-}"

if [[ -z "$VIP" ]]; then
    echo "usage: $0 <vip> [iface]" >&2
    echo "  e.g. $0 188.184.100.10 eth0" >&2
    exit 2
fi

# Auto-detect the default-route interface if the operator didn't pass one.
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip -j route show default 2>/dev/null | python3 -c \
        'import sys,json; r=json.load(sys.stdin); print(r[0]["dev"]) if r else exit(1)' 2>/dev/null || true)
    if [[ -z "$IFACE" ]]; then
        echo "could not auto-detect data interface; pass it explicitly" >&2
        exit 2
    fi
fi

fails=0
warns=0

pass()  { printf '  [\033[32mPASS\033[0m] %s\n' "$1"; }
warn()  { printf '  [\033[33mWARN\033[0m] %s\n' "$1"; warns=$((warns+1)); }
fail()  { printf '  [\033[31mFAIL\033[0m] %s\n' "$1"; fails=$((fails+1)); }

echo "== DSR backend check: VIP=$VIP iface=$IFACE =="

# 1. VIP bound on lo, not on the data interface ------------------------------
echo "1. VIP binding"
if ip -4 addr show dev lo | grep -qE "inet ${VIP}/32 "; then
    pass "$VIP is bound on lo as /32"
else
    fail "$VIP is NOT bound on lo as /32 — fix:  ip addr add ${VIP}/32 dev lo"
fi

if ip -4 addr show dev "$IFACE" | grep -qE "inet ${VIP}/"; then
    fail "$VIP is also bound on $IFACE — DSR ARP collision; fix: ip addr del ${VIP}/<prefix> dev ${IFACE}"
else
    pass "$VIP is not bound on $IFACE"
fi

# 2. rp_filter relaxed -------------------------------------------------------
echo "2. Reverse path filter"
read_sysctl() { sysctl -n "$1" 2>/dev/null || echo "?"; }
all_rpf=$(read_sysctl "net.ipv4.conf.all.rp_filter")
ifc_rpf=$(read_sysctl "net.ipv4.conf.${IFACE}.rp_filter")
# Effective rp_filter is the *max* of all and per-iface (per kernel docs).
if [[ "$all_rpf" == "0" && "$ifc_rpf" == "0" ]]; then
    pass "rp_filter relaxed on all and $IFACE"
elif [[ "$all_rpf" == "2" && "$ifc_rpf" == "2" ]]; then
    pass "rp_filter is loose mode (2) on all and $IFACE — accepts asymmetric returns"
else
    warn "rp_filter is strict (all=$all_rpf, $IFACE=$ifc_rpf); set to 0 or 2 in /etc/sysctl.d/lb-dsr.conf"
fi

# 3. GRE decap tunnel device -------------------------------------------------
echo "3. GRE decap tunnel"
if ip -d link show type gre 2>/dev/null | grep -q "gre"; then
    pass "GRE tunnel device(s) present"
else
    fail "no GRE tunnel device — fix:  ip tunnel add lb-gre mode gre local <node-ip> remote <lb-loopback>; ip link set lb-gre up"
fi

# Linux's "gre" module needs to be loaded for inbound GRE on a bare device
# to be accepted; check.
if lsmod 2>/dev/null | grep -qE "^(ip_gre|gre) "; then
    pass "ip_gre kernel module loaded"
else
    warn "ip_gre kernel module not loaded — fix:  modprobe ip_gre"
fi

# 4. ARP suppression for the loopback VIP -----------------------------------
echo "4. ARP behaviour"
arp_ignore_lo=$(read_sysctl "net.ipv4.conf.lo.arp_ignore")
arp_ignore_all=$(read_sysctl "net.ipv4.conf.all.arp_ignore")
arp_announce_lo=$(read_sysctl "net.ipv4.conf.lo.arp_announce")
arp_announce_all=$(read_sysctl "net.ipv4.conf.all.arp_announce")

# Effective is max(all, iface) for both knobs; we want all/lo at 1/2.
if [[ "$arp_ignore_lo" -ge 1 && "$arp_ignore_all" -ge 1 ]]; then
    pass "arp_ignore set (lo=$arp_ignore_lo, all=$arp_ignore_all)"
else
    fail "arp_ignore should be 1 (lo=$arp_ignore_lo, all=$arp_ignore_all) — fix in /etc/sysctl.d/lb-dsr.conf"
fi

if [[ "$arp_announce_lo" -ge 2 && "$arp_announce_all" -ge 2 ]]; then
    pass "arp_announce set (lo=$arp_announce_lo, all=$arp_announce_all)"
else
    fail "arp_announce should be 2 (lo=$arp_announce_lo, all=$arp_announce_all) — fix in /etc/sysctl.d/lb-dsr.conf"
fi

# 5. Routing sanity ---------------------------------------------------------
# The default route should NOT be via the VIP (would loop back at us).
echo "5. Routing"
if ip -4 route show default | grep -q "via ${VIP}"; then
    fail "default route via $VIP — would loop traffic back; check route configuration"
else
    pass "default route does not go via $VIP"
fi

# Summary -------------------------------------------------------------------
echo
echo "== Result =="
if (( fails > 0 )); then
    printf 'DSR is NOT correctly configured: %d fail(s), %d warning(s).\n' "$fails" "$warns"
    cat <<EOF

Suggested /etc/sysctl.d/lb-dsr.conf (apply with sysctl -p /etc/sysctl.d/lb-dsr.conf):

  net.ipv4.conf.all.rp_filter = 0
  net.ipv4.conf.${IFACE}.rp_filter = 0
  net.ipv4.conf.all.arp_ignore = 1
  net.ipv4.conf.lo.arp_ignore = 1
  net.ipv4.conf.all.arp_announce = 2
  net.ipv4.conf.lo.arp_announce = 2

VIP binding (in your interface management — e.g. /etc/network/interfaces or
systemd-networkd):

  ip addr add ${VIP}/32 dev lo

GRE tunnel (one-shot):

  ip tunnel add lb-gre mode gre local <this-node-ip> remote <lb-node-loopback>
  ip link set lb-gre up

EOF
    exit 1
elif (( warns > 0 )); then
    printf 'DSR setup is mostly correct but has %d warning(s) — review above.\n' "$warns"
    exit 2
else
    printf 'DSR backend is well-configured for VIP %s on %s.\n' "$VIP" "$IFACE"
    exit 0
fi
