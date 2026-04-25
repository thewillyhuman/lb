// Minimal XDP redirect program for `lb-node`'s AF_XDP backend.
//
// What it does:
//   * Looks up the RX queue index from the XDP context.
//   * `bpf_redirect_map` into the per-queue XSKMAP entry. If `lb-node`
//     has bound an AF_XDP socket on that queue, the redirect succeeds
//     and the packet lands in the userspace ring. If no socket is
//     present (e.g. the LB process is starting up or down), the packet
//     falls through to XDP_PASS and the kernel stack handles it.
//
// What it deliberately does NOT do:
//   * No L2/L3 filtering. Steering by MAC or IP belongs in the userspace
//     `VipMatcher`, which has the full configured-VIP set. Doing it
//     here would mean compiling and reloading the BPF program on every
//     config reload — a much bigger blast radius.
//   * No counters / observability. Every packet that reaches `lb-node`
//     is already counted by `lb_packets_received_total`. Adding a BPF
//     map for stats would just duplicate that.
//
// Build with:
//   make -C deploy/xdp
//
// Or directly:
//   clang -O2 -g -target bpf -c deploy/xdp/redirect.bpf.c \
//         -o deploy/xdp/redirect.bpf.o
//
// Then load with `deploy/xdp/load.sh <iface>`.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// XSKMAP: kernel→userspace dispatch. Indexed by RX queue id.
//
// Operators populate this map after attaching: for each queue id i
// served by an `lb-node` rewriter, write the AF_XDP socket fd into
// `xsks_map[i]`. `deploy/xdp/load.sh` does this via `bpftool map update`.
//
// `max_entries = 64` covers the worst case of a 64-queue NIC. Bumping
// it later is a build-time change, not a runtime one.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int lb_redirect(struct xdp_md *ctx)
{
    // `bpf_redirect_map` looks up `ctx->rx_queue_index` in xsks_map. If
    // the entry holds a valid XSK fd, the verifier-emitted code returns
    // XDP_REDIRECT; if not, BPF_F_DROP would drop, but we want
    // XDP_PASS so the host stack stays usable for SSH / health checks /
    // BGP control-plane traffic. Pass `0` flags so the helper falls
    // back to XDP_PASS on map-miss.
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

char LICENSE[] SEC("license") = "GPL";
