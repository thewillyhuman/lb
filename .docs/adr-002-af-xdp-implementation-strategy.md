# ADR-002: AF_XDP implementation strategy

**Status:** accepted
**Date:** 2026-04-20
**Deciders:** maintainers

## Context

The data plane today runs on `lb-io::mock::MockIo` (in-memory queues, useful
for tests but not for line-rate traffic) and ships a scaffold AF_XDP backend
at `crates/lb-io/src/af_xdp.rs` that opens an `AF_XDP` socket and registers
UMEM memory but performs the actual RX/TX path through `recvfrom`/`sendto`
syscalls. That hits roughly 1 Mpps on a single core — an order of magnitude
short of the 10–12 Mpps the rest of the design assumes (Maglev hashing
benchmarks at 0.79 ns/lookup, the rewriter pipeline at ~400 ns/packet
end-to-end through `MockIo`).

A previous DPDK scaffold has been deleted (PR 8) so AF_XDP is the only
production-direction kernel-bypass option in the tree. This ADR locks in
the implementation approach for the remaining work.

## Decision drivers

1. **Throughput target**: 10 Mpps per node, leaving headroom for ECMP-driven
   bursts and the GRE encap overhead (~24 bytes / packet).
2. **Time budget**: ~1–2 engineer-weeks, not a multi-month rewrite. The
   project already has the surrounding infrastructure (per-thread rewriter
   loop, packet pool, completion queues mirroring the AF_XDP UMEM model).
3. **Operational surface**: minimum new tooling. The deploy story is
   already systemd + capabilities; we don't want to require operators to
   install a userspace runtime (DPDK), recompile a kernel, or maintain
   a parallel BPF toolchain build.
4. **Maintenance burden**: the bytes-on-the-wire layer should be a thin
   adapter, not a project of its own. Long-lived investment goes into the
   forwarder/control plane where the differentiated logic lives.
5. **Portability**: ARM64 must remain a first-class target alongside
   x86_64 — the release workflow ships both. Anything pinned to Intel
   intrinsics or x86-only XDP features is out.

## Options considered

### Option A — Hand-roll the XSK ring plumbing against `libbpf-sys`

Implement `xsk_ring_cons__peek` / `xsk_ring_prod__reserve` ourselves, drive
the FILL and COMPLETION rings, and load a minimal XDP redirect program
via `libbpf` to dispatch packets onto our XSK socket.

* **Pros**: zero-dependency on third-party Rust crates; full control over
  the ring layout; can co-locate fixes with the rest of `lb-io`.
* **Cons**: AF_XDP is a moving target (`xsk.h` was deprecated in libxdp
  1.0); we'd be re-implementing what `libxdp` and `xdpilone`/`aya` already
  expose. Burn rate is high — every kernel quirk (pacing-on-busy-poll,
  the `XDP_USE_NEED_WAKEUP` dance, BPF prog reload semantics) becomes our
  bug.

### Option B — Adopt `xdpilone`

`xdpilone` (formerly `xsk-rs`) is a maintained Rust crate that wraps
`libxdp`'s XSK API directly. As of 2026-Q1 it builds cleanly on stable
Rust, supports both `aarch64` and `x86_64`, and has a working zero-copy
example.

* **Pros**: thin layer (~3 kLOC of safe Rust over `libxdp`); survives
  kernel-side API churn because `libxdp` does; matches the surrounding
  code's style (no `unsafe` in our wrapper). Reduces the AF_XDP impl to
  "wire xdpilone's `Socket`/`Umem`/`Ring` types into `lb-io::PacketIo`".
* **Cons**: pulls in `libxdp` and `libbpf` as system deps; the `BUILD.md`
  lists them as install steps. Not in `crates.io` allowlist by default
  but `xdpilone` itself is published.

### Option C — Adopt `aya-xdp`

`aya` is a pure-Rust BPF toolchain; `aya-xdp` is the equivalent of
`xdpilone` built on it.

* **Pros**: pure Rust, no `libbpf` system dep. Strong story for loading
  the redirect BPF program from the same project that uses it.
* **Cons**: heavier (~30 kLOC); the AF_XDP coverage is newer and less
  battle-tested than `libxdp`'s. Documentation is API-reference-only;
  worked examples for AF_XDP zero-copy are scarce.

### Option D — Stick with the syscall-based scaffold

Treat the existing `recvfrom`/`sendto` path as good enough and document
the throughput ceiling. Optionally add `BUSY_POLL`/`SO_PREFER_BUSY_POLL`
tuning to claw back another ~20%.

* **Pros**: zero new code or deps. Already passes the unit tests.
* **Cons**: caps the project at ~1 Mpps per core. The whole point of
  Maglev (and of having a ~400 ns/packet rewriter) is undone by spending
  ~30 µs per packet on syscalls. This violates decision driver #1.

## Decision

**Option B — adopt `xdpilone`.**

It's the only choice that hits the 10 Mpps target without committing
multiple weeks to ring-plumbing maintenance, and the dependency footprint
(`libxdp` + `libbpf`) is already required by any production AF_XDP user.

The work breaks into three commits, sized for one week of engineering.

### Commit 1 — `lb-io`: replace the syscall path

* Add `xdpilone` to `lb-io`'s `Cargo.toml` (Linux-only via `cfg(target_os = "linux")`).
* Replace the `recvfrom`/`sendto` body in `AfXdpIo::recv_batch` /
  `send_batch` with `xdpilone` ring drains. Frame layout: 2048-byte UMEM
  frames, FILL ring sized to `2 × QUEUE_CAPACITY`, COMPLETION ring sized
  to `2 × QUEUE_CAPACITY`. `XDP_USE_NEED_WAKEUP` enabled.
* Map `xdpilone`'s descriptor/buffer split onto our existing `PacketBuf`
  trait by pointing `PacketBuf` at the UMEM frame address; the rewriter
  hot path stays unchanged.
* On non-Linux, the existing `cfg`-gated stub stays — `AfXdpIo::new`
  returns `Unsupported` and operators see the same boot-time error they
  see today.

### Commit 2 — XDP redirect program load

* Compile a minimal XDP redirect program (5–10 instructions) from C via
  the existing `bindgen` build dep, or hand-write the BPF bytecode (it's
  short enough). The program inspects only the destination MAC; if it
  matches the configured data interface, it `bpf_redirect_map`s onto the
  XSKMAP. Anything else passes through XDP_PASS so the host stack still
  works for control traffic.
* `AfXdpIo::new` loads the program via `libxdp` (also via `xdpilone`),
  attaches to `data_iface`, and binds a per-queue XSK socket. RX queue ID
  is per rewriter thread.
* Detach on `Drop` so a clean shutdown leaves the interface in its
  pre-LB state. No leaked attached programs.

### Commit 3 — operations and benchmarks

* Update `.docs/operations.md` with the AF_XDP setup: kernel ≥5.10,
  required NIC features (`XDP-flags HW`, `Channels combined N`),
  IRQ pinning to match `[node.cpu_affinity].rewriters`, `LimitMEMLOCK`
  bumping in the systemd unit.
* Extend `forwarding_bench` with an AF_XDP scenario behind a feature
  flag (`#[cfg(feature = "af-xdp-bench")]`) that exercises the full
  pipeline against a `veth` pair. CI keeps the existing `MockIo`
  benches; the AF_XDP bench runs only when the feature flag is set.
* Document the throughput delta in the bench output. Target: 10 Mpps
  per rewriter on a Mellanox CX-5 / Intel E810-class NIC.

### Things deliberately deferred

* **Hardware offload** of the redirect program (`XDP_FLAGS_HW_MODE`):
  vendor-specific, can ship in a follow-up.
* **Multi-queue per rewriter**: the rewriter is single-threaded; one
  queue per rewriter is the obvious mapping. Combining queues at the LB
  level only matters if the NIC can't expose one queue per core.
* **AF_XDP busy-poll**: tradeoff against batching latency; revisit
  after the bench numbers land.

## Consequences

* The crates.io allowlist in `deny.toml` will grow by `xdpilone` (and its
  transitive deps, currently 6 crates total). All MIT/Apache-2.0.
* `BUILD.md` (or operations.md's installation section) gains a Linux-only
  prerequisite step: `apt install libxdp-dev libbpf-dev`. macOS dev
  builds keep working because the AF_XDP code is `cfg`-gated.
* Container image will need either matching base packages or a static
  build; the `release.yml` musl path can keep working if we vendor the
  AF_XDP-only crate behind a feature gate (default off for the standard
  release tarball, on for the production AF_XDP image).
* Once Commit 3 lands, the `mock` backend should be flagged as
  test-only in operations.md and the default `[node].io_backend` flipped
  to `af_xdp` in the example configs.

## Out of this ADR

* **DPDK reconsideration**: explicitly out of scope; if anyone proposes
  resurrecting it, that's a new ADR superseding this one.
* **eBPF-based load balancing without GRE encap** (Cilium/Katran-style
  XDP_TX rewriting): different architecture; can be a future ADR-003,
  but not before AF_XDP is at line rate.
