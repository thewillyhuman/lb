# LB

A high-performance L4 packet-forwarding load balancer written in Rust, inspired by Google's Maglev (NSDI '16). Designed as a shared infrastructure service with backends spanning multiple IP service domains.

## Features

- **Maglev consistent hashing** -- minimal disruption when backends change, deterministic backend selection across all LB nodes without coordination
- **Connection tracking** -- per-flow affinity via fixed-size Robin Hood hash table with TTL-based eviction and O(ln n) bounded probe length
- **GRE encapsulation** -- RFC 2784 tunneling to backends, supports IPv4/IPv6 inner packets, Direct Server Return (DSR)
- **MTU-aware tunneling** -- automatic MSS clamping on TCP SYN/SYN-ACK (incremental checksum, RFC 1624), ICMP Fragmentation Needed generation for oversized non-TCP packets with DF set, rate-limited. Operator sets `network_mtu`; all tunnel parameters derived automatically
- **Kernel bypass I/O** -- AF_XDP and DPDK backends for line-rate packet processing on commodity hardware
- **Multi-threaded data plane** -- steering thread distributes to per-rewriter SPSC queues; muxer thread collects TX output. Zero-copy hot path: packets live in a shared `PacketPool` arena, only 4-byte frame indices flow through queues (AF_XDP UMEM model)
- **Health checking** -- TCP, HTTP, and HTTPS probes with configurable thresholds and state machine (UNKNOWN/HEALTHY/UNHEALTHY)
- **BGP speaker** -- minimal custom implementation (OPEN/UPDATE/KEEPALIVE/NOTIFICATION) with active-active announcement to multiple router peers. Each peer holds an independent session with exponential-backoff reconnect (1s→60s); VIPs fan out to every Established peer so loss of any single router does not withdraw the VIP from the others. Driven by the controller: a VIP is announced while at least one backend in its pool is healthy and withdrawn otherwise
- **File-based config** -- LB config (VIPs + pools) loaded from a local JSON file, watched via inotify, reloaded atomically ([ADR-001](.docs/adr-001-configuration-model.md))
- **Debounced health rebuilds** -- correlated failures (rack switch dies) are coalesced into a single Maglev table rebuild per affected pool via a 50ms accumulation window
- **Atomic config reload** -- lookup tables and VIP matcher swapped via `ArcSwap`; in-flight packets are never dropped
- **Observability** -- Prometheus metrics (packets, connection table, latency), structured logging, health/readiness endpoints

## Performance

### Benchmark output

All benchmarks run on Apple M-series (MacBook Pro), single-core pinned, `cargo bench` release profile.

**Hashing (`lb-hashing`)**

```
maglev_table_build_100_backends     1.17 ms     (M=65537, 100 backends)
maglev_table_build_10_backends      997 µs      (M=65537, 10 backends)
maglev_lookup_10k                   7.86 µs     (0.79 ns/lookup)
```

**Maglev table build scaling (single table, M=65537)**

```
table_build_scaling/backends/5      819 µs
table_build_scaling/backends/10     978 µs
table_build_scaling/backends/20     1.04 ms
table_build_scaling/backends/50     1.11 ms
table_build_scaling/backends/100    1.15 ms
table_build_scaling/backends/200    1.19 ms
```

**Cascading rebuild on health flap (all pools contain the flapping backend, 20 backends/pool)**

```
cascading_rebuild/all_pools/10       10.8 ms     (1.08 ms/pool)
cascading_rebuild/all_pools/50       54.1 ms     (1.08 ms/pool)
cascading_rebuild/all_pools/100      108 ms      (1.08 ms/pool)
cascading_rebuild/all_pools/200      216 ms      (1.08 ms/pool)
```

**Forwarding (`lb-forwarder`)**

```
gre_encapsulate_ipv4                74.9 ns     (in-place, 40-byte inner packet)
conn_table_lookup_10k               75.9 µs     (7.6 ns/lookup, 15% fill, Robin Hood)
full_pipeline_per_packet            394 µs       (394 ns/pkt: parse + VIP match + conn miss + Maglev + GRE)
```

**Connection table under load (Robin Hood hashing, skewed 80/20 distribution, 1000 lookups)**

```
conn_table_high_fill_skewed/lookup_skewed_hit/70%     11.3 µs     (11.3 ns/lookup)
conn_table_high_fill_skewed/lookup_miss/70%            4.1 µs     (4.1 ns/lookup)
conn_table_high_fill_skewed/lookup_skewed_hit/90%     14.3 µs     (14.3 ns/lookup)
conn_table_high_fill_skewed/lookup_miss/90%            7.5 µs     (7.5 ns/lookup)
conn_table_high_fill_skewed/lookup_skewed_hit/95%     23.3 µs     (23.3 ns/lookup)
conn_table_high_fill_skewed/lookup_miss/95%           16.2 µs     (16.2 ns/lookup)
```

**SPSC queue handoff (crossbeam ArrayQueue, cross-core, 1000 ops)**

```
spsc_descriptor_handoff             7.90 µs     (7.9 ns/op, u32 frame index)
spsc_packetbuf_handoff              168 µs      (168 ns/op, 2KB PacketBuf -- 21x slower)
```

**Per-hop latency (cross-thread, 1000 packets)**

```
hop_steering_to_rewriter            221 µs      (221 ns/pkt, parse + queue push)
hop_rewriter_to_muxer               205 µs      (205 ns/pkt, GRE-encapped packets)
```

**End-to-end multi-threaded pipeline (steering + 2 rewriters + muxer, 1000 packets)**

```
thread_to_thread_mutex_1000pkt      311 µs      (311 ns/pkt, Mutex MockIo)
thread_to_thread_lockfree_1000pkt   521 µs      (521 ns/pkt, lock-free MockIo)
```

**MTU handling (`lb-forwarder`)**

```
mss_clamp_syn_packet                16.9 ns     (parse TCP options + clamp MSS + incremental checksum)
mss_clamp_noop_not_syn              14.7 ns     (early exit for non-SYN packets)
icmp_frag_needed_generation         264 ns      (construct ICMP Type 3 Code 4 response)
icmp_full_path_allowed              288 ns      (oversized check + rate limiter + ICMP generation)
icmp_rate_limiter_allow             23.4 ns     (rate limiter allow path, dominated by Instant::now())
icmp_rate_limiter_deny              3.6 ns      (rate limiter deny path, budget exhausted)
```

**MTU sweep (performance is MTU-independent)**

```
mtu_sweep_mss_clamp/clamp/mtu_1280     17.1 ns
mtu_sweep_mss_clamp/clamp/mtu_1500     16.7 ns
mtu_sweep_mss_clamp/clamp/mtu_4000     16.8 ns
mtu_sweep_mss_clamp/clamp/mtu_9000     17.3 ns
mtu_sweep_icmp/icmp_gen/mtu_1280        263.7 ns
mtu_sweep_icmp/icmp_gen/mtu_1500        263.8 ns
mtu_sweep_icmp/icmp_gen/mtu_4000        265.9 ns
mtu_sweep_icmp/icmp_gen/mtu_9000        263.1 ns
mtu_sweep_oversized_check/check/*       ~541 ps     (sub-nanosecond, two u16 comparisons)
```

**Controller debounce (`lb-controller`)**

Correlated failure: N backends fail simultaneously, each in 50 pools with 15 healthy backends per pool.

```
correlated_failure/no_debounce/5        570.9 ms    (5 backends x 50 pools, each pool rebuilt per event)
correlated_failure/with_debounce/5      113.8 ms    (50 pools rebuilt once)           5.0x speedup
correlated_failure/no_debounce/10       1.155 s
correlated_failure/with_debounce/10     114.8 ms                                     10.1x speedup
correlated_failure/no_debounce/20       2.373 s
correlated_failure/with_debounce/20     115.8 ms                                     20.5x speedup
```

Single backend flap (1 backend across N pools, full Controller path):

```
single_backend_flap/10_pools            22.2 ms     (2.2 ms/pool)
single_backend_flap/50_pools            114.4 ms    (2.3 ms/pool)
single_backend_flap/100_pools           226.9 ms    (2.3 ms/pool)
single_backend_flap/200_pools           453.6 ms    (2.3 ms/pool)
```

Controller overhead:

```
health_change_overhead_100_pools        12.8 µs     (DashMap + reverse index + pending set, no rebuild)
apply_config/pools/10                   11.6 ms     (full config reload)
apply_config/pools/50                   58.2 ms
apply_config/pools/100                  115.0 ms
```

### Theoretical throughput analysis

The end-to-end pipeline processes each packet through steering (RX + pool alloc + parse + queue), rewriter (conn table + Maglev + GRE encap in-place), and muxer (queue drain + TX + pool free). At **311 ns/packet** measured on a single pipeline (1 steering + 2 rewriters + 1 muxer):

| Metric | Value |
|--------|-------|
| Measured per-packet latency | 311 ns |
| Theoretical single-pipeline throughput | **3.2 Mpps** |
| With 7 rewriter threads (typical production) | **~10-12 Mpps** (rewriter-bound, ~394 ns/pkt per rewriter) |
| At 64-byte minimum packets | **~6.1 Gbps** (single pipeline) |
| At 512-byte average packets | **~13.1 Gbps** (single pipeline) |

The bottleneck at 7+ rewriters shifts from the rewriter to the steering and muxer threads, which are single-threaded and must handle the aggregate packet rate. The NIC I/O boundary (steering RX copy, muxer TX copy) accounts for ~200ns of the per-packet cost; with AF_XDP zero-copy these copies are eliminated, and the expected throughput would approach the rewriter-limited rate of ~2.5 Mpps per thread.

### Control plane scaling

At CERN scale with hundreds of distinct services, the dominant concern is not bandwidth but the number of concurrent VIPs and backend pools. Each VIP service maps to a backend pool with its own Maglev lookup table.

| Metric | Value |
|--------|-------|
| Connection table entries per node | ~900K (131,072 per thread x 7 threads) |
| Maglev table build time | ~1.1 ms per pool (invariant of pool size: 5-200 backends) |
| Cascading rebuild (worst case) | 200 pools x 1.1 ms = **216 ms** sequential |

The Maglev table build cost is dominated by the M=65537 fill loop, not the number of backends. This means the per-pool cost is essentially constant (~1.1ms), and total rebuild time scales linearly with the number of affected pools.

A health check flap on a shared backend IP triggers lookup table rebuilds for every pool that contains it. The controller uses a **reverse index** (`backend IP -> set of pool IDs`) computed on config load to rebuild only the affected pools, not all pools. If a backend appears in 5 out of 200 pools, only 5 tables are rebuilt (~5.5ms instead of 216ms).

**Debounce for correlated failures:** When a rack switch dies and takes N backends offline simultaneously, the controller accumulates health changes for a 50ms window, then rebuilds each affected pool once with all changes applied. Without debounce, each pool containing K of the N failing backends gets rebuilt K times. Benchmarked savings: 20 backends failing across 50 pools drops from 2.37s (no debounce) to 116ms (debounced) -- a 20x improvement. The health status in `DashMap` is updated immediately on each event, so the rewriter's per-packet health check sees the change right away and falls back to Maglev for flows pinned to dead backends, even before the table rebuild completes.

During the sequential rebuild window, pools processed later still reference the stale table (pointing at the unhealthy backend). The rewriter's per-packet health check on the cached connection table entry catches this: if the cached backend is unhealthy, it falls back to a fresh Maglev lookup against the (already-swapped) table. This bounds the worst case to one extra Maglev lookup per flow, not sustained traffic to a dead backend.

**Key design decisions validated by benchmarks:**

- **Robin Hood hashing** bounds miss cost to O(ln n): at 95% fill, misses cost 16.2 ns/lookup vs 214 ns with linear probing (13x improvement). This is critical under SYN floods where every packet is a miss.
- **PacketPool + FrameIndex queues** eliminate the 2KB memcpy between threads: SPSC handoff drops from 168 ns (PacketBuf) to 7.9 ns (u32 index), a 21x improvement. End-to-end pipeline improves from ~967 ns/pkt to ~311 ns/pkt.
- **Batch timestamp** (`Instant::now()` once per 64-packet batch) eliminates per-packet clock_gettime overhead: conn_table lookup improved 67% (235 µs to 76 µs per 10k batch).
- **On-the-fly Maglev permutations** reduce table build memory from O(N*M) (~50MB for 100 backends) to O(N) (~1.6KB), with build time at 1.17 ms.
- **Targeted pool rebuild** on health change: reverse index (`backend IP -> pool IDs`) avoids O(total_pools) rebuild cost, reducing a 200-pool flap from 216ms to only the affected subset.
- **Debounce on correlated failures**: 50ms accumulation window coalesces simultaneous health changes into a single rebuild per affected pool, yielding 5-20x speedup when multiple backends fail at once (rack switch failure scenario).
- **MSS clamping at ~17ns/SYN** adds negligible overhead to the hot path. Non-SYN packets early-exit at ~15ns. The incremental checksum update (RFC 1624) avoids full TCP checksum recomputation.
- **ICMP generation at ~264ns** is MTU-independent (always copies the same first 28 bytes of the original packet). Rate limiter deny path is 3.6ns, so bursts of oversized traffic are cheap to suppress.

## Quick start

```bash
# Build
cargo build --release

# Validate config
./target/release/lb-node --config config/lb.example.toml --check-config

# Generate an LB config scaffold
./deploy/generate-config.sh --scaffold -o /tmp/lb-config.json

# Run (uses MockIo by default -- real I/O requires AF_XDP or DPDK on Linux)
./target/release/lb-node --config config/lb.example.toml
```

## Documentation

- **[Installation guide](.docs/installation.md)** -- building from source, dependencies, system preparation
- **[Operations guide](.docs/operations.md)** -- configuration reference, deployment, monitoring, troubleshooting
- **[Design specification](.docs/lb-spec-v2.md)** -- full architecture and protocol details
- **[MTU handling spec](.docs/mtu-handling-spec.md)** -- MSS clamping, ICMP Frag Needed, MTU configuration
- **[ADR-001: Configuration model](.docs/adr-001-configuration-model.md)** -- rationale for file-based configuration

## Project structure

```
crates/
  lb-types/           Domain model: VIP, Backend, Protocol, PacketMeta, MtuConfig, config
  lb-hashing/         Maglev consistent hash: permutation, lookup table
  lb-io/              Packet I/O trait + backends: MockIo, AF_XDP, DPDK
  lb-forwarder/       Data plane: steering, rewriter, connection table,
                      fragment table, GRE encap, MSS clamp, ICMP generation,
                      packet pool, multi-threaded engine
  lb-metrics/         Prometheus counters, gauges, histograms
  lb-health/          Health checking: TCP, HTTP, HTTPS probes, state machine
  lb-bgp/             Minimal BGP speaker (RFC 4271)
  lb-config-manager/  Config loading, validation, cache, inotify watcher
  lb-controller/      Control plane orchestrator: health + BGP + config
  lb-tracer/          Packet tracing types
  lb-node/            Main binary: forwarder + controller + config watcher
  lb-trace/           Packet tracing CLI
config/
  lb.example.toml     Example node configuration
deploy/
  generate-config.sh  Generate LB config JSON
  validate-config.sh  Validate config before deployment
  deploy-config.sh    Deploy config to LB nodes via scp + atomic mv
  lb-node.service     systemd unit file
```

## Development

```bash
# Run all tests (159 tests)
cargo test --workspace

# Run clippy
cargo clippy --workspace --all-targets

# Run benchmarks
cargo bench -p lb-hashing
cargo bench -p lb-forwarder
cargo bench -p lb-controller
```

## Architecture

```
                    Internet / internal clients
                              |
                      [ BGP Router ]
                              |
                ECMP across all LB nodes
                /         |         \
          [LB Node 1] [LB Node 2] [LB Node 3]
                \         |         /
                 GRE encapsulation
                /         |         \
      [Backend A]    [Backend B]   [Backend C]
                \         |         /
                 Direct Server Return
```

Each LB node runs independently with no shared state. All nodes produce identical Maglev lookup tables from the same configuration file, ensuring consistent backend selection across the cluster.

### Data plane (per node)

```
NIC RX --> [Steering] --u32 idx--> SPSC queues --u32 idx--> [Rewriter 0..N] --u32 idx--> SPSC queues --> [Muxer] --> NIC TX
                |                                                                                           |
                \--- alloc frame from PacketPool --------------------------------- free frame back to pool --/
```

All packet data lives in a shared `PacketPool` (pre-allocated frame arena). Only 4-byte frame indices flow through SPSC queues -- no 2KB copies between threads.

- **Steering**: RX from NIC, allocate pool frame, copy packet data in, parse 5-tuple, push frame index to rewriter queue
- **Rewriter**: pop frame index, process frame in-place (VIP match, MSS clamp, connection table, Maglev hash, oversized check + ICMP, GRE encapsulation)
- **Muxer**: drain frame indices, copy to NIC TX buffer, return indices to pool (completion queue)

### Control plane (per node)

- **Config watcher**: inotify on config file, atomic reload
- **Health checker**: probe backends, update health status
- **BGP speaker**: announce/withdraw VIPs based on backend health
- **Controller**: orchestrate config reload, trigger lookup table rebuild on health changes

## License

MIT
