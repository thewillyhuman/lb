# Software Load Balancer — Design Specification v0.2

> Inspired by Google's Maglev (NSDI '16). This document specifies a Rust-implemented, L4 packet-forwarding load balancer designed for a multi-domain network environment.

---

## Table of Contents

1. [Goals and Non-Goals](#1-goals-and-non-goals)
2. [Architecture Overview](#2-architecture-overview)
3. [Project Structure](#3-project-structure)
4. [Network Model](#4-network-model)
5. [Packet Flow](#5-packet-flow)
6. [Forwarder Design (Data Plane)](#6-forwarder-design-data-plane)
   - 6.1 [Kernel Bypass and Packet I/O](#61-kernel-bypass-and-packet-io)
   - 6.2 [Steering Module](#62-steering-module)
   - 6.3 [Packet Rewriter Threads](#63-packet-rewriter-threads)
   - 6.4 [Connection Tracking](#64-connection-tracking)
   - 6.5 [Consistent Hashing — LB Hash](#65-consistent-hashing--lb-hash)
   - 6.6 [GRE Encapsulation](#66-gre-encapsulation)
   - 6.7 [Fragment Handling](#67-fragment-handling)
   - 6.8 [Muxing Module](#68-muxing-module)
7. [Controller Design (Control Plane)](#7-controller-design-control-plane)
   - 7.1 [Health Checking](#71-health-checking)
   - 7.2 [BGP Announcer](#72-bgp-announcer)
   - 7.3 [Config Manager](#73-config-manager)
8. [Control Plane API](#8-control-plane-api)
   - 8.1 [VIP Management](#81-vip-management)
   - 8.2 [Backend Pool Management](#82-backend-pool-management)
   - 8.3 [Health Check Configuration](#83-health-check-configuration)
9. [Configuration Model](#9-configuration-model)
10. [Backend Requirements](#10-backend-requirements)
11. [Frontend (GFE) Integration](#11-frontend-gfe-integration)
12. [Observability](#12-observability)
13. [Failure Modes and Resilience](#13-failure-modes-and-resilience)
14. [Operational Considerations](#14-operational-considerations)
15. [Implementation Roadmap](#15-implementation-roadmap)
16. [Technology Stack](#16-technology-stack)

---

## 1. Goals and Non-Goals

### Goals

- Provide a **centralized, shared L4 load balancing service** for all teams, eliminating per-team load balancer management.
- Support backends spanning **multiple IP service domains** (network domains that are routable between each other but are independent L3 segments).
- Operate at **line rate** on commodity servers using kernel bypass techniques.
- Provide **connection persistence** (packets of a TCP/UDP flow always reach the same backend) even as the set of forwarder machines changes.
- Enable **horizontal scaling** of forwarder capacity by adding commodity servers to an ECMP pool — no single point of failure, N+1 redundancy model.
- Serve as the **L4 foundation** for a future centralized TLS termination layer (GFE layer), solving the certificate management problem across teams.
- Be **fully programmable in software**, allowing rapid iteration and feature development.

### Non-Goals

- This system is **not an L7 proxy**. It does not terminate TCP, inspect HTTP, or manage TLS. That is the responsibility of the GFE layer described in Section 11.
- This system does **not perform NAT**. Backends receive the real client IP address in the inner packet after GRE decapsulation.
- This system does **not replace internal Kubernetes ingress** for services that already self-contain their load balancing needs within a single domain.
- This system is **not a firewall or DDoS scrubber** (though its architecture is compatible with adding such layers upstream).

---

## 2. Architecture Overview

```
                        Internet / internal clients
                                      |
                              [ BGP Router ]
                                      |
                    ECMP: distribute evenly across all LB machines
                    /           |           \
              [LB Node 1]  [LB Node 2]  [LB Node 3]     ← commodity servers
                    \           |           /
                     GRE encapsulation per packet
                    /           |           \
          [Backend A]      [Backend B]    [Backend C]
          Domain: net1      Domain: net2   Domain: net1
                    \           |           /
                     Direct Server Return (DSR)
                          response packets go
                          directly to client,
                          bypassing LB nodes
```

Each LB node contains two logical components:

- **Forwarder**: the fast-path data plane. Receives packets from the NIC, selects a backend, GRE-encapsulates the packet, and transmits. Runs entirely in userspace with kernel bypass.
- **Controller**: the slow-path control plane. Manages BGP announcements, health checks backends, pushes config updates to the local forwarder.

---

## 3. Project Structure

The codebase is organized as a Cargo workspace with strict separation of concerns. Each crate has a single, well-defined responsibility. Dependencies flow inward: binary crates depend on library crates, never the reverse.

```
lb/
├── Cargo.toml                          # Workspace root
├── Cargo.lock
├── README.md
├── docs/
│   ├── spec.md                         # This specification
│   ├── architecture.md                 # ADRs and design rationale
│   └── ops-runbook.md                  # Operational procedures
│
├── config/
│   ├── lb.example.toml            # Reference node configuration
│   └── systemd/
│       └── lb.service             # systemd unit file
│
│  ─────────────────────────────────────
│  DOMAIN LAYER — pure types and traits, no I/O, no frameworks
│  ─────────────────────────────────────
│
├── crates/
│   ├── lb-types/                  # Canonical domain types
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── vip.rs                  # Vip, VipService, Protocol
│   │       ├── backend.rs              # Backend, BackendPool, HealthStatus
│   │       ├── packet.rs               # PacketMeta (5-tuple), FragmentId (3-tuple)
│   │       └── config.rs               # NodeConfig, BgpConfig, ForwarderConfig, etc.
│   │
│   ├── lb-hashing/                # Maglev consistent-hash algorithm
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── lookup_table.rs         # LookupTable: build, lookup, atomic swap
│   │       └── permutation.rs          # offset/skip derivation, preference list
│   │
│   │  ─────────────────────────────────
│   │  DATA PLANE — fast-path, no async, no allocations on hot path
│   │  ─────────────────────────────────
│   │
│   ├── lb-forwarder/              # Forwarder data-plane engine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # ForwarderEngine public API
│   │       ├── steering.rs             # Steering module: 5-tuple hash → queue assignment
│   │       ├── rewriter.rs             # Per-thread packet processing loop
│   │       ├── conn_table.rs           # Fixed-size per-thread connection tracking table
│   │       ├── fragment_table.rs       # Fragment reassembly table (3-tuple → backend)
│   │       ├── gre.rs                  # GRE + outer IP header encapsulation
│   │       ├── muxer.rs               # Egress multiplexer: TX queue → NIC
│   │       ├── vip_matcher.rs          # VIP + (proto, port) lookup
│   │       └── packet_pool.rs          # Pre-allocated ring buffer descriptors
│   │
│   ├── lb-io/                     # Packet I/O abstraction (AF_XDP / DPDK / mock)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # PacketIo trait
│   │       ├── af_xdp.rs              # AF_XDP implementation via aya
│   │       ├── dpdk.rs                 # DPDK implementation (feature-gated)
│   │       └── mock.rs                 # In-memory packet I/O for testing
│   │
│   │  ─────────────────────────────────
│   │  CONTROL PLANE — async, Tokio-based
│   │  ─────────────────────────────────
│   │
│   ├── lb-controller/             # Control-plane orchestrator
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # Controller public API
│   │       └── orchestrator.rs         # Coordinates health, BGP, config lifecycle
│   │
│   ├── lb-health/                 # Backend health checking
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── checker.rs              # HealthChecker: runs probes, deduplicates
│   │       ├── probe.rs                # Probe trait + impls: TcpProbe, HttpProbe, HttpsProbe, IcmpProbe
│   │       └── state_machine.rs        # UNKNOWN → HEALTHY ↔ UNHEALTHY transitions
│   │
│   ├── lb-bgp/                    # BGP speaker (VIP announce/withdraw)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── speaker.rs              # BgpSpeaker: session lifecycle
│   │       └── messages.rs             # OPEN, UPDATE, KEEPALIVE, NOTIFICATION
│   │
│   ├── lb-config-manager/         # Config loading, validation, caching
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── loader.rs               # Poll API or receive push, deserialize
│   │       ├── validator.rs            # Semantic validation (no dangling pool refs, etc.)
│   │       ├── applier.rs              # Atomic config → hash table rebuild + swap
│   │       └── cache.rs                # Local filesystem cache for resilience
│   │
│   │  ─────────────────────────────────
│   │  API LAYER — HTTP/gRPC, runs as a separate service
│   │  ─────────────────────────────────
│   │
│   ├── lb-api/                    # Centralized control-plane REST/gRPC API
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs               # axum router setup, middleware
│   │       ├── handlers/
│   │       │   ├── mod.rs
│   │       │   ├── vips.rs             # CRUD /api/v1/vips
│   │       │   ├── pools.rs            # CRUD /api/v1/pools
│   │       │   └── health.rs           # /healthz, /readyz, /metrics
│   │       ├── models.rs               # API request/response DTOs (serde)
│   │       └── store.rs                # Storage trait (DB-agnostic)
│   │
│   │  ─────────────────────────────────
│   │  OBSERVABILITY
│   │  ─────────────────────────────────
│   │
│   ├── lb-metrics/                # Metrics registration and exposition
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── forwarder_metrics.rs    # Counters/gauges/histograms for data plane
│   │       └── controller_metrics.rs   # Health check, BGP, config metrics
│   │
│   ├── lb-tracer/                 # Packet tracer diagnostic tool
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── trace.rs                # Construct marked packet, collect node reports
│   │
│   │  ─────────────────────────────────
│   │  BINARIES
│   │  ─────────────────────────────────
│   │
│   ├── lb-node/                   # Main binary: forwarder + controller on one box
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs                 # CLI args, config load, spawn forwarder & controller
│   │
│   ├── lb-api-server/             # Binary: centralized API service
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs                 # CLI args, DB init, start axum server
│   │
│   └── lb-trace/                  # Binary: CLI packet tracer
│       ├── Cargo.toml
│       └── src/
│           └── main.rs                 # Parse args, run trace, print results
│
├── tests/
│   ├── integration/
│   │   ├── netns_helpers.rs            # Linux network namespace test harness
│   │   ├── forwarding_test.rs          # End-to-end packet forwarding
│   │   ├── failover_test.rs            # Backend failure + hash table rebuild
│   │   └── config_reload_test.rs       # Hot config swap under traffic
│   └── benchmarks/
│       ├── hashing_bench.rs            # Maglev table build + lookup throughput
│       └── forwarding_bench.rs         # Packets-per-second micro-benchmark
│
├── deploy/
│   ├── controller.sh                   # Provision & configure a controller node
│   ├── worker.sh                       # Provision & configure a worker (LB) node
│   ├── backend-onboard.sh              # Set up GRE tunnel + loopback VIP on a backend
│   └── grafana/
│       └── lb-dashboard.json      # Pre-built Grafana dashboard
│
└── scripts/
    ├── dev-setup.sh                    # Install dev dependencies, create test netns
    └── run-integration-tests.sh        # Wrapper for netns-based integration tests
```

### Design Principles Behind the Structure

**Single Responsibility per Crate.** Each crate owns exactly one concern. `lb-hashing` knows about Maglev tables but nothing about packets. `lb-gre` (embedded in the forwarder) knows how to prepend headers but nothing about which backend was selected. This makes each crate independently testable and replaceable.

**Dependency Direction: Inward Only.** Binary crates (`lb-node`, `lb-api-server`) depend on library crates. Library crates depend only on `lb-types` and each other at the same or lower layer. No library crate depends on a binary crate. The dependency graph is a DAG with `lb-types` at the root.

```
                  lb-node (binary)
                 /          \
    lb-forwarder    lb-controller
       /     |    \         /      |       \
  lb-io |  lb-  lb- lb- lb-
             |  hashing   health   bgp      config-manager
             |                                    |
         lb-metrics                   lb-api (client)
              \           |                /
               ────── lb-types ──────
```

**Data Plane / Control Plane Separation.** The `lb-forwarder` crate and everything it depends on are strictly synchronous, `no_std`-compatible where feasible, and never allocate on the hot path. The control-plane crates (`lb-controller`, `lb-health`, `lb-bgp`, `lb-config-manager`) use Tokio async. The two layers communicate through a narrow interface: atomic pointer swaps for the hash lookup table, and a shared health status bitmap.

**I/O Abstraction via Traits.** `lb-io` defines a `PacketIo` trait with `recv_batch` / `send_batch` methods. The AF_XDP, DPDK, and mock implementations live behind this trait. Integration tests use the mock; production uses AF_XDP. The forwarder is generic over `PacketIo` and never knows which backend is in use.

**API DTOs are Separate from Domain Types.** `lb-api/models.rs` defines request/response structs with `#[derive(Serialize, Deserialize)]` and validation annotations. These are mapped to/from `lb-types` at the handler boundary. Domain types are never polluted with HTTP serialization concerns.

**Tests Live Close to What They Test.** Unit tests are `#[cfg(test)] mod tests` inside each crate. Integration tests that require network namespaces or multi-crate coordination live in the top-level `tests/` directory. Benchmarks use `criterion` and live in `tests/benchmarks/`.

---

## 4. Network Model

### Virtual IPs (VIPs)

A VIP is an IP address (IPv4 or IPv6) that is **not assigned to any physical interface**. It is announced to the router via BGP from all healthy LB nodes simultaneously. The router distributes arriving packets across all LB nodes through ECMP.

- Each service registers one or more VIPs.
- A VIP is associated with one or more (protocol, port) pairs.
- Example: `VIP 188.184.100.10, TCP/443` → backend pool `web-frontend`.

### Backend Pools

A backend pool is an ordered set of backend endpoints (IP address + optional port). Backends are the actual servers that serve the application.

- A VIP maps to exactly one backend pool per (protocol, port) tuple.
- Backend pools may be shared across VIPs.
- Backend pools may be **recursive**: a pool may reference other pools, allowing composition. Circular references are rejected at validation time by `lb-config-manager/validator.rs`.
- Backends are health-checked independently; only healthy backends receive traffic.

### IP Service Domains

the organization operates multiple independent L3 network domains (called "IP services"). These domains are **routable between each other** — any machine in one domain can IP-reach any machine in another. All instances receive a globally routable IP address.

This means:
- The LB nodes can always **GRE-encapsulate** and forward packets to any backend regardless of its IP service domain, since the outer GRE destination IP is always reachable.
- The health checker can always reach any backend directly via its public IP.
- No per-domain LB deployment is needed. A single pool of LB nodes serves all domains.

---

## 5. Packet Flow

### Inbound (client → backend)

```
1. Client sends packet to VIP.
2. Router receives packet, hashes 5-tuple via ECMP, forwards to one LB node.
3. LB node forwarder receives packet:
   a. Steering module (steering.rs) hashes 5-tuple → assigns to packet thread queue.
   b. Packet thread (rewriter.rs) matches packet to a configured VIP (vip_matcher.rs).
   c. Packet thread looks up 5-tuple in local connection tracking table (conn_table.rs).
      - HIT (backend still healthy) → reuse backend selection.
      - MISS → consult the organization consistent hash table (lb-hashing) → select backend → store in connection table.
   d. Packet thread prepends GRE + outer IP header (gre.rs), dst = backend IP.
   e. Packet placed on TX queue.
4. NIC transmits encapsulated packet (muxer.rs → PacketIo::send_batch).
5. Packet is routed via normal IP routing to backend (across any domain).
6. Backend's GRE tunnel interface decapsulates packet.
7. Backend processes request, sees real client IP as source.
```

### Outbound (backend → client, Direct Server Return)

```
8. Backend sends response directly to client IP.
   - Source IP in response packet is the VIP (not the backend's IP).
   - This requires the VIP to be configured on the backend's loopback interface.
9. Response packet goes directly to the router and back to the client.
   - LB nodes are NOT on the return path.
```

DSR is essential for performance: response traffic (typically larger than requests) never passes through LB nodes, eliminating a bottleneck and reducing LB hardware requirements.

---

## 6. Forwarder Design (Data Plane)

> **Code location:** `crates/lb-forwarder/` (engine) + `crates/lb-io/` (packet I/O abstraction)

### 6.1 Kernel Bypass and Packet I/O

The forwarder operates entirely in **userspace**, bypassing the Linux kernel network stack for the data path. The kernel stack is computationally expensive and adds unnecessary overhead (interrupts, context switches, memory copies, system calls). The forwarder does not need TCP/IP processing — it only needs to read raw packets, rewrite headers, and transmit.

**I/O abstraction (`lb-io`):**

All packet I/O flows through the `PacketIo` trait:

```rust
/// crates/lb-io/src/lib.rs
pub trait PacketIo: Send + 'static {
    fn recv_batch(&mut self, buf: &mut [PacketBuf]) -> io::Result<usize>;
    fn send_batch(&mut self, buf: &[PacketBuf]) -> io::Result<usize>;
    fn fd(&self) -> RawFd;  // for epoll/polling if needed
}
```

Three implementations:

| Implementation | Crate feature | Use case |
|---|---|---|
| `AfXdpIo` | `af-xdp` (default) | Production. Safe Rust eBPF/XDP via `aya`; no kernel modification; works with standard NICs. |
| `DpdkIo` | `dpdk` | Optional. Higher throughput if AF_XDP proves insufficient, at the cost of NIC vendor dependency. |
| `MockIo` | `mock` (test only) | Integration tests. In-memory ring buffers, deterministic, no root required. |

The forwarder is generic over `PacketIo` and is constructed as `ForwarderEngine<T: PacketIo>`. This means all forwarding logic is testable without hardware.

**Packet pool (`packet_pool.rs`):**

- At startup, the forwarder pre-allocates a fixed-size **packet pool** — a shared arena of `Frame` structs (each a 2048-byte buffer + length), indexed by `FrameIndex` (u32).
- SPSC queues between threads carry only frame indices (4 bytes), not packet data. This mirrors AF_XDP's UMEM model where descriptors flow through queues while frame data stays in a shared memory region.
- After the muxer sends a frame, it returns the index to a lock-free completion queue (crossbeam `ArrayQueue`) so steering can reuse it: `free list → steering → rx_queue → rewriter → tx_queue → muxer → free list`.
- Interior mutability is provided via `UnsafeCell<Frame>`, with safety guaranteed by the single-owner index protocol: at any point, exactly one thread holds a given index.
- Pool size is computed to cover all in-flight frames: `queue_capacity × num_rewriters × 2 + batch_size × 2`. A typical configuration with 2 rewriters and 4096-deep queues allocates ~16K frames (~33MB).

**CPU pinning:**

- Each packet thread is pinned to a **dedicated CPU core**.
- Steering and muxing share one core.
- All other processes (controller, health checker, API server) run on the remaining cores.
- NUMA awareness: packet threads should be on the same NUMA node as the NIC.

### 6.2 Steering Module

> **Code location:** `crates/lb-forwarder/src/steering.rs`

The steering module is the **ingress demultiplexer**. It runs on the NIC receive interrupt path and distributes packets to per-core packet thread queues.

**Algorithm:**

1. Compute the **5-tuple hash** of each arriving packet: `(src_ip, dst_ip, src_port, dst_port, protocol)`.
2. Map the hash to a receiving queue using `queue_id = hash % num_packet_threads`.
3. This ensures all packets of the same flow (same 5-tuple) always go to the same packet thread, making per-thread connection tracking consistent without cross-thread synchronization.

**Fallback:**

- If a receiving queue is full (backpressure), the steering module falls back to **round-robin** distribution across available queues. This prevents head-of-line blocking under flood conditions (e.g., SYN floods with a single source tuple).

**Note:** The 5-tuple hash computed by steering is **not reused** by the packet thread. The packet thread recomputes it independently to avoid a dependency on the steering path and to eliminate the need for cross-thread coordination.

### 6.3 Packet Rewriter Threads

> **Code location:** `crates/lb-forwarder/src/rewriter.rs`

One packet rewriter thread runs per CPU core. Each thread:

1. Reads packets from its dedicated receiving queue.
2. Processes packets in **batches** (default batch size: 64 packets) to amortize per-packet overhead. A periodic timer (default: 50µs) flushes partial batches to bound latency under low load.
3. For each packet:
   - **VIP match** (`vip_matcher.rs`): check if `dst_ip` matches a configured VIP and `(protocol, dst_port)` matches a configured service on that VIP. Packets not matching any VIP are dropped and counted via `lb_packets_dropped_total`.
   - **5-tuple hash**: recompute `hash(src_ip, dst_ip, src_port, dst_port, proto)`.
   - **Connection table lookup** (`conn_table.rs`, Section 6.4).
   - **Backend selection** via consistent hash if needed (`lb-hashing`, Section 6.5).
   - **GRE encapsulation** (`gre.rs`, Section 6.6).
4. Places rewritten packets on its TX queue.

**No shared state between threads.** Each thread has its own connection tracking table. This is intentional: the overhead of shared state (locks, cache coherence) at packet rates in the millions per second is prohibitive. Consistent hashing provides correctness guarantees even when different threads (or different LB nodes) make independent decisions for the same flow.

### 6.4 Connection Tracking

> **Code location:** `crates/lb-forwarder/src/conn_table.rs`

Each packet thread maintains a **local connection tracking table** — a fixed-size hash table mapping 5-tuple hash values to selected backend IPs.

**Lookup on each packet:**

```
entry = table.get(five_tuple_hash)
if entry exists AND entry.backend is healthy:
    use entry.backend
else:
    backend = consistent_hash(five_tuple_hash, backend_pool)
    table.insert(five_tuple_hash, backend)
    use backend
```

**Table properties:**

- Fixed size (default: 131,072 entries per thread). Must be a power of two. Sized at 2x expected peak concurrent flows per thread to keep fill ratio below 50%.
- Collision resolution: open addressing with **Robin Hood hashing**. On insert, entries with shorter probe distances are displaced by entries with longer probe distances, bounding worst-case probe length to O(ln n) instead of linear probing's O(1/(1-alpha)^2). This is critical for miss performance under SYN floods.
- Early termination on miss: a lookup can stop as soon as it encounters an entry with a probe distance shorter than the current search distance, avoiding full-table scans at high fill ratios.
- Batch timestamp: a single `Instant::now()` is captured per batch of 64 packets and passed to all connection table operations, eliminating per-packet clock_gettime overhead.
- Eviction: entries expire after a configurable TTL (default: 60 seconds of inactivity). There is no active eviction thread — entries are lazily reclaimed on collision during insert.
- Under SYN flood: the table may saturate. When full, the forwarder falls back to pure consistent hashing for new entries without storing them. This degrades connection persistence but maintains forwarding correctness.

**Why per-thread tables are sufficient:**

The ECMP router may send packets of the same flow to different LB nodes (especially after ECMP rebalancing). Within a single LB node, the steering module ensures same-flow packets always reach the same thread. The consistent hash provides the cross-node guarantee: even a thread that has never seen a flow will select the same backend as any other thread or node, as long as the backend pool has not changed.

### 6.5 Consistent Hashing — LB Hash

> **Code location:** `crates/lb-hashing/`

The consistent hashing module provides **backend selection without shared state**. All threads and all LB nodes independently compute the same backend for a given (flow, backend pool) pair.

**Algorithm (Maglev hashing):**

Given a backend pool of N backends and a lookup table of size M (M must be prime, M ≫ N, default M = 65,537):

1. For each backend `i`, derive two values from its IP address (or name) in `permutation.rs`:
   ```
   offset_i = h1(backend_name_i) mod M
   skip_i   = h2(backend_name_i) mod (M - 1) + 1
   ```
   where `h1` and `h2` are independent hash functions (e.g., xxHash with different seeds).

2. Generate a preference list (permutation) for backend `i`:
   ```
   permutation[i][j] = (offset_i + j * skip_i) mod M
   ```

3. Populate the lookup table in `lookup_table.rs` — backends take turns filling their most-preferred empty slot:
   ```
   next[i] = 0 for all i
   entry[j] = -1 for all j
   n = 0
   loop:
     for each backend i:
       c = permutation[i][next[i]]
       while entry[c] != -1:
         next[i]++
         c = permutation[i][next[i]]
       entry[c] = i
       next[i]++
       n++
       if n == M: return
   ```

4. To select a backend for a packet:
   ```
   idx = five_tuple_hash mod M
   backend = entry[idx]
   ```

**Properties:**

- **Even distribution**: each backend receives at most 1 more entry than any other backend (difference ≤ 1/M).
- **Minimal disruption on backend change**: adding or removing a backend reshuffles only the minimum necessary entries. In practice, removing 1 backend from a pool of 100 affects ~1% of entries.
- **No coordination required**: any thread, any LB node, independently builds the same lookup table from the same config.

**Lookup table regeneration:**

- Triggered by: backend added, backend removed, backend health status change.
- Regeneration is atomic: the new table is built in a separate allocation, then swapped in with a single pointer update via `ArcSwap`.
- Regeneration time for M=65537, N=100: approximately 1.2ms. Preference lists are computed on-the-fly from pre-computed `(offset, skip)` pairs rather than materialized into O(N*M) memory, reducing table build memory from ~50MB to ~1.6KB. This is acceptable as it happens on the control plane, not the fast path.

**Handling unhealthy backends:**

- Unhealthy backends are **removed from the lookup table** before it is swapped in. The consistent hash thus never selects a known-unhealthy backend.
- If a backend becomes unhealthy after a connection table entry was written, the connection tracking lookup will detect it (health status check on the cached backend) and fall back to a fresh consistent hash lookup.

### 6.6 GRE Encapsulation

> **Code location:** `crates/lb-forwarder/src/gre.rs`

When a backend is selected, the packet thread prepends a GRE + outer IP header.

**Encapsulated packet structure:**

```
[ Outer Ethernet header  ]  dst MAC = next-hop router MAC
[ Outer IP header        ]  src = LB node IP, dst = backend IP
[ GRE header             ]  protocol type = 0x0800 (IPv4) or 0x86DD (IPv6)
[ Original IP packet     ]  src = client IP, dst = VIP  ← preserved intact
[ Original TCP/UDP ...   ]
```

**GRE header format (RFC 2784):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C| |K|S| Reserved0       | Ver |      Protocol Type            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- C=0, K=0, S=0 (no checksum, no key, no sequence number) for minimal overhead.
- Protocol type: `0x0800` for inner IPv4, `0x86DD` for inner IPv6.

**MTU considerations:**

- GRE adds 24 bytes overhead (20 bytes outer IP + 4 bytes GRE header).
- If the network MTU is 1500, the effective payload MTU drops to 1476.
- The forwarder must either:
  - Check inner packet size and send ICMP Fragmentation Needed (type 3, code 4) back to the sender if the packet exceeds the effective MTU and DF bit is set.
  - Or negotiate a lower MTU via path MTU discovery.
- Jumbo frames (9000 byte MTU) on the network backbone eliminate this issue in most cases and are the **recommended configuration**.

**IPv6 support:**

- Both inner and outer packets support IPv4 and IPv6.
- Four encapsulation combinations are supported: IPv4-in-IPv4, IPv6-in-IPv4, IPv4-in-IPv6, IPv6-in-IPv6.

### 6.7 Fragment Handling

> **Code location:** `crates/lb-forwarder/src/fragment_table.rs`

IP fragmentation breaks 5-tuple matching because non-first fragments carry only the L3 header (no L4 ports). The forwarder must handle this correctly.

**Problem:** Non-first fragments cannot be matched to a VIP by (protocol, port). They must be sent to the same backend as the first fragment.

**Solution (two-hop fragment redirection):**

1. Each LB node is configured with a special **fragment backend pool** consisting of all LB nodes in the cluster.
2. When a fragment arrives:
   - Compute a **3-tuple hash**: `(src_ip, dst_ip, ip_identification)`.
   - Forward the fragment (via GRE) to an LB node selected by this 3-tuple hash. All fragments of the same datagram share the same 3-tuple and thus always reach the same LB node.
   - Use the GRE recursion control field (or a custom flag) to mark the packet as already-redirected, preventing infinite loops.
3. The receiving LB node maintains a **fragment table**: a fixed-size hash map from `(src_ip, dst_ip, ip_id)` to the backend selected for the first fragment.
   - First fragment arrives → select backend via normal 5-tuple path → store in fragment table → forward.
   - Non-first fragment arrives → look up fragment table → forward to stored backend (or buffer if first fragment hasn't arrived yet, with a short TTL).

**Limitations and mitigations:**

- Adds one extra hop for fragmented packets; potential for out-of-order delivery. Backends must tolerate out-of-order packets (standard TCP behavior).
- Fragment table is finite; entries expire after 10 seconds. Uses Robin Hood hashing (same as connection table) for bounded probe length and batch timestamps to avoid per-packet clock overhead.
- In practice, IP fragmentation is rare on the network. The fragment handling path is correct but not performance-optimized.

### 6.8 Muxing Module

> **Code location:** `crates/lb-forwarder/src/muxer.rs`

The muxing module is the **egress multiplexer**. It runs on the NIC transmit path:

1. Drains frame indices from all rewriter TX queues (round-robin).
2. Copies frame data into a `PacketBuf` send buffer and passes it to the NIC TX ring via `PacketIo::send_batch`. With AF_XDP zero-copy, this would be a descriptor submission instead.
3. Returns transmitted frame indices to the `PacketPool` free list (completion queue), making them available for steering to reuse.

The muxer uses the same spin-for-N-then-park strategy as the rewriter threads: spin for 64 iterations, then `park_timeout(100us)` to balance latency and CPU usage.

---

## 7. Controller Design (Control Plane)

> **Code location:** `crates/lb-controller/` (orchestrator) + `crates/lb-health/`, `crates/lb-bgp/`, `crates/lb-config-manager/`

The controller runs as a separate Tokio async task on the same machine as the forwarder. It does not process packets and does not share data structures with the forwarder except through atomic config updates (pointer swaps on the lookup table and a shared health status bitmap).

### 7.1 Health Checking

> **Code location:** `crates/lb-health/`

The controller health-checks all backends in all configured backend pools.

**Health check types (configurable per backend pool):**

Each probe type implements the `Probe` trait in `probe.rs`:

```rust
/// crates/lb-health/src/probe.rs
#[async_trait]
pub trait Probe: Send + Sync {
    async fn check(&self, target: &Backend, timeout: Duration) -> ProbeResult;
}
```

| Type    | Implementation | Description |
|---------|---------------|-----------------------------------------------------------|
| `tcp`   | `TcpProbe`    | Establish a TCP connection to `backend_ip:port`. Success = connection established. |
| `http`  | `HttpProbe`   | Issue an HTTP GET request to a configurable path. Success = 2xx response. |
| `https` | `HttpsProbe`  | Same as HTTP but over TLS. Certificate validation configurable. |
| `icmp`  | `IcmpProbe`   | ICMP echo (ping). Use only for backends where TCP/HTTP health checks are not possible. |

**Health check parameters (per pool):**

```toml
interval       = "5s"       # how often to probe each backend
timeout        = "2s"       # max time to wait for response
healthy_threshold   = 2     # consecutive successes to mark healthy
unhealthy_threshold = 3     # consecutive failures to mark unhealthy
```

**Deduplication (`checker.rs`):** If the same backend IP appears in multiple pools, health checks are run only once per (IP, port, type) tuple. The result is shared across all pools referencing that backend.

**State machine (`state_machine.rs`) per backend:**

```
UNKNOWN → (threshold successes) → HEALTHY
HEALTHY → (threshold failures)  → UNHEALTHY
UNHEALTHY → (threshold successes) → HEALTHY
```

Any state change triggers a consistent hash table rebuild for the affected pools (Section 6.5). The controller maintains a **reverse index** (`backend IP -> set of pool IDs`) that is rebuilt on every config change. On a health state transition, only the pools that contain the affected backend are rebuilt, not all pools. At scale with hundreds of pools, this reduces rebuild latency from O(total_pools * 1.1ms) to O(affected_pools * 1.1ms).

**Debounce for correlated failures (`orchestrator.rs`):**

When multiple backends fail simultaneously (e.g., a rack switch dies and takes 20 backends offline), the controller debounces health change events to avoid redundant rebuilds:

1. Each `on_health_change` call updates the shared `DashMap<IpAddr, HealthStatus>` **immediately** — the rewriter's per-packet health check sees the change right away and falls back to a fresh Maglev lookup for flows pinned to the dead backend.
2. The affected pool IDs (from the reverse index) are accumulated into a `pending_pools` set.
3. A debounce timer starts on the first pending change. After the window elapses (default: 50ms), all pending pools are rebuilt in a single batch — each pool exactly once, regardless of how many of its backends changed.
4. The control-plane event loop calls `tick()` periodically to flush pending rebuilds after the window.

Without debounce, a pool containing K of N failing backends is rebuilt K times. With debounce, it is rebuilt once with all K changes applied. Benchmarked: 20 backends failing across 50 pools takes 2.37s without debounce vs 116ms with debounce (20x improvement).

A full config reload (`apply_config`) supersedes any pending debounced rebuilds, since it rebuilds all tables from scratch.

**Network domain note:** Since all backends have globally routable IP addresses, the health checker connects directly to each backend's IP without any special routing configuration. No per-domain health checker instances are needed.

### 7.2 BGP Announcer

> **Code location:** `crates/lb-bgp/`

Each LB node announces all configured VIPs to **every configured upstream router** via BGP, in active-active mode. Per-VIP reachability survives the loss of any single router (Maglev §4.2: N+1 redundancy, not active/passive 1+1).

**Behavior:**

- On startup: one BGP session is opened per peer. Each session drives its own connect → OPEN handshake → KEEPALIVE loop independently.
- Normal operation: every VIP announce/withdraw call fans out to every Established peer. Per-peer failure is contained: a broken session does not block announces to the rest of the fleet.
- Reconnect: a disconnected session retries with exponential backoff starting at 1s, doubling up to a 60s cap. The backoff resets on successful Established. On reconnect, the controller re-announces the full current VIP set to the recovered peer so any drops during the outage are replayed.
- VIP lifecycle: a VIP is announced while its backend pool has at least one healthy backend, and withdrawn the moment the last healthy backend fails (this reconciliation is eager — not debounced — because a dead VIP must stop receiving traffic immediately).

**BGP configuration:**

```toml
[bgp]
local_asn       = 65000              # internal ASN
router_id       = "10.0.0.1"         # this LB node's loopback IP
communities     = ["65000:100"]      # default; per-peer override available
next_hop_self   = true

[[bgp.peers]]
peer_ip         = "10.0.0.254"
peer_asn        = 65000

[[bgp.peers]]
peer_ip         = "10.0.0.253"
peer_asn        = 65000
hold_time_secs  = 30                 # optional per-peer override
```

The legacy flat form (top-level `peer_ip`/`peer_asn`) is still accepted and converted to a one-element `peers` list. Mixing the two forms in one file is rejected.

**Implementation (`speaker.rs`, `messages.rs`):** The supervisor holds `Vec<PeerHandle>`, one `mpsc::UnboundedSender<SessionCmd>` per peer. Each session runs as an independent tokio task so panics or stalls in one session cannot affect another. Out of scope (future work): graceful restart, route refresh, IPv6 NEXT_HOP, MD5 auth.

### 7.3 Config Manager

> **Code location:** `crates/lb-config-manager/`

The config manager is responsible for:

1. **Loading configuration** (`loader.rs`) from the central control plane API (Section 8) via periodic polling (default: every 10 seconds) or push notifications (gRPC streaming preferred).
2. **Validating** (`validator.rs`) the configuration before applying it. Validation includes: no dangling pool references, no circular recursive pools, VIP address format, port range, backend reachability plausibility.
3. **Applying changes atomically** (`applier.rs`): building the new consistent hash lookup tables, then swapping them in via a single atomic pointer update. In-flight packets using the old table complete normally.
4. **Persisting** (`cache.rs`) the last known good config to a local file, so the forwarder can restart with a valid configuration even if the control plane API is temporarily unreachable.

**Config update ordering:**

- When backends are removed: update hash table first, then stop health checks. This ensures the removed backend is not selected during the transition.
- When backends are added: start health checks first, wait for `healthy_threshold` successes, then add to hash table. This ensures new backends are not selected before they are confirmed healthy.

---

## 8. Control Plane API

> **Code location:** `crates/lb-api/` (library) + `crates/lb-api-server/` (binary)

The control plane is a centralized HTTP/gRPC API service (separate from the LB nodes themselves) that stores the authoritative configuration for all VIPs and backend pools. LB nodes are clients of this API.

The API layer follows a clean handler → service → store architecture:

- **Handlers** (`handlers/*.rs`): HTTP concerns only — parse request, call service, serialize response.
- **Models** (`models.rs`): API DTOs with serde annotations and validation. Mapped to/from `lb-types` at the handler boundary.
- **Store** (`store.rs`): `trait ConfigStore` abstracts persistence. Implementations (Postgres, SQLite, in-memory for tests) are injected at startup.

### 8.1 VIP Management

```
POST   /api/v1/vips              Create a new VIP
GET    /api/v1/vips              List all VIPs
GET    /api/v1/vips/{vip_id}     Get VIP details
PUT    /api/v1/vips/{vip_id}     Update VIP configuration
DELETE /api/v1/vips/{vip_id}     Remove a VIP (drains traffic first)
```

**VIP object:**

```json
{
  "id": "atlas-web",
  "address": "188.184.100.10",
  "services": [
    { "protocol": "TCP", "port": 443, "backend_pool": "atlas-web-backends" },
    { "protocol": "TCP", "port": 80,  "backend_pool": "atlas-web-backends" }
  ],
  "owner": "atlas-team@example.org",
  "description": "ATLAS experiment web frontend"
}
```

### 8.2 Backend Pool Management

```
POST   /api/v1/pools             Create a backend pool
GET    /api/v1/pools             List all pools
GET    /api/v1/pools/{pool_id}   Get pool details and current backend health
PUT    /api/v1/pools/{pool_id}   Update pool (add/remove backends)
DELETE /api/v1/pools/{pool_id}   Delete pool (must not be referenced by any VIP)
```

**Backend pool object:**

```json
{
  "id": "atlas-web-backends",
  "backends": [
    { "ip": "188.185.10.1", "port": 443, "weight": 1 },
    { "ip": "188.185.10.2", "port": 443, "weight": 1 },
    { "ip": "10.254.0.5",   "port": 443, "weight": 1 }
  ],
  "health_check": {
    "type": "https",
    "path": "/healthz",
    "interval": "5s",
    "timeout": "2s",
    "healthy_threshold": 2,
    "unhealthy_threshold": 3
  }
}
```

**Backend health status (read-only, returned in GET):**

```json
{
  "backends": [
    { "ip": "188.185.10.1", "port": 443, "status": "HEALTHY",   "last_checked": "2024-03-15T10:00:00Z" },
    { "ip": "188.185.10.2", "port": 443, "status": "UNHEALTHY", "last_checked": "2024-03-15T10:00:01Z" },
    { "ip": "10.254.0.5",   "port": 443, "status": "HEALTHY",   "last_checked": "2024-03-15T10:00:02Z" }
  ]
}
```

### 8.3 Health Check Configuration

Health check parameters can be overridden globally or per-pool. Global defaults are configurable by the LB operations team and stored in the `ConfigStore`.

---

## 9. Configuration Model

Each LB node reads its runtime configuration from the control plane API. The local bootstrap configuration is structured as follows:

```toml
# /etc/lb/config.toml
# Deserialized by lb-types/src/config.rs

[node]
id              = "lb-node-01"
loopback_ip     = "188.184.0.1"   # this node's stable IP, used as GRE source
data_iface      = "eth0"          # NIC used for packet forwarding
num_threads     = 7               # packet rewriter threads (leave 1 core for steering/muxing)

[bgp]
local_asn       = 65000
router_id       = "188.184.0.1"
peer_ip         = "188.184.0.254"
peer_asn        = 65000

[control_plane]
api_url         = "https://lb-api.internal"
poll_interval   = "10s"
local_cache     = "/var/lib/lb/config-cache.json"

[forwarder]
packet_pool_size       = 4096
connection_table_size  = 65536      # per thread
fragment_table_size    = 8192
batch_size             = 64
batch_flush_interval   = "50us"
connection_ttl         = "60s"

[health_check_defaults]
interval             = "5s"
timeout              = "2s"
healthy_threshold    = 2
unhealthy_threshold  = 3
```

---

## 10. Backend Requirements

Any server registered as a backend must be configured to participate in DSR. This requires two things:

### 10.1 GRE Tunnel Interface

The backend must have a GRE tunnel interface that decapsulates packets from LB nodes. On Linux:

```bash
# Create GRE tunnel (run once, persist via network config)
ip tunnel add gre-lb mode gre local <backend_ip> ttl 64
ip link set gre-lb up
```

### 10.2 VIP on Loopback

The backend must have the VIP configured on its loopback interface (with ARP disabled) so it accepts packets destined to the VIP:

```bash
# Add VIP to loopback (ARP disabled so the backend does not respond to ARP for the VIP)
ip addr add <vip>/32 dev lo
```

ARP must be disabled for the VIP on all interfaces except the loopback:

```bash
sysctl -w net.ipv4.conf.all.arp_ignore=1
sysctl -w net.ipv4.conf.all.arp_announce=2
```

### 10.3 Response Source IP

The backend application must bind to the VIP address (or the OS must be configured to use the VIP as the source IP for responses). The simplest approach is to configure the application to listen on `0.0.0.0` and ensure the routing table sends return traffic via the default route, which will use the VIP on loopback as source.

### 10.4 Automation

The LB control plane API should provide a **self-registration endpoint** and reference configuration scripts (`deploy/backend-onboard.sh` / cloud-init snippet) so teams can onboard backends with minimal manual steps.

---

## 11. Frontend (GFE) Integration

This L4 load balancer is designed to be the foundation for a higher-level **centralized TLS termination and HTTP routing layer** (analogous to Google's GFE). The GFE layer sits behind a Maglev-style VIP and terminates TLS on behalf of all services.

```
Client
  ↓
[LB — L4, this document]  ← VIP: 188.184.100.10:443
  ↓  (GRE, DSR return)
[GFE pool — L7 TLS termination]
  ↓  (HTTP/2 or HTTP/1.1 upstream, long-lived connections)
[Application backends — any domain]
```

**Benefits delivered by the GFE layer on top of this L4 layer:**

- **Centralized TLS termination**: one team manages certificates, cipher suites, and TLS policy. Individual teams never touch certificates.
- **Automated certificate renewal**: integrate with the internal CA or Let's Encrypt via ACME. Zero team involvement after initial registration.
- **Uniform TLS policy**: TLS 1.2 minimum, approved cipher suites, HSTS, enforced centrally.
- **HTTP-level health checking**: GFEs health-check application backends at L7, not just TCP connectivity.
- **Connection pooling**: GFEs maintain long-lived encrypted connections to backends, reducing TLS handshake overhead per request.
- **Lame duck mode**: backends signal readiness to drain by failing health checks while continuing to serve in-flight requests, enabling zero-downtime deploys.

**The GFE layer is a separate project** and is not specified in this document. The L4 load balancer is intentionally unaware of TLS or HTTP.

---

## 12. Observability

> **Code location:** `crates/lb-metrics/` (registration) + `crates/lb-tracer/` (diagnostics)

### 12.1 Metrics

Each LB node exposes a Prometheus metrics endpoint at `http://<node_ip>:9100/metrics`.

**Forwarder metrics (`forwarder_metrics.rs`):**

| Metric | Type | Description |
|---|---|---|
| `lb_packets_received_total` | Counter | Total packets received by the steering module |
| `lb_packets_forwarded_total` | Counter | Total packets successfully GRE-forwarded |
| `lb_packets_dropped_total` | Counter | Total packets dropped (no VIP match, no healthy backend, pool full) |
| `lb_connection_table_hits_total` | Counter | Connection tracking cache hits |
| `lb_connection_table_misses_total` | Counter | Connection tracking cache misses (fell back to consistent hash) |
| `lb_connection_table_size` | Gauge | Current number of active entries in connection table (per thread) |
| `lb_packet_processing_latency_ns` | Histogram | Per-packet processing latency in nanoseconds |
| `lb_throughput_pps` | Gauge | Current packets per second |
| `lb_throughput_bps` | Gauge | Current bits per second |

**Controller metrics (`controller_metrics.rs`):**

| Metric | Type | Description |
|---|---|---|
| `lb_backend_health_status` | Gauge | 1=HEALTHY, 0=UNHEALTHY, per backend (labels: pool, ip, port) |
| `lb_health_check_duration_ms` | Histogram | Health check round-trip time per backend |
| `lb_bgp_state` | Gauge | 1=announcing, 0=withdrawn |
| `lb_config_last_reload_timestamp` | Gauge | Unix timestamp of last successful config reload |
| `lb_config_reload_errors_total` | Counter | Number of failed config reload attempts |

### 12.2 Packet Tracer

> **Code location:** `crates/lb-tracer/` (library) + `crates/lb-trace/` (CLI binary)

A diagnostic tool for tracing the exact path of a specific flow through the system:

```
lb-trace --src 128.141.10.5:54321 --dst 188.184.100.10:443 --proto tcp
```

This constructs a specially marked packet with the given 5-tuple and sends it through the LB. Each LB node that processes it logs:
- Its own node ID
- The 5-tuple hash value computed
- The backend selected
- Whether the connection table was hit or missed

Output is returned to the caller. Essential for debugging misrouted connections or unexpected backend selections.

### 12.3 Logging

- **Structured JSON logs** via `tracing` + `tracing-subscriber` in Rust.
- Forwarded to the central logging infrastructure (ELK stack or equivalent).
- Log levels: ERROR and WARN always on; INFO and DEBUG configurable at runtime without restart.
- **No per-packet logging** in the fast path. Packet-level events are only emitted by the packet tracer tool.

### 12.4 Health Endpoint

```
GET /healthz       → 200 OK if forwarder is running and healthy
GET /readyz        → 200 OK if forwarder is ready to serve (BGP announced)
GET /metrics       → Prometheus metrics
```

These are served by the `health` handler in `crates/lb-api/src/handlers/health.rs`.

---

## 13. Failure Modes and Resilience

### LB Node Failure

- When an LB node fails, the router detects the BGP session drop and removes the node from ECMP within the BGP hold time (default: 90 seconds; tunable, recommend 10–30 seconds for fast failover).
- Remaining nodes absorb traffic. The consistent hash ensures they select the same backends for existing flows without any coordination.
- **Connection impact**: flows that were on the failed node and were mid-connection will be reset. This is unavoidable without shared connection state. In practice, TCP clients retry, and for HTTP/2 the impact is minimal.
- **Capacity**: the system is designed with N+1 headroom. Any N-1 nodes must be able to handle full traffic load.

### Backend Failure

- The health checker (`lb-health`) detects failure within `interval × unhealthy_threshold` seconds (default: 15 seconds).
- The failed backend is removed from the consistent hash table atomically via `lb-config-manager/applier.rs`.
- Existing connection table entries pointing to the failed backend are invalidated at next lookup (health check in connection table lookup path).
- Traffic redistributes to remaining healthy backends.

### Config API Unreachability

- Each LB node caches the last known good configuration locally via `lb-config-manager/cache.rs` (`local_cache` in config).
- If the control plane API is unreachable, the node continues operating with the cached config.
- A metric and alert is raised after the cache is more than `max_config_staleness` old (default: 5 minutes).

### Consistent Hash Table Rebuild During Traffic

- Rebuilds are done in a shadow copy; the live table is atomically swapped (`lookup_table.rs`).
- In-flight packets using the old table complete normally (no locks, no pauses).
- Rebuild time is bounded at ~2ms for M=65537, N=100.

### SYN Flood

- The forwarder's per-thread connection table (`conn_table.rs`) may fill up under a SYN flood.
- Fallback: consistent hash without table insertion. This correctly forwards SYNs to backends but does not track the connection.
- Backends are responsible for SYN cookie protection.
- Future enhancement: rate limiting at the steering module for new connection rate per source IP.

---

## 14. Operational Considerations

### Rolling Restarts and Upgrades

1. Drain the node: withdraw BGP announcements (`lb-bgp`). The router stops sending new packets within seconds.
2. Wait for in-flight packets to drain (default: 5 seconds).
3. Restart the forwarder binary (`lb-node`).
4. Forwarder starts, passes health check, controller re-announces VIPs.
5. Router adds node back to ECMP set.

The consistent hash ensures that, after the restart, the node selects the same backends as before, so returning flows are unaffected.

### Adding a New LB Node

1. Provision the node using `deploy/worker.sh`.
2. Start the LB service (`systemctl start lb`).
3. The controller announces VIPs via BGP.
4. The router adds the node to ECMP.
5. Capacity increases immediately; existing connections on other nodes are unaffected.

### Adding a New VIP

1. Team registers VIP + backend pool via the control plane API (`POST /api/v1/vips`).
2. LB nodes pick up the new config within one polling interval (≤10 seconds) or immediately via push.
3. Controller begins announcing the new VIP via BGP.
4. Health checks begin for the new backend pool.

### Decommissioning a VIP

1. Team marks VIP as draining via the control plane API.
2. Controller withdraws BGP announcement.
3. After a configurable drain period (default: 60 seconds), VIP is removed from config.
4. Teams should redirect DNS before initiating drain to avoid user impact.

---

## 15. Implementation Roadmap

### Phase 1 — Core Data Plane (MVP)

- [ ] `lb-types`: domain types (Vip, Backend, BackendPool, PacketMeta, config structs)
- [ ] `lb-io`: `PacketIo` trait + AF_XDP implementation + mock implementation
- [ ] `lb-hashing`: Maglev consistent hashing (lookup_table.rs, permutation.rs)
- [ ] `lb-forwarder`: steering, rewriter, conn_table, gre, muxer, vip_matcher, packet_pool
- [ ] `lb-metrics`: forwarder metrics (basic Prometheus endpoint)
- [ ] `lb-node`: binary that wires forwarder + static config file (no control plane API yet)
- [ ] Loopback and integration tests using `MockIo` and Linux network namespace testbed
- [ ] `tests/benchmarks/`: hashing and forwarding micro-benchmarks

### Phase 2 — Control Plane

- [ ] `lb-bgp`: BGP speaker (VIP announce/withdraw based on forwarder health)
- [ ] `lb-health`: TCP and HTTP health checkers with state machine
- [ ] `lb-config-manager`: loader, validator, applier, cache (atomic config reload)
- [ ] `lb-controller`: orchestrator wiring health + BGP + config
- [ ] `lb-api` + `lb-api-server`: control plane REST API (VIP and pool CRUD)
- [ ] `lb-metrics`: controller metrics
- [ ] Structured logging via `tracing`

### Phase 3 — Completeness and Operations

- [ ] IPv6 support (inner and outer) across `lb-forwarder` and `lb-hashing`
- [ ] Fragment handling (`fragment_table.rs`: two-hop redirection + fragment table)
- [ ] HTTPS health checker (`HttpsProbe` in `lb-health`)
- [ ] `lb-tracer` + `lb-trace`: packet tracer diagnostic tool
- [ ] `deploy/backend-onboard.sh`: Shell script for backend onboarding (GRE tunnel + loopback VIP)
- [ ] `deploy/grafana/`: Grafana dashboard for LB metrics
- [ ] Load and chaos testing framework in `tests/integration/`

### Phase 4 — GFE Integration (separate project, LB prerequisite)

- [ ] Centralized TLS termination pool behind LB VIPs
- [ ] ACME-based automated certificate management
- [ ] HTTP/2 upstream connections to application backends
- [ ] Lame duck drain protocol

---

## 16. Technology Stack

| Component | Technology | Crate(s) | Rationale |
|---|---|---|---|
| Language | Rust | all | Memory safety without GC pauses; zero-cost abstractions critical at packet rates; strong concurrency primitives |
| Packet I/O | `aya` (AF_XDP) | `lb-io` | Safe Rust eBPF/XDP; no kernel modification; works with standard NICs in production |
| Async runtime | `tokio` | `lb-controller`, `lb-health`, `lb-bgp`, `lb-api` | Control plane, health checks, API server |
| BGP | `zettabgp` or custom minimal BGP | `lb-bgp` | Only need UPDATE/KEEPALIVE/OPEN; avoid heavy dependency |
| HTTP API | `axum` | `lb-api` | Ergonomic, tokio-native |
| Metrics | `prometheus` crate | `lb-metrics` | Direct Prometheus exposition |
| Hashing | `xxhash-rust` | `lb-hashing` | Fast, non-cryptographic; suitable for 5-tuple hashing and Maglev permutation generation |
| Config serialization | `serde` + `toml` / `serde_json` | `lb-types`, `lb-config-manager` | Standard in the Rust ecosystem |
| Logging | `tracing` + `tracing-subscriber` | all | Structured, async-aware |
| Testing | `cargo test` + Linux network namespaces | `tests/` | Full integration tests without physical hardware |

---

*Document version: 0.2 — Added project structure, crate-level code location references, clean separation of concerns*
*Authors: Network Load Balancing Project*
*Based on: Maglev (Eisenbud et al., NSDI 2016) and Google SRE Workbook Chapter 11*
