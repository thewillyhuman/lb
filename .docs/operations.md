# Operations Guide

## Running the LB node

```bash
lb-node --config /etc/lb/config.toml
```

The node loads the TOML configuration, reads the LB config JSON file (VIPs + pools), starts the multi-threaded forwarder, and begins watching the config file for changes. It does not announce VIPs via BGP until the initial configuration is loaded and validated.

## Configuration reference

The LB node uses two configuration files:

1. **Node config** (`config.toml`) -- per-node settings: BGP, forwarder tuning, health check defaults. Read once at startup.
2. **LB config** (`lb-config.json`) -- VIPs and backend pools. Watched via inotify and reloaded atomically on change (see [ADR-001](adr-001-configuration-model.md)).

### Node config (TOML)

#### `[node]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `id` | string | -- | Unique node identifier |
| `loopback_ip` | string | -- | Node's stable IP, used as GRE outer source |
| `data_iface` | string | -- | NIC used for packet forwarding |
| `num_threads` | integer | `7` | Number of packet rewriter threads |
| `metrics_addr` | string | `127.0.0.1:9100` | Bind address for `/healthz`, `/readyz`, `/metrics`. Use `0.0.0.0:9100` for cross-host scrape |
| `io_backend` | string | `mock` | `"mock"` (in-memory queues, dev/test) or `"af_xdp"` (production). AF_XDP requires building with `--features af-xdp` and running `deploy/xdp/load.sh <iface>` once on the host before startup; see [Loading the XDP redirect program](#loading-the-xdp-redirect-program-af_xdp-only). |
| `cpu_affinity` | table | unset | Optional per-role CPU pinning (`steering`, `rewriters`, `muxer`). See [CPU pinning](#cpu-pinning). |

#### `[bgp]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `local_asn` | integer | -- | Local BGP AS number |
| `router_id` | string | -- | BGP router ID (typically same as `loopback_ip`) |
| `communities` | list | `[]` | Default BGP community strings (peers may override) |
| `next_hop_self` | bool | `true` | Rewrite next-hop to self in BGP updates |
| `peers` | list | -- | One entry per upstream router (see below) |

##### `[[bgp.peers]]`

Each entry opens an independent BGP session. Every VIP announce/withdraw
fans out to every Established peer simultaneously. Per-peer TCP failure is
contained: the speaker reconnects with exponential backoff (1s → 2s → ... →
60s capped) without affecting other peers. On reconnect, the controller
re-announces the full current VIP set to the recovered peer.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `peer_ip` | string | -- | Router IP |
| `peer_asn` | integer | -- | Router AS number |
| `port` | integer | `179` | TCP port for the BGP session |
| `hold_time_secs` | integer | `90` | Hold time advertised in OPEN; keepalive interval is `hold_time / 3` |
| `communities` | list | inherit | Per-peer community override (falls back to `[bgp].communities` when omitted) |
| `enabled` | bool | `true` | Disable a peer without removing it from config |
| `md5_password` | string | -- | RFC 2385 TCP-MD5 signature key (max 80 bytes, Linux only). Segments are signed with `MD5(header \| payload \| key)`. **Treat the config file as a secret** when set — `lb-node` refuses to start if the TOML has any group/other read bits while an inline `md5_password` is configured. On non-Linux the speaker logs a warning and falls back to plain TCP. |
| `md5_password_env` | string | -- | Name of an environment variable whose value is used as the TCP-MD5 key. Mutually exclusive with `md5_password`. Use with systemd `EnvironmentFile=/etc/lb/bgp.env` (mode `0600`) so the TOML can stay world-readable while the secret stays locked down. The variable must be set and non-empty at startup or the BGP session refuses to connect. |

Legacy single-peer form (flat `peer_ip`/`peer_asn` at the top level of
`[bgp]`) is still accepted and silently converted to a one-element `peers`
list. It cannot be mixed with `[[bgp.peers]]` in the same file.

##### BGP metrics

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `lb_bgp_state` | gauge | -- | 1 if at least one peer is Established, else 0 |
| `lb_bgp_peer_state` | gauge | `peer_ip` | 1 = Established, 0 = Idle/Connecting/Backoff/Disabled |
| `lb_bgp_peer_connects_total` | counter | `peer_ip` | Successful establishments |
| `lb_bgp_peer_disconnects_total` | counter | `peer_ip` | Session disconnects (any reason) |
| `lb_bgp_announce_failures_total` | counter | `peer_ip` | Announce failed on an Established session |
| `lb_bgp_withdraw_failures_total` | counter | `peer_ip` | Withdraw failed on an Established session |
| `lb_bgp_vips_announced` | gauge | -- | VIPs currently being announced |

#### `[control_plane]`

| Key | Type | Description |
|-----|------|-------------|
| `config_file` | string | Path to the LB config JSON file (VIPs + pools) |
| `local_cache` | string | Path for caching the last validated config |

#### `[forwarder]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `packet_pool_size` | integer | `4096` | Number of pre-allocated packet buffers |
| `connection_table_size` | integer | `131072` | Per-thread connection table entries (power of two, >= 2x peak concurrent flows). Uses Robin Hood hashing; keep fill ratio below 50% to bound probe length |
| `fragment_table_size` | integer | `8192` | Per-thread IP fragment→backend map, keyed on (src, dst, ip_id). Must be a power of two |
| `fragment_ttl` | string | `"10s"` | Time a fragment→backend mapping is kept. Non-first fragments arriving after expiry have no reassembly context and are dropped |
| `batch_size` | integer | `64` | Packets per batch in RX/TX |
| `batch_flush_interval` | string | `"50us"` | Max time before flushing a partial batch |
| `connection_ttl` | string | `"60s"` | Legacy single TTL. Used as the default for `connection_ttls.tcp_established` when the section below is absent |
| `network_mtu` | integer | `1500` | Network MTU of the data interface. Derives `effective_inner_mtu` (network_mtu - 24) and `tcp_mss_clamp` (effective_inner_mtu - 40) automatically. Must be >= 1280. |
| `icmp_rate_limit` | integer | `100` | Maximum ICMP Fragmentation Needed responses per second. Prevents amplification from oversized non-TCP traffic bursts. Set to 0 to disable ICMP generation. |

##### `[forwarder.connection_ttls]`

Per-protocol-and-state TTLs for the connection tracker. Any field not set
defaults to the value derived from `connection_ttl` (TCP established) or
sensible constants (5s handshake, 10s closing, 30s UDP/other). Matches the
Maglev paper's behaviour (§3.3): short TTLs for half-open and closing flows
so slots are reclaimed promptly under attack patterns like SYN floods or
FIN scans, long TTL for established sessions.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tcp_handshake` | string | `"5s"` | SYN seen, no ACK yet |
| `tcp_established` | string | `connection_ttl` | After the first bare ACK (or initial data) |
| `tcp_closing` | string | `"10s"` | FIN or RST seen — entry will expire quickly |
| `udp` | string | `"30s"` | UDP flows (no state machine) |
| `other` | string | `"30s"` | Any other L4 protocol |

##### Connection-tracking metrics

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `lb_connection_table_hits_total` | counter | -- | Cache hits where the cached backend is still healthy |
| `lb_connection_table_misses_total` | counter | -- | Cold misses (no entry existed for the flow) |
| `lb_connection_table_fallback_to_maglev_total` | counter | -- | Hits where the cached backend became unhealthy — fell back to Maglev lookup and re-pinned |
| `lb_connection_table_inserts_total` | counter | -- | New inserts (fresh or reclaimed from an expired slot) |
| `lb_connection_table_evictions_total` | counter | `reason` ∈ `{expired_on_insert, dropped_full}` | Evictions during `insert`; `dropped_full` is the fall-through case where every probe slot was occupied (falls back to pure Maglev) |
| `lb_connection_table_tcp_transitions_total` | counter | `to` ∈ `{established, closing_fin, closing_rst}` | TCP state transitions driven by observed flags |
| `lb_connection_table_size` | gauge | -- | Current occupied entries per thread |
| `lb_connection_table_fill_bp` | gauge | -- | Fill ratio in basis points (0–10 000, so 5000 = 50%) |
| `lb_fragment_first_total` | counter | -- | First IP fragments seen (MF=1, offset=0); these populate the fragment table |
| `lb_fragment_subsequent_forwarded_total` | counter | -- | Non-first fragments forwarded via a 3-tuple fragment-table lookup |
| `lb_fragment_drop_no_mapping_total` | counter | -- | Non-first fragments dropped because no fragment-table mapping was found (first fragment never seen or entry expired) |

#### `[health_check_defaults]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interval` | string | `"5s"` | Time between health probes |
| `timeout` | string | `"2s"` | Probe timeout |
| `healthy_threshold` | integer | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | integer | `3` | Consecutive failures to mark unhealthy |

### LB config (JSON)

The LB config file defines VIPs and backend pools. It is the file watched by inotify.

```json
{
  "vips": [
    {
      "id": "web-vip",
      "address": "188.184.100.10",
      "services": [
        {
          "protocol": "tcp",
          "port": 443,
          "backend_pool": "web-pool"
        }
      ],
      "owner": "web-team",
      "description": "Public HTTPS VIP"
    }
  ],
  "pools": [
    {
      "id": "web-pool",
      "backends": [
        { "ip": "10.0.0.1", "port": 443, "weight": 1 },
        { "ip": "10.0.0.2", "port": 443, "weight": 1 }
      ],
      "health_check": {
        "interval": "5s",
        "timeout": "2s",
        "healthy_threshold": 2,
        "unhealthy_threshold": 3
      }
    }
  ]
}
```

## Configuration management

Per [ADR-001](adr-001-configuration-model.md), the LB config is a local file. How it is generated and deployed is the responsibility of existing tooling (Puppet, Ansible, Foreman).

### Generating a config

```bash
# Generate an empty scaffold
./deploy/generate-config.sh --scaffold -o /etc/lb/lb-config.json

# Merge VIP and pool definitions
./deploy/generate-config.sh -v vips.json -p pools.json -o /etc/lb/lb-config.json
```

### Validating a config

Always validate before deploying:

```bash
./deploy/validate-config.sh /etc/lb/lb-config.json
./deploy/validate-config.sh --strict /etc/lb/lb-config.json
```

Checks performed:
- JSON syntax
- Required fields present
- No dangling pool references (VIP references a pool that doesn't exist)
- No empty backend pools
- Valid IP addresses

### Deploying to nodes

```bash
# Deploy to specific nodes
./deploy/deploy-config.sh -c lb-config.json -n node1.cern.ch,node2.cern.ch

# Deploy using a hosts file
./deploy/deploy-config.sh -c lb-config.json -f nodes.txt

# Dry run
./deploy/deploy-config.sh -c lb-config.json -n node1.cern.ch --dry-run
```

The deploy script:
1. Validates the config locally
2. Copies via `scp` to a temp file on the target
3. Atomic `mv` on the target (inotify detects this and triggers reload)

### Config reload behavior

When the config file changes:
- The watcher detects the file modification via inotify (Linux) or kqueue (macOS)
- The new file is parsed and validated
- If valid: VIP matcher and lookup tables are rebuilt and swapped atomically via `ArcSwap`. In-flight packets are never dropped.
- If invalid: the change is logged and skipped. The previous config remains active.

## Health checking

The LB node runs health checks against all backends. Supported probe types:

| Type | Description |
|------|-------------|
| TCP | Connects to `ip:port`. Success if connection is established. |
| HTTP | Sends `GET <path>`. Success if response is 2xx. |
| HTTPS | TLS handshake + `GET <path>`. Success if response is 2xx. Supports self-signed certs via insecure mode. |

Health state machine:
```
UNKNOWN ──(N successes)──> HEALTHY
UNKNOWN ──(M failures)──> UNHEALTHY
HEALTHY ──(M failures)──> UNHEALTHY
UNHEALTHY ──(N successes)──> HEALTHY
```

When a backend becomes unhealthy:
1. It is removed from the Maglev lookup table (rebuilt atomically)
2. Existing connections in the connection table that point to it will be re-hashed on next packet
3. The VIP is withdrawn via BGP if all backends in all pools are unhealthy

When a backend recovers:
1. It is added back to the lookup table
2. Maglev's minimal disruption property ensures most existing connections are unaffected

## Monitoring

All three endpoints below are served by the same HTTP listener bound to
`[node].metrics_addr` (default `127.0.0.1:9100`; set to `0.0.0.0:9100`
in the node TOML for remote scrape). Plain text, no authentication —
bind to loopback and scrape from a sidecar, or firewall the interface.

### Health endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Process is alive. Returns `200 ok`. Kubernetes-style liveness — a failing probe triggers restart, not de-pooling, so nothing gates this. |
| `GET /readyz` | Returns `200 ok` iff the initial config has been applied *and* the multi-threaded forwarder is still running. Returns `503` otherwise. Use as the load-balancer / systemd-notify readiness signal. |

### Packet tracing

The ops server exposes a read-only tracer at `POST /v1/trace`. Send it a
5-tuple as JSON and it tells you which backend a matching packet would be
sent to, without injecting anything on the wire:

```bash
curl -s http://127.0.0.1:9100/v1/trace \
     -H 'Content-Type: application/json' \
     -d '{"src_ip":"10.0.0.100","src_port":12345,
          "dst_ip":"188.184.100.10","dst_port":443,
          "protocol":"Tcp"}'
```

Response (abbreviated):

```json
{
  "node_id": "lb-node-01",
  "pool_id": "web",
  "flow_hash": 4919583209831287808,
  "selected_backend": "10.0.0.2",
  "backend_healthy": true,
  "steps": ["parsed 5-tuple: ...", "VIP matched → pool `web`", ...]
}
```

The `lb-trace` CLI wraps the endpoint:

```bash
lb-trace --node http://127.0.0.1:9100 \
         --src 10.0.0.100:12345 --dst 188.184.100.10:443
```

The tracer reads the VIP matcher, Maglev lookup tables, and health map —
the same shared state the hot path uses — but *not* the per-thread
connection table (which would drift between rewriter threads). The answer
is therefore the steady-state Maglev decision, which is what you usually
want when debugging VIP config or health flaps.

### Logs

Structured JSON is the default format, suitable for journald → Loki /
Vector / Fluent Bit. Log level is driven by the `RUST_LOG` environment
variable (default `info`). For pretty console output during local dev,
set `LB_LOG_FORMAT=pretty`.

### Prometheus metrics

Available at `GET /metrics` (`text/plain; version=0.0.4`). Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `lb_packets_received_total` | counter | Total packets received by the steering module |
| `lb_packets_forwarded_total` | counter | Packets successfully GRE-forwarded |
| `lb_packets_dropped_total` | counter | Packets dropped (no VIP match, parse error, etc.) |
| `lb_connection_table_hits_total` | counter | Connection tracking cache hits |
| `lb_connection_table_misses_total` | counter | Connection tracking cache misses (triggers hash lookup) |
| `lb_connection_table_size` | gauge | Current active entries in connection table |
| `lb_packet_processing_latency_ns` | histogram | Per-packet processing latency in nanoseconds |
| `lb_mss_clamp_total` | counter | TCP SYN packets where MSS was clamped |
| `lb_mss_clamp_noop_total` | counter | TCP SYN packets where MSS was already within limit |
| `lb_mss_clamp_missing_total` | counter | TCP SYN packets with no MSS option |
| `lb_icmp_frag_needed_sent_total` | counter | ICMP Fragmentation Needed responses generated |
| `lb_icmp_frag_needed_ratelimited_total` | counter | ICMP responses suppressed by rate limiter |
| `lb_packets_oversized_dropped_total` | counter | Oversized packets dropped (DF set, exceeds inner MTU) |

### Structured logging

All logs are emitted via `tracing` with structured fields. Set `RUST_LOG=info` (or `debug`, `trace`) for different verbosity levels. JSON output is available via `tracing-subscriber`'s JSON layer.

## Deployment

The recommended path is **systemd** (below). The container image at
`ghcr.io/<owner>/lb-node:<version>` exists for CI integration tests and
for environments that already standardise on container delivery; it
expects the operator to grant `--cap-add=NET_ADMIN --cap-add=NET_RAW`
(plus `--cap-add=BPF` for AF_XDP) and to mount `/etc/lb` read-only.

Releases are cut by pushing a `v*` tag to the repo; see
`.github/workflows/release.yml` for the artifact list (musl x86_64 +
aarch64 tarballs containing `lb-node` + `lb-trace` + the unit file, plus
a multi-arch container image).

### Loading the XDP redirect program (AF_XDP only)

`lb-node` on the `af_xdp` backend depends on a kernel-side XDP program
that redirects packets into the userspace XSK ring. Build and attach it
once per host before starting `lb-node`:

```bash
# One-time per host — installs clang + libbpf headers
sudo apt install clang libbpf-dev bpftool

# Build the redirect program (deploy/xdp/redirect.bpf.o is gitignored)
make -C deploy/xdp

# Attach to the data interface. Default mode is `auto`: try native
# (driver-attached, fastest), fall back to skb (generic kernel hook,
# works on every NIC since 5.10). Pass `native` or `skb` explicitly
# to force a mode.
sudo deploy/xdp/load.sh eth0
```

The script attaches the program, pins the XSKMAP at
`/sys/fs/bpf/lb/xsks_map`, and prints which mode it ended up using.
`lb-node` opens the pinned map at startup and inserts its own XSK fd
at index `queue_id` (per `[node].cpu_affinity.rewriters`); no manual
`bpftool map update` is needed.

The commodity-hardware path is **skb mode**: it works on any Linux
kernel ≥ 5.10 regardless of NIC vendor or driver vintage, at the
cost of ~30–40% throughput compared to native. Native mode is
preferred when available (Intel ixgbe/i40e/ice, Mellanox CX-4+, AWS
ENA, virtio-net 5.13+, Broadcom bnxt 5.9+); the auto path picks it
when the driver supports it and silently falls back when not.

To detach (e.g. before swapping to a different program):

```bash
sudo deploy/xdp/unload.sh eth0
```

`mock` backend deployments don't need any of this — skip straight to
the systemd setup below.

### Systemd

A ready-to-use unit file is at `deploy/lb-node.service`. The service runs as a dedicated unprivileged `lb-node` user with capabilities granted explicitly — create the user first, then install the unit:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lb-node
sudo install -d -o lb-node -g lb-node /var/lib/lb
sudo cp deploy/lb-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lb-node
```

The unit file:

- Runs as `User=lb-node` with `NoNewPrivileges=yes`. Production-ready capabilities are granted via `AmbientCapabilities=`: `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`, `CAP_SYS_RESOURCE`, `CAP_BPF`, `CAP_PERFMON`. (Drop the last two on kernels older than 5.8 where they didn't exist.)
- Pre-start config validation (`--check-config`).
- Restart on failure with backoff.
- File descriptor and memory lock limits sized for kernel bypass.
- Hardening: `ProtectSystem=strict`, `ProtectKernelTunables`, `ProtectKernelModules`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service @network-io` (subtracting `@privileged @resources @reboot @swap @debug`).

### Thread layout

The LB node uses one of two threading models depending on the I/O backend:

**Per-queue (AF_XDP)**: each rewriter owns its own AF_XDP socket bound
to one kernel queue. The kernel's RSS hardware hash partitions traffic
across queues, so userspace steering would just add latency. No
inter-thread queues, no `PacketPool`; each thread runs `recv_batch →
process_batch → send_batch` inline.

| Thread | Name | Role |
|--------|------|------|
| Rewriter 0..N | `lb-rewriter-{i}` | Bound to queue *i*. RX, conn-table lookup, Maglev, GRE encap, TX. |
| Config watcher | `lb-config-watcher` | Watch config file, trigger reload |
| Main | -- | Monitors thread health, signal handling |

**Steering+muxer (mock IO, tests)**: a single shared NIC handle for RX
and TX, with userspace steering distributing 4-byte frame indices to
per-rewriter SPSC queues.

| Thread | Name | Role |
|--------|------|------|
| Steering | `lb-steering` | RX from NIC, allocate pool frames, parse 5-tuple, distribute frame indices to rewriter queues |
| Rewriter 0..N | `lb-rewriter-{i}` | Connection table lookup, Maglev hash, GRE encapsulation (in-place on pool frame) |
| Muxer | `lb-muxer` | Drain frame indices from rewriter TX queues, send via NIC, return frames to pool (completion) |
| Config watcher | `lb-config-watcher` | Watch config file, trigger reload |
| Main | -- | Monitors thread health, signal handling |

SPSC queues in the steering+muxer model carry 4-byte frame indices, not 2KB packet buffers, eliminating the ~166ns/packet memcpy overhead.

#### CPU pinning

For best performance, pin each thread to a dedicated CPU core and isolate those cores from the OS scheduler. Set `[node.cpu_affinity]` to opt in:

```toml
[node.cpu_affinity]
steering  = [1]              # one steering thread → CPU 1
rewriters = [2, 3, 4, 5, 6]  # one rewriter per CPU; cycles if shorter than num_threads
muxer     = [7]              # one muxer thread → CPU 7
```

Each list names OS-level CPU IDs (the IDs Linux exposes via `/sys/devices/system/cpu/`, equivalently the IDs `taskset` accepts). Out-of-range IDs are logged and skipped — the thread runs unpinned rather than refusing to start. If a list is shorter than the number of threads in that role, threads cycle through it (so 3 IDs for 6 rewriters means rewriter `i` lands on `ids[i % 3]`).

Recommended Linux setup:

1. Reserve cores at boot via `isolcpus=2-7,nohz_full=2-7,rcu_nocbs=2-7` on the kernel command line. This stops the OS scheduler from picking them.
2. Pin IRQs for the data NIC's RX/TX queues to one of the isolated cores via `/proc/irq/$IRQ/smp_affinity_list` (or `irqbalance --banscript=...`). Match the IRQ core(s) to the steering thread's pin so the kernel-side packet path stays on a single L1.
3. Disable C-states deeper than C1 on the pinned cores: `cpupower idle-set --disable 2..` or `processor.max_cstate=1` on the kernel command line. Tail latency drops sharply when the LLC and TLB stay warm.
4. Confirm with `ps -L -o pid,tid,psr,comm $(pgrep lb-node)` — each rewriter thread should sit on the configured core.

If `[node.cpu_affinity]` is unset the OS scheduler picks placement, which is fine for dev. At line rate (10+ Mpps) the difference is large enough to dominate the rest of the tuning.

#### Capacity sizing

Rough sizing for an `lb-node` running on AF_XDP (production target). Numbers are per node; ECMP across N nodes scales horizontally.

| Resource | Rule of thumb | Where to tune |
|----------|--------------|---------------|
| RX/TX queues per NIC | One pair per rewriter thread | NIC vendor tooling (e.g. `ethtool -L`) |
| `[node].num_threads` | Reserved cores − 2 (steering + muxer take 1 each) | Node config |
| `[forwarder].connection_table_size` | ≥ 2× peak concurrent flows, power of two. Aim for ≤ 50% fill ratio (`lb_connection_table_fill_bp` ≤ 5000) | Node config |
| `[forwarder].fragment_table_size` | Power of two; ≥ peak in-flight fragmented datagrams (~ tens of thousands at 10 Gbps with mixed traffic) | Node config |
| `[forwarder].batch_size` | 32–64. Larger batches improve throughput but push tail latency up | Node config |
| `[forwarder].network_mtu` | Match the data interface's MTU. Auto-derives `effective_inner_mtu` and `tcp_mss_clamp` | Node config |
| Pool size | `QUEUE_CAPACITY (4096) × num_rewriters × 2 + 2 × batch_size` — derived automatically | Implicit |
| ulimit `MEMLOCK` | At least 1 GB for AF_XDP UMEM | systemd unit (`LimitMEMLOCK=`) |

Typical 10 Gbps, mostly TCP, 1.5M concurrent flows:

```toml
[node]
num_threads = 6
[node.cpu_affinity]
steering  = [1]
rewriters = [2, 3, 4, 5, 6, 7]
muxer     = [8]
[forwarder]
connection_table_size = 4194304   # 4M; 2× peak flows
fragment_table_size   = 65536
batch_size            = 64
network_mtu           = 1500
icmp_rate_limit       = 100
```

### Alerting

Templates live at `deploy/alerts.yaml`. Drop into `/etc/prometheus/rules/lb-node.yaml` and `promtool check rules` before reloading. Coverage:

- Availability: `LbNodeDown` (page), `LbNodeNotReady` (page).
- BGP: `LbBgpAllPeersDown` (page), per-peer flap (warn), announce failures (warn).
- Forwarder: drop rate > 1% (warn), conn-table fill > 70% (warn), conn-table exhaustion (page), ICMP rate-limit hits (warn).
- Control plane: health checker stalled (page), config reloads failing (warn).

Tune thresholds for your traffic profile — defaults are sized for 10k+ rps. The `for:` durations bias against single-scrape blips; raise them on flaky probes.

### Multiple instances

Each LB node is fully independent. There is no shared state between nodes at runtime. Backend selection consistency across nodes is guaranteed by Maglev consistent hashing: given the same configuration, all nodes produce identical lookup tables. Temporary config divergence between nodes is tolerable (see [ADR-001](adr-001-configuration-model.md)).

Deploy LB nodes behind an ECMP router. The router distributes traffic evenly across all nodes. Adding or removing a node only disrupts flows that were hashed to that specific node.

## Troubleshooting

### Node won't start

- **Config parse error** -- validate with `lb-node --config /etc/lb/config.toml --check-config`.
- **LB config missing** -- the node starts with an empty config and logs a warning. It will begin forwarding once the config file is created.
- **Port in use** -- check if another process is bound to the configured interface.

### Packets not being forwarded

- Check `lb_packets_received_total` -- if zero, the NIC/IO backend is not receiving traffic.
- Check `lb_packets_dropped_total` -- if high relative to received, packets are not matching any VIP. Verify VIP config matches the traffic's destination IP, port, and protocol.
- Check `lb_connection_table_size` -- if zero, no flows are being tracked.

### Backend not receiving traffic

- Check health status -- an unhealthy backend is excluded from the lookup table.
- Check that the backend can decapsulate GRE (IP protocol 47) and that its loopback interface has the VIP address configured for DSR. Run `sudo deploy/validate-backend.sh <vip> <iface>` *on the backend host* — it checks VIP loopback binding, `rp_filter`, GRE tunnel device, ARP suppression, and routing in one shot, prints PASS/WARN/FAIL with the matching remediation command, and exits non-zero if DSR will not work.
- Verify GRE connectivity: `ping -I <lb-node-ip> <backend-ip>`.
- Ask the node which backend it *thinks* a given 5-tuple maps to, without injecting anything:

  ```bash
  lb-trace --node http://127.0.0.1:9100 \
           --src 10.0.0.100:12345 --dst 188.184.100.10:443
  ```

  The CLI hits `POST /v1/trace` on the ops HTTP server and prints the decision trail (VIP match → pool → Maglev selection → health status). Add `--json` for machine-readable output. Can also be invoked with `curl` directly; see the `/v1/trace` endpoint below.

### High latency

- Check `lb_packet_processing_latency_ns` histogram for p99 spikes.
- High connection table miss rate (`lb_connection_table_misses_total`) indicates many new flows or table eviction -- consider increasing `connection_table_size` or `connection_ttl`.
- Ensure forwarder threads are pinned to isolated CPU cores.

### Health flap causing brief misdirection

When a backend health status changes, the controller rebuilds Maglev lookup tables only for the affected pools (using a reverse index). During the sequential rebuild window (~1.1ms per affected pool), some pools may still reference the stale table. This is safe: the rewriter checks the cached backend's health status on every packet. If the cached backend is unhealthy, it falls back to a fresh Maglev lookup against the already-swapped table.

A backend that appears in many pools (e.g., a shared infrastructure backend in 50 pools) will cause a ~55ms rebuild window. If this latency is problematic, consider splitting shared backends into dedicated instances per pool or reducing `connection_ttl` to flush stale connection table entries faster.

### Correlated failure (rack switch dies)

When multiple backends fail simultaneously (e.g., a rack switch takes 20 servers offline), the controller's debounce mechanism coalesces all health change events within a 50ms window into a single rebuild per affected pool. This avoids rebuilding the same pool multiple times as each backend is marked unhealthy one by one.

- The health status in `DashMap` is updated immediately on each event, so the rewriter's per-packet health check sees the change right away
- Lookup table rebuilds are deferred until the debounce window elapses, then each affected pool is rebuilt once with all changes applied
- Benchmarked: 20 backends failing across 50 pools takes ~116ms with debounce vs ~2.37s without (20x improvement)

No configuration is needed -- the 50ms debounce window is built-in. The window is small enough to be imperceptible to traffic (rewriter falls back to Maglev for affected flows immediately) but large enough to capture burst health events from correlated failures.

### MTU misconfiguration

**`network_mtu` set too high** (e.g., 9000 but the actual link is 1500): encapsulated packets exceed the real link MTU and are silently dropped by the network. TCP connections stall after the SYN (the small SYN succeeds, but the first data packet exceeds the link). Diagnose by comparing `lb_packets_forwarded_total` with backend-side `packets_received_total`. Fix: set `network_mtu` to the actual link MTU.

**`network_mtu` set too low** (e.g., 1280 but the network supports 1500): MSS is clamped more aggressively than necessary, resulting in smaller TCP segments and slightly reduced throughput. No correctness issue. Self-corrects when the config is fixed.

**`lb_icmp_frag_needed_ratelimited_total` increasing**: either the rate limit is too low or there is a flood of oversized non-TCP traffic. Increase `icmp_rate_limit` if the drops are affecting legitimate PMTUD convergence.

**`lb_mss_clamp_total` is zero while traffic is flowing**: either there is no TCP SYN traffic (unlikely) or MSS clamping is broken. Check that `network_mtu` is set in the config and that the derived `tcp_mss_clamp` value is logged at startup.
