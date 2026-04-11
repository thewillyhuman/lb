# MTU-Aware Tunneling — Feature Specification

> Automatic MSS clamping and ICMP Fragmentation Needed generation for GRE tunneling across any network MTU.

---

## 1. Problem Statement

GRE encapsulation adds 24 bytes of overhead (20-byte outer IPv4 header + 4-byte GRE header) to every forwarded packet. When the network MTU is 1500 bytes — common in environments where jumbo frames are not available — a client sending a standard 1500-byte packet produces a 1524-byte encapsulated packet that exceeds the link MTU and cannot be transmitted.

This affects all traffic where the inner packet size plus GRE overhead exceeds the network MTU. With DF (Don't Fragment) set — the default for virtually all modern TCP traffic due to Path MTU Discovery (RFC 1191) — oversized packets must be dropped, causing connection stalls or black holes.

The system must handle this transparently, requiring no configuration changes on clients or backends.

---

## 2. Goals

- Support **any network MTU** (1280–9000+). The operator configures a single value (`network_mtu`) and the system derives all other parameters automatically.
- **TCP traffic**: clamp the MSS in SYN/SYN-ACK packets so clients and backends negotiate segment sizes that fit inside the GRE tunnel. This prevents oversized packets from ever being generated.
- **Non-TCP traffic** (UDP, ICMP, SCTP, etc.): generate ICMP Fragmentation Needed (Type 3, Code 4) responses when an oversized packet with DF set cannot be forwarded, allowing the sender's PMTUD to adapt.
- **No performance regression** on the fast path. MSS clamping only runs on SYN packets (~0.1% of traffic). ICMP generation only runs on the rare oversized non-TCP packet.
- **Testable across MTU values** without physical hardware changes, using network namespaces with configurable MTU.
- **Benchmarkable** to quantify per-packet cost of MSS parsing, rewriting, and checksum recomputation.

### Non-Goals

- Fragmenting the outer (encapsulated) packet. This defeats PMTUD on the tunnel path and shifts reassembly cost to backends. Not implemented.
- Handling IPv6 fragmentation (IPv6 does not allow intermediate fragmentation; ICMP Packet Too Big is the only option). Deferred to the IPv6 phase.

---

## 3. Design

### 3.1 Automatic Parameter Derivation

The operator sets a single value in the node configuration:

```toml
[forwarder]
network_mtu = 1500
```

All other parameters are derived at startup and logged:

```
effective_inner_mtu = network_mtu - gre_overhead
                    = network_mtu - 24
                    = 1476  (for network_mtu = 1500)

tcp_mss_clamp       = effective_inner_mtu - 40
                    = effective_inner_mtu - (20 IP + 20 TCP)
                    = 1436  (for network_mtu = 1500)
```

The GRE overhead is fixed at 24 bytes (C=0, K=0, S=0 as per the spec — no optional GRE fields). If GRE keys or checksums are added in the future, the overhead constant increases and all derived values adjust automatically.

**Derivation table for common MTU values:**

| network_mtu | GRE overhead | effective_inner_mtu | tcp_mss_clamp |
|---|---|---|---|
| 1280 (IPv6 minimum) | 24 | 1256 | 1216 |
| 1500 (Ethernet default) | 24 | 1476 | 1436 |
| 9000 (jumbo frames) | 24 | 8976 | 8936 |

**Validation at startup:**

- `network_mtu` must be ≥ 1280 (minimum for meaningful IP traffic).
- `network_mtu` must be ≤ 65535 (IP maximum).
- `tcp_mss_clamp` must be ≥ 536 (RFC 879 minimum MSS). This fails if `network_mtu` < 600, which is not a realistic configuration but should produce a clear error.

### 3.2 MSS Clamping (TCP, Option 1)

**When:** a packet has the TCP SYN flag set (SYN or SYN-ACK). Checked in the rewriter loop after VIP matching, before GRE encapsulation.

**What:** parse the TCP options field, locate the MSS option (kind=2, length=4), and if the advertised MSS exceeds `tcp_mss_clamp`, overwrite it with `tcp_mss_clamp`. Then recompute the TCP checksum.

**Algorithm:**

```
fn clamp_mss(packet: &mut [u8], max_mss: u16) -> bool:
    if not tcp or not syn_flag:
        return false

    tcp_header_offset = ip_header_length(packet)
    data_offset = tcp_data_offset(packet, tcp_header_offset)  // in bytes
    options_start = tcp_header_offset + 20  // fixed TCP header
    options_end = tcp_header_offset + data_offset

    offset = options_start
    while offset < options_end:
        kind = packet[offset]
        if kind == 0: break          // end of options
        if kind == 1:                // NOP
            offset += 1
            continue
        if offset + 1 >= options_end: break
        length = packet[offset + 1]
        if length < 2: break         // malformed

        if kind == 2 and length == 4:  // MSS option
            current_mss = u16::from_be_bytes(packet[offset+2..offset+4])
            if current_mss > max_mss:
                packet[offset+2..offset+4] = max_mss.to_be_bytes()
                recompute_tcp_checksum(packet)
                return true  // clamped
            return false     // already within limit

        offset += length

    return false  // MSS option not found
```

**Checksum recomputation:** since only 2 bytes change (the MSS value), use incremental checksum update (RFC 1624) rather than full recomputation. This is O(1) — subtract the old MSS contribution, add the new one.

**Edge cases:**

- SYN without MSS option: the TCP default MSS is 536, which is always below the clamp value. No action needed.
- SYN-ACK: clamp identically. The MSS in SYN-ACK is the backend's advertised MSS, which may also exceed the tunnel MTU if the backend has a larger local MTU.
- Packets with TCP options but no MSS (e.g., SYN with only window scale, SACK permitted): no action.
- Malformed TCP options (length=0, truncated): stop parsing, skip clamping. The packet is forwarded as-is; if it's oversized after encapsulation, the ICMP path handles it.

### 3.3 ICMP Fragmentation Needed (Non-TCP, Option 2)

**When:** a packet's inner length plus GRE overhead exceeds `network_mtu`, AND the DF bit is set in the inner IP header. Checked in the rewriter loop after backend selection, before GRE encapsulation.

**What:** drop the packet and send an ICMP Destination Unreachable (Type 3, Code 4) message back to the source IP, with the Next-Hop MTU field set to `effective_inner_mtu`.

**ICMP packet structure (RFC 792 + RFC 1191):**

```
[ Ethernet header    ]  dst = original src MAC (or ARP lookup)
[ IP header          ]  src = VIP, dst = original src_ip, TTL = 64
[ ICMP header        ]  type=3, code=4, next_hop_mtu=effective_inner_mtu
[ Original IP header ]  first 28 bytes of the original packet (IP header + 8 bytes)
```

**Key details:**

- Source IP of the ICMP reply is the **VIP**, not the LB node IP. The client's PMTUD associates the MTU with the destination (the VIP), so the ICMP source must match what the client expects.
- Include the first 28 bytes of the offending packet (IP header + 8 bytes of payload), as required by RFC 792. This allows the client to match the ICMP to the original flow.
- Rate-limit ICMP generation to prevent amplification. Default: 100 ICMP packets per second per VIP. Configurable.

**Rewriter loop integration:**

```
fn should_generate_icmp(packet: &[u8], network_mtu: u16, gre_overhead: u16) -> bool:
    inner_len = ip_total_length(packet)
    df_set = ip_flags(packet) & DF_FLAG != 0
    return df_set and (inner_len + gre_overhead) > network_mtu

fn generate_icmp_frag_needed(
    original: &[u8],
    vip: IpAddr,
    effective_inner_mtu: u16,
    pool: &PacketPool,
) -> Option<FrameIndex>:
    // allocate a frame from the pool
    frame = pool.alloc()?
    buf = pool.frame_mut(frame)

    // build ICMP response in buf
    // IP header: src=vip, dst=original.src_ip
    // ICMP: type=3, code=4, next_hop_mtu=effective_inner_mtu
    // payload: first 28 bytes of original packet
    // compute IP checksum, ICMP checksum

    return Some(frame)  // routed to TX queue, not GRE-encapsulated
```

**ICMP packets bypass GRE encapsulation.** They are placed directly on the TX queue with the LB node's next-hop MAC as the Ethernet destination, routed back toward the client via normal IP routing.

### 3.4 Rewriter Loop Integration

The complete per-packet flow with MTU handling:

```
for each packet in batch:
    // 1. VIP match
    vip = match_vip(packet)
    if vip is None: drop; continue

    // 2. MSS clamp (TCP SYN only)
    if is_tcp_syn(packet):
        clamp_mss(packet, config.tcp_mss_clamp)

    // 3. Backend selection
    backend = conn_table.get(hash) or maglev.lookup(hash)

    // 4. Oversized check (all protocols)
    if should_generate_icmp(packet, config.network_mtu, GRE_OVERHEAD):
        if icmp_rate_limiter.allow(vip):
            icmp_frame = generate_icmp_frag_needed(packet, vip, config.effective_inner_mtu)
            tx_queue.push(icmp_frame)  // direct to NIC, no GRE
        drop; continue

    // 5. GRE encapsulation
    gre_encapsulate(packet, backend)
    tx_queue.push(packet)
```

**Why MSS clamp runs before the oversized check:** clamping prevents future packets in this flow from being oversized. The SYN itself is small (typically 60-80 bytes), so it will never trigger the oversized check. The clamp ensures the data packets that follow are also within budget.

**Why the oversized check runs after backend selection:** the ICMP response doesn't need the backend, but the conn_table insert does happen. This way, if the client retransmits with a smaller packet (after receiving the ICMP), the conn_table already has the correct backend mapping and avoids a Maglev lookup.

---

## 4. Code Location

| File | Crate | Responsibility |
|---|---|---|
| `mss_clamp.rs` | `lb-forwarder` | `clamp_mss()`, TCP options parsing, incremental checksum |
| `icmp.rs` | `lb-forwarder` | `generate_icmp_frag_needed()`, rate limiter, ICMP packet construction |
| `mtu.rs` | `lb-types` | `MtuConfig` struct: derives `effective_inner_mtu` and `tcp_mss_clamp` from `network_mtu`, validates at construction |
| `rewriter.rs` | `lb-forwarder` | Integration point: calls `clamp_mss` and `should_generate_icmp` in the per-packet loop |
| `config.rs` | `lb-types` | `ForwarderConfig` includes `network_mtu`; `MtuConfig` is derived from it |

---

## 5. Configuration

```toml
[forwarder]
# Network MTU of the data interface. The system derives all tunnel
# parameters from this single value:
#   effective_inner_mtu = network_mtu - 24 (GRE overhead)
#   tcp_mss_clamp       = effective_inner_mtu - 40 (IP + TCP headers)
#
# Examples:
#   1500 → inner 1476, MSS clamp 1436 (standard Ethernet)
#   9000 → inner 8976, MSS clamp 8936 (jumbo frames)
network_mtu = 1500

# Maximum ICMP Fragmentation Needed responses per second per VIP.
# Prevents amplification from oversized non-TCP traffic bursts.
# Set to 0 to disable ICMP generation entirely (not recommended).
icmp_rate_limit = 100
```

No other MTU-related configuration exists. The operator sets `network_mtu` to match their link MTU; everything else is automatic.

---

## 6. Metrics

| Metric | Type | Description |
|---|---|---|
| `lb_mss_clamp_total` | Counter | TCP SYN packets where MSS was clamped |
| `lb_mss_clamp_noop_total` | Counter | TCP SYN packets where MSS was already within limit |
| `lb_mss_clamp_missing_total` | Counter | TCP SYN packets with no MSS option (no action taken) |
| `lb_icmp_frag_needed_sent_total` | Counter | ICMP Fragmentation Needed responses generated |
| `lb_icmp_frag_needed_ratelimited_total` | Counter | ICMP responses suppressed by rate limiter |
| `lb_packets_oversized_dropped_total` | Counter | Oversized packets dropped (DF set, exceeds inner MTU) |

Labels: `vip` on all counters.

---

## 7. Testing

### 7.1 Unit Tests (`lb-forwarder`)

**`mss_clamp.rs` tests:**

| Test | What it verifies |
|---|---|
| `clamp_reduces_oversized_mss` | MSS 1460 → 1436 at MTU 1500 |
| `clamp_noop_when_mss_within_limit` | MSS 1400 unchanged at MTU 1500 |
| `clamp_noop_when_no_mss_option` | SYN with window scale only, no MSS, no crash |
| `clamp_ignores_non_syn` | Non-SYN TCP packet with MSS option is not modified |
| `clamp_handles_syn_ack` | SYN-ACK MSS is clamped identically |
| `clamp_malformed_options_no_panic` | Truncated options, zero-length options, garbage bytes |
| `clamp_checksum_correct` | TCP checksum is valid after clamp (verified by independent full recomputation) |
| `clamp_incremental_checksum_matches_full` | Incremental update produces identical result to full checksum |
| `clamp_at_various_mtus` | Parameterized: MTU 1280, 1500, 4000, 9000 — correct clamp value each time |

**`icmp.rs` tests:**

| Test | What it verifies |
|---|---|
| `icmp_generated_for_oversized_df_packet` | UDP packet 1500 bytes + DF → ICMP Type 3 Code 4 |
| `icmp_not_generated_when_df_clear` | Same packet without DF → forwarded normally (fragmentation is sender's problem) |
| `icmp_not_generated_when_packet_fits` | 1400-byte packet at MTU 1500 → no ICMP |
| `icmp_source_is_vip` | ICMP reply source IP matches the VIP, not the LB node IP |
| `icmp_contains_original_header` | First 28 bytes of original packet are in ICMP payload |
| `icmp_next_hop_mtu_correct` | Next-hop MTU field matches `effective_inner_mtu` |
| `icmp_checksums_valid` | Both IP and ICMP checksums are correct |
| `icmp_rate_limiter_allows_burst` | 100 ICMP in 1 second → all sent |
| `icmp_rate_limiter_drops_excess` | 101st ICMP in same second → dropped, counter incremented |
| `icmp_rate_limiter_resets_after_window` | After 1 second, new burst is allowed |
| `icmp_bypasses_gre` | ICMP response frame goes directly to TX queue, not through GRE encapsulation |

**`mtu.rs` tests (in `lb-types`):**

| Test | What it verifies |
|---|---|
| `mtu_config_derives_correctly` | 1500 → inner 1476, clamp 1436 |
| `mtu_config_jumbo` | 9000 → inner 8976, clamp 8936 |
| `mtu_config_minimum` | 1280 → inner 1256, clamp 1216 |
| `mtu_config_rejects_too_small` | MTU 500 → error (MSS below 536) |
| `mtu_config_rejects_too_large` | MTU 70000 → error (exceeds IP max) |

**Rewriter integration tests:**

| Test | What it verifies |
|---|---|
| `rewriter_clamps_syn_before_gre` | Full pipeline: SYN packet enters, MSS is clamped, GRE encap succeeds |
| `rewriter_drops_oversized_and_sends_icmp` | Full pipeline: oversized UDP + DF → dropped, ICMP on TX queue |
| `rewriter_forwards_fitting_packet_unchanged` | Full pipeline: normal 800-byte packet → GRE encap, no clamp, no ICMP |

### 7.2 Network Namespace Integration Tests (`tests/integration/`)

These tests create a full topology in Linux network namespaces with configurable MTU on every veth link.

**`mtu_integration_test.rs`:**

| Test | Setup | What it verifies |
|---|---|---|
| `tcp_mss_negotiation_1500` | MTU 1500 on all links | Client SYN has MSS 1460. After LB, backend sees MSS 1436. TCP transfer completes with no fragmentation. |
| `tcp_mss_negotiation_9000` | MTU 9000 on all links | Client SYN has MSS 8960. After LB, backend sees MSS 8936. Large TCP segments transfer correctly. |
| `tcp_mss_negotiation_1280` | MTU 1280 on all links | Minimum MTU. Client SYN has MSS 1220. After LB, backend sees MSS 1216. |
| `udp_oversized_icmp_1500` | MTU 1500 on all links | Client sends 1500-byte UDP + DF. Client receives ICMP Frag Needed with next-hop 1476. Client retransmits at 1476. Backend receives packet. |
| `mixed_traffic_mtu_1500` | MTU 1500 on all links | Simultaneous TCP (clamped) and UDP (ICMP) flows. Both complete successfully. |
| `mtu_mismatch_client_jumbo_lb_standard` | Client link 9000, LB link 1500 | Client sends jumbo TCP SYN with MSS 8960. LB clamps to 1436. Data transfer works despite asymmetric MTU. |

### 7.3 Benchmarks (`lb-forwarder/benches/`)

**`mtu_bench.rs`:**

| Benchmark | What it measures |
|---|---|
| `mss_clamp_syn_packet` | Time to parse TCP options + clamp MSS + incremental checksum. Measured per-packet on SYN packets with standard options (MSS + window scale + SACK permitted + timestamps = 24 bytes of options). Expected: ~15-25ns. |
| `mss_clamp_noop` | Same as above but MSS is already within limit. Measures parsing cost without rewrite. Expected: ~10-15ns (no checksum update). |
| `icmp_generation` | Time to construct a complete ICMP Frag Needed response from an oversized packet. Includes frame allocation, header construction, checksums. Expected: ~50-100ns. |
| `rewriter_with_mtu_checks` | Full pipeline (VIP match → clamp → select → GRE) on a SYN packet vs a non-SYN packet. Quantifies the overhead MSS clamping adds to the SYN path. |
| `mtu_sweep` | Parameterized across MTU values (1280, 1500, 4000, 9000). Verifies that MTU value does not affect per-packet processing time (it shouldn't — the clamp logic is identical regardless of the threshold value). |

All benchmarks use `PacketPool` with zero-copy frame access and are pinned to core 1 (consistent with existing benchmark infrastructure).

---

## 8. Observability

### Dashboard Panels

- **MSS clamp rate**: `rate(lb_mss_clamp_total[5m])` — should correlate with new TCP connection rate.
- **ICMP generation rate**: `rate(lb_icmp_frag_needed_sent_total[5m])` — should be near zero in steady state. Sustained non-zero means something is sending oversized non-TCP traffic.
- **ICMP rate-limited**: `rate(lb_icmp_frag_needed_ratelimited_total[5m])` — if non-zero, either the rate limit is too low or there's an oversized traffic flood.
- **Oversized drops**: `rate(lb_packets_oversized_dropped_total[5m])` — should equal ICMP sent + ICMP rate-limited.

### Alerts

- `lb_icmp_frag_needed_ratelimited_total` increasing for >5 minutes: possible misconfigured client or application sending oversized UDP without PMTUD.
- `lb_mss_clamp_total` is zero while `lb_packets_received_total` is non-zero: either no TCP SYN traffic (unlikely) or MSS clamping is broken. Investigate.

---

## 9. Failure Modes

| Scenario | Behavior | Impact |
|---|---|---|
| `network_mtu` configured too high (e.g., 9000 but network is 1500) | Encapsulated packets exceed real link MTU. Network drops them silently or fragments at the outer layer. | Black hole. TCP stalls after SYN (small SYN succeeds, first data packet fails). Fix: set `network_mtu` to the actual link MTU. Detectable by monitoring `lb_packets_forwarded_total` vs backend `packets_received_total` divergence. |
| `network_mtu` configured too low (e.g., 1280 but network is 1500) | MSS clamped more aggressively than necessary. Smaller TCP segments. | Slightly reduced throughput (more packets per byte transferred). No correctness issue. Self-corrects when config is fixed. |
| ICMP Frag Needed blocked by client's firewall | Client never learns the path MTU. Oversized non-TCP packets are dropped indefinitely. | Black hole for oversized UDP. This is a general PMTUD problem, not specific to the LB. Mitigation: MSS clamping handles TCP; for UDP, applications should implement PMTUD or send smaller datagrams. |
| Rate limiter too aggressive | Legitimate ICMP responses dropped. Multiple clients take longer to discover path MTU. | Slower PMTUD convergence. Increase `icmp_rate_limit` if `lb_icmp_frag_needed_ratelimited_total` is consistently non-zero. |

---

## 10. Implementation Roadmap

This feature fits into **Phase 1** (Core Data Plane) since it is part of the rewriter's packet processing logic.

### Step 1: Types and configuration

- [x] `MtuConfig` in `lb-types/src/mtu.rs` — derivation, validation, unit tests
- [x] `ForwarderConfig` updated with `network_mtu` and `icmp_rate_limit`
- [x] `config/lb.example.toml` updated

### Step 2: MSS clamping

- [x] `lb-forwarder/src/mss_clamp.rs` — parser, clamper, incremental checksum
- [x] Unit tests (9 tests)
- [x] Integration into `rewriter.rs`
- [x] Benchmark `mss_clamp_syn_packet`, `mss_clamp_noop`

### Step 3: ICMP generation

- [x] `lb-forwarder/src/icmp.rs` — packet construction, rate limiter
- [x] Unit tests (11 tests)
- [x] Integration into `rewriter.rs` (oversized check + TX queue bypass)
- [x] Benchmark `icmp_generation`, `icmp_full_path_allowed`, `icmp_rate_limiter_allow`, `icmp_rate_limiter_deny`

### Step 4: Metrics and integration tests

- [x] 6 new Prometheus counters in `lb-metrics/src/forwarder_metrics.rs`
- [x] Rewriter integration tests (3 tests)
- [ ] Network namespace integration tests (6 tests) — deferred (requires Linux network namespaces)
- [x] Full pipeline benchmark with MTU sweep (1280, 1500, 4000, 9000)
- [ ] Grafana dashboard panels and alert rules — deferred

---

*Feature version: 1.0*
*Depends on: lb-forwarder (rewriter, GRE encap, PacketPool), lb-types (config)*
*Estimated new tests: 29 unit + 6 integration = 35*
*Estimated new benchmarks: 5*
