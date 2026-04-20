use crate::conn_table::{ConnTable, InsertResult};
use crate::gre;
use crate::icmp;
use crate::mss_clamp::{self, ClampResult};
use crate::vip_matcher::VipMatcher;
use lb_hashing::LookupTable;
use lb_io::PacketBuf;
use lb_metrics::{EvictionLabels, ForwarderMetrics, TcpTransitionLabels};
use lb_types::{
    BackendPoolId, ConnTtls, FlowProto, HealthStatus, MtuConfig, PacketMeta, TcpFlags, TcpFlowState,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

/// Per-thread packet processing pipeline.
pub struct RewriterThread {
    src_ip: IpAddr,
    conn_table: ConnTable,
    lookup_tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
    vip_matcher: Arc<ArcSwap<VipMatcher>>,
    health_status: Arc<DashMap<IpAddr, HealthStatus>>,
    metrics: ForwarderMetrics,
    mtu_config: MtuConfig,
    icmp_rate_limiter: icmp::IcmpRateLimiter,
}

impl RewriterThread {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src_ip: IpAddr,
        conn_table_size: usize,
        conn_ttls: ConnTtls,
        lookup_tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
        vip_matcher: Arc<ArcSwap<VipMatcher>>,
        health_status: Arc<DashMap<IpAddr, HealthStatus>>,
        metrics: ForwarderMetrics,
        mtu_config: MtuConfig,
        icmp_rate_limit: u32,
    ) -> Self {
        Self {
            src_ip,
            conn_table: ConnTable::new(conn_table_size, conn_ttls),
            lookup_tables,
            vip_matcher,
            health_status,
            metrics,
            mtu_config,
            icmp_rate_limiter: icmp::IcmpRateLimiter::new(icmp_rate_limit),
        }
    }

    /// Process a batch of packets. Rewrites packets in-place with GRE encapsulation.
    /// Returns the number of successfully processed packets (compacted to the front of the slice).
    /// ICMP responses for oversized packets are also placed into the output.
    pub fn process_batch(&mut self, packets: &mut [PacketBuf]) -> usize {
        let vip_matcher = self.vip_matcher.load();
        let now = std::time::Instant::now();
        let mut write_idx = 0;

        for read_idx in 0..packets.len() {
            self.metrics.packets_received.inc();

            match self.process_one(&packets[read_idx].clone(), &vip_matcher, now) {
                ProcessResult::Forwarded(pkt) => {
                    packets[write_idx] = pkt;
                    write_idx += 1;
                    self.metrics.packets_forwarded.inc();
                }
                ProcessResult::Icmp(pkt) => {
                    packets[write_idx] = pkt;
                    write_idx += 1;
                    self.metrics.icmp_frag_needed_sent_total.inc();
                    self.metrics.packets_oversized_dropped_total.inc();
                }
                ProcessResult::OversizedRateLimited => {
                    self.metrics.icmp_frag_needed_ratelimited_total.inc();
                    self.metrics.packets_oversized_dropped_total.inc();
                    self.metrics.packets_dropped.inc();
                }
                ProcessResult::Dropped => {
                    self.metrics.packets_dropped.inc();
                }
            }
        }

        self.metrics
            .conn_table_size
            .set(self.conn_table.len() as i64);
        self.metrics
            .conn_table_fill_bp
            .set(self.conn_table.fill_bp());
        write_idx
    }

    fn process_one(
        &mut self,
        input: &PacketBuf,
        vip_matcher: &VipMatcher,
        now: std::time::Instant,
    ) -> ProcessResult {
        // Parse 5-tuple
        let meta = match PacketMeta::from_ipv4_bytes(input.as_slice()) {
            Some(m) => m,
            None => return ProcessResult::Dropped,
        };

        // VIP match
        let pool_id = match vip_matcher.match_packet(meta.dst_ip, meta.protocol, meta.dst_port) {
            Some(id) => id,
            None => return ProcessResult::Dropped,
        };

        // MSS clamp (TCP SYN only, before backend selection per spec §3.4)
        let mut output = input.clone();
        match mss_clamp::clamp_mss(output.as_mut_slice(), self.mtu_config.tcp_mss_clamp) {
            ClampResult::Clamped => {
                self.metrics.mss_clamp_total.inc();
            }
            ClampResult::Noop => {
                self.metrics.mss_clamp_noop_total.inc();
            }
            ClampResult::MssMissing => {
                self.metrics.mss_clamp_missing_total.inc();
            }
            ClampResult::NotTcp | ClampResult::NotSyn => {}
        }

        // Backend selection (connection table + Maglev)
        let lookup_table_swap = match self.lookup_tables.get(pool_id) {
            Some(lt) => lt,
            None => return ProcessResult::Dropped,
        };
        let lookup_table = lookup_table_swap.load();

        let flow_hash = meta.flow_hash();
        let proto = FlowProto::from(meta.protocol);
        let initial_state = initial_tcp_state(meta.tcp_flags);

        let backend_ip = if let Some(cached_ip) = self.conn_table.get(flow_hash, now) {
            let healthy = self
                .health_status
                .get(&cached_ip)
                .map(|s| *s != HealthStatus::Unhealthy)
                .unwrap_or(true);

            if healthy {
                self.metrics.conn_table_hits.inc();
                self.conn_table.touch(flow_hash, now);
                cached_ip
            } else {
                // Cached backend went unhealthy: fall back to a fresh Maglev
                // lookup and re-pin. Count this separately from cold misses so
                // operators can tell whether churn is driven by table TTL
                // expiry (cold miss) or by backend health flaps.
                self.metrics.conn_table_fallback_to_maglev_total.inc();
                let backend = lookup_table.lookup(flow_hash);
                self.insert_tracked(flow_hash, backend.ip, proto, initial_state, now);
                backend.ip
            }
        } else {
            self.metrics.conn_table_misses.inc();
            let backend = lookup_table.lookup(flow_hash);
            self.insert_tracked(flow_hash, backend.ip, proto, initial_state, now);
            backend.ip
        };

        // Apply TCP state transitions *after* the backend is resolved so that
        // the Handshake-vs-Established distinction affects TTL bucket but
        // never changes the backend selection. Retransmitted SYNs do not
        // demote Established flows (promote_state enforces monotonicity).
        if let Some(flags) = meta.tcp_flags {
            self.apply_tcp_transitions(flow_hash, flags, now);
        }

        // Oversized check (after backend selection per spec §3.4)
        if icmp::should_generate_icmp(output.as_slice(), self.mtu_config.network_mtu) {
            if self.icmp_rate_limiter.allow(now) {
                let vip_v4 = match meta.dst_ip {
                    IpAddr::V4(v4) => v4,
                    _ => Ipv4Addr::UNSPECIFIED,
                };
                let icmp_pkt = icmp::generate_icmp_frag_needed(
                    output.as_slice(),
                    vip_v4,
                    self.mtu_config.effective_inner_mtu,
                );
                return ProcessResult::Icmp(icmp_pkt);
            }
            return ProcessResult::OversizedRateLimited;
        }

        // GRE encapsulation
        let src_ipv4 = match self.src_ip {
            IpAddr::V4(v4) => v4,
            _ => return ProcessResult::Dropped,
        };
        let dst_ipv4 = match backend_ip {
            IpAddr::V4(v4) => v4,
            _ => return ProcessResult::Dropped,
        };

        if gre::encapsulate_ipv4(&mut output, src_ipv4, dst_ipv4) {
            ProcessResult::Forwarded(output)
        } else {
            ProcessResult::Dropped
        }
    }

    #[inline(always)]
    fn insert_tracked(
        &mut self,
        hash: u64,
        backend_ip: IpAddr,
        proto: FlowProto,
        tcp_state: TcpFlowState,
        now: std::time::Instant,
    ) {
        match self
            .conn_table
            .insert(hash, backend_ip, proto, tcp_state, now)
        {
            InsertResult::Inserted | InsertResult::Updated => {
                self.metrics.conn_table_inserts_total.inc();
            }
            InsertResult::EvictedExpired => {
                self.metrics.conn_table_inserts_total.inc();
                self.metrics
                    .conn_table_evictions_total
                    .get_or_create(&EvictionLabels {
                        reason: "expired_on_insert".into(),
                    })
                    .inc();
            }
            InsertResult::DroppedFull => {
                self.metrics
                    .conn_table_evictions_total
                    .get_or_create(&EvictionLabels {
                        reason: "dropped_full".into(),
                    })
                    .inc();
            }
        }
    }

    #[inline(always)]
    fn apply_tcp_transitions(&mut self, hash: u64, flags: TcpFlags, now: std::time::Instant) {
        // RST takes priority: even on a SYN+RST (malformed but possible under
        // attack), the connection is terminated.
        if flags.rst() {
            self.conn_table.mark_closing(hash, now);
            self.metrics
                .conn_table_tcp_transitions_total
                .get_or_create(&TcpTransitionLabels {
                    to: "closing_rst".into(),
                })
                .inc();
            return;
        }
        if flags.fin() {
            self.conn_table.mark_closing(hash, now);
            self.metrics
                .conn_table_tcp_transitions_total
                .get_or_create(&TcpTransitionLabels {
                    to: "closing_fin".into(),
                })
                .inc();
            return;
        }
        // ACK without SYN is a good signal the handshake has completed (either
        // the client's final ACK or any subsequent data packet). Promote the
        // flow to Established so it uses the long TTL. Packets in the middle
        // of a session trigger this repeatedly — `mark_established` is cheap
        // and a no-op if the state is already Established or Closing.
        if flags.ack() && !flags.syn() {
            self.conn_table.mark_established(hash, now);
            self.metrics
                .conn_table_tcp_transitions_total
                .get_or_create(&TcpTransitionLabels {
                    to: "established".into(),
                })
                .inc();
        }
    }
}

/// Initial TCP flow state inferred from the first packet of a flow.
#[inline(always)]
fn initial_tcp_state(flags: Option<TcpFlags>) -> TcpFlowState {
    match flags {
        None => TcpFlowState::NotTcp,
        Some(f) if f.rst() || f.fin() => TcpFlowState::Closing,
        Some(f) if f.syn() && !f.ack() => TcpFlowState::Handshake,
        Some(f) if f.ack() => TcpFlowState::Established,
        Some(_) => TcpFlowState::Handshake,
    }
}

enum ProcessResult {
    Forwarded(PacketBuf),
    Icmp(PacketBuf),
    OversizedRateLimited,
    Dropped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_hashing::LookupTable;
    use lb_types::{Backend, Protocol};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn vip_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10))
    }

    fn build_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> PacketBuf {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        PacketBuf::from_slice(&pkt)
    }

    fn setup_rewriter() -> RewriterThread {
        let backends = vec![
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        ];

        let lookup_table = LookupTable::build(&backends, 17).unwrap();
        let pool_id = BackendPoolId("web".into());

        let mut tables = HashMap::new();
        tables.insert(
            pool_id.clone(),
            Arc::new(ArcSwap::from_pointee(lookup_table)),
        );

        let vip_matcher = VipMatcher::from_entries(vec![(vip_ip(), Protocol::Tcp, 443, pool_id)]);

        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);

        let mtu_config = lb_types::MtuConfig::new(1500).unwrap();

        RewriterThread::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            64,
            ConnTtls::with_established(Duration::from_secs(60)),
            tables,
            Arc::new(ArcSwap::from_pointee(vip_matcher)),
            Arc::new(DashMap::new()),
            metrics,
            mtu_config,
            100,
        )
    }

    #[test]
    fn process_valid_packet() {
        let mut rewriter = setup_rewriter();
        let pkt = build_tcp_packet([10, 0, 0, 100], [188, 184, 100, 10], 12345, 443);
        let mut batch = vec![pkt];
        let processed = rewriter.process_batch(&mut batch);
        assert_eq!(processed, 1);
        // Output should be GRE-encapsulated (original 40 + 24 overhead = 64)
        assert_eq!(batch[0].len, 64);
    }

    #[test]
    fn drop_non_vip_packet() {
        let mut rewriter = setup_rewriter();
        let pkt = build_tcp_packet([10, 0, 0, 100], [10, 0, 0, 99], 12345, 80);
        let mut batch = vec![pkt];
        let processed = rewriter.process_batch(&mut batch);
        assert_eq!(processed, 0);
    }

    #[test]
    fn conn_table_caching() {
        let mut rewriter = setup_rewriter();

        // Process the same flow twice
        let pkt1 = build_tcp_packet([10, 0, 0, 100], [188, 184, 100, 10], 12345, 443);
        let pkt2 = pkt1.clone();
        let mut batch = vec![pkt1];
        rewriter.process_batch(&mut batch);

        let mut batch2 = vec![pkt2];
        rewriter.process_batch(&mut batch2);

        // Second call should hit the conn table
        assert_eq!(rewriter.metrics.conn_table_hits.get(), 1);
        assert_eq!(rewriter.metrics.conn_table_misses.get(), 1);
    }

    fn build_tcp_packet_with_flags(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> PacketBuf {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = (20u8 / 4) << 4; // data offset
        pkt[33] = flags;
        PacketBuf::from_slice(&pkt)
    }

    #[test]
    fn syn_creates_handshake_entry_and_fin_evicts_quickly() {
        // TTLs chosen so only Closing flows expire within the test budget.
        let backends = vec![
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        ];
        let lookup_table = LookupTable::build(&backends, 17).unwrap();
        let pool_id = BackendPoolId("web".into());
        let mut tables = HashMap::new();
        tables.insert(
            pool_id.clone(),
            Arc::new(ArcSwap::from_pointee(lookup_table)),
        );
        let vip_matcher = VipMatcher::from_entries(vec![(vip_ip(), Protocol::Tcp, 443, pool_id)]);
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_secs(60),
            tcp_established: Duration::from_secs(60),
            tcp_closing: Duration::from_millis(5),
            udp: Duration::from_secs(60),
            other: Duration::from_secs(60),
        };
        let mut rewriter = RewriterThread::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            64,
            ttls,
            tables,
            Arc::new(ArcSwap::from_pointee(vip_matcher)),
            Arc::new(DashMap::new()),
            metrics,
            lb_types::MtuConfig::new(1500).unwrap(),
            100,
        );

        // SYN → Handshake entry created.
        let syn =
            build_tcp_packet_with_flags([10, 0, 0, 100], [188, 184, 100, 10], 11111, 443, 0x02);
        rewriter.process_batch(&mut [syn]);
        assert!(rewriter.metrics.conn_table_inserts_total.get() >= 1);

        // FIN from the same flow → Closing transition.
        let fin =
            build_tcp_packet_with_flags([10, 0, 0, 100], [188, 184, 100, 10], 11111, 443, 0x11);
        rewriter.process_batch(&mut [fin]);
        let fin_count = rewriter
            .metrics
            .conn_table_tcp_transitions_total
            .get_or_create(&TcpTransitionLabels {
                to: "closing_fin".into(),
            })
            .get();
        assert_eq!(fin_count, 1);

        // The entry should be gone within `tcp_closing`.
        std::thread::sleep(Duration::from_millis(20));
        let mut data_pkt = vec![build_tcp_packet_with_flags(
            [10, 0, 0, 100],
            [188, 184, 100, 10],
            11111,
            443,
            0x10,
        )];
        rewriter.process_batch(&mut data_pkt);
        // After Closing + TTL expiry: the data packet should not find a cached
        // entry, so misses should have increased.
        assert!(rewriter.metrics.conn_table_misses.get() >= 2);
    }

    #[test]
    fn ack_promotes_to_established() {
        let mut rewriter = setup_rewriter();

        // First: SYN → Handshake.
        let syn =
            build_tcp_packet_with_flags([10, 0, 0, 50], [188, 184, 100, 10], 22222, 443, 0x02);
        rewriter.process_batch(&mut [syn]);

        // Then: bare ACK → promotion transition recorded.
        let ack =
            build_tcp_packet_with_flags([10, 0, 0, 50], [188, 184, 100, 10], 22222, 443, 0x10);
        rewriter.process_batch(&mut [ack]);

        let promoted = rewriter
            .metrics
            .conn_table_tcp_transitions_total
            .get_or_create(&TcpTransitionLabels {
                to: "established".into(),
            })
            .get();
        assert!(promoted >= 1);
    }

    #[test]
    fn rst_marks_closing() {
        let mut rewriter = setup_rewriter();

        let syn =
            build_tcp_packet_with_flags([10, 0, 0, 77], [188, 184, 100, 10], 33333, 443, 0x02);
        rewriter.process_batch(&mut [syn]);

        let rst =
            build_tcp_packet_with_flags([10, 0, 0, 77], [188, 184, 100, 10], 33333, 443, 0x04);
        rewriter.process_batch(&mut [rst]);

        let rst_count = rewriter
            .metrics
            .conn_table_tcp_transitions_total
            .get_or_create(&TcpTransitionLabels {
                to: "closing_rst".into(),
            })
            .get();
        assert_eq!(rst_count, 1);
    }

    #[test]
    fn fallback_to_maglev_metric_on_unhealthy_cache() {
        let backends = vec![
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        ];
        let lookup_table = LookupTable::build(&backends, 17).unwrap();
        let pool_id = BackendPoolId("web".into());
        let mut tables = HashMap::new();
        tables.insert(
            pool_id.clone(),
            Arc::new(ArcSwap::from_pointee(lookup_table)),
        );
        let vip_matcher = VipMatcher::from_entries(vec![(vip_ip(), Protocol::Tcp, 443, pool_id)]);
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);
        let health = Arc::new(DashMap::new());

        let mut rewriter = RewriterThread::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            64,
            ConnTtls::with_established(Duration::from_secs(60)),
            tables,
            Arc::new(ArcSwap::from_pointee(vip_matcher)),
            Arc::clone(&health),
            metrics,
            lb_types::MtuConfig::new(1500).unwrap(),
            100,
        );

        // Prime the cache.
        let first = build_tcp_packet([10, 0, 0, 123], [188, 184, 100, 10], 44444, 443);
        rewriter.process_batch(&mut [first]);

        // Read the cached backend, then mark it unhealthy.
        let cached = {
            let pool_id = BackendPoolId("web".into());
            let lt = rewriter.lookup_tables.get(&pool_id).unwrap().load();
            let hash = PacketMeta::from_ipv4_bytes(
                build_tcp_packet([10, 0, 0, 123], [188, 184, 100, 10], 44444, 443).as_slice(),
            )
            .unwrap()
            .flow_hash();
            lt.lookup(hash).ip
        };
        health.insert(cached, HealthStatus::Unhealthy);

        // A second packet from the same flow should trip the fallback path.
        let second = build_tcp_packet([10, 0, 0, 123], [188, 184, 100, 10], 44444, 443);
        rewriter.process_batch(&mut [second]);

        assert_eq!(
            rewriter.metrics.conn_table_fallback_to_maglev_total.get(),
            1
        );
    }

    #[test]
    fn fill_bp_gauge_updated_each_batch() {
        let mut rewriter = setup_rewriter();
        // fill_bp is 0 before any packets are processed.
        assert_eq!(rewriter.metrics.conn_table_fill_bp.get(), 0);

        let mut batch: Vec<PacketBuf> = (0..10)
            .map(|i| build_tcp_packet([10, 0, 0, i as u8 + 1], [188, 184, 100, 10], 5000 + i, 443))
            .collect();
        rewriter.process_batch(&mut batch);

        assert!(rewriter.metrics.conn_table_fill_bp.get() > 0);
    }

    #[test]
    fn batch_processing_multiple_packets() {
        let mut rewriter = setup_rewriter();
        let mut batch: Vec<PacketBuf> = (0..10)
            .map(|i| build_tcp_packet([10, 0, 0, i as u8 + 1], [188, 184, 100, 10], 10000 + i, 443))
            .collect();

        let processed = rewriter.process_batch(&mut batch);
        assert_eq!(processed, 10);
    }

    /// Build a TCP SYN packet with MSS option for MTU integration tests.
    fn build_syn_with_mss(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        mss: u16,
    ) -> PacketBuf {
        let tcp_header_len = 24u8; // 6 words (base 20 + MSS option 4)
        let total_len = 20 + tcp_header_len as usize;
        let mut pkt = vec![0u8; total_len];

        // IP header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);

        // TCP header
        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = (tcp_header_len / 4) << 4;
        tcp[13] = 0x02; // SYN

        // MSS option
        tcp[20] = 2; // kind
        tcp[21] = 4; // len
        tcp[22..24].copy_from_slice(&mss.to_be_bytes());

        PacketBuf::from_slice(&pkt)
    }

    /// Build an oversized UDP packet with DF set.
    fn build_oversized_udp_df(src: [u8; 4], dst: [u8; 4], total_len: u16) -> PacketBuf {
        let len = total_len as usize;
        let mut pkt = vec![0u8; len.max(28)];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF set
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        // UDP header (port 443)
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((len - 20) as u16).to_be_bytes());
        PacketBuf::from_slice(&pkt[..len.max(28)])
    }

    fn setup_rewriter_with_vip_udp() -> RewriterThread {
        let backends = vec![
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        ];

        let lookup_table = LookupTable::build(&backends, 17).unwrap();
        let pool_id = BackendPoolId("web".into());

        let mut tables = HashMap::new();
        tables.insert(
            pool_id.clone(),
            Arc::new(ArcSwap::from_pointee(lookup_table)),
        );

        let vip_matcher = VipMatcher::from_entries(vec![
            (vip_ip(), Protocol::Tcp, 443, pool_id.clone()),
            (vip_ip(), Protocol::Udp, 443, pool_id),
        ]);

        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);
        let mtu_config = lb_types::MtuConfig::new(1500).unwrap();

        RewriterThread::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            64,
            ConnTtls::with_established(Duration::from_secs(60)),
            tables,
            Arc::new(ArcSwap::from_pointee(vip_matcher)),
            Arc::new(DashMap::new()),
            metrics,
            mtu_config,
            100,
        )
    }

    #[test]
    fn rewriter_clamps_syn_before_gre() {
        let mut rewriter = setup_rewriter();
        // SYN with MSS=1460, should be clamped to 1436 (1500 - 24 - 40)
        let pkt = build_syn_with_mss([10, 0, 0, 100], [188, 184, 100, 10], 12345, 443, 1460);
        let mut batch = vec![pkt];
        let processed = rewriter.process_batch(&mut batch);
        assert_eq!(processed, 1);
        assert_eq!(rewriter.metrics.mss_clamp_total.get(), 1);
        // Output should be GRE-encapsulated
        assert_eq!(batch[0].len, 44 + crate::gre::ENCAP_OVERHEAD);
    }

    #[test]
    fn rewriter_drops_oversized_and_sends_icmp() {
        let mut rewriter = setup_rewriter_with_vip_udp();
        // 1500-byte UDP packet with DF: 1500 + 24 GRE overhead > 1500 network MTU
        let pkt = build_oversized_udp_df([10, 0, 0, 100], [188, 184, 100, 10], 1500);
        let mut batch = vec![pkt];
        let processed = rewriter.process_batch(&mut batch);
        // ICMP response should be in the output
        assert_eq!(processed, 1);
        assert_eq!(rewriter.metrics.icmp_frag_needed_sent_total.get(), 1);
        assert_eq!(rewriter.metrics.packets_oversized_dropped_total.get(), 1);
        // Output is ICMP (protocol=1), not GRE (protocol=47)
        assert_eq!(batch[0].as_slice()[9], 1);
    }

    #[test]
    fn rewriter_forwards_fitting_packet_unchanged() {
        let mut rewriter = setup_rewriter();
        // Small TCP packet that fits in the tunnel
        let pkt = build_tcp_packet([10, 0, 0, 100], [188, 184, 100, 10], 12345, 443);
        let original_len = pkt.len;
        let mut batch = vec![pkt];
        let processed = rewriter.process_batch(&mut batch);
        assert_eq!(processed, 1);
        assert_eq!(rewriter.metrics.packets_forwarded.get(), 1);
        assert_eq!(rewriter.metrics.packets_oversized_dropped_total.get(), 0);
        // GRE-encapsulated: original + 24 overhead
        assert_eq!(batch[0].len, original_len + crate::gre::ENCAP_OVERHEAD);
    }
}
