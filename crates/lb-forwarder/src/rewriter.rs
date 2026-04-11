use crate::conn_table::ConnTable;
use crate::gre;
use crate::icmp;
use crate::mss_clamp::{self, ClampResult};
use crate::vip_matcher::VipMatcher;
use lb_hashing::LookupTable;
use lb_io::PacketBuf;
use lb_metrics::ForwarderMetrics;
use lb_types::{BackendPoolId, HealthStatus, MtuConfig, PacketMeta};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

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
    pub fn new(
        src_ip: IpAddr,
        conn_table_size: usize,
        conn_ttl: Duration,
        lookup_tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
        vip_matcher: Arc<ArcSwap<VipMatcher>>,
        health_status: Arc<DashMap<IpAddr, HealthStatus>>,
        metrics: ForwarderMetrics,
        mtu_config: MtuConfig,
        icmp_rate_limit: u32,
    ) -> Self {
        Self {
            src_ip,
            conn_table: ConnTable::new(conn_table_size, conn_ttl),
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

        self.metrics.conn_table_size.set(self.conn_table.len() as i64);
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
            ClampResult::Clamped => { self.metrics.mss_clamp_total.inc(); }
            ClampResult::Noop => { self.metrics.mss_clamp_noop_total.inc(); }
            ClampResult::MssMissing => { self.metrics.mss_clamp_missing_total.inc(); }
            ClampResult::NotTcp | ClampResult::NotSyn => {}
        }

        // Backend selection (connection table + Maglev)
        let lookup_table_swap = match self.lookup_tables.get(pool_id) {
            Some(lt) => lt,
            None => return ProcessResult::Dropped,
        };
        let lookup_table = lookup_table_swap.load();

        let flow_hash = meta.flow_hash();

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
                self.metrics.conn_table_misses.inc();
                let backend = lookup_table.lookup(flow_hash);
                self.conn_table.insert(flow_hash, backend.ip, now);
                backend.ip
            }
        } else {
            self.metrics.conn_table_misses.inc();
            let backend = lookup_table.lookup(flow_hash);
            self.conn_table.insert(flow_hash, backend.ip, now);
            backend.ip
        };

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
        tables.insert(pool_id.clone(), Arc::new(ArcSwap::from_pointee(lookup_table)));

        let vip_matcher = VipMatcher::from_entries(vec![(
            vip_ip(),
            Protocol::Tcp,
            443,
            pool_id,
        )]);

        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);

        let mtu_config = lb_types::MtuConfig::new(1500).unwrap();

        RewriterThread::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            64,
            Duration::from_secs(60),
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

    #[test]
    fn batch_processing_multiple_packets() {
        let mut rewriter = setup_rewriter();
        let mut batch: Vec<PacketBuf> = (0..10)
            .map(|i| {
                build_tcp_packet(
                    [10, 0, 0, i as u8 + 1],
                    [188, 184, 100, 10],
                    10000 + i,
                    443,
                )
            })
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
        tables.insert(pool_id.clone(), Arc::new(ArcSwap::from_pointee(lookup_table)));

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
            Duration::from_secs(60),
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
