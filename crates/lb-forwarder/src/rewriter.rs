use crate::conn_table::ConnTable;
use crate::gre;
use crate::vip_matcher::VipMatcher;
use lb_hashing::LookupTable;
use lb_io::PacketBuf;
use lb_metrics::ForwarderMetrics;
use lb_types::{BackendPoolId, HealthStatus, PacketMeta};
use std::collections::HashMap;
use std::net::IpAddr;
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
    ) -> Self {
        Self {
            src_ip,
            conn_table: ConnTable::new(conn_table_size, conn_ttl),
            lookup_tables,
            vip_matcher,
            health_status,
            metrics,
        }
    }

    /// Process a batch of packets. Rewrites packets in-place with GRE encapsulation.
    /// Returns the number of successfully processed packets (compacted to the front of the slice).
    pub fn process_batch(&mut self, packets: &mut [PacketBuf]) -> usize {
        let vip_matcher = self.vip_matcher.load();
        // Grab timestamp once per batch — avoids clock_gettime vDSO call per packet.
        let now = std::time::Instant::now();
        let mut write_idx = 0;

        for read_idx in 0..packets.len() {
            self.metrics.packets_received.inc();

            if self.process_one(&packets[read_idx].clone(), &vip_matcher, &mut packets[write_idx], now) {
                write_idx += 1;
                self.metrics.packets_forwarded.inc();
            } else {
                self.metrics.packets_dropped.inc();
            }
        }

        self.metrics.conn_table_size.set(self.conn_table.len() as i64);
        write_idx
    }

    fn process_one(&mut self, input: &PacketBuf, vip_matcher: &VipMatcher, output: &mut PacketBuf, now: std::time::Instant) -> bool {
        // Parse 5-tuple
        let meta = match PacketMeta::from_ipv4_bytes(input.as_slice()) {
            Some(m) => m,
            None => return false,
        };

        // VIP match
        let pool_id = match vip_matcher.match_packet(meta.dst_ip, meta.protocol, meta.dst_port) {
            Some(id) => id,
            None => return false,
        };

        // Get lookup table for this pool
        let lookup_table_swap = match self.lookup_tables.get(pool_id) {
            Some(lt) => lt,
            None => return false,
        };
        let lookup_table = lookup_table_swap.load();

        let flow_hash = meta.flow_hash();

        // Connection table lookup
        let backend_ip = if let Some(cached_ip) = self.conn_table.get(flow_hash, now) {
            // Check if cached backend is still healthy
            let healthy = self
                .health_status
                .get(&cached_ip)
                .map(|s| *s != HealthStatus::Unhealthy)
                .unwrap_or(true); // if no health status, assume healthy

            if healthy {
                self.metrics.conn_table_hits.inc();
                self.conn_table.touch(flow_hash, now);
                cached_ip
            } else {
                // Backend unhealthy, fall through to consistent hash
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

        // GRE encapsulation (IPv4-in-IPv4 for now)
        let src_ipv4 = match self.src_ip {
            IpAddr::V4(v4) => v4,
            _ => return false,
        };
        let dst_ipv4 = match backend_ip {
            IpAddr::V4(v4) => v4,
            _ => return false,
        };

        // Copy input to output, then encapsulate
        *output = input.clone();
        gre::encapsulate_ipv4(output, src_ipv4, dst_ipv4)
    }
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

        RewriterThread::new(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            64,
            Duration::from_secs(60),
            tables,
            Arc::new(ArcSwap::from_pointee(vip_matcher)),
            Arc::new(DashMap::new()),
            metrics,
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
}
