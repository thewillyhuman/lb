pub mod conn_table;
pub mod fragment_table;
pub mod gre;
pub mod icmp;
pub mod mss_clamp;
pub mod packet_pool;
pub mod rewriter;
pub mod steering;
pub mod threading;
pub mod tracer;
pub mod vip_matcher;

use lb_hashing::LookupTable;
use lb_io::{PacketBuf, PacketIo};
use lb_metrics::ForwarderMetrics;
use lb_types::{BackendPoolId, ConnTtls, HealthStatus, MtuConfig};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use crate::rewriter::RewriterThread;
use crate::vip_matcher::VipMatcher;

/// Configuration for the ForwarderEngine.
pub struct ForwarderConfig {
    pub src_ip: IpAddr,
    pub connection_table_size: usize,
    pub conn_ttls: ConnTtls,
    pub fragment_table_size: usize,
    pub fragment_ttl: std::time::Duration,
    pub batch_size: usize,
    pub mtu_config: MtuConfig,
    pub icmp_rate_limit: u32,
}

/// Single-threaded forwarder engine.
///
/// **Not for production.** `lb-node` uses [`threading::MultiThreadedForwarder`]
/// — that's the steering + rewriter + muxer pipeline with the zero-copy
/// `PacketPool` that benchmarks at ~400 ns/packet end-to-end.
/// `ForwarderEngine` exists only as the test/dev-mode driver:
///
///   * Drives one rewriter on the calling thread, no inter-thread queues.
///   * `process_one` calls `PacketBuf::clone()` twice per packet (once at
///     batch entry, once before MSS clamp) because the engine doesn't have
///     a `PacketPool` to mutate frames in place. This is fine for tests
///     where you process a few packets per iteration; it's not what you
///     want at line rate.
///   * Used by the `end_to_end_with_mock_io` integration test in this
///     module and by some benches that want a tighter measurement loop
///     than the multi-threaded pipeline can give them.
///
/// Hidden from user-facing rustdoc to keep the public surface honest;
/// still `pub` because tests across crates use it.
#[doc(hidden)]
pub struct ForwarderEngine<T: PacketIo> {
    io: T,
    rewriter: RewriterThread,
    batch_size: usize,
}

impl<T: PacketIo> ForwarderEngine<T> {
    pub fn new(
        io: T,
        config: ForwarderConfig,
        lookup_tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
        vip_matcher: Arc<ArcSwap<VipMatcher>>,
        health_status: Arc<DashMap<IpAddr, HealthStatus>>,
        metrics: ForwarderMetrics,
    ) -> Self {
        let rewriter = RewriterThread::new(
            config.src_ip,
            config.connection_table_size,
            config.conn_ttls,
            config.fragment_table_size,
            config.fragment_ttl,
            lookup_tables,
            vip_matcher,
            health_status,
            metrics,
            config.mtu_config,
            config.icmp_rate_limit,
        );

        Self {
            io,
            rewriter,
            batch_size: config.batch_size,
        }
    }

    /// Run a single receive-process-send cycle. Returns the number of packets forwarded.
    pub fn run_once(&mut self) -> usize {
        let mut rx_buf = vec![PacketBuf::new(); self.batch_size];
        let received = match self.io.recv_batch(&mut rx_buf) {
            Ok(n) => n,
            Err(_) => return 0,
        };

        if received == 0 {
            return 0;
        }

        let processed = self.rewriter.process_batch(&mut rx_buf[..received]);

        if processed > 0 {
            let _ = self.io.send_batch(&rx_buf[..processed]);
        }

        processed
    }

    /// Run the forwarding loop indefinitely.
    pub fn run(&mut self) {
        loop {
            self.run_once();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_hashing::LookupTable;
    use lb_io::mock::mock_io;
    use lb_types::{Backend, Protocol};
    use std::net::Ipv4Addr;

    fn build_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn end_to_end_with_mock_io() {
        let (io, handle) = mock_io();

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

        let vip_matcher = vip_matcher::VipMatcher::from_entries(vec![(
            IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            Protocol::Tcp,
            443,
            pool_id,
        )]);

        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);

        let config = ForwarderConfig {
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            connection_table_size: 64,
            conn_ttls: ConnTtls::with_established(std::time::Duration::from_secs(60)),
            fragment_table_size: 64,
            fragment_ttl: std::time::Duration::from_secs(10),
            batch_size: 64,
            mtu_config: MtuConfig::new(1500).unwrap(),
            icmp_rate_limit: 100,
        };

        let mut engine = ForwarderEngine::new(
            io,
            config,
            tables,
            Arc::new(ArcSwap::from_pointee(vip_matcher)),
            Arc::new(DashMap::new()),
            metrics,
        );

        // Inject 5 packets to the VIP
        for i in 0..5 {
            let pkt = build_tcp_packet(
                [10, 0, 0, 100 + i],
                [188, 184, 100, 10],
                12345 + i as u16,
                443,
            );
            handle.inject_packet(&pkt);
        }

        // Also inject 2 packets to a non-VIP (should be dropped)
        for _ in 0..2 {
            let pkt = build_tcp_packet([10, 0, 0, 200], [10, 0, 0, 99], 54321, 80);
            handle.inject_packet(&pkt);
        }

        let forwarded = engine.run_once();
        assert_eq!(forwarded, 5);
        assert_eq!(handle.tx_count(), 5);

        // Verify each transmitted packet is GRE-encapsulated
        for _ in 0..5 {
            let pkt = handle.read_transmitted().unwrap();
            assert_eq!(pkt.len(), 40 + gre::ENCAP_OVERHEAD);
            assert_eq!(pkt[0], 0x45); // outer IPv4
            assert_eq!(pkt[9], 47); // GRE protocol
            assert_eq!(&pkt[12..16], &[172, 16, 0, 1]); // src = LB node IP
        }
    }
}
