use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

/// Data-plane metrics for the forwarder.
#[derive(Clone)]
pub struct ForwarderMetrics {
    pub packets_received: Counter,
    pub packets_forwarded: Counter,
    pub packets_dropped: Counter,
    pub conn_table_hits: Counter,
    pub conn_table_misses: Counter,
    pub conn_table_size: Gauge,
    pub processing_latency_ns: Histogram,
    // Connection-tracking details (aligns with Maglev paper §3.3)
    pub conn_table_inserts_total: Counter,
    pub conn_table_evictions_total: Family<EvictionLabels, Counter>,
    pub conn_table_tcp_transitions_total: Family<TcpTransitionLabels, Counter>,
    pub conn_table_fallback_to_maglev_total: Counter,
    pub conn_table_fill_bp: Gauge,
    // MTU handling metrics
    pub mss_clamp_total: Counter,
    pub mss_clamp_noop_total: Counter,
    pub mss_clamp_missing_total: Counter,
    pub icmp_frag_needed_sent_total: Counter,
    pub icmp_frag_needed_ratelimited_total: Counter,
    pub packets_oversized_dropped_total: Counter,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EvictionLabels {
    /// `expired_on_insert` when an expired slot was reclaimed on insert,
    /// `dropped_full` when every probe slot was occupied.
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TcpTransitionLabels {
    /// `established`, `closing_fin`, or `closing_rst`.
    pub to: String,
}

impl ForwarderMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let packets_received = Counter::default();
        let packets_forwarded = Counter::default();
        let packets_dropped = Counter::default();
        let conn_table_hits = Counter::default();
        let conn_table_misses = Counter::default();
        let conn_table_size = Gauge::default();
        let processing_latency_ns = Histogram::new(
            [100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0],
        );
        let mss_clamp_total = Counter::default();
        let mss_clamp_noop_total = Counter::default();
        let mss_clamp_missing_total = Counter::default();
        let icmp_frag_needed_sent_total = Counter::default();
        let icmp_frag_needed_ratelimited_total = Counter::default();
        let packets_oversized_dropped_total = Counter::default();
        let conn_table_inserts_total = Counter::default();
        let conn_table_evictions_total: Family<EvictionLabels, Counter> = Family::default();
        let conn_table_tcp_transitions_total: Family<TcpTransitionLabels, Counter> =
            Family::default();
        let conn_table_fallback_to_maglev_total = Counter::default();
        let conn_table_fill_bp = Gauge::default();

        registry.register(
            "lb_packets_received_total",
            "Total packets received by the steering module",
            packets_received.clone(),
        );
        registry.register(
            "lb_packets_forwarded_total",
            "Total packets successfully GRE-forwarded",
            packets_forwarded.clone(),
        );
        registry.register(
            "lb_packets_dropped_total",
            "Total packets dropped",
            packets_dropped.clone(),
        );
        registry.register(
            "lb_connection_table_hits_total",
            "Connection tracking cache hits",
            conn_table_hits.clone(),
        );
        registry.register(
            "lb_connection_table_misses_total",
            "Connection tracking cache misses",
            conn_table_misses.clone(),
        );
        registry.register(
            "lb_connection_table_size",
            "Current number of active entries in connection table",
            conn_table_size.clone(),
        );
        registry.register(
            "lb_packet_processing_latency_ns",
            "Per-packet processing latency in nanoseconds",
            processing_latency_ns.clone(),
        );
        registry.register(
            "lb_mss_clamp_total",
            "TCP SYN packets where MSS was clamped",
            mss_clamp_total.clone(),
        );
        registry.register(
            "lb_mss_clamp_noop_total",
            "TCP SYN packets where MSS was already within limit",
            mss_clamp_noop_total.clone(),
        );
        registry.register(
            "lb_mss_clamp_missing_total",
            "TCP SYN packets with no MSS option",
            mss_clamp_missing_total.clone(),
        );
        registry.register(
            "lb_icmp_frag_needed_sent_total",
            "ICMP Fragmentation Needed responses generated",
            icmp_frag_needed_sent_total.clone(),
        );
        registry.register(
            "lb_icmp_frag_needed_ratelimited_total",
            "ICMP responses suppressed by rate limiter",
            icmp_frag_needed_ratelimited_total.clone(),
        );
        registry.register(
            "lb_packets_oversized_dropped_total",
            "Oversized packets dropped (DF set, exceeds inner MTU)",
            packets_oversized_dropped_total.clone(),
        );
        registry.register(
            "lb_connection_table_inserts_total",
            "Connection tracking insertions (new or reclaimed expired slot)",
            conn_table_inserts_total.clone(),
        );
        registry.register(
            "lb_connection_table_evictions_total",
            "Connection tracking evictions labelled by reason",
            conn_table_evictions_total.clone(),
        );
        registry.register(
            "lb_connection_table_tcp_transitions_total",
            "TCP flow state transitions observed by the connection tracker",
            conn_table_tcp_transitions_total.clone(),
        );
        registry.register(
            "lb_connection_table_fallback_to_maglev_total",
            "Cache hit re-routed via Maglev because the cached backend became unhealthy",
            conn_table_fallback_to_maglev_total.clone(),
        );
        registry.register(
            "lb_connection_table_fill_bp",
            "Connection table fill ratio in basis points (0-10000)",
            conn_table_fill_bp.clone(),
        );

        Self {
            packets_received,
            packets_forwarded,
            packets_dropped,
            conn_table_hits,
            conn_table_misses,
            conn_table_size,
            processing_latency_ns,
            conn_table_inserts_total,
            conn_table_evictions_total,
            conn_table_tcp_transitions_total,
            conn_table_fallback_to_maglev_total,
            conn_table_fill_bp,
            mss_clamp_total,
            mss_clamp_noop_total,
            mss_clamp_missing_total,
            icmp_frag_needed_sent_total,
            icmp_frag_needed_ratelimited_total,
            packets_oversized_dropped_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment() {
        let mut registry = Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);

        metrics.packets_received.inc();
        metrics.packets_received.inc();
        metrics.packets_forwarded.inc();

        assert_eq!(metrics.packets_received.get(), 2);
        assert_eq!(metrics.packets_forwarded.get(), 1);
        assert_eq!(metrics.packets_dropped.get(), 0);
    }

    #[test]
    fn gauge_set() {
        let mut registry = Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);

        metrics.conn_table_size.set(1024);
        assert_eq!(metrics.conn_table_size.get(), 1024);
    }

    #[test]
    fn histogram_observe() {
        let mut registry = Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);
        metrics.processing_latency_ns.observe(500.0);
        // Just verify it doesn't panic
    }

    #[test]
    fn encode_produces_output() {
        let mut registry = Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);
        metrics.packets_received.inc();

        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
        assert!(buf.contains("lb_packets_received_total"));
    }
}
