use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

/// Control-plane metrics.
#[derive(Clone)]
pub struct ControllerMetrics {
    pub bgp_state: Gauge,
    pub config_last_reload_timestamp: Gauge,
    pub config_reload_errors: Counter,
    pub bgp: BgpMetrics,
}

impl ControllerMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let bgp_state = Gauge::default();
        let config_last_reload_timestamp = Gauge::default();
        let config_reload_errors = Counter::default();

        registry.register(
            "lb_bgp_state",
            "1=announcing (at least one peer established), 0=all peers down",
            bgp_state.clone(),
        );
        registry.register(
            "lb_config_last_reload_timestamp",
            "Unix timestamp of last successful config reload",
            config_last_reload_timestamp.clone(),
        );
        registry.register(
            "lb_config_reload_errors_total",
            "Number of failed config reload attempts",
            config_reload_errors.clone(),
        );

        let bgp = BgpMetrics::register(registry);

        Self {
            bgp_state,
            config_last_reload_timestamp,
            config_reload_errors,
            bgp,
        }
    }
}

/// Per-peer BGP metrics. Labelled by peer IP so operators can see exactly
/// which router is flapping.
#[derive(Clone)]
pub struct BgpMetrics {
    pub peer_state: Family<PeerLabels, Gauge>,
    pub peer_connects: Family<PeerLabels, Counter>,
    pub peer_disconnects: Family<PeerLabels, Counter>,
    pub announce_failures: Family<PeerLabels, Counter>,
    pub withdraw_failures: Family<PeerLabels, Counter>,
    pub vips_announced: Gauge,
    pub peer_notifications: Family<PeerNotificationLabels, Counter>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PeerLabels {
    pub peer_ip: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PeerNotificationLabels {
    pub peer_ip: String,
    /// BGP error code (RFC 4271 §4.5). `1`=msg header, `2`=OPEN, `3`=UPDATE,
    /// `4`=hold-timer-expired, `5`=FSM, `6`=Cease.
    pub code: u8,
    pub subcode: u8,
}

impl BgpMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let peer_state: Family<PeerLabels, Gauge> = Family::default();
        let peer_connects: Family<PeerLabels, Counter> = Family::default();
        let peer_disconnects: Family<PeerLabels, Counter> = Family::default();
        let announce_failures: Family<PeerLabels, Counter> = Family::default();
        let withdraw_failures: Family<PeerLabels, Counter> = Family::default();
        let vips_announced = Gauge::default();
        let peer_notifications: Family<PeerNotificationLabels, Counter> = Family::default();

        registry.register(
            "lb_bgp_peer_state",
            "1=Established, 0=not Established (Idle/Connecting/Backoff/Disabled)",
            peer_state.clone(),
        );
        registry.register(
            "lb_bgp_peer_connects_total",
            "Successful BGP session establishments",
            peer_connects.clone(),
        );
        registry.register(
            "lb_bgp_peer_disconnects_total",
            "BGP session disconnects (any reason)",
            peer_disconnects.clone(),
        );
        registry.register(
            "lb_bgp_announce_failures_total",
            "Announce operations that failed on an established session",
            announce_failures.clone(),
        );
        registry.register(
            "lb_bgp_withdraw_failures_total",
            "Withdraw operations that failed on an established session",
            withdraw_failures.clone(),
        );
        registry.register(
            "lb_bgp_vips_announced",
            "Count of VIPs currently being announced to the fleet",
            vips_announced.clone(),
        );
        registry.register(
            "lb_bgp_peer_notifications_total",
            "NOTIFICATION messages received from a peer (RFC 4271 §4.5); session is torn down after each",
            peer_notifications.clone(),
        );

        Self {
            peer_state,
            peer_connects,
            peer_disconnects,
            announce_failures,
            withdraw_failures,
            vips_announced,
            peer_notifications,
        }
    }
}
