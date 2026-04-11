use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

/// Control-plane metrics.
#[derive(Clone)]
pub struct ControllerMetrics {
    pub bgp_state: Gauge,
    pub config_last_reload_timestamp: Gauge,
    pub config_reload_errors: Counter,
}

impl ControllerMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let bgp_state = Gauge::default();
        let config_last_reload_timestamp = Gauge::default();
        let config_reload_errors = Counter::default();

        registry.register(
            "lb_bgp_state",
            "1=announcing, 0=withdrawn",
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

        Self {
            bgp_state,
            config_last_reload_timestamp,
            config_reload_errors,
        }
    }
}
