pub mod controller_metrics;
pub mod forwarder_metrics;

pub use controller_metrics::{BgpMetrics, ControllerMetrics, PeerLabels};
pub use forwarder_metrics::{EvictionLabels, ForwarderMetrics, TcpTransitionLabels};

use parking_lot::Mutex;
use prometheus_client::registry::Registry;

/// Global metrics registry shared across the application.
pub struct LbMetrics {
    pub registry: Mutex<Registry>,
    pub forwarder: ForwarderMetrics,
    pub controller: ControllerMetrics,
}

impl LbMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let forwarder = ForwarderMetrics::register(&mut registry);
        let controller = ControllerMetrics::register(&mut registry);
        Self {
            registry: Mutex::new(registry),
            forwarder,
            controller,
        }
    }

    /// Encode all metrics as Prometheus text format.
    pub fn encode(&self) -> String {
        let registry = self.registry.lock();
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
        buf
    }
}

impl Default for LbMetrics {
    fn default() -> Self {
        Self::new()
    }
}
