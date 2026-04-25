use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Unique identifier for a backend pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackendPoolId(pub String);

/// Health status of a backend as determined by the health checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Unknown,
    Healthy,
    Unhealthy,
}

/// A single backend server in a pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Backend {
    pub ip: IpAddr,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Operator-initiated drain. When `true`, the backend is excluded
    /// from the next Maglev rebuild (no new flows land here) but is *not*
    /// marked unhealthy — the rewriter's per-packet health check still
    /// returns "healthy", so existing connection-tracking entries
    /// pointing at this backend complete naturally on the connection's
    /// own timeline rather than getting force-rehashed.
    ///
    /// Use this when an operator is taking a backend out of rotation
    /// for maintenance: flip `drain = true` in `lb-config.json`, wait
    /// for the connection-table TTL to elapse (operations doc has the
    /// procedure), then take the backend down. Compare with
    /// `HealthStatus::Unhealthy`, which the *health checker* sets
    /// automatically and which forces existing flows to rehash.
    #[serde(default)]
    pub drain: bool,
}

fn default_weight() -> u32 {
    1
}

impl Backend {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port,
            weight: 1,
            drain: false,
        }
    }

    /// Stable name used for Maglev hashing permutation derivation.
    pub fn name(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

/// An ordered set of backend endpoints serving a VIP service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendPool {
    pub id: BackendPoolId,
    pub backends: Vec<Backend>,
    pub health_check: Option<crate::config::HealthCheckConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn backend_name_format() {
        let b = Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        assert_eq!(b.name(), "10.0.0.1:443");
    }

    #[test]
    fn backend_default_weight() {
        let json = r#"{"ip":"10.0.0.1","port":80}"#;
        let b: Backend = serde_json::from_str(json).unwrap();
        assert_eq!(b.weight, 1);
    }

    #[test]
    fn health_status_variants() {
        assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
        assert_ne!(HealthStatus::Unknown, HealthStatus::Healthy);
    }
}
