use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Top-level node configuration deserialized from TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node: NodeSection,
    pub bgp: BgpConfig,
    pub control_plane: ControlPlaneConfig,
    pub forwarder: ForwarderConfig,
    pub health_check_defaults: HealthCheckConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    pub id: String,
    pub loopback_ip: IpAddr,
    pub data_iface: String,
    #[serde(default = "default_num_threads")]
    pub num_threads: usize,
}

fn default_num_threads() -> usize {
    7
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpConfig {
    pub local_asn: u32,
    pub router_id: IpAddr,
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
    #[serde(default)]
    pub communities: Vec<String>,
    #[serde(default = "default_true")]
    pub next_hop_self: bool,
}

fn default_true() -> bool {
    true
}

/// Per ADR-001: configuration is loaded from a local file, watched via inotify.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfig {
    /// Path to the LB config JSON file (VIPs + pools).
    pub config_file: PathBuf,
    /// Local cache path for persisting validated config.
    pub local_cache: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwarderConfig {
    #[serde(default = "default_packet_pool_size")]
    pub packet_pool_size: usize,
    #[serde(default = "default_connection_table_size")]
    pub connection_table_size: usize,
    #[serde(default = "default_fragment_table_size")]
    pub fragment_table_size: usize,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(deserialize_with = "deserialize_duration")]
    pub batch_flush_interval: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub connection_ttl: Duration,
}

fn default_packet_pool_size() -> usize {
    4096
}
fn default_connection_table_size() -> usize {
    // Must be at least 2× expected peak concurrent flows to keep fill ratio under 50%.
    // At high fill ratios, even Robin Hood hashing sees degraded miss latency (e.g. 95%
    // fill → 214ns/miss vs 7ns at 50%), and during a SYN flood the scan cost to discover
    // the table is full dominates the forwarding path.
    131072
}
fn default_fragment_table_size() -> usize {
    8192
}
fn default_batch_size() -> usize {
    64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(
        deserialize_with = "deserialize_duration",
        serialize_with = "serialize_duration"
    )]
    pub interval: Duration,
    #[serde(
        deserialize_with = "deserialize_duration",
        serialize_with = "serialize_duration"
    )]
    pub timeout: Duration,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_healthy_threshold() -> u32 {
    2
}
fn default_unhealthy_threshold() -> u32 {
    3
}

/// Serialize a duration as a human-readable string.
fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let micros = duration.as_micros();
    let s = if micros.is_multiple_of(1_000_000) {
        format!("{}s", micros / 1_000_000)
    } else if micros.is_multiple_of(1_000) {
        format!("{}ms", micros / 1_000)
    } else {
        format!("{micros}us")
    };
    serializer.serialize_str(&s)
}

/// Deserialize a duration from a human-readable string like "5s", "50us", "10ms".
fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(val) = s.strip_suffix("us") {
        let n: u64 = val.trim().parse().map_err(|e| format!("{e}"))?;
        Ok(Duration::from_micros(n))
    } else if let Some(val) = s.strip_suffix("ms") {
        let n: u64 = val.trim().parse().map_err(|e| format!("{e}"))?;
        Ok(Duration::from_millis(n))
    } else if let Some(val) = s.strip_suffix('s') {
        let n: u64 = val.trim().parse().map_err(|e| format!("{e}"))?;
        Ok(Duration::from_secs(n))
    } else {
        Err(format!("unknown duration format: {s}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
    }

    #[test]
    fn parse_duration_milliseconds() {
        assert_eq!(parse_duration("100ms").unwrap(), Duration::from_millis(100));
    }

    #[test]
    fn parse_duration_microseconds() {
        assert_eq!(parse_duration("50us").unwrap(), Duration::from_micros(50));
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn deserialize_node_config_from_toml() {
        let toml_str = r#"
[node]
id = "lb-node-01"
loopback_ip = "188.184.0.1"
data_iface = "eth0"
num_threads = 7

[bgp]
local_asn = 65000
router_id = "188.184.0.1"
peer_ip = "188.184.0.254"
peer_asn = 65000
communities = ["65000:100"]
next_hop_self = true

[control_plane]
config_file = "/etc/lb/lb-config.json"
local_cache = "/var/lib/lb/config-cache.json"

[forwarder]
packet_pool_size = 4096
connection_table_size = 131072
fragment_table_size = 8192
batch_size = 64
batch_flush_interval = "50us"
connection_ttl = "60s"

[health_check_defaults]
interval = "5s"
timeout = "2s"
healthy_threshold = 2
unhealthy_threshold = 3
"#;

        let config: NodeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.id, "lb-node-01");
        assert_eq!(config.bgp.local_asn, 65000);
        assert_eq!(config.forwarder.connection_table_size, 131072);
        assert_eq!(config.forwarder.batch_flush_interval, Duration::from_micros(50));
        assert_eq!(config.health_check_defaults.healthy_threshold, 2);
    }
}
