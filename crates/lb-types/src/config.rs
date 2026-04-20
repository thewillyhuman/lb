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

/// BGP configuration for VIP announcement.
///
/// Each LB node holds one independent BGP session per configured peer. All
/// sessions are active-active: VIP announce/withdraw fans out to every live
/// peer, so loss of any single router does not remove the VIP from the other
/// routers' routing tables.
///
/// For backward compatibility, the legacy single-peer form with top-level
/// `peer_ip`/`peer_asn` is still accepted and converted to a one-element
/// `peers` vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpConfig {
    pub local_asn: u32,
    pub router_id: IpAddr,
    pub communities: Vec<String>,
    pub next_hop_self: bool,
    /// At least one peer must be configured.
    pub peers: Vec<BgpPeerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BgpPeerConfig {
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
    #[serde(default = "default_bgp_port")]
    pub port: u16,
    /// Hold time in seconds. `None` defers to the speaker default (90s).
    #[serde(default)]
    pub hold_time_secs: Option<u16>,
    /// Per-peer community override. `None` inherits top-level `communities`.
    #[serde(default)]
    pub communities: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_bgp_port() -> u16 {
    179
}

fn default_true() -> bool {
    true
}

// Raw deserialization helper: accepts both the legacy flat single-peer form
// (`peer_ip`/`peer_asn` at the top level) and the new `peers = [...]` list.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BgpConfigRaw {
    local_asn: u32,
    router_id: IpAddr,
    #[serde(default)]
    communities: Vec<String>,
    #[serde(default = "default_true")]
    next_hop_self: bool,
    #[serde(default)]
    peer_ip: Option<IpAddr>,
    #[serde(default)]
    peer_asn: Option<u32>,
    #[serde(default)]
    peers: Option<Vec<BgpPeerConfig>>,
}

impl<'de> Deserialize<'de> for BgpConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = BgpConfigRaw::deserialize(deserializer)?;

        let peers = match (raw.peers, raw.peer_ip, raw.peer_asn) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(serde::de::Error::custom(
                    "bgp: specify either `peers = [...]` or legacy `peer_ip`/`peer_asn`, not both",
                ));
            }
            (Some(peers), None, None) => {
                if peers.is_empty() {
                    return Err(serde::de::Error::custom(
                        "bgp.peers must contain at least one peer",
                    ));
                }
                peers
            }
            (None, Some(peer_ip), Some(peer_asn)) => vec![BgpPeerConfig {
                peer_ip,
                peer_asn,
                port: default_bgp_port(),
                hold_time_secs: None,
                communities: None,
                enabled: true,
            }],
            (None, None, None) => {
                return Err(serde::de::Error::custom(
                    "bgp: no peers configured (expected `peers = [...]` or legacy `peer_ip`+`peer_asn`)",
                ));
            }
            (None, Some(_), None) | (None, None, Some(_)) => {
                return Err(serde::de::Error::custom(
                    "bgp: legacy single-peer form requires both `peer_ip` and `peer_asn`",
                ));
            }
        };

        Ok(BgpConfig {
            local_asn: raw.local_asn,
            router_id: raw.router_id,
            communities: raw.communities,
            next_hop_self: raw.next_hop_self,
            peers,
        })
    }
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
    /// Legacy single TTL. Used as the default for `connection_ttls.tcp_established`
    /// when `[forwarder.connection_ttls]` is not provided.
    #[serde(deserialize_with = "deserialize_duration")]
    pub connection_ttl: Duration,
    /// Per-protocol-and-state TTLs used by the connection tracker.
    /// Omit the section to use defaults derived from `connection_ttl`.
    #[serde(default)]
    pub connection_ttls: Option<ConnTtlsConfig>,
    /// Network MTU of the data interface. The system derives all tunnel
    /// parameters (effective inner MTU, TCP MSS clamp) from this value.
    #[serde(default = "default_network_mtu")]
    pub network_mtu: u16,
    /// Maximum ICMP Fragmentation Needed responses per second per VIP.
    #[serde(default = "default_icmp_rate_limit")]
    pub icmp_rate_limit: u32,
}

impl ForwarderConfig {
    /// Resolve the effective connection-tracking TTLs, applying defaults for
    /// any field not explicitly set.
    pub fn resolved_conn_ttls(&self) -> ConnTtls {
        let defaults = ConnTtls::with_established(self.connection_ttl);
        match &self.connection_ttls {
            None => defaults,
            Some(c) => ConnTtls {
                tcp_handshake: c
                    .tcp_handshake
                    .unwrap_or(defaults.tcp_handshake),
                tcp_established: c
                    .tcp_established
                    .unwrap_or(defaults.tcp_established),
                tcp_closing: c.tcp_closing.unwrap_or(defaults.tcp_closing),
                udp: c.udp.unwrap_or(defaults.udp),
                other: c.other.unwrap_or(defaults.other),
            },
        }
    }
}

/// Resolved per-protocol-and-state connection TTLs.
///
/// Shorter TTLs for handshake (SYN without ACK) and closing (FIN/RST seen)
/// prevent half-open connections and graceful-closed flows from occupying a
/// slot for the full established duration — this matters at scale where
/// FIN-flood patterns or half-open SYN scans could otherwise bloat the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnTtls {
    pub tcp_handshake: Duration,
    pub tcp_established: Duration,
    pub tcp_closing: Duration,
    pub udp: Duration,
    pub other: Duration,
}

impl ConnTtls {
    /// Build a TTL set where `tcp_established` is the operator-chosen value
    /// and the other buckets use sensible defaults derived from it.
    pub fn with_established(established: Duration) -> Self {
        Self {
            tcp_handshake: Duration::from_secs(5),
            tcp_established: established,
            tcp_closing: Duration::from_secs(10),
            udp: Duration::from_secs(30),
            other: Duration::from_secs(30),
        }
    }
}

/// TOML-facing view of [`ConnTtls`] where every field is optional.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnTtlsConfig {
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    pub tcp_handshake: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    pub tcp_established: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    pub tcp_closing: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    pub udp: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_opt_duration")]
    pub other: Option<Duration>,
}

fn deserialize_opt_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        None => Ok(None),
        Some(s) => parse_duration(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
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
fn default_network_mtu() -> u16 {
    1500
}
fn default_icmp_rate_limit() -> u32 {
    100
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
communities = ["65000:100"]
next_hop_self = true

[[bgp.peers]]
peer_ip = "188.184.0.254"
peer_asn = 65000

[[bgp.peers]]
peer_ip = "188.184.0.253"
peer_asn = 65000
hold_time_secs = 30

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
network_mtu = 1500
icmp_rate_limit = 100

[health_check_defaults]
interval = "5s"
timeout = "2s"
healthy_threshold = 2
unhealthy_threshold = 3
"#;

        let config: NodeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.id, "lb-node-01");
        assert_eq!(config.bgp.local_asn, 65000);
        assert_eq!(config.bgp.peers.len(), 2);
        assert_eq!(config.bgp.peers[0].port, 179);
        assert_eq!(config.bgp.peers[1].hold_time_secs, Some(30));
        assert_eq!(config.forwarder.connection_table_size, 131072);
        assert_eq!(config.forwarder.batch_flush_interval, Duration::from_micros(50));
        assert_eq!(config.health_check_defaults.healthy_threshold, 2);
    }

    #[test]
    fn bgp_legacy_single_peer_form_still_accepted() {
        let toml_str = r#"
local_asn = 65000
router_id = "10.0.0.1"
peer_ip = "10.0.0.254"
peer_asn = 65000
"#;
        let cfg: BgpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(
            cfg.peers[0].peer_ip,
            "10.0.0.254".parse::<IpAddr>().unwrap()
        );
        assert_eq!(cfg.peers[0].peer_asn, 65000);
        assert_eq!(cfg.peers[0].port, 179);
        assert!(cfg.peers[0].enabled);
    }

    #[test]
    fn bgp_rejects_mixed_legacy_and_new_forms() {
        let toml_str = r#"
local_asn = 65000
router_id = "10.0.0.1"
peer_ip = "10.0.0.254"
peer_asn = 65000
[[peers]]
peer_ip = "10.0.0.253"
peer_asn = 65000
"#;
        let err = toml::from_str::<BgpConfig>(toml_str).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("peers"), "error was: {msg}");
    }

    #[test]
    fn bgp_rejects_empty_peers() {
        let toml_str = r#"
local_asn = 65000
router_id = "10.0.0.1"
peers = []
"#;
        let err = toml::from_str::<BgpConfig>(toml_str).unwrap_err();
        assert!(err.to_string().contains("at least one peer"));
    }

    #[test]
    fn bgp_rejects_partial_legacy_form() {
        let toml_str = r#"
local_asn = 65000
router_id = "10.0.0.1"
peer_ip = "10.0.0.254"
"#;
        let err = toml::from_str::<BgpConfig>(toml_str).unwrap_err();
        assert!(err.to_string().contains("peer_ip"));
    }

    #[test]
    fn bgp_accepts_per_peer_community_override() {
        let toml_str = r#"
local_asn = 65000
router_id = "10.0.0.1"
communities = ["65000:100"]
[[peers]]
peer_ip = "10.0.0.254"
peer_asn = 65000
communities = ["65000:200"]
[[peers]]
peer_ip = "10.0.0.253"
peer_asn = 65000
"#;
        let cfg: BgpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.communities, vec!["65000:100"]);
        assert_eq!(cfg.peers[0].communities, Some(vec!["65000:200".into()]));
        assert_eq!(cfg.peers[1].communities, None);
    }
}
