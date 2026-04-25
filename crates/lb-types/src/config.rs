use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
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
    /// Address the operations HTTP server binds to (`/healthz`, `/readyz`,
    /// `/metrics`). Defaults to `127.0.0.1:9100` so operators scraping
    /// Prometheus from localhost work out of the box; bind to `0.0.0.0:9100`
    /// for cross-host scraping.
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: SocketAddr,
    /// Which `PacketIo` backend the forwarder uses. `"mock"` is the default
    /// (in-memory queues, useful for local dev and integration tests).
    /// `"af_xdp"` is the strategic production path but currently returns
    /// `Unsupported` at init — see `crates/lb-io/src/af_xdp.rs` for the
    /// roadmap. Anything else is a config error.
    #[serde(default)]
    pub io_backend: IoBackend,
}

/// Packet I/O backend selector. Kept as a small enum (not a free-form
/// string) so serde rejects typos at config-load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoBackend {
    /// In-memory ring buffers; no real NIC traffic. The default, suitable
    /// for local dev and integration tests.
    #[default]
    Mock,
    /// AF_XDP socket bound to `data_iface`. Production direction. Currently
    /// a scaffold — instantiating this errors at startup with a message
    /// pointing at the roadmap.
    AfXdp,
}

fn default_num_threads() -> usize {
    7
}

fn default_metrics_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9100))
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
    /// TCP-MD5 signature (RFC 2385). When set, the speaker installs a
    /// `TCP_MD5SIG` socket option with the given password before connecting
    /// so every TCP segment carries an MD5 signature of the header plus
    /// payload plus peer-shared key. Max length is 80 bytes (Linux
    /// TCP_MD5SIG_MAXKEYLEN). Linux-only; on other OSes the speaker logs a
    /// warning and falls back to plain TCP.
    ///
    /// **Prefer `md5_password_env`** — putting the literal secret here
    /// means anyone with read access to the TOML file can impersonate this
    /// peer. If you do use `md5_password`, lock the config to mode `0600`
    /// and audit who has access.
    #[serde(default)]
    pub md5_password: Option<String>,
    /// Name of an environment variable holding the TCP-MD5 password.
    /// Resolved at startup; mutually exclusive with `md5_password`.
    ///
    /// Use this when you'd rather not check the secret into the config
    /// file — typical setup is a systemd `EnvironmentFile=` pointing at a
    /// separately-locked-down file (e.g. `/etc/lb/bgp.env` mode `0600`),
    /// so the TOML stays world-readable for ops convenience while the
    /// secret stays protected. The variable must be set when the process
    /// starts; missing or empty is a fatal config error rather than a
    /// silent fall-back to unauthenticated peering.
    #[serde(default)]
    pub md5_password_env: Option<String>,
}

impl BgpPeerConfig {
    /// Resolve the effective TCP-MD5 password, reading from the env var
    /// named by `md5_password_env` when set. Errors if both fields are set
    /// (mutually exclusive) or if the named env var is missing/empty.
    /// `Ok(None)` means MD5 is not configured for this peer.
    pub fn resolved_md5_password(&self) -> Result<Option<String>, String> {
        match (&self.md5_password, &self.md5_password_env) {
            (Some(_), Some(_)) => Err(format!(
                "peer {}: md5_password and md5_password_env are mutually exclusive",
                self.peer_ip
            )),
            (Some(p), None) => Ok(Some(p.clone())),
            (None, Some(var)) => match std::env::var(var) {
                Ok(v) if !v.is_empty() => Ok(Some(v)),
                Ok(_) => Err(format!(
                    "peer {}: env var ${var} is empty (md5_password_env)",
                    self.peer_ip
                )),
                Err(_) => Err(format!(
                    "peer {}: env var ${var} not set (md5_password_env)",
                    self.peer_ip
                )),
            },
            (None, None) => Ok(None),
        }
    }
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
                md5_password: None,
                md5_password_env: None,
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
    /// Time an IP-fragment → backend mapping is kept. A non-first fragment
    /// that arrives after this window expires is dropped (its 5-tuple can't
    /// be recovered without the first fragment's L4 header). Defaults to
    /// the RFC 791 reassembly timeout of 30 seconds; for a datacentre with
    /// sub-ms reordering 10s is more typical.
    #[serde(
        default = "default_fragment_ttl",
        deserialize_with = "deserialize_duration"
    )]
    pub fragment_ttl: Duration,
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
                tcp_handshake: c.tcp_handshake.unwrap_or(defaults.tcp_handshake),
                tcp_established: c.tcp_established.unwrap_or(defaults.tcp_established),
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
fn default_fragment_ttl() -> Duration {
    Duration::from_secs(10)
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
metrics_addr = "127.0.0.1:9200"

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
        assert_eq!(config.node.metrics_addr.port(), 9200);
        assert_eq!(config.bgp.local_asn, 65000);
        assert_eq!(config.bgp.peers.len(), 2);
        assert_eq!(config.bgp.peers[0].port, 179);
        assert_eq!(config.bgp.peers[1].hold_time_secs, Some(30));
        assert_eq!(config.forwarder.connection_table_size, 131072);
        assert_eq!(
            config.forwarder.batch_flush_interval,
            Duration::from_micros(50)
        );
        assert_eq!(config.health_check_defaults.healthy_threshold, 2);
    }

    #[test]
    fn metrics_addr_defaults_to_localhost_9100() {
        let toml_str = r#"
id = "node"
loopback_ip = "10.0.0.1"
data_iface = "eth0"
"#;
        let section: NodeSection = toml::from_str(toml_str).unwrap();
        assert_eq!(section.metrics_addr.port(), 9100);
        assert!(section.metrics_addr.ip().is_loopback());
    }

    #[test]
    fn io_backend_defaults_to_mock() {
        let toml_str = r#"
id = "node"
loopback_ip = "10.0.0.1"
data_iface = "eth0"
"#;
        let section: NodeSection = toml::from_str(toml_str).unwrap();
        assert_eq!(section.io_backend, IoBackend::Mock);
    }

    #[test]
    fn io_backend_accepts_af_xdp_variant() {
        let toml_str = r#"
id = "node"
loopback_ip = "10.0.0.1"
data_iface = "eth0"
io_backend = "af_xdp"
"#;
        let section: NodeSection = toml::from_str(toml_str).unwrap();
        assert_eq!(section.io_backend, IoBackend::AfXdp);
    }

    #[test]
    fn io_backend_rejects_unknown_variant() {
        let toml_str = r#"
id = "node"
loopback_ip = "10.0.0.1"
data_iface = "eth0"
io_backend = "dpdk"
"#;
        let err = toml::from_str::<NodeSection>(toml_str).unwrap_err();
        // Serde's error message includes the list of known variants; assert
        // it mentions the ones we actually expose.
        let msg = err.to_string();
        assert!(msg.contains("mock"), "error should list `mock`: {msg}");
        assert!(msg.contains("af_xdp"), "error should list `af_xdp`: {msg}");
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
    fn bgp_accepts_per_peer_md5_password() {
        let toml_str = r#"
local_asn = 65000
router_id = "10.0.0.1"
[[peers]]
peer_ip = "10.0.0.254"
peer_asn = 65000
md5_password = "s3cret"
[[peers]]
peer_ip = "10.0.0.253"
peer_asn = 65000
"#;
        let cfg: BgpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.peers[0].md5_password.as_deref(), Some("s3cret"));
        assert_eq!(cfg.peers[1].md5_password, None);
    }

    #[test]
    fn bgp_accepts_md5_password_env() {
        let toml_str = r#"
local_asn = 65000
router_id = "10.0.0.1"
[[peers]]
peer_ip = "10.0.0.254"
peer_asn = 65000
md5_password_env = "LB_BGP_KEY_PEER_A"
"#;
        let cfg: BgpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.peers[0].md5_password, None);
        assert_eq!(
            cfg.peers[0].md5_password_env.as_deref(),
            Some("LB_BGP_KEY_PEER_A")
        );
    }

    #[test]
    fn resolved_md5_password_prefers_inline_when_alone() {
        let p = BgpPeerConfig {
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: 65000,
            port: 179,
            hold_time_secs: None,
            communities: None,
            enabled: true,
            md5_password: Some("inline".into()),
            md5_password_env: None,
        };
        assert_eq!(p.resolved_md5_password().unwrap(), Some("inline".into()));
    }

    #[test]
    fn resolved_md5_password_reads_env_var() {
        // Pick a uniquely-named var so we don't collide with concurrent tests.
        let name = "LB_TEST_BGP_KEY_4f6a";
        std::env::set_var(name, "from-env");
        let p = BgpPeerConfig {
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: 65000,
            port: 179,
            hold_time_secs: None,
            communities: None,
            enabled: true,
            md5_password: None,
            md5_password_env: Some(name.into()),
        };
        assert_eq!(p.resolved_md5_password().unwrap(), Some("from-env".into()));
        std::env::remove_var(name);
    }

    #[test]
    fn resolved_md5_password_errors_when_env_missing() {
        let p = BgpPeerConfig {
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: 65000,
            port: 179,
            hold_time_secs: None,
            communities: None,
            enabled: true,
            md5_password: None,
            md5_password_env: Some("LB_TEST_MISSING_VAR_b71d".into()),
        };
        let err = p.resolved_md5_password().unwrap_err();
        assert!(err.contains("not set"), "got: {err}");
    }

    #[test]
    fn resolved_md5_password_rejects_both_set() {
        let p = BgpPeerConfig {
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: 65000,
            port: 179,
            hold_time_secs: None,
            communities: None,
            enabled: true,
            md5_password: Some("inline".into()),
            md5_password_env: Some("X".into()),
        };
        let err = p.resolved_md5_password().unwrap_err();
        assert!(err.contains("mutually exclusive"));
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
