use lb_types::{BackendPoolId, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;

/// Key for VIP matching: (destination IP, protocol, port).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VipKey {
    ip: IpAddr,
    protocol: Protocol,
    port: u16,
}

/// Matches incoming packets against configured VIPs.
///
/// Immutable after construction. Swap via `ArcSwap` on config change.
#[derive(Clone)]
pub struct VipMatcher {
    table: HashMap<VipKey, BackendPoolId>,
}

impl VipMatcher {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    /// Build a VipMatcher from a list of (ip, protocol, port, pool_id) tuples.
    pub fn from_entries(entries: Vec<(IpAddr, Protocol, u16, BackendPoolId)>) -> Self {
        let mut table = HashMap::new();
        for (ip, protocol, port, pool_id) in entries {
            table.insert(VipKey { ip, protocol, port }, pool_id);
        }
        Self { table }
    }

    /// Match a packet's destination to a backend pool.
    pub fn match_packet(
        &self,
        dst_ip: IpAddr,
        protocol: Protocol,
        dst_port: u16,
    ) -> Option<&BackendPoolId> {
        self.table.get(&VipKey {
            ip: dst_ip,
            protocol,
            port: dst_port,
        })
    }
}

impl Default for VipMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn vip_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10))
    }

    #[test]
    fn match_configured_vip() {
        let matcher = VipMatcher::from_entries(vec![(
            vip_ip(),
            Protocol::Tcp,
            443,
            BackendPoolId("web".into()),
        )]);
        let result = matcher.match_packet(vip_ip(), Protocol::Tcp, 443);
        assert_eq!(result, Some(&BackendPoolId("web".into())));
    }

    #[test]
    fn miss_on_unknown_vip() {
        let matcher = VipMatcher::from_entries(vec![(
            vip_ip(),
            Protocol::Tcp,
            443,
            BackendPoolId("web".into()),
        )]);
        let other_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(matcher.match_packet(other_ip, Protocol::Tcp, 443).is_none());
    }

    #[test]
    fn miss_on_wrong_port() {
        let matcher = VipMatcher::from_entries(vec![(
            vip_ip(),
            Protocol::Tcp,
            443,
            BackendPoolId("web".into()),
        )]);
        assert!(matcher.match_packet(vip_ip(), Protocol::Tcp, 80).is_none());
    }

    #[test]
    fn miss_on_wrong_protocol() {
        let matcher = VipMatcher::from_entries(vec![(
            vip_ip(),
            Protocol::Tcp,
            443,
            BackendPoolId("web".into()),
        )]);
        assert!(matcher.match_packet(vip_ip(), Protocol::Udp, 443).is_none());
    }

    #[test]
    fn multiple_services_on_same_vip() {
        let matcher = VipMatcher::from_entries(vec![
            (vip_ip(), Protocol::Tcp, 443, BackendPoolId("https".into())),
            (vip_ip(), Protocol::Tcp, 80, BackendPoolId("http".into())),
        ]);
        assert_eq!(
            matcher.match_packet(vip_ip(), Protocol::Tcp, 443),
            Some(&BackendPoolId("https".into()))
        );
        assert_eq!(
            matcher.match_packet(vip_ip(), Protocol::Tcp, 80),
            Some(&BackendPoolId("http".into()))
        );
    }
}
