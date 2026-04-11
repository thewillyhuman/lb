use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Unique identifier for a VIP.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VipId(pub String);

/// A Virtual IP address announced via BGP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vip {
    pub id: VipId,
    pub address: IpAddr,
    pub services: Vec<VipService>,
    pub owner: String,
    pub description: String,
}

/// L4 protocol discriminator matching IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
}

impl Protocol {
    pub fn from_ip_proto(proto: u8) -> Option<Self> {
        match proto {
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            _ => None,
        }
    }
}

/// A (protocol, port) service bound to a VIP, mapping to a backend pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VipService {
    pub protocol: Protocol,
    pub port: u16,
    pub backend_pool: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn protocol_from_ip_proto() {
        assert_eq!(Protocol::from_ip_proto(6), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_ip_proto(17), Some(Protocol::Udp));
        assert_eq!(Protocol::from_ip_proto(1), None);
    }

    #[test]
    fn vip_service_equality() {
        let a = VipService {
            protocol: Protocol::Tcp,
            port: 443,
            backend_pool: "web".into(),
        };
        let b = VipService {
            protocol: Protocol::Tcp,
            port: 443,
            backend_pool: "web".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn vip_serde_round_trip() {
        let vip = Vip {
            id: VipId("test".into()),
            address: IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            services: vec![VipService {
                protocol: Protocol::Tcp,
                port: 443,
                backend_pool: "web-backends".into(),
            }],
            owner: "team@example.org".into(),
            description: "Test VIP".into(),
        };
        let json = serde_json::to_string(&vip).unwrap();
        let back: Vip = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, vip.id);
        assert_eq!(back.address, vip.address);
        assert_eq!(back.services.len(), 1);
    }
}
