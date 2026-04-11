use crate::vip::Protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extracted 5-tuple from an IP packet for flow identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl PacketMeta {
    /// Parse a 5-tuple from raw IPv4 packet bytes (starting at the IP header).
    /// Returns `None` if the packet is too short or not TCP/UDP.
    pub fn from_ipv4_bytes(data: &[u8]) -> Option<Self> {
        // Minimum IPv4 header (20 bytes) + 4 bytes for ports
        if data.len() < 24 {
            return None;
        }

        let version = data[0] >> 4;
        if version != 4 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize * 4;
        if data.len() < ihl + 4 {
            return None;
        }

        let protocol_byte = data[9];
        let protocol = Protocol::from_ip_proto(protocol_byte)?;

        let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
        let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);

        Some(PacketMeta {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        })
    }

    /// Parse a 5-tuple from raw IPv6 packet bytes (starting at the IPv6 header).
    /// Returns `None` if the packet is too short or not TCP/UDP.
    pub fn from_ipv6_bytes(data: &[u8]) -> Option<Self> {
        // IPv6 header is 40 bytes + 4 bytes for ports
        if data.len() < 44 {
            return None;
        }

        let version = data[0] >> 4;
        if version != 6 {
            return None;
        }

        let next_header = data[6];
        let protocol = Protocol::from_ip_proto(next_header)?;

        let src_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([data[8], data[9]]),
            u16::from_be_bytes([data[10], data[11]]),
            u16::from_be_bytes([data[12], data[13]]),
            u16::from_be_bytes([data[14], data[15]]),
            u16::from_be_bytes([data[16], data[17]]),
            u16::from_be_bytes([data[18], data[19]]),
            u16::from_be_bytes([data[20], data[21]]),
            u16::from_be_bytes([data[22], data[23]]),
        ));

        let dst_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([data[24], data[25]]),
            u16::from_be_bytes([data[26], data[27]]),
            u16::from_be_bytes([data[28], data[29]]),
            u16::from_be_bytes([data[30], data[31]]),
            u16::from_be_bytes([data[32], data[33]]),
            u16::from_be_bytes([data[34], data[35]]),
            u16::from_be_bytes([data[36], data[37]]),
            u16::from_be_bytes([data[38], data[39]]),
        ));

        let src_port = u16::from_be_bytes([data[40], data[41]]);
        let dst_port = u16::from_be_bytes([data[42], data[43]]);

        Some(PacketMeta {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        })
    }

    /// Auto-detect IP version and parse accordingly.
    pub fn from_ip_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        match data[0] >> 4 {
            4 => Self::from_ipv4_bytes(data),
            6 => Self::from_ipv6_bytes(data),
            _ => None,
        }
    }

    /// Compute a hash of the 5-tuple using xxh3 for flow identification.
    pub fn flow_hash(&self) -> u64 {
        let mut buf = [0u8; 37]; // 16+16+2+2+1
        match self.src_ip {
            IpAddr::V4(v4) => buf[0..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => buf[0..16].copy_from_slice(&v6.octets()),
        }
        match self.dst_ip {
            IpAddr::V4(v4) => buf[16..20].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => buf[16..32].copy_from_slice(&v6.octets()),
        }
        buf[32..34].copy_from_slice(&self.src_port.to_be_bytes());
        buf[34..36].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[36] = self.protocol as u8;
        xxhash_rust::xxh3::xxh3_64(&buf)
    }
}

/// 3-tuple for fragment identification (no L4 ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentId {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ip_id: u16,
}

impl FragmentId {
    /// Parse a fragment identifier from raw IPv4 packet bytes.
    pub fn from_ipv4_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let version = data[0] >> 4;
        if version != 4 {
            return None;
        }

        let ip_id = u16::from_be_bytes([data[4], data[5]]);
        let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        Some(FragmentId {
            src_ip,
            dst_ip,
            ip_id,
        })
    }

    /// Compute a hash of the 3-tuple for fragment routing.
    pub fn fragment_hash(&self) -> u64 {
        let mut buf = [0u8; 34]; // 16+16+2
        match self.src_ip {
            IpAddr::V4(v4) => buf[0..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => buf[0..16].copy_from_slice(&v6.octets()),
        }
        match self.dst_ip {
            IpAddr::V4(v4) => buf[16..20].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => buf[16..32].copy_from_slice(&v6.octets()),
        }
        buf[32..34].copy_from_slice(&self.ip_id.to_be_bytes());
        xxhash_rust::xxh3::xxh3_64(&buf)
    }
}

/// Check if an IPv4 packet is a fragment (MF flag set or fragment offset != 0).
pub fn is_fragment(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let flags_and_offset = u16::from_be_bytes([data[6], data[7]]);
    let mf = (flags_and_offset & 0x2000) != 0;
    let offset = flags_and_offset & 0x1FFF;
    mf || offset != 0
}

/// Check if this is a non-first fragment (fragment offset > 0).
pub fn is_non_first_fragment(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let flags_and_offset = u16::from_be_bytes([data[6], data[7]]);
    let offset = flags_and_offset & 0x1FFF;
    offset != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_tcp_packet(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_ipv4_tcp_packet() {
        let pkt = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let meta = PacketMeta::from_ipv4_bytes(&pkt).unwrap();
        assert_eq!(meta.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(meta.dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(meta.src_port, 12345);
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.protocol, Protocol::Tcp);
    }

    #[test]
    fn parse_too_short_packet() {
        let pkt = vec![0u8; 10];
        assert!(PacketMeta::from_ipv4_bytes(&pkt).is_none());
    }

    #[test]
    fn parse_non_tcp_udp_packet() {
        let mut pkt = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 100, 200);
        pkt[9] = 1; // ICMP
        assert!(PacketMeta::from_ipv4_bytes(&pkt).is_none());
    }

    #[test]
    fn flow_hash_deterministic() {
        let pkt = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let meta = PacketMeta::from_ipv4_bytes(&pkt).unwrap();
        let h1 = meta.flow_hash();
        let h2 = meta.flow_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_flows_different_hashes() {
        let pkt1 = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let pkt2 = build_ipv4_tcp_packet([10, 0, 0, 2], [192, 168, 1, 1], 12345, 443);
        let h1 = PacketMeta::from_ipv4_bytes(&pkt1).unwrap().flow_hash();
        let h2 = PacketMeta::from_ipv4_bytes(&pkt2).unwrap().flow_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn fragment_detection() {
        let mut pkt = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 100, 200);
        assert!(!is_fragment(&pkt));
        assert!(!is_non_first_fragment(&pkt));

        // Set MF flag
        pkt[6] = 0x20;
        assert!(is_fragment(&pkt));
        assert!(!is_non_first_fragment(&pkt));

        // Set fragment offset
        pkt[6] = 0x00;
        pkt[7] = 0x10;
        assert!(is_fragment(&pkt));
        assert!(is_non_first_fragment(&pkt));
    }

    fn build_ipv6_tcp_packet(src: [u16; 8], dst: [u16; 8], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 60]; // 40 IPv6 header + 20 TCP
        pkt[0] = 0x60; // version=6
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload length
        pkt[6] = 6; // next header = TCP
        pkt[7] = 64; // hop limit
        for (i, &seg) in src.iter().enumerate() {
            pkt[8 + i * 2..10 + i * 2].copy_from_slice(&seg.to_be_bytes());
        }
        for (i, &seg) in dst.iter().enumerate() {
            pkt[24 + i * 2..26 + i * 2].copy_from_slice(&seg.to_be_bytes());
        }
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_ipv6_tcp_packet() {
        let pkt = build_ipv6_tcp_packet(
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1],
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 2],
            12345,
            443,
        );
        let meta = PacketMeta::from_ipv6_bytes(&pkt).unwrap();
        assert_eq!(meta.src_port, 12345);
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.protocol, Protocol::Tcp);
        assert!(meta.src_ip.is_ipv6());
    }

    #[test]
    fn auto_detect_ipv4() {
        let pkt = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 100, 200);
        let meta = PacketMeta::from_ip_bytes(&pkt).unwrap();
        assert!(meta.src_ip.is_ipv4());
    }

    #[test]
    fn auto_detect_ipv6() {
        let pkt = build_ipv6_tcp_packet(
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1],
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 2],
            100,
            200,
        );
        let meta = PacketMeta::from_ip_bytes(&pkt).unwrap();
        assert!(meta.src_ip.is_ipv6());
    }

    #[test]
    fn fragment_id_parsing() {
        let mut pkt = build_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 100, 200);
        pkt[4..6].copy_from_slice(&42u16.to_be_bytes());
        let fid = FragmentId::from_ipv4_bytes(&pkt).unwrap();
        assert_eq!(fid.ip_id, 42);
        assert_eq!(fid.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
