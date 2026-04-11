use lb_io::PacketBuf;
use std::net::Ipv4Addr;

/// GRE header size: 4 bytes (flags=0, protocol type).
const GRE_HEADER_SIZE: usize = 4;
/// Outer IPv4 header size: 20 bytes (no options).
const OUTER_IP_HEADER_SIZE: usize = 20;
/// Total encapsulation overhead.
pub const ENCAP_OVERHEAD: usize = GRE_HEADER_SIZE + OUTER_IP_HEADER_SIZE;

/// GRE protocol type for inner IPv4.
const GRE_PROTO_IPV4: u16 = 0x0800;
/// GRE protocol type for inner IPv6.
const GRE_PROTO_IPV6: u16 = 0x86DD;

/// Encapsulate a packet with GRE + outer IPv4 header in-place.
///
/// The packet data is shifted right by ENCAP_OVERHEAD bytes to make room
/// for the outer headers. Returns false if the packet doesn't fit.
pub fn encapsulate_ipv4(
    pkt: &mut PacketBuf,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> bool {
    match encapsulate_ipv4_buf(&mut pkt.data, pkt.len, src_ip, dst_ip) {
        Some(new_len) => {
            pkt.len = new_len;
            true
        }
        None => false,
    }
}

/// Encapsulate a packet with GRE + outer IPv4 header in-place on a raw buffer.
///
/// Operates directly on `&mut [u8]` + length, avoiding PacketBuf intermediaries.
/// Returns the new length on success, or `None` if the packet doesn't fit.
#[inline]
pub fn encapsulate_ipv4_buf(
    data: &mut [u8],
    inner_len: usize,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Option<usize> {
    let new_len = inner_len + ENCAP_OVERHEAD;

    if new_len > data.len() {
        return None;
    }

    // Detect inner protocol version
    let inner_proto = if inner_len > 0 {
        match data[0] >> 4 {
            6 => GRE_PROTO_IPV6,
            _ => GRE_PROTO_IPV4,
        }
    } else {
        GRE_PROTO_IPV4
    };

    // Shift inner packet right to make room for outer headers
    data.copy_within(0..inner_len, ENCAP_OVERHEAD);

    // Write outer IPv4 header
    let total_len = new_len as u16;
    let outer = &mut data[0..OUTER_IP_HEADER_SIZE];
    outer[0] = 0x45; // version=4, IHL=5 (20 bytes)
    outer[1] = 0x00; // DSCP/ECN
    outer[2..4].copy_from_slice(&total_len.to_be_bytes());
    outer[4..6].copy_from_slice(&[0, 0]); // identification
    outer[6..8].copy_from_slice(&[0x40, 0x00]); // DF flag set, fragment offset = 0
    outer[8] = 64; // TTL
    outer[9] = 47; // protocol = GRE
    outer[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    outer[12..16].copy_from_slice(&src_ip.octets());
    outer[16..20].copy_from_slice(&dst_ip.octets());

    // Compute IP header checksum
    let checksum = ip_checksum(&data[0..OUTER_IP_HEADER_SIZE]);
    data[10..12].copy_from_slice(&checksum.to_be_bytes());

    // Write GRE header (immediately after outer IP header)
    let gre = &mut data[OUTER_IP_HEADER_SIZE..OUTER_IP_HEADER_SIZE + GRE_HEADER_SIZE];
    gre[0] = 0x00; // no flags
    gre[1] = 0x00;
    gre[2..4].copy_from_slice(&inner_proto.to_be_bytes());

    Some(new_len)
}

/// Compute the one's complement checksum for an IP header.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < header.len() - 1 {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if !header.len().is_multiple_of(2) {
        sum += (header[header.len() - 1] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn encapsulate_adds_correct_overhead() {
        let inner = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let inner_len = inner.len();
        let mut pkt = PacketBuf::from_slice(&inner);

        let ok = encapsulate_ipv4(
            &mut pkt,
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        );

        assert!(ok);
        assert_eq!(pkt.len, inner_len + ENCAP_OVERHEAD);
    }

    #[test]
    fn outer_ip_header_fields() {
        let inner = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let mut pkt = PacketBuf::from_slice(&inner);

        encapsulate_ipv4(
            &mut pkt,
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        );

        let data = pkt.as_slice();
        assert_eq!(data[0], 0x45); // version + IHL
        assert_eq!(data[8], 64); // TTL
        assert_eq!(data[9], 47); // GRE protocol
        assert_eq!(&data[12..16], &[172, 16, 0, 1]); // src
        assert_eq!(&data[16..20], &[10, 0, 0, 5]); // dst
    }

    #[test]
    fn gre_header_fields() {
        let inner = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let mut pkt = PacketBuf::from_slice(&inner);

        encapsulate_ipv4(
            &mut pkt,
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        );

        let data = pkt.as_slice();
        let gre_offset = OUTER_IP_HEADER_SIZE;
        assert_eq!(data[gre_offset], 0x00); // no flags
        assert_eq!(data[gre_offset + 1], 0x00);
        // Protocol type = 0x0800 (inner IPv4)
        assert_eq!(
            u16::from_be_bytes([data[gre_offset + 2], data[gre_offset + 3]]),
            0x0800
        );
    }

    #[test]
    fn inner_packet_preserved() {
        let inner = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let mut pkt = PacketBuf::from_slice(&inner);

        encapsulate_ipv4(
            &mut pkt,
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        );

        let data = pkt.as_slice();
        let inner_start = ENCAP_OVERHEAD;
        assert_eq!(&data[inner_start..inner_start + inner.len()], &inner[..]);
    }

    #[test]
    fn ip_header_checksum_valid() {
        let inner = build_ipv4_tcp_packet([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443);
        let mut pkt = PacketBuf::from_slice(&inner);

        encapsulate_ipv4(
            &mut pkt,
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        );

        // Verify checksum: computing checksum over the header (including the checksum field)
        // should yield 0
        let check = ip_checksum(&pkt.data[0..OUTER_IP_HEADER_SIZE]);
        assert_eq!(check, 0, "IP header checksum verification failed");
    }

    #[test]
    fn oversized_packet_returns_false() {
        let inner = vec![0xAA; lb_io::PACKET_BUF_SIZE - 10];
        let mut pkt = PacketBuf::from_slice(&inner);
        let ok = encapsulate_ipv4(
            &mut pkt,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
        );
        assert!(!ok);
    }
}
