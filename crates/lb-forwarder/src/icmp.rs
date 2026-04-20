/// ICMP Fragmentation Needed (Type 3, Code 4) generation and rate limiting.
///
/// When an oversized packet with DF set cannot fit inside the GRE tunnel,
/// the LB generates an ICMP error back to the sender with the effective
/// inner MTU. The ICMP source is the VIP (not the LB node IP) so the
/// sender's PMTUD associates the MTU correctly.
use lb_io::PacketBuf;
use std::net::Ipv4Addr;
use std::time::Instant;

use lb_types::mtu::GRE_OVERHEAD;

/// DF flag in IPv4 flags+fragment offset field.
const DF_FLAG: u16 = 0x4000;

/// ICMP Type 3 = Destination Unreachable.
const ICMP_TYPE_DEST_UNREACH: u8 = 3;
/// ICMP Code 4 = Fragmentation Needed and DF Set.
const ICMP_CODE_FRAG_NEEDED: u8 = 4;

/// Check if a packet is oversized for the GRE tunnel and has DF set.
///
/// `data` starts at the inner IP header.
#[inline]
pub fn should_generate_icmp(data: &[u8], network_mtu: u16) -> bool {
    if data.len() < 20 {
        return false;
    }
    // Only IPv4 for now
    if data[0] >> 4 != 4 {
        return false;
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let df_set = (flags_frag & DF_FLAG) != 0;

    df_set && (total_len + GRE_OVERHEAD) > network_mtu
}

/// Generate an ICMP Fragmentation Needed response.
///
/// Returns a `PacketBuf` containing the complete ICMP response (IP + ICMP + payload).
/// The source IP is set to `vip` (not the LB node IP).
///
/// `original` is the oversized inner packet (starting at its IP header).
pub fn generate_icmp_frag_needed(
    original: &[u8],
    vip: Ipv4Addr,
    effective_inner_mtu: u16,
) -> PacketBuf {
    // ICMP payload: first 28 bytes of original packet (IP header + 8 bytes)
    let payload_len = original.len().min(28);

    // Total: 20 (IP) + 8 (ICMP header) + payload_len
    let total_len = 20 + 8 + payload_len;

    let mut pkt = PacketBuf::new();
    let buf = &mut pkt.data[..total_len];

    // Extract original source IP (the sender we're replying to)
    let dst_ip = if original.len() >= 16 {
        Ipv4Addr::new(original[12], original[13], original[14], original[15])
    } else {
        Ipv4Addr::UNSPECIFIED
    };

    // IP header
    buf[0] = 0x45; // version=4, IHL=5
    buf[1] = 0xC0; // DSCP=CS6 (network control), ECN=0
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&[0, 0]); // identification
    buf[6..8].copy_from_slice(&[0, 0]); // flags=0, no DF on ICMP
    buf[8] = 64; // TTL
    buf[9] = 1; // protocol = ICMP
    buf[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    buf[12..16].copy_from_slice(&vip.octets()); // src = VIP
    buf[16..20].copy_from_slice(&dst_ip.octets()); // dst = original sender

    // IP header checksum
    let ip_cksum = ip_checksum(&buf[0..20]);
    buf[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ICMP header (8 bytes)
    let icmp = &mut buf[20..28];
    icmp[0] = ICMP_TYPE_DEST_UNREACH;
    icmp[1] = ICMP_CODE_FRAG_NEEDED;
    icmp[2..4].copy_from_slice(&[0, 0]); // checksum placeholder
    // Bytes 4-5: unused (must be zero)
    icmp[4] = 0;
    icmp[5] = 0;
    // Bytes 6-7: Next-Hop MTU
    icmp[6..8].copy_from_slice(&effective_inner_mtu.to_be_bytes());

    // ICMP payload: first 28 bytes of original packet
    buf[28..28 + payload_len].copy_from_slice(&original[..payload_len]);

    // ICMP checksum (over ICMP header + payload)
    let icmp_cksum = ip_checksum(&buf[20..total_len]);
    buf[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

    pkt.len = total_len;
    pkt
}

/// Simple token-bucket rate limiter for ICMP generation.
pub struct IcmpRateLimiter {
    max_per_second: u32,
    count: u32,
    window_start: Instant,
}

impl IcmpRateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            count: 0,
            window_start: Instant::now(),
        }
    }

    /// Returns true if an ICMP response is allowed.
    pub fn allow(&mut self, now: Instant) -> bool {
        if self.max_per_second == 0 {
            return false;
        }
        if now.duration_since(self.window_start).as_secs() >= 1 {
            self.count = 0;
            self.window_start = now;
        }
        if self.count < self.max_per_second {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

/// Ones-complement checksum (shared with gre.rs but kept local to avoid coupling).
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() - 1 {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if !data.len().is_multiple_of(2) {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IPv4 UDP packet of a given total length with DF set.
    fn build_udp_packet_df(src: [u8; 4], dst: [u8; 4], total_len: u16) -> Vec<u8> {
        let len = total_len as usize;
        let mut pkt = vec![0u8; len.max(28)];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF set
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt.truncate(len.max(28));
        pkt
    }

    fn build_udp_packet_no_df(src: [u8; 4], dst: [u8; 4], total_len: u16) -> Vec<u8> {
        let mut pkt = build_udp_packet_df(src, dst, total_len);
        pkt[6] = 0;
        pkt[7] = 0;
        pkt
    }

    #[test]
    fn icmp_generated_for_oversized_df_packet() {
        let pkt = build_udp_packet_df([10, 0, 0, 1], [188, 184, 100, 10], 1500);
        assert!(should_generate_icmp(&pkt, 1500));
    }

    #[test]
    fn icmp_not_generated_when_df_clear() {
        let pkt = build_udp_packet_no_df([10, 0, 0, 1], [188, 184, 100, 10], 1500);
        assert!(!should_generate_icmp(&pkt, 1500));
    }

    #[test]
    fn icmp_not_generated_when_packet_fits() {
        let pkt = build_udp_packet_df([10, 0, 0, 1], [188, 184, 100, 10], 1400);
        assert!(!should_generate_icmp(&pkt, 1500));
    }

    #[test]
    fn icmp_source_is_vip() {
        let original = build_udp_packet_df([10, 0, 0, 1], [188, 184, 100, 10], 1500);
        let vip = Ipv4Addr::new(188, 184, 100, 10);
        let icmp = generate_icmp_frag_needed(&original, vip, 1476);

        let data = icmp.as_slice();
        assert_eq!(&data[12..16], &vip.octets());
    }

    #[test]
    fn icmp_contains_original_header() {
        let original = build_udp_packet_df([10, 0, 0, 1], [188, 184, 100, 10], 1500);
        let icmp = generate_icmp_frag_needed(&original, Ipv4Addr::new(188, 184, 100, 10), 1476);

        let data = icmp.as_slice();
        // ICMP payload starts at offset 28, should contain first 28 bytes of original
        assert_eq!(&data[28..56], &original[..28]);
    }

    #[test]
    fn icmp_next_hop_mtu_correct() {
        let original = build_udp_packet_df([10, 0, 0, 1], [188, 184, 100, 10], 1500);
        let icmp = generate_icmp_frag_needed(&original, Ipv4Addr::new(188, 184, 100, 10), 1476);

        let data = icmp.as_slice();
        let next_hop_mtu = u16::from_be_bytes([data[26], data[27]]);
        assert_eq!(next_hop_mtu, 1476);
    }

    #[test]
    fn icmp_checksums_valid() {
        let original = build_udp_packet_df([10, 0, 0, 1], [188, 184, 100, 10], 1500);
        let icmp = generate_icmp_frag_needed(&original, Ipv4Addr::new(188, 184, 100, 10), 1476);
        let data = icmp.as_slice();

        // IP header checksum verification (compute over header including checksum should yield 0)
        let ip_check = ip_checksum(&data[0..20]);
        assert_eq!(ip_check, 0, "IP header checksum invalid");

        // ICMP checksum verification
        let icmp_check = ip_checksum(&data[20..]);
        assert_eq!(icmp_check, 0, "ICMP checksum invalid");
    }

    #[test]
    fn icmp_rate_limiter_allows_burst() {
        let mut limiter = IcmpRateLimiter::new(100);
        let now = Instant::now();
        for _ in 0..100 {
            assert!(limiter.allow(now));
        }
    }

    #[test]
    fn icmp_rate_limiter_drops_excess() {
        let mut limiter = IcmpRateLimiter::new(100);
        let now = Instant::now();
        for _ in 0..100 {
            limiter.allow(now);
        }
        assert!(!limiter.allow(now));
    }

    #[test]
    fn icmp_rate_limiter_resets_after_window() {
        let mut limiter = IcmpRateLimiter::new(100);
        let start = Instant::now();
        for _ in 0..100 {
            limiter.allow(start);
        }
        assert!(!limiter.allow(start));

        // Simulate 1 second later
        let later = start + std::time::Duration::from_secs(1);
        assert!(limiter.allow(later));
    }

    #[test]
    fn icmp_bypasses_gre() {
        // Verify the ICMP packet is a plain IP packet (not GRE-encapsulated)
        let original = build_udp_packet_df([10, 0, 0, 1], [188, 184, 100, 10], 1500);
        let icmp = generate_icmp_frag_needed(&original, Ipv4Addr::new(188, 184, 100, 10), 1476);
        let data = icmp.as_slice();

        // Outer protocol should be ICMP (1), not GRE (47)
        assert_eq!(data[9], 1);
        // Total length should be 20 (IP) + 8 (ICMP) + 28 (payload) = 56
        let total_len = u16::from_be_bytes([data[2], data[3]]);
        assert_eq!(total_len, 56);
    }
}
