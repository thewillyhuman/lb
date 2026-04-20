//! TCP MSS clamping for GRE tunnel MTU compliance.
//!
//! Parses the TCP options field on SYN/SYN-ACK packets and rewrites the
//! MSS option if it exceeds `max_mss`. Uses incremental checksum update
//! (RFC 1624) so only the 2 changed bytes are recomputed — O(1).

/// TCP option kinds.
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_MSS_LEN: u8 = 4;

/// TCP flags byte offset within the TCP header (relative to TCP header start).
const TCP_FLAGS_OFFSET: usize = 13;
/// SYN flag bit.
const TCP_SYN: u8 = 0x02;

/// Clamp the MSS in a TCP SYN or SYN-ACK packet.
///
/// `data` is the full IP packet starting at the IP header.
/// Returns `true` if the MSS was rewritten, `false` otherwise.
///
/// Preconditions checked internally:
/// - Must be TCP (protocol byte = 6)
/// - Must have SYN flag set
/// - MSS option must be present and exceed `max_mss`
#[inline]
pub fn clamp_mss(data: &mut [u8], max_mss: u16) -> ClampResult {
    // Need at least 20 (IP) + 20 (TCP fixed) = 40 bytes
    if data.len() < 40 {
        return ClampResult::NotTcp;
    }

    // Check IPv4
    if data[0] >> 4 != 4 {
        return ClampResult::NotTcp;
    }

    // Check TCP
    if data[9] != 6 {
        return ClampResult::NotTcp;
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl + 20 {
        return ClampResult::NotTcp;
    }

    // Check SYN flag
    let flags = data[ihl + TCP_FLAGS_OFFSET];
    if flags & TCP_SYN == 0 {
        return ClampResult::NotSyn;
    }

    // TCP data offset (header length in 32-bit words)
    let data_offset = ((data[ihl + 12] >> 4) as usize) * 4;
    if data_offset < 20 || data.len() < ihl + data_offset {
        return ClampResult::MssMissing;
    }

    let options_start = ihl + 20;
    let options_end = ihl + data_offset;

    // Parse TCP options looking for MSS (kind=2, length=4)
    let mut offset = options_start;
    while offset < options_end {
        let kind = data[offset];
        if kind == TCP_OPT_END {
            break;
        }
        if kind == TCP_OPT_NOP {
            offset += 1;
            continue;
        }
        if offset + 1 >= options_end {
            break;
        }
        let length = data[offset + 1] as usize;
        if length < 2 {
            break; // malformed
        }

        if kind == TCP_OPT_MSS && length == TCP_OPT_MSS_LEN as usize {
            if offset + 4 > options_end {
                break; // truncated
            }
            let current_mss = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            if current_mss > max_mss {
                // Rewrite MSS
                let old_bytes = [data[offset + 2], data[offset + 3]];
                let new_bytes = max_mss.to_be_bytes();
                data[offset + 2] = new_bytes[0];
                data[offset + 3] = new_bytes[1];

                // Incremental TCP checksum update (RFC 1624)
                let checksum_offset = ihl + 16;
                incremental_checksum_update(data, checksum_offset, &old_bytes, &new_bytes);

                return ClampResult::Clamped;
            }
            return ClampResult::Noop;
        }

        offset += length;
    }

    ClampResult::MssMissing
}

/// Result of MSS clamp operation, used for metric classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClampResult {
    /// Not a TCP packet.
    NotTcp,
    /// TCP but not SYN.
    NotSyn,
    /// MSS was rewritten to a lower value.
    Clamped,
    /// MSS was present but already within limit.
    Noop,
    /// SYN packet but no MSS option found.
    MssMissing,
}

/// Incremental checksum update per RFC 1624.
///
/// Updates a ones-complement checksum in-place when 2 bytes change.
fn incremental_checksum_update(
    data: &mut [u8],
    checksum_offset: usize,
    old_bytes: &[u8; 2],
    new_bytes: &[u8; 2],
) {
    let old_checksum = u16::from_be_bytes([data[checksum_offset], data[checksum_offset + 1]]);
    // ~C' = ~C + ~old + new  (ones-complement arithmetic)
    let mut sum: u32 = (!old_checksum) as u32;
    sum += (!u16::from_be_bytes(*old_bytes)) as u32;
    sum += u16::from_be_bytes(*new_bytes) as u32;
    // Fold carry
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let new_checksum = !(sum as u16);
    data[checksum_offset] = (new_checksum >> 8) as u8;
    data[checksum_offset + 1] = (new_checksum & 0xFF) as u8;
}

/// Compute a full TCP checksum from scratch (for verification in tests).
#[cfg(test)]
fn full_tcp_checksum(data: &[u8], ihl: usize) -> u16 {
    let tcp_start = ihl;
    let tcp_len = data.len() - tcp_start;

    // Pseudo-header
    let mut sum: u32 = 0;
    // src IP
    sum += u16::from_be_bytes([data[12], data[13]]) as u32;
    sum += u16::from_be_bytes([data[14], data[15]]) as u32;
    // dst IP
    sum += u16::from_be_bytes([data[16], data[17]]) as u32;
    sum += u16::from_be_bytes([data[18], data[19]]) as u32;
    // protocol
    sum += data[9] as u32;
    // TCP length
    sum += tcp_len as u32;

    // TCP segment (with checksum field zeroed)
    let mut i = tcp_start;
    while i < data.len() - 1 {
        if i == tcp_start + 16 {
            // skip checksum field
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if !(data.len() - tcp_start).is_multiple_of(2) {
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

    /// Build a TCP SYN packet with MSS option.
    fn build_syn_with_mss(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        mss: u16,
    ) -> Vec<u8> {
        // IP header (20) + TCP header (20 base) + TCP options (MSS=4 + NOP + NOP + WS=3 + pad=1 = 8, round to 8)
        // Keep it simple: 20 IP + 24 TCP (base 20 + MSS option 4)
        let tcp_header_len = 24u8; // 6 words
        let total_len = 20 + tcp_header_len as usize;
        let mut pkt = vec![0u8; total_len];

        // IP header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);

        // TCP header
        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        // data offset = 6 words (24 bytes)
        tcp[12] = (tcp_header_len / 4) << 4;
        // SYN flag
        tcp[13] = TCP_SYN;

        // MSS option at offset 20 (TCP options start)
        tcp[20] = TCP_OPT_MSS;
        tcp[21] = TCP_OPT_MSS_LEN;
        tcp[22..24].copy_from_slice(&mss.to_be_bytes());

        // Compute TCP checksum
        let checksum = full_tcp_checksum(&pkt, 20);
        pkt[20 + 16] = (checksum >> 8) as u8;
        pkt[20 + 17] = (checksum & 0xFF) as u8;

        pkt
    }

    /// Build a TCP SYN packet without MSS option (just window scale).
    fn build_syn_without_mss(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        // 20 IP + 24 TCP (base 20 + WS option 3 + NOP = 4)
        let tcp_header_len = 24u8;
        let total_len = 20 + tcp_header_len as usize;
        let mut pkt = vec![0u8; total_len];

        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);

        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = (tcp_header_len / 4) << 4;
        tcp[13] = TCP_SYN;

        // Window scale option (kind=3, len=3, shift=7) + NOP
        tcp[20] = 1; // NOP
        tcp[21] = 3; // WS kind
        tcp[22] = 3; // WS length
        tcp[23] = 7; // WS shift count

        pkt
    }

    #[test]
    fn clamp_reduces_oversized_mss() {
        let mut pkt = build_syn_with_mss([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443, 1460);
        let result = clamp_mss(&mut pkt, 1436);
        assert_eq!(result, ClampResult::Clamped);

        // Verify MSS was rewritten
        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss, 1436);
    }

    #[test]
    fn clamp_noop_when_mss_within_limit() {
        let mut pkt = build_syn_with_mss([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443, 1400);
        let result = clamp_mss(&mut pkt, 1436);
        assert_eq!(result, ClampResult::Noop);

        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss, 1400);
    }

    #[test]
    fn clamp_noop_when_no_mss_option() {
        let mut pkt = build_syn_without_mss([10, 0, 0, 1], [192, 168, 1, 1]);
        let result = clamp_mss(&mut pkt, 1436);
        assert_eq!(result, ClampResult::MssMissing);
    }

    #[test]
    fn clamp_ignores_non_syn() {
        let mut pkt = build_syn_with_mss([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443, 1460);
        // Clear SYN flag, set ACK
        pkt[20 + 13] = 0x10;
        let result = clamp_mss(&mut pkt, 1436);
        assert_eq!(result, ClampResult::NotSyn);
    }

    #[test]
    fn clamp_handles_syn_ack() {
        let mut pkt = build_syn_with_mss([10, 0, 0, 1], [192, 168, 1, 1], 443, 12345, 1460);
        // Set SYN+ACK
        pkt[20 + 13] = TCP_SYN | 0x10;

        // Recompute checksum for modified flags
        pkt[20 + 16] = 0;
        pkt[20 + 17] = 0;
        let checksum = full_tcp_checksum(&pkt, 20);
        pkt[20 + 16] = (checksum >> 8) as u8;
        pkt[20 + 17] = (checksum & 0xFF) as u8;

        let result = clamp_mss(&mut pkt, 1436);
        assert_eq!(result, ClampResult::Clamped);

        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss, 1436);
    }

    #[test]
    fn clamp_malformed_options_no_panic() {
        let mut pkt = build_syn_with_mss([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443, 1460);
        // Corrupt the option length to 0 (malformed)
        pkt[20 + 21] = 0;
        let result = clamp_mss(&mut pkt, 1436);
        // Should not panic, returns MssMissing since MSS option was not successfully parsed
        assert_eq!(result, ClampResult::MssMissing);
    }

    #[test]
    fn clamp_checksum_correct() {
        let mut pkt = build_syn_with_mss([10, 0, 0, 1], [192, 168, 1, 1], 12345, 443, 1460);
        clamp_mss(&mut pkt, 1436);

        // Verify by full recomputation
        let stored = u16::from_be_bytes([pkt[20 + 16], pkt[20 + 17]]);
        pkt[20 + 16] = 0;
        pkt[20 + 17] = 0;
        let expected = full_tcp_checksum(&pkt, 20);
        assert_eq!(stored, expected, "TCP checksum mismatch after MSS clamp");
    }

    #[test]
    fn clamp_incremental_checksum_matches_full() {
        let mut pkt = build_syn_with_mss([10, 0, 0, 1], [192, 168, 1, 1], 54321, 80, 8960);
        clamp_mss(&mut pkt, 1436);

        let stored = u16::from_be_bytes([pkt[20 + 16], pkt[20 + 17]]);
        pkt[20 + 16] = 0;
        pkt[20 + 17] = 0;
        let full = full_tcp_checksum(&pkt, 20);
        assert_eq!(stored, full);
    }

    #[test]
    fn clamp_at_various_mtus() {
        for (mtu, expected_clamp) in [(1280, 1216), (1500, 1436), (4000, 3936), (9000, 8936)] {
            let max_mss = mtu - 24 - 40; // network_mtu - GRE - IP+TCP
            let mut pkt = build_syn_with_mss([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443, 8960);
            let result = clamp_mss(&mut pkt, max_mss);
            assert_eq!(result, ClampResult::Clamped, "failed at MTU {mtu}");

            let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
            assert_eq!(mss, expected_clamp, "wrong clamp at MTU {mtu}");
        }
    }
}
