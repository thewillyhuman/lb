use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;

/// BGP message marker (16 bytes of 0xFF).
const MARKER: [u8; 16] = [0xFF; 16];

/// BGP message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpMessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
}

/// Serialize a BGP OPEN message (RFC 4271 Section 4.2).
pub fn encode_open(
    local_asn: u16,
    hold_time: u16,
    router_id: Ipv4Addr,
) -> BytesMut {
    let mut buf = BytesMut::new();

    // BGP header: marker (16) + length (2) + type (1)
    buf.put_slice(&MARKER);
    let length_pos = buf.len();
    buf.put_u16(0); // placeholder for length
    buf.put_u8(BgpMessageType::Open as u8);

    // OPEN body
    buf.put_u8(4); // BGP version 4
    buf.put_u16(local_asn);
    buf.put_u16(hold_time);
    buf.put_slice(&router_id.octets());
    buf.put_u8(0); // optional parameters length = 0

    // Fix up length
    let total_len = buf.len() as u16;
    buf[length_pos] = (total_len >> 8) as u8;
    buf[length_pos + 1] = total_len as u8;

    buf
}

/// Serialize a BGP KEEPALIVE message (RFC 4271 Section 4.4).
pub fn encode_keepalive() -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_slice(&MARKER);
    buf.put_u16(19); // length = 19 (header only)
    buf.put_u8(BgpMessageType::Keepalive as u8);
    buf
}

/// Serialize a BGP UPDATE message to announce an IPv4 prefix (RFC 4271 Section 4.3).
pub fn encode_update_announce(
    prefix: Ipv4Addr,
    prefix_len: u8,
    next_hop: Ipv4Addr,
    local_asn: u16,
) -> BytesMut {
    let mut buf = BytesMut::new();

    buf.put_slice(&MARKER);
    let length_pos = buf.len();
    buf.put_u16(0); // placeholder for total length
    buf.put_u8(BgpMessageType::Update as u8);

    // Withdrawn Routes Length = 0
    buf.put_u16(0);

    // Path Attributes
    let path_attrs_len_pos = buf.len();
    buf.put_u16(0); // placeholder for path attributes length

    // ORIGIN (type 1): IGP
    buf.put_u8(0x40); // flags: transitive
    buf.put_u8(1); // type code: ORIGIN
    buf.put_u8(1); // length
    buf.put_u8(0); // IGP

    // AS_PATH (type 2): AS_SEQUENCE [local_asn]
    buf.put_u8(0x40); // flags: transitive
    buf.put_u8(2); // type code: AS_PATH
    buf.put_u8(4); // length: 1 (type) + 1 (count) + 2 (asn)
    buf.put_u8(2); // AS_SEQUENCE
    buf.put_u8(1); // 1 AS in path
    buf.put_u16(local_asn);

    // NEXT_HOP (type 3)
    buf.put_u8(0x40); // flags: transitive
    buf.put_u8(3); // type code: NEXT_HOP
    buf.put_u8(4); // length
    buf.put_slice(&next_hop.octets());

    // Fix path attributes length
    let path_attrs_len = (buf.len() - path_attrs_len_pos - 2) as u16;
    buf[path_attrs_len_pos] = (path_attrs_len >> 8) as u8;
    buf[path_attrs_len_pos + 1] = path_attrs_len as u8;

    // NLRI: prefix
    buf.put_u8(prefix_len);
    let prefix_bytes = prefix_len.div_ceil(8) as usize;
    buf.put_slice(&prefix.octets()[..prefix_bytes]);

    // Fix total length
    let total_len = buf.len() as u16;
    buf[length_pos] = (total_len >> 8) as u8;
    buf[length_pos + 1] = total_len as u8;

    buf
}

/// Serialize a BGP UPDATE message to withdraw an IPv4 prefix.
pub fn encode_update_withdraw(prefix: Ipv4Addr, prefix_len: u8) -> BytesMut {
    let mut buf = BytesMut::new();

    buf.put_slice(&MARKER);
    let length_pos = buf.len();
    buf.put_u16(0); // placeholder
    buf.put_u8(BgpMessageType::Update as u8);

    // Withdrawn Routes
    let prefix_bytes = prefix_len.div_ceil(8) as usize;
    let withdrawn_len = 1 + prefix_bytes; // 1 byte prefix_len + prefix octets
    buf.put_u16(withdrawn_len as u16);
    buf.put_u8(prefix_len);
    buf.put_slice(&prefix.octets()[..prefix_bytes]);

    // Path Attributes Length = 0 (no attributes for withdraw)
    buf.put_u16(0);

    // No NLRI

    // Fix total length
    let total_len = buf.len() as u16;
    buf[length_pos] = (total_len >> 8) as u8;
    buf[length_pos + 1] = total_len as u8;

    buf
}

/// Parse the BGP message type from a raw BGP message header.
pub fn parse_message_type(data: &[u8]) -> Option<BgpMessageType> {
    if data.len() < 19 {
        return None;
    }
    match data[18] {
        1 => Some(BgpMessageType::Open),
        2 => Some(BgpMessageType::Update),
        3 => Some(BgpMessageType::Notification),
        4 => Some(BgpMessageType::Keepalive),
        _ => None,
    }
}

/// Parse the length field from a BGP message header.
pub fn parse_message_length(data: &[u8]) -> Option<u16> {
    if data.len() < 18 {
        return None;
    }
    Some(u16::from_be_bytes([data[16], data[17]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_message_layout() {
        let msg = encode_open(65000, 90, Ipv4Addr::new(10, 0, 0, 1));
        // Header: 16 (marker) + 2 (length) + 1 (type) = 19
        // Body: 1 (version) + 2 (ASN) + 2 (hold_time) + 4 (router_id) + 1 (opt params) = 10
        assert_eq!(msg.len(), 29);

        // Marker
        assert_eq!(&msg[0..16], &MARKER);
        // Length
        assert_eq!(u16::from_be_bytes([msg[16], msg[17]]), 29);
        // Type = OPEN
        assert_eq!(msg[18], 1);
        // Version
        assert_eq!(msg[19], 4);
        // ASN
        assert_eq!(u16::from_be_bytes([msg[20], msg[21]]), 65000);
        // Hold time
        assert_eq!(u16::from_be_bytes([msg[22], msg[23]]), 90);
        // Router ID
        assert_eq!(&msg[24..28], &[10, 0, 0, 1]);
    }

    #[test]
    fn keepalive_message_layout() {
        let msg = encode_keepalive();
        assert_eq!(msg.len(), 19);
        assert_eq!(&msg[0..16], &MARKER);
        assert_eq!(u16::from_be_bytes([msg[16], msg[17]]), 19);
        assert_eq!(msg[18], 4);
    }

    #[test]
    fn announce_update_contains_nlri() {
        let msg = encode_update_announce(
            Ipv4Addr::new(188, 184, 100, 0),
            24,
            Ipv4Addr::new(10, 0, 0, 1),
            65000,
        );

        assert_eq!(parse_message_type(&msg), Some(BgpMessageType::Update));

        // Last bytes should be the NLRI: prefix_len + prefix octets
        let len = msg.len();
        assert_eq!(msg[len - 4], 24); // /24
        assert_eq!(&msg[len - 3..], &[188, 184, 100]); // 3 bytes for /24
    }

    #[test]
    fn withdraw_update_contains_withdrawn_routes() {
        let msg = encode_update_withdraw(Ipv4Addr::new(188, 184, 100, 0), 24);

        assert_eq!(parse_message_type(&msg), Some(BgpMessageType::Update));

        // After header (19 bytes): withdrawn routes length (2 bytes)
        let withdrawn_len = u16::from_be_bytes([msg[19], msg[20]]);
        assert_eq!(withdrawn_len, 4); // 1 byte prefix_len + 3 bytes prefix
    }

    #[test]
    fn parse_type_and_length() {
        let msg = encode_keepalive();
        assert_eq!(parse_message_type(&msg), Some(BgpMessageType::Keepalive));
        assert_eq!(parse_message_length(&msg), Some(19));
    }
}
