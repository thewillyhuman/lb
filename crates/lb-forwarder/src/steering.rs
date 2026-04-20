use lb_types::PacketMeta;

/// Assign a packet to a rewriter thread queue based on its 5-tuple hash.
///
/// Ensures all packets of the same flow go to the same thread.
pub fn assign_queue(meta: &PacketMeta, num_queues: usize) -> usize {
    (meta.flow_hash() % num_queues as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_types::Protocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_meta(src_last: u8, src_port: u16) -> PacketMeta {
        PacketMeta {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, src_last)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port,
            dst_port: 443,
            protocol: Protocol::Tcp,
            tcp_flags: None,
        }
    }

    #[test]
    fn same_flow_same_queue() {
        let meta = make_meta(1, 12345);
        let q1 = assign_queue(&meta, 8);
        let q2 = assign_queue(&meta, 8);
        assert_eq!(q1, q2);
    }

    #[test]
    fn queue_within_range() {
        let meta = make_meta(1, 12345);
        let q = assign_queue(&meta, 8);
        assert!(q < 8);
    }

    #[test]
    fn different_flows_distribute() {
        let num_queues = 8;
        let mut queues_used = std::collections::HashSet::new();
        for i in 0..100 {
            let meta = make_meta(i, 10000 + i as u16);
            queues_used.insert(assign_queue(&meta, num_queues));
        }
        // With 100 different flows and 8 queues, we should hit most queues
        assert!(
            queues_used.len() >= 4,
            "expected distribution across queues"
        );
    }
}
