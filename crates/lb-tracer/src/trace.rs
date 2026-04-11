use lb_types::Protocol;
use std::net::IpAddr;

/// A request to trace a specific flow through the LB system.
#[derive(Debug, Clone)]
pub struct TraceRequest {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

/// Result from tracing a packet through the LB.
#[derive(Debug, Clone)]
pub struct TraceResult {
    pub node_id: String,
    pub flow_hash: u64,
    pub backend_selected: IpAddr,
    pub conn_table_hit: bool,
}

impl std::fmt::Display for TraceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Node: {}, Hash: 0x{:016x}, Backend: {}, ConnTable: {}",
            self.node_id,
            self.flow_hash,
            self.backend_selected,
            if self.conn_table_hit { "HIT" } else { "MISS" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn trace_result_display() {
        let result = TraceResult {
            node_id: "lb-node-01".into(),
            flow_hash: 0xDEADBEEF,
            backend_selected: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            conn_table_hit: false,
        };
        let s = format!("{result}");
        assert!(s.contains("lb-node-01"));
        assert!(s.contains("MISS"));
    }
}
