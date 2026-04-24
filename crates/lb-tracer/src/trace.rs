use lb_types::Protocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A request to trace a specific flow through the LB system.
///
/// Serde-friendly so the `POST /v1/trace` endpoint in `lb-node` can accept
/// it as a JSON body. All fields are required — the tracer does not
/// substitute defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRequest {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

/// Result from tracing a packet through the LB.
///
/// The tracer runs the VIP-match → Maglev-lookup → health-check sequence
/// read-only: it does *not* touch the connection table, does *not*
/// increment metrics, and does *not* perform GRE encapsulation. What you
/// get is the LB's *steady-state* decision, independent of any connection
/// tracking state that might have accumulated in a particular rewriter
/// thread. This is usually what you want when debugging "why is traffic
/// going to backend X?".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    /// Node that served the trace, from `[node].id`.
    pub node_id: String,
    /// Outcome of the VIP matcher lookup. `None` means the packet does not
    /// match any configured VIP — the forwarder would drop it silently.
    pub pool_id: Option<String>,
    /// xxh3 flow hash of the 5-tuple. Diagnostic only.
    pub flow_hash: u64,
    /// Backend the Maglev lookup table would select *now*, given the
    /// current healthy subset. `None` when `pool_id` is also `None`, or
    /// when the named pool has no entry in the shared lookup-table map
    /// (should only happen during a config reload race).
    pub selected_backend: Option<IpAddr>,
    /// Whether `selected_backend` is currently marked healthy. `true` by
    /// default when no health signal has been recorded yet (the rewriter
    /// treats unknown-health backends as healthy too).
    pub backend_healthy: bool,
    /// Human-readable trail for operators. Each step corresponds to one
    /// decision point in the hot path.
    pub steps: Vec<String>,
}

impl std::fmt::Display for TraceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "node:    {}", self.node_id)?;
        writeln!(f, "hash:    0x{:016x}", self.flow_hash)?;
        match &self.pool_id {
            Some(id) => writeln!(f, "pool:    {id}")?,
            None => writeln!(f, "pool:    (no VIP match)")?,
        }
        match self.selected_backend {
            Some(ip) => writeln!(
                f,
                "backend: {ip} ({})",
                if self.backend_healthy {
                    "healthy"
                } else {
                    "unhealthy"
                }
            )?,
            None => writeln!(f, "backend: (none)")?,
        }
        writeln!(f, "steps:")?;
        for step in &self.steps {
            writeln!(f, "  - {step}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn trace_request_round_trips_through_json() {
        let req = TraceRequest {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            dst_port: 443,
            protocol: Protocol::Tcp,
        };
        let j = serde_json::to_string(&req).unwrap();
        let back: TraceRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.src_ip, req.src_ip);
        assert_eq!(back.dst_port, 443);
    }

    #[test]
    fn trace_result_display_renders_human_trail() {
        let r = TraceResult {
            node_id: "lb-node-01".into(),
            pool_id: Some("web".into()),
            flow_hash: 0xDEAD_BEEF_CAFE_0000,
            selected_backend: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            backend_healthy: true,
            steps: vec![
                "parsed 5-tuple".into(),
                "VIP matched → pool `web`".into(),
                "Maglev → 10.0.0.1".into(),
            ],
        };
        let s = format!("{r}");
        assert!(s.contains("lb-node-01"));
        assert!(s.contains("web"));
        assert!(s.contains("10.0.0.1"));
        assert!(s.contains("healthy"));
        assert!(s.contains("parsed 5-tuple"));
    }
}
