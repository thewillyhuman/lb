//! Read-only tracer for the forwarder decision pipeline.
//!
//! `trace_packet` answers the question operators actually ask — "if a packet
//! matching this 5-tuple arrived right now, which backend would it land on,
//! and why?" — without injecting anything, mutating connection-table state,
//! or moving any bytes. It reads the same shared state the hot path reads
//! (`VipMatcher`, `lookup_tables`, `health_status`) and returns a
//! [`TraceResult`] describing each decision.
//!
//! What the tracer deliberately does NOT do:
//!
//!   * Consult the per-thread connection table. Those are private to rewriter
//!     threads and their state drifts depending on which thread last saw a
//!     given flow. The tracer reports the steady-state Maglev answer, which
//!     is what stays consistent across nodes and restarts.
//!   * Apply TCP state transitions. No packet is really being processed.
//!   * Touch MSS clamping, ICMP, fragment handling, or GRE encap. Those are
//!     packet-rewriting concerns irrelevant to the "where does this flow
//!     go?" question.
//!
//! The tracer is intended to be called by the ops HTTP server's
//! `POST /v1/trace` handler; it's a pure function of the shared state.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use lb_hashing::LookupTable;
use lb_tracer::{TraceRequest, TraceResult};
use lb_types::{BackendPoolId, HealthStatus, PacketMeta};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::vip_matcher::VipMatcher;

/// Snapshot of the forwarder's read-side shared state.
///
/// Every field is already `Arc`-wrapped in the running binary so copying
/// this struct is cheap; the tracer takes it by reference to avoid even
/// that.
pub struct TraceInputs<'a> {
    pub node_id: &'a str,
    pub vip_matcher: &'a Arc<ArcSwap<VipMatcher>>,
    pub lookup_tables: &'a HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
    pub health_status: &'a Arc<DashMap<IpAddr, HealthStatus>>,
}

/// Run the decision pipeline for `req` against `inputs` and return a
/// `TraceResult`. Never mutates anything.
pub fn trace_packet(req: &TraceRequest, inputs: &TraceInputs<'_>) -> TraceResult {
    let mut steps: Vec<String> = Vec::new();

    // Synthesise a `PacketMeta` directly — the tracer is called with a
    // parsed 5-tuple, so we don't need to build a wire-format IP packet
    // just to re-parse it. Keeping `tcp_flags = None` is correct: the
    // trace asks the steady-state question, and TCP flags only drive
    // connection-table state, which the tracer ignores.
    let meta = PacketMeta {
        src_ip: req.src_ip,
        dst_ip: req.dst_ip,
        src_port: req.src_port,
        dst_port: req.dst_port,
        protocol: req.protocol,
        tcp_flags: None,
    };
    let flow_hash = meta.flow_hash();
    steps.push(format!(
        "parsed 5-tuple: {}:{} → {}:{} ({:?})",
        req.src_ip, req.src_port, req.dst_ip, req.dst_port, req.protocol
    ));

    let vip_matcher = inputs.vip_matcher.load();
    let Some(pool_id) = vip_matcher.match_packet(meta.dst_ip, meta.protocol, meta.dst_port) else {
        steps.push("no VIP match — packet would be dropped".into());
        return TraceResult {
            node_id: inputs.node_id.to_string(),
            pool_id: None,
            flow_hash,
            selected_backend: None,
            backend_healthy: false,
            steps,
        };
    };
    let pool_id_str = pool_id.0.clone();
    steps.push(format!("VIP matched → pool `{pool_id_str}`"));

    let Some(lookup_swap) = inputs.lookup_tables.get(pool_id) else {
        steps.push(format!(
            "pool `{pool_id_str}` has no lookup table (config-reload race?) — packet would be dropped"
        ));
        return TraceResult {
            node_id: inputs.node_id.to_string(),
            pool_id: Some(pool_id_str),
            flow_hash,
            selected_backend: None,
            backend_healthy: false,
            steps,
        };
    };
    let lookup = lookup_swap.load();
    let backend = lookup.lookup(flow_hash);
    steps.push(format!(
        "Maglev lookup → {} (flow_hash=0x{:016x})",
        backend.ip, flow_hash
    ));

    let backend_healthy = inputs
        .health_status
        .get(&backend.ip)
        .map(|s| *s != HealthStatus::Unhealthy)
        .unwrap_or(true);
    steps.push(format!(
        "health status: {}",
        if backend_healthy {
            "healthy (or unknown — treated as healthy)"
        } else {
            "UNHEALTHY — rewriter would fall back to another Maglev slot at packet time"
        }
    ));

    TraceResult {
        node_id: inputs.node_id.to_string(),
        pool_id: Some(pool_id_str),
        flow_hash,
        selected_backend: Some(backend.ip),
        backend_healthy,
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_hashing::LookupTable;
    use lb_types::{Backend, Protocol};
    use std::net::Ipv4Addr;

    fn with_pool(
        pool_id: &str,
        backends: Vec<Backend>,
    ) -> (
        HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
        Arc<ArcSwap<VipMatcher>>,
    ) {
        let lookup = LookupTable::build(&backends, 17).unwrap();
        let mut tables = HashMap::new();
        let id = BackendPoolId(pool_id.into());
        tables.insert(id.clone(), Arc::new(ArcSwap::from_pointee(lookup)));
        let matcher = VipMatcher::from_entries(vec![(
            IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            Protocol::Tcp,
            443,
            id,
        )]);
        (tables, Arc::new(ArcSwap::from_pointee(matcher)))
    }

    fn req() -> TraceRequest {
        TraceRequest {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            dst_port: 443,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn trace_returns_backend_for_matching_vip() {
        let (tables, matcher) = with_pool(
            "web",
            vec![
                Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
            ],
        );
        let health = Arc::new(DashMap::new());
        let inputs = TraceInputs {
            node_id: "lb-node-test",
            vip_matcher: &matcher,
            lookup_tables: &tables,
            health_status: &health,
        };
        let res = trace_packet(&req(), &inputs);
        assert_eq!(res.pool_id.as_deref(), Some("web"));
        assert!(res.selected_backend.is_some());
        assert!(res.backend_healthy); // unknown-health defaults to healthy
        assert!(res.steps.iter().any(|s| s.contains("VIP matched")));
        assert!(res.steps.iter().any(|s| s.contains("Maglev lookup")));
    }

    #[test]
    fn trace_reports_unhealthy_backend() {
        let backends = vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)];
        let (tables, matcher) = with_pool("web", backends);
        let health = Arc::new(DashMap::new());
        health.insert(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            HealthStatus::Unhealthy,
        );
        let inputs = TraceInputs {
            node_id: "lb-node-test",
            vip_matcher: &matcher,
            lookup_tables: &tables,
            health_status: &health,
        };
        let res = trace_packet(&req(), &inputs);
        assert_eq!(
            res.selected_backend.unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert!(!res.backend_healthy);
        assert!(res.steps.iter().any(|s| s.contains("UNHEALTHY")));
    }

    #[test]
    fn trace_reports_vip_miss_cleanly() {
        let (tables, matcher) = with_pool(
            "web",
            vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)],
        );
        let health = Arc::new(DashMap::new());
        let inputs = TraceInputs {
            node_id: "lb-node-test",
            vip_matcher: &matcher,
            lookup_tables: &tables,
            health_status: &health,
        };
        let mut bad = req();
        bad.dst_port = 22; // not a configured service
        let res = trace_packet(&bad, &inputs);
        assert!(res.pool_id.is_none());
        assert!(res.selected_backend.is_none());
        assert!(res.steps.iter().any(|s| s.contains("no VIP match")));
    }

    #[test]
    fn trace_is_deterministic_for_same_flow() {
        let (tables, matcher) = with_pool(
            "web",
            vec![
                Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
                Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 443),
            ],
        );
        let health = Arc::new(DashMap::new());
        let inputs = TraceInputs {
            node_id: "lb-node-test",
            vip_matcher: &matcher,
            lookup_tables: &tables,
            health_status: &health,
        };
        let a = trace_packet(&req(), &inputs);
        let b = trace_packet(&req(), &inputs);
        assert_eq!(a.selected_backend, b.selected_backend);
        assert_eq!(a.flow_hash, b.flow_hash);
    }
}
