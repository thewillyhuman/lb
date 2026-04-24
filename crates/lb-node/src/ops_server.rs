//! Operations HTTP server: `/healthz`, `/readyz`, `/metrics`, `/v1/trace`.
//!
//! Bound at startup to `config.node.metrics_addr` and spawned on the BGP
//! tokio runtime. All endpoints plain-text or JSON responses, no auth — the
//! defaults bind loopback so cross-host scraping requires operator opt-in.
//!
//! * `/healthz` — liveness. Returns 200 as long as the process is up.
//!   Kubernetes-style: a failing liveness probe triggers restart, not de-
//!   pooling, so we don't gate this on anything.
//! * `/readyz` — readiness. Returns 200 iff the initial config has been
//!   applied *and* the multi-threaded forwarder is still running. Used by
//!   load balancers / systemd notify to decide whether traffic should be
//!   steered at this node.
//! * `/metrics` — Prometheus text exposition (version 0.0.4 content type).
//! * `/v1/trace` — POST a `TraceRequest` JSON body; returns a `TraceResult`
//!   describing the forwarder's decision for the synthetic 5-tuple. Does
//!   not inject anything on the wire.

use arc_swap::ArcSwap;
use axum::{
    extract::State,
    http::{HeaderName, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use lb_forwarder::tracer::{trace_packet, TraceInputs};
use lb_forwarder::vip_matcher::VipMatcher;
use lb_hashing::LookupTable;
use lb_metrics::LbMetrics;
use lb_tracer::{TraceRequest, TraceResult};
use lb_types::{BackendPoolId, HealthStatus};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared state handed to every route.
#[derive(Clone)]
pub struct OpsState {
    pub metrics: Arc<LbMetrics>,
    pub ready: Arc<AtomicBool>,
    /// Closure the readiness endpoint calls to verify the forwarder hasn't
    /// panicked since it was declared ready. Kept as a boxed `Fn` so the
    /// server module doesn't need to depend on `lb-forwarder`.
    pub forwarder_running: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Node identifier from `[node].id`. Included in every trace response
    /// so operators running the same trace against multiple nodes can tell
    /// which one answered.
    pub node_id: Arc<str>,
    /// Read-side shared state the tracer needs — same handles the forwarder
    /// hot path reads. Holding `Arc` clones alongside the forwarder is
    /// cheap: the inner `ArcSwap`/`DashMap`/HashMap-of-`ArcSwap` values are
    /// already shared.
    pub vip_matcher: Arc<ArcSwap<VipMatcher>>,
    pub lookup_tables: Arc<HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>>,
    pub health_status: Arc<DashMap<IpAddr, HealthStatus>>,
}

/// Build the router and bind the listener. Returns the bound `SocketAddr`
/// (useful when the caller asked for port 0 in tests) and a future that
/// drives the server to completion; keep that future alive with
/// `tokio::spawn`.
pub async fn serve(
    addr: SocketAddr,
    state: OpsState,
) -> std::io::Result<(
    SocketAddr,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/trace", post(trace))
        .with_state(state);
    tracing::info!(%bound, "ops HTTP server listening");
    let fut = async move { axum::serve(listener, app).await };
    Ok((bound, fut))
}

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok\n")
}

async fn readyz(State(s): State<OpsState>) -> (StatusCode, &'static str) {
    if !s.ready.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, "config not applied\n");
    }
    if !(s.forwarder_running)() {
        return (StatusCode::SERVICE_UNAVAILABLE, "forwarder stopped\n");
    }
    (StatusCode::OK, "ok\n")
}

async fn metrics(State(s): State<OpsState>) -> impl IntoResponse {
    let body = s.metrics.encode();
    (
        StatusCode::OK,
        [(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        body,
    )
}

/// `POST /v1/trace` — JSON body `TraceRequest`, JSON response `TraceResult`.
/// Runs the forwarder's read-only tracer against the current shared state.
async fn trace(
    State(s): State<OpsState>,
    Json(req): Json<TraceRequest>,
) -> (StatusCode, Json<TraceResult>) {
    let inputs = TraceInputs {
        node_id: &s.node_id,
        vip_matcher: &s.vip_matcher,
        lookup_tables: &s.lookup_tables,
        health_status: &s.health_status,
    };
    let result = trace_packet(&req, &inputs);
    (StatusCode::OK, Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_types::{Backend, Protocol};
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicBool;

    fn make_state(ready: bool, running: bool) -> OpsState {
        make_state_with_pool(ready, running, None)
    }

    /// If `pool` is `Some((vip_ip, pool_id, backends))`, register that pool
    /// in the shared state so `/v1/trace` has something to match. Useful
    /// for the trace tests; other tests pass `None` and get empty state.
    fn make_state_with_pool(
        ready: bool,
        running: bool,
        pool: Option<(IpAddr, &str, Vec<Backend>)>,
    ) -> OpsState {
        let (vip_matcher, lookup_tables) = match pool {
            Some((vip_ip, pool_name, backends)) => {
                let lookup = LookupTable::build(&backends, 17).unwrap();
                let id = BackendPoolId(pool_name.into());
                let mut tables = HashMap::new();
                tables.insert(id.clone(), Arc::new(ArcSwap::from_pointee(lookup)));
                let matcher = VipMatcher::from_entries(vec![(vip_ip, Protocol::Tcp, 443, id)]);
                (Arc::new(ArcSwap::from_pointee(matcher)), Arc::new(tables))
            }
            None => (
                Arc::new(ArcSwap::from_pointee(VipMatcher::new())),
                Arc::new(HashMap::new()),
            ),
        };
        OpsState {
            metrics: Arc::new(LbMetrics::new()),
            ready: Arc::new(AtomicBool::new(ready)),
            forwarder_running: Arc::new(move || running),
            node_id: Arc::from("lb-node-test"),
            vip_matcher,
            lookup_tables,
            health_status: Arc::new(DashMap::new()),
        }
    }

    #[tokio::test]
    async fn healthz_is_always_ok() {
        let (code, body) = healthz().await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body, "ok\n");
    }

    #[tokio::test]
    async fn readyz_reflects_ready_flag_and_forwarder() {
        let (code, _) = readyz(State(make_state(false, true))).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);

        let (code, _) = readyz(State(make_state(true, false))).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);

        let (code, _) = readyz(State(make_state(true, true))).await;
        assert_eq!(code, StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_binds_and_serves_prometheus_text() {
        // End-to-end bind on an ephemeral port, hit it with a bare TCP
        // request, assert the body mentions a known metric name.
        let state = make_state(true, true);
        // Register a packet counter bump so /metrics has something to emit.
        state.metrics.forwarder.packets_received.inc();

        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let (bound, server) = serve(addr, state).await.expect("bind");
        tokio::spawn(server);

        // Give axum a moment to spin up.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(bound)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let response = String::from_utf8_lossy(&buf);
        assert!(
            response.contains("200 OK"),
            "expected 200 OK, got: {response}"
        );
        assert!(
            response.contains("lb_packets_received_total"),
            "expected metric name in body, got: {response}"
        );
    }

    #[tokio::test]
    async fn trace_endpoint_returns_selected_backend() {
        let vip = IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10));
        let backends = vec![
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 443),
        ];
        let state = make_state_with_pool(true, true, Some((vip, "web", backends)));

        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let (bound, server) = serve(addr, state).await.expect("bind");
        tokio::spawn(server);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let body = serde_json::json!({
            "src_ip": "10.0.0.100",
            "src_port": 12345,
            "dst_ip": "188.184.100.10",
            "dst_port": 443,
            "protocol": "Tcp"
        })
        .to_string();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(bound).await.unwrap();
        let req = format!(
            "POST /v1/trace HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("200 OK"), "response: {response}");
        // Response body should contain JSON with node_id + pool_id.
        assert!(
            response.contains("lb-node-test"),
            "missing node_id in: {response}"
        );
        assert!(
            response.contains("\"pool_id\":\"web\""),
            "missing pool_id in: {response}"
        );
        // Backend must be one of the three we configured.
        let backend_picked = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            .iter()
            .any(|b| response.contains(b));
        assert!(backend_picked, "no configured backend in: {response}");
    }

    #[tokio::test]
    async fn trace_endpoint_reports_vip_miss() {
        let state = make_state_with_pool(true, true, None);
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let (bound, server) = serve(addr, state).await.expect("bind");
        tokio::spawn(server);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let body = serde_json::json!({
            "src_ip": "10.0.0.100",
            "src_port": 12345,
            "dst_ip": "1.2.3.4",
            "dst_port": 443,
            "protocol": "Tcp"
        })
        .to_string();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(bound).await.unwrap();
        let req = format!(
            "POST /v1/trace HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("200 OK"));
        // No VIP configured, so pool_id should be null and steps should
        // contain the miss message.
        assert!(
            response.contains("\"pool_id\":null"),
            "response: {response}"
        );
        assert!(response.contains("no VIP match"), "response: {response}");
    }

    #[tokio::test]
    async fn healthz_endpoint_end_to_end() {
        let state = make_state(true, true);
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let (bound, server) = serve(addr, state).await.expect("bind");
        tokio::spawn(server);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(bound)
            .await
            .expect("connect");
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("200 OK"));
        assert!(response.contains("ok"));
    }
}
