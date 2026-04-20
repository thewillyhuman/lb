//! Operations HTTP server: `/healthz`, `/readyz`, `/metrics`.
//!
//! Bound at startup to `config.node.metrics_addr` and spawned on the BGP
//! tokio runtime. Three endpoints, all plain-text responses, no auth — the
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

use axum::{
    extract::State,
    http::{HeaderName, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use lb_metrics::LbMetrics;
use std::net::SocketAddr;
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
}

/// Build the router and bind the listener. Returns the bound `SocketAddr`
/// (useful when the caller asked for port 0 in tests) and a future that
/// drives the server to completion; keep that future alive with
/// `tokio::spawn`.
pub async fn serve(
    addr: SocketAddr,
    state: OpsState,
) -> std::io::Result<(SocketAddr, impl std::future::Future<Output = std::io::Result<()>>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn make_state(ready: bool, running: bool) -> OpsState {
        OpsState {
            metrics: Arc::new(LbMetrics::new()),
            ready: Arc::new(AtomicBool::new(ready)),
            forwarder_running: Arc::new(move || running),
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
        let mut stream = tokio::net::TcpStream::connect(bound).await.expect("connect");
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
    async fn healthz_endpoint_end_to_end() {
        let state = make_state(true, true);
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let (bound, server) = serve(addr, state).await.expect("bind");
        tokio::spawn(server);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(bound).await.expect("connect");
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
