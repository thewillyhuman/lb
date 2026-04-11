use crate::probe::Probe;
use crate::state_machine::HealthState;
use lb_types::{Backend, HealthStatus};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time;

/// Key for deduplicating health checks across pools.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProbeKey {
    ip: IpAddr,
    port: u16,
}

/// Manages health checking for all backends.
pub struct HealthChecker<P: Probe> {
    probe: Arc<P>,
    interval: Duration,
    timeout: Duration,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
}

impl<P: Probe + 'static> HealthChecker<P> {
    pub fn new(
        probe: P,
        interval: Duration,
        timeout: Duration,
        healthy_threshold: u32,
        unhealthy_threshold: u32,
    ) -> Self {
        Self {
            probe: Arc::new(probe),
            interval,
            timeout,
            healthy_threshold,
            unhealthy_threshold,
        }
    }

    /// Start health checking all given backends. Returns a receiver that gets notified
    /// on any health status change as `(IpAddr, HealthStatus)`.
    pub fn start(
        &self,
        backends: Vec<Backend>,
    ) -> watch::Receiver<HashMap<IpAddr, HealthStatus>> {
        let (tx, rx) = watch::channel(HashMap::new());

        // Deduplicate by (ip, port)
        let mut unique_backends = HashMap::new();
        for b in backends {
            let key = ProbeKey {
                ip: b.ip,
                port: b.port,
            };
            unique_backends.entry(key).or_insert(b);
        }

        for backend in unique_backends.into_values() {
            let probe = Arc::clone(&self.probe);
            let tx = tx.clone();
            let interval = self.interval;
            let timeout = self.timeout;
            let healthy_threshold = self.healthy_threshold;
            let unhealthy_threshold = self.unhealthy_threshold;

            tokio::spawn(async move {
                let mut state = HealthState::new();
                let mut ticker = time::interval(interval);

                loop {
                    ticker.tick().await;
                    let result = probe.check(&backend, timeout).await;
                    let success = result.is_success();

                    if let Some(new_status) =
                        state.record_result(success, healthy_threshold, unhealthy_threshold)
                    {
                        tracing::info!(
                            backend_ip = %backend.ip,
                            backend_port = backend.port,
                            status = ?new_status,
                            "health status changed"
                        );
                        tx.send_modify(|map| {
                            map.insert(backend.ip, new_status);
                        });
                    }
                }
            });
        }

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::TcpProbe;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn checker_detects_healthy_backend() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Accept connections in background
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let checker = HealthChecker::new(
            TcpProbe,
            Duration::from_millis(50),
            Duration::from_millis(100),
            2,
            3,
        );

        let backend = Backend::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut rx = checker.start(vec![backend.clone()]);

        // Wait for health transitions
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("timed out waiting for health change")
            .expect("channel closed");

        let map = rx.borrow();
        assert_eq!(
            map.get(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(&HealthStatus::Healthy)
        );
    }

    #[tokio::test]
    async fn checker_detects_unhealthy_backend() {
        let checker = HealthChecker::new(
            TcpProbe,
            Duration::from_millis(50),
            Duration::from_millis(50),
            2,
            2,
        );

        // Backend on a port that's not listening
        let backend = Backend::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19998);
        let mut rx = checker.start(vec![backend]);

        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("timed out")
            .expect("channel closed");

        let map = rx.borrow();
        assert_eq!(
            map.get(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(&HealthStatus::Unhealthy)
        );
    }
}
