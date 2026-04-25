use lb_types::Backend;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone)]
pub enum ProbeResult {
    Success,
    Failure(String),
}

impl ProbeResult {
    pub fn is_success(&self) -> bool {
        matches!(self, ProbeResult::Success)
    }
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("probe timed out")]
    Timeout,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),
}

/// Trait for health check probes.
pub trait Probe: Send + Sync {
    fn check(
        &self,
        target: &Backend,
        probe_timeout: Duration,
    ) -> impl std::future::Future<Output = ProbeResult> + Send;
}

/// TCP health check: success if a TCP connection can be established.
pub struct TcpProbe;

impl Probe for TcpProbe {
    async fn check(&self, target: &Backend, probe_timeout: Duration) -> ProbeResult {
        let addr = format!("{}:{}", target.ip, target.port);
        match timeout(probe_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => ProbeResult::Success,
            Ok(Err(e)) => ProbeResult::Failure(format!("tcp connect failed: {e}")),
            Err(_) => ProbeResult::Failure("tcp connect timed out".into()),
        }
    }
}

/// HTTP health check: success if an HTTP GET returns a 2xx status.
pub struct HttpProbe {
    pub path: String,
}

impl HttpProbe {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl Probe for HttpProbe {
    async fn check(&self, target: &Backend, probe_timeout: Duration) -> ProbeResult {
        let addr = format!("{}:{}", target.ip, target.port);
        let stream = match timeout(probe_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return ProbeResult::Failure(format!("connect failed: {e}")),
            Err(_) => return ProbeResult::Failure("connect timed out".into()),
        };

        // Minimal HTTP/1.1 GET request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.path, target.ip
        );

        if let Err(e) = stream.writable().await {
            return ProbeResult::Failure(format!("stream not writable: {e}"));
        }

        match stream.try_write(request.as_bytes()) {
            Ok(_) => {}
            Err(e) => return ProbeResult::Failure(format!("write failed: {e}")),
        }

        // Read response
        let mut buf = vec![0u8; 1024];
        match timeout(probe_timeout, stream.readable()).await {
            Ok(Ok(())) => match stream.try_read(&mut buf) {
                Ok(n) if n > 0 => {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    if let Some(status_line) = response.lines().next() {
                        if status_line.contains(" 2") {
                            ProbeResult::Success
                        } else {
                            ProbeResult::Failure(format!("non-2xx response: {status_line}"))
                        }
                    } else {
                        ProbeResult::Failure("empty response".into())
                    }
                }
                _ => ProbeResult::Failure("no response data".into()),
            },
            Ok(Err(e)) => ProbeResult::Failure(format!("read error: {e}")),
            Err(_) => ProbeResult::Failure("read timed out".into()),
        }
    }
}

/// HTTPS health check: success if an HTTPS GET returns a 2xx status.
///
/// Uses tokio-rustls with system root certificates by default.
/// For backends with self-signed certs, use `HttpsProbe::insecure()`.
pub struct HttpsProbe {
    pub path: String,
    connector: TlsConnector,
}

impl HttpsProbe {
    /// Create a probe that validates server certificates against system roots.
    pub fn new(path: impl Into<String>) -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            path: path.into(),
            connector: TlsConnector::from(Arc::new(tls_config)),
        }
    }

    /// Create a probe that skips certificate validation (for self-signed certs).
    pub fn insecure(path: impl Into<String>) -> Self {
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        Self {
            path: path.into(),
            connector: TlsConnector::from(Arc::new(tls_config)),
        }
    }

    /// Build a probe with mutual TLS: server is validated against
    /// `server_roots` (PEM-formatted bundle), and the client presents its
    /// own certificate chain + private key during the handshake. Backends
    /// can therefore demand `verify-client-cert` and reject probes coming
    /// from anything but the LB.
    ///
    /// Inputs:
    ///   * `server_roots_pem` — PEM bundle the probe trusts as server CAs.
    ///     Pass an empty bundle to mean "use the system trust store
    ///     (webpki-roots)" — callers usually want a private CA here, not
    ///     public roots, so the empty case is rare.
    ///   * `client_cert_pem` — PEM-encoded client cert chain (leaf first).
    ///   * `client_key_pem` — PEM-encoded private key (PKCS#8 or PKCS#1).
    ///
    /// Errors are returned as `String` so callers (typically the
    /// config-loader path) can surface them at startup rather than at
    /// the first probe — the trust store doesn't change between probes.
    pub fn with_mtls(
        path: impl Into<String>,
        server_roots_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
    ) -> Result<Self, String> {
        let mut root_store = rustls::RootCertStore::empty();
        if server_roots_pem.is_empty() {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(server_roots_pem)) {
                let cert = cert.map_err(|e| format!("invalid server CA PEM: {e}"))?;
                root_store
                    .add(cert)
                    .map_err(|e| format!("server CA rejected: {e}"))?;
            }
            if root_store.is_empty() {
                return Err("server_roots_pem contained no certificates".into());
            }
        }

        let client_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(client_cert_pem))
                .collect::<Result<_, _>>()
                .map_err(|e| format!("invalid client cert PEM: {e}"))?;
        if client_certs.is_empty() {
            return Err("client_cert_pem contained no certificates".into());
        }

        let client_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(client_key_pem))
            .map_err(|e| format!("invalid client key PEM: {e}"))?
            .ok_or_else(|| "client_key_pem contained no private key".to_string())?;

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| format!("client auth setup failed: {e}"))?;

        Ok(Self {
            path: path.into(),
            connector: TlsConnector::from(Arc::new(tls_config)),
        })
    }
}

impl Probe for HttpsProbe {
    async fn check(&self, target: &Backend, probe_timeout: Duration) -> ProbeResult {
        let addr = format!("{}:{}", target.ip, target.port);

        let stream = match timeout(probe_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return ProbeResult::Failure(format!("connect failed: {e}")),
            Err(_) => return ProbeResult::Failure("connect timed out".into()),
        };

        let server_name = match rustls::pki_types::ServerName::try_from(target.ip.to_string()) {
            Ok(name) => name,
            Err(_) => {
                // IP addresses need IpAddr variant
                rustls::pki_types::ServerName::from(target.ip)
            }
        };

        let mut tls_stream =
            match timeout(probe_timeout, self.connector.connect(server_name, stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return ProbeResult::Failure(format!("TLS handshake failed: {e}")),
                Err(_) => return ProbeResult::Failure("TLS handshake timed out".into()),
            };

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.path, target.ip
        );

        if let Err(e) = tls_stream.write_all(request.as_bytes()).await {
            return ProbeResult::Failure(format!("write failed: {e}"));
        }

        let mut buf = vec![0u8; 1024];
        match timeout(probe_timeout, tls_stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let response = String::from_utf8_lossy(&buf[..n]);
                if let Some(status_line) = response.lines().next() {
                    if status_line.contains(" 2") {
                        ProbeResult::Success
                    } else {
                        ProbeResult::Failure(format!("non-2xx response: {status_line}"))
                    }
                } else {
                    ProbeResult::Failure("empty response".into())
                }
            }
            Ok(Ok(_)) => ProbeResult::Failure("no response data".into()),
            Ok(Err(e)) => ProbeResult::Failure(format!("read error: {e}")),
            Err(_) => ProbeResult::Failure("read timed out".into()),
        }
    }
}

/// Certificate verifier that accepts any certificate (for self-signed backends).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn backend(port: u16) -> Backend {
        Backend::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn tcp_probe_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let probe = TcpProbe;
        let result = probe.check(&backend(port), Duration::from_secs(1)).await;
        assert!(result.is_success());
    }

    #[tokio::test]
    async fn tcp_probe_failure() {
        // Use a port that's almost certainly not listening
        let probe = TcpProbe;
        let result = probe
            .check(&backend(19999), Duration::from_millis(100))
            .await;
        assert!(!result.is_success());
    }

    #[tokio::test]
    async fn http_probe_success() {
        // Start a tiny HTTP server
        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = HttpProbe::new("/healthz");
        let result = probe.check(&backend(port), Duration::from_secs(1)).await;
        assert!(result.is_success(), "expected success, got {result:?}");
    }

    #[tokio::test]
    async fn https_probe_insecure_success() {
        // Generate a self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        // Spawn a minimal TLS server
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls_stream.read(&mut buf).await;
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                    let _ = tls_stream.shutdown().await;
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = HttpsProbe::insecure("/healthz");
        let result = probe.check(&backend(port), Duration::from_secs(2)).await;
        assert!(result.is_success(), "expected success, got {result:?}");
    }

    #[tokio::test]
    async fn https_probe_connection_refused() {
        let probe = HttpsProbe::insecure("/healthz");
        let result = probe
            .check(&backend(19997), Duration::from_millis(100))
            .await;
        assert!(!result.is_success());
    }

    #[tokio::test]
    async fn https_probe_mtls_success() {
        // Server CA, server cert, client CA, client cert.
        // For brevity we use one CA (rcgen's default-self-signed) for both
        // server and client auth — production would use separate CAs.
        let server_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["lb-node".into()]).unwrap();

        let server_cert_der =
            rustls::pki_types::CertificateDer::from(server_cert.cert.der().to_vec());
        let server_key_der =
            rustls::pki_types::PrivateKeyDer::try_from(server_cert.key_pair.serialize_der())
                .unwrap();

        // Server requires a client cert signed by client_cert (acting as its
        // own CA — fine for a self-signed test) — meaning only probes using
        // the matching client cert can complete the handshake.
        let mut client_root_store = rustls::RootCertStore::empty();
        let client_ca_der =
            rustls::pki_types::CertificateDer::from(client_cert.cert.der().to_vec());
        client_root_store.add(client_ca_der.clone()).unwrap();
        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(client_root_store))
                .build()
                .unwrap();

        let server_tls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert_der.clone()], server_key_der)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls_stream.read(&mut buf).await;
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                    let _ = tls_stream.shutdown().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Probe trusts the server CA (= server's self-signed cert) and
        // presents the client cert + key.
        let server_pem = server_cert.cert.pem();
        let client_pem = client_cert.cert.pem();
        let client_key_pem = client_cert.key_pair.serialize_pem();
        let probe = HttpsProbe::with_mtls(
            "/healthz",
            server_pem.as_bytes(),
            client_pem.as_bytes(),
            client_key_pem.as_bytes(),
        )
        .expect("mTLS probe construction");

        let result = probe.check(&backend(port), Duration::from_secs(2)).await;
        assert!(result.is_success(), "expected success, got {result:?}");
    }

    #[test]
    fn https_probe_mtls_rejects_empty_client_cert() {
        let err = match HttpsProbe::with_mtls("/h", b"", b"", b"") {
            Err(e) => e,
            Ok(_) => panic!("expected with_mtls to error on empty PEM"),
        };
        assert!(err.contains("client_cert_pem"), "got: {err}");
    }

    #[test]
    fn https_probe_mtls_rejects_invalid_pem() {
        let err = match HttpsProbe::with_mtls("/h", b"", b"not a cert", b"not a key") {
            Err(e) => e,
            Ok(_) => panic!("expected with_mtls to error on garbage PEM"),
        };
        // Either "invalid client cert PEM" or "no certificates" — the
        // important thing is we surface it instead of crashing later.
        assert!(
            err.contains("client_cert") || err.contains("no certificates"),
            "got: {err}"
        );
    }
}
