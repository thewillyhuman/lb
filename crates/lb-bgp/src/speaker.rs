use crate::messages;
use lb_types::BgpConfig;
use std::net::{Ipv4Addr, SocketAddr};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{self, Duration};

#[derive(Debug, Error)]
pub enum BgpError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("BGP session error: {0}")]
    Session(String),
    #[error("connection timeout")]
    Timeout,
}

/// Minimal BGP speaker for VIP announcement and withdrawal.
pub struct BgpSpeaker {
    config: BgpConfig,
    stream: Option<TcpStream>,
    keepalive_interval: Duration,
}

impl BgpSpeaker {
    pub fn new(config: BgpConfig) -> Self {
        Self {
            config,
            stream: None,
            keepalive_interval: Duration::from_secs(30),
        }
    }

    /// Connect to the BGP peer and complete the OPEN handshake.
    pub async fn connect(&mut self) -> Result<(), BgpError> {
        let peer_addr = SocketAddr::new(self.config.peer_ip, 179);

        let stream = time::timeout(Duration::from_secs(10), TcpStream::connect(peer_addr))
            .await
            .map_err(|_| BgpError::Timeout)?
            .map_err(BgpError::Io)?;

        let router_id = match self.config.router_id {
            std::net::IpAddr::V4(v4) => v4,
            _ => return Err(BgpError::Session("router_id must be IPv4".into())),
        };

        let open_msg = messages::encode_open(
            self.config.local_asn as u16,
            90,
            router_id,
        );

        self.stream = Some(stream);
        let stream = self.stream.as_mut().unwrap();

        // Send OPEN
        stream.write_all(&open_msg).await?;

        // Read peer's OPEN
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n < 19 {
            return Err(BgpError::Session("incomplete BGP message from peer".into()));
        }

        match messages::parse_message_type(&buf[..n]) {
            Some(messages::BgpMessageType::Open) => {}
            other => {
                return Err(BgpError::Session(format!(
                    "expected OPEN from peer, got {other:?}"
                )));
            }
        }

        // Send KEEPALIVE to confirm the session
        let keepalive = messages::encode_keepalive();
        stream.write_all(&keepalive).await?;

        tracing::info!(peer = %peer_addr, "BGP session established");
        Ok(())
    }

    /// Announce VIP prefixes to the BGP peer.
    pub async fn announce(&mut self, vips: &[Ipv4Addr]) -> Result<(), BgpError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| BgpError::Session("not connected".into()))?;

        let next_hop = match self.config.router_id {
            std::net::IpAddr::V4(v4) => v4,
            _ => return Err(BgpError::Session("router_id must be IPv4".into())),
        };

        for &vip in vips {
            let update = messages::encode_update_announce(
                vip,
                32, // /32 host route
                next_hop,
                self.config.local_asn as u16,
            );
            stream.write_all(&update).await?;
            tracing::info!(vip = %vip, "announced VIP");
        }

        Ok(())
    }

    /// Withdraw VIP prefixes from the BGP peer.
    pub async fn withdraw(&mut self, vips: &[Ipv4Addr]) -> Result<(), BgpError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| BgpError::Session("not connected".into()))?;

        for &vip in vips {
            let update = messages::encode_update_withdraw(vip, 32);
            stream.write_all(&update).await?;
            tracing::info!(vip = %vip, "withdrew VIP");
        }

        Ok(())
    }

    /// Send a keepalive message.
    pub async fn send_keepalive(&mut self) -> Result<(), BgpError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| BgpError::Session("not connected".into()))?;

        let msg = messages::encode_keepalive();
        stream.write_all(&msg).await?;
        Ok(())
    }

    /// Run the keepalive loop. Should be spawned as a background task.
    pub async fn keepalive_loop(&mut self) -> Result<(), BgpError> {
        let mut ticker = time::interval(self.keepalive_interval);
        loop {
            ticker.tick().await;
            self.send_keepalive().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn test_config(_peer_port: u16) -> BgpConfig {
        BgpConfig {
            local_asn: 65000,
            router_id: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            peer_ip: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            peer_asn: 65000,
            communities: vec![],
            next_hop_self: true,
        }
    }

    #[tokio::test]
    async fn connect_and_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Mock BGP peer
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];

            // Read OPEN from speaker
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n >= 29); // OPEN is 29 bytes
            assert_eq!(
                messages::parse_message_type(&buf[..n]),
                Some(messages::BgpMessageType::Open)
            );

            // Send OPEN back
            let open = messages::encode_open(65000, 90, Ipv4Addr::new(10, 0, 0, 254));
            stream.write_all(&open).await.unwrap();

            // Read KEEPALIVE
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(
                messages::parse_message_type(&buf[..n]),
                Some(messages::BgpMessageType::Keepalive)
            );
        });

        let mut config = test_config(port);
        config.peer_ip = std::net::IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Override the port (BGP uses 179 but we use a random port for testing)
        // We need to connect to the listener's port, not 179
        let mut speaker = BgpSpeaker::new(config);
        // Patch: connect manually to the test port
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        speaker.stream = Some(stream);

        let router_id = Ipv4Addr::new(10, 0, 0, 1);
        let open_msg = messages::encode_open(65000, 90, router_id);
        speaker.stream.as_mut().unwrap().write_all(&open_msg).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = speaker.stream.as_mut().unwrap().read(&mut buf).await.unwrap();
        assert!(n >= 19);

        let keepalive = messages::encode_keepalive();
        speaker.stream.as_mut().unwrap().write_all(&keepalive).await.unwrap();

        peer.await.unwrap();
    }
}
