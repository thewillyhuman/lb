use crate::messages;
use lb_types::{BgpConfig, BgpPeerConfig};
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration, Instant};

const DEFAULT_HOLD_TIME_SECS: u16 = 90;
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum BgpError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("BGP session error: {0}")]
    Session(String),
    #[error("connection timeout")]
    Timeout,
}

/// Abstract fan-out API for VIP announcements. A test double can record
/// announce/withdraw calls without touching real sockets.
pub trait BgpAnnouncer: Send + Sync {
    fn announce(&self, vips: &[Ipv4Addr]);
    fn withdraw(&self, vips: &[Ipv4Addr]);
}

/// Observable state of a BGP peer session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Initial state before the first connect attempt.
    Idle,
    /// TCP connecting or OPEN handshake in progress.
    Connecting,
    /// Session is up; announces will be delivered.
    Established,
    /// Backing off after a failure. Reconnect is scheduled.
    Backoff,
    /// Explicitly disabled in config.
    Disabled,
}

/// Event stream emitted by the speaker. Downstream consumers (e.g. metrics)
/// subscribe via [`BgpSpeaker::take_event_rx`].
#[derive(Debug, Clone)]
pub enum BgpEvent {
    PeerConnected {
        peer_ip: IpAddr,
    },
    PeerDisconnected {
        peer_ip: IpAddr,
        reason: String,
    },
    AnnounceFailed {
        peer_ip: IpAddr,
    },
    WithdrawFailed {
        peer_ip: IpAddr,
    },
    /// Peer sent us a NOTIFICATION. RFC 4271 §6.3 says the session MUST be
    /// torn down after sending or receiving one — we record the code/subcode
    /// for operator visibility and then fall through to the transient
    /// disconnect path.
    PeerNotification {
        peer_ip: IpAddr,
        error_code: u8,
        error_subcode: u8,
    },
}

/// Command sent from the supervisor to a per-peer session task.
#[derive(Debug, Clone)]
enum SessionCmd {
    Announce(Vec<Ipv4Addr>),
    Withdraw(Vec<Ipv4Addr>),
    Shutdown,
}

struct PeerHandle {
    peer_ip: IpAddr,
    tx: mpsc::UnboundedSender<SessionCmd>,
    state: Arc<Mutex<PeerState>>,
    /// Wrapped in a Mutex so `shutdown` can take the `JoinHandle` out through
    /// `&self`, letting the speaker sit behind `Arc` without interior-mutability
    /// ceremony at the announce/withdraw call sites.
    task: Mutex<Option<JoinHandle<()>>>,
    enabled: bool,
}

/// BGP supervisor: holds one session per configured peer and fans out
/// announcements to every live peer. Per-peer failures are contained — a
/// disconnected or backoff-waiting peer does not block announces to the rest.
pub struct BgpSpeaker {
    config: BgpConfig,
    peers: Vec<PeerHandle>,
    event_tx: mpsc::UnboundedSender<BgpEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<BgpEvent>>,
}

impl BgpSpeaker {
    pub fn new(config: BgpConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            config,
            peers: Vec::new(),
            event_tx,
            event_rx: Some(event_rx),
        }
    }

    /// Take the event receiver exactly once. Returns `None` on subsequent calls.
    pub fn take_event_rx(&mut self) -> Option<mpsc::UnboundedReceiver<BgpEvent>> {
        self.event_rx.take()
    }

    /// Spawn one tokio task per configured peer. Must be called on an active
    /// tokio runtime. Idempotent: calling twice is a programming error.
    pub fn spawn(&mut self, rt: &tokio::runtime::Handle) {
        assert!(self.peers.is_empty(), "BgpSpeaker::spawn called twice");

        let router_id = match self.config.router_id {
            IpAddr::V4(v4) => v4,
            _ => {
                tracing::error!("router_id must be IPv4; no BGP sessions will start");
                return;
            }
        };

        for peer_cfg in &self.config.peers {
            let (tx, rx) = mpsc::unbounded_channel();
            let state = Arc::new(Mutex::new(if peer_cfg.enabled {
                PeerState::Idle
            } else {
                PeerState::Disabled
            }));

            let handle = if peer_cfg.enabled {
                let session = PeerSessionCtx {
                    peer: peer_cfg.clone(),
                    local_asn: self.config.local_asn as u16,
                    router_id,
                    state: Arc::clone(&state),
                    events: self.event_tx.clone(),
                };
                Some(rt.spawn(session.run(rx)))
            } else {
                // Drain any commands received for a disabled peer.
                Some(rt.spawn(async move {
                    let mut rx = rx;
                    while let Some(cmd) = rx.recv().await {
                        if matches!(cmd, SessionCmd::Shutdown) {
                            break;
                        }
                    }
                }))
            };

            self.peers.push(PeerHandle {
                peer_ip: peer_cfg.peer_ip,
                tx,
                state,
                task: Mutex::new(handle),
                enabled: peer_cfg.enabled,
            });
        }
    }

    /// Current state of every configured peer (alive or not).
    pub fn peer_states(&self) -> Vec<(IpAddr, PeerState)> {
        self.peers
            .iter()
            .map(|p| (p.peer_ip, *p.state.lock()))
            .collect()
    }

    /// Graceful shutdown: signal every peer session to terminate, then await.
    ///
    /// Takes `&self` so the speaker can live behind `Arc` and be shut down
    /// from a signal handler without needing exclusive ownership. Awaiting
    /// the `JoinHandle`s is cheap (they typically resolve within a TCP RST
    /// round-trip) so we don't need to impose a deadline here — callers that
    /// want bounded shutdown time should wrap with `tokio::time::timeout`.
    pub async fn shutdown(&self) {
        for peer in &self.peers {
            let _ = peer.tx.send(SessionCmd::Shutdown);
        }
        for peer in &self.peers {
            let handle = peer.task.lock().take();
            if let Some(task) = handle {
                let _ = task.await;
            }
        }
    }
}

impl BgpAnnouncer for BgpSpeaker {
    fn announce(&self, vips: &[Ipv4Addr]) {
        if vips.is_empty() {
            return;
        }
        for peer in &self.peers {
            if !peer.enabled {
                continue;
            }
            // UnboundedSender::send only fails if the receiver is closed,
            // which means the peer task panicked or already exited — log and
            // move on; do not poison other peers.
            if peer.tx.send(SessionCmd::Announce(vips.to_vec())).is_err() {
                tracing::warn!(peer = %peer.peer_ip, "announce dropped: session channel closed");
            }
        }
    }

    fn withdraw(&self, vips: &[Ipv4Addr]) {
        if vips.is_empty() {
            return;
        }
        for peer in &self.peers {
            if !peer.enabled {
                continue;
            }
            if peer.tx.send(SessionCmd::Withdraw(vips.to_vec())).is_err() {
                tracing::warn!(peer = %peer.peer_ip, "withdraw dropped: session channel closed");
            }
        }
    }
}

struct PeerSessionCtx {
    peer: BgpPeerConfig,
    local_asn: u16,
    router_id: Ipv4Addr,
    state: Arc<Mutex<PeerState>>,
    events: mpsc::UnboundedSender<BgpEvent>,
}

impl PeerSessionCtx {
    fn set_state(&self, new: PeerState) {
        *self.state.lock() = new;
    }

    async fn run(self, mut rx: mpsc::UnboundedReceiver<SessionCmd>) {
        let mut backoff = RECONNECT_BACKOFF_MIN;
        let our_hold = self.peer.hold_time_secs.unwrap_or(DEFAULT_HOLD_TIME_SECS);

        loop {
            // Drain any queued commands: a shutdown should win over a reconnect
            // attempt. Peek via try_recv on a best-effort basis.
            while let Ok(cmd) = rx.try_recv() {
                if matches!(cmd, SessionCmd::Shutdown) {
                    self.set_state(PeerState::Idle);
                    return;
                }
                // Drop announce/withdraw that arrived while we were not
                // connected; the supervisor will re-announce from the
                // controller's fresh VIP set on reconnect. (The controller's
                // current-state snapshot is re-announced by the caller when
                // `PeerConnected` is observed — see wiring in lb-controller.)
            }

            self.set_state(PeerState::Connecting);
            match self.connect(our_hold).await {
                Ok((stream, negotiated_hold)) => {
                    backoff = RECONNECT_BACKOFF_MIN;
                    self.set_state(PeerState::Established);
                    let _ = self.events.send(BgpEvent::PeerConnected {
                        peer_ip: self.peer.peer_ip,
                    });

                    tracing::info!(
                        peer = %self.peer.peer_ip,
                        our_hold,
                        negotiated_hold,
                        "BGP hold time negotiated"
                    );

                    let shutdown = self.drive(stream, &mut rx, negotiated_hold).await;
                    let _ = self.events.send(BgpEvent::PeerDisconnected {
                        peer_ip: self.peer.peer_ip,
                        reason: shutdown.reason.clone(),
                    });

                    if shutdown.terminal {
                        self.set_state(PeerState::Idle);
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!(peer = %self.peer.peer_ip, error = %e, "BGP connect failed");
                }
            }

            self.set_state(PeerState::Backoff);
            let sleep = tokio::time::sleep(backoff);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => {}
                cmd = rx.recv() => {
                    if matches!(cmd, Some(SessionCmd::Shutdown) | None) {
                        self.set_state(PeerState::Idle);
                        return;
                    }
                }
            }
            backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
        }
    }

    /// Complete the OPEN handshake and return the live stream plus the
    /// **negotiated** hold time (seconds). Per RFC 4271 §4.2, the accepted
    /// hold time is `min(our_hold, peer_hold)`. A negotiated value of `0`
    /// disables both keepalive generation and hold-timer enforcement.
    async fn connect(&self, our_hold: u16) -> Result<(TcpStream, u16), BgpError> {
        let peer_addr = SocketAddr::new(self.peer.peer_ip, self.peer.port);

        // Build the socket ourselves so `TCP_MD5SIG` can be installed before
        // the SYN goes out — MD5 is a per-segment signature, so missing it on
        // the handshake packets means the peer rejects them.
        let tcp_sock = match self.peer.peer_ip {
            IpAddr::V4(_) => tokio::net::TcpSocket::new_v4().map_err(BgpError::Io)?,
            IpAddr::V6(_) => tokio::net::TcpSocket::new_v6().map_err(BgpError::Io)?,
        };
        // `resolved_md5_password` reads from `md5_password_env` when set;
        // both validation (mutually-exclusive, env var present) and the
        // actual lookup happen here so a misconfigured peer is reported as
        // a clear connect-time error rather than silently peering plain.
        let md5 = self
            .peer
            .resolved_md5_password()
            .map_err(|e| BgpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
        if let Some(password) = md5.as_deref() {
            apply_tcp_md5sig(&tcp_sock, self.peer.peer_ip, password).map_err(BgpError::Io)?;
        }

        let mut stream = time::timeout(CONNECT_TIMEOUT, tcp_sock.connect(peer_addr))
            .await
            .map_err(|_| BgpError::Timeout)?
            .map_err(BgpError::Io)?;

        let open = messages::encode_open(self.local_asn, our_hold, self.router_id);
        stream.write_all(&open).await?;

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

        let peer_hold = messages::parse_open_hold_time(&buf[..n]).ok_or_else(|| {
            BgpError::Session("peer OPEN was malformed; missing hold_time".into())
        })?;
        let negotiated = our_hold.min(peer_hold);

        let keepalive = messages::encode_keepalive();
        stream.write_all(&keepalive).await?;

        tracing::info!(peer = %peer_addr, negotiated, "BGP session established");
        Ok((stream, negotiated))
    }

    /// Pump commands + keepalives until the session dies or shutdown arrives.
    ///
    /// `negotiated_hold` is the RFC-4271-negotiated hold time in seconds
    /// (`min(our_hold, peer_hold)`). Zero means the peer disabled the
    /// keepalive regime — we neither send KEEPALIVEs nor enforce a hold
    /// timer against them. Non-zero enables both: keepalives fire at
    /// `hold / 3`, and if we see no inbound bytes for `hold` seconds we
    /// emit a Hold Timer Expired NOTIFICATION and drop the session.
    async fn drive(
        &self,
        mut stream: TcpStream,
        rx: &mut mpsc::UnboundedReceiver<SessionCmd>,
        negotiated_hold: u16,
    ) -> Disconnect {
        let keepalives_enabled = negotiated_hold > 0;
        let keepalive_interval = if keepalives_enabled {
            Duration::from_secs((negotiated_hold / 3).max(1) as u64)
        } else {
            // A never-firing interval; select! will just never take this arm.
            Duration::from_secs(u64::MAX / 2)
        };
        let hold_deadline = |since: Instant| {
            if keepalives_enabled {
                since + Duration::from_secs(negotiated_hold as u64)
            } else {
                // Effectively never.
                Instant::now() + Duration::from_secs(u64::MAX / 2)
            }
        };

        let mut ticker = time::interval_at(Instant::now() + keepalive_interval, keepalive_interval);
        let mut read_buf = [0u8; 4096];
        // Inbound TCP bytes accumulate here; we extract whole BGP messages
        // (they always start with the 16-byte `0xFF` marker + 2-byte length).
        let mut incoming: Vec<u8> = Vec::with_capacity(4096);
        let mut last_inbound = Instant::now();

        loop {
            let hold_sleep = tokio::time::sleep_until(hold_deadline(last_inbound));
            tokio::pin!(hold_sleep);
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else {
                        return Disconnect::terminal("supervisor dropped");
                    };
                    match cmd {
                        SessionCmd::Shutdown => return Disconnect::terminal("shutdown"),
                        SessionCmd::Announce(vips) => {
                            if let Err(e) = self.send_announce(&mut stream, &vips).await {
                                let _ = self.events.send(BgpEvent::AnnounceFailed {
                                    peer_ip: self.peer.peer_ip,
                                });
                                return Disconnect::transient(format!("announce: {e}"));
                            }
                        }
                        SessionCmd::Withdraw(vips) => {
                            if let Err(e) = self.send_withdraw(&mut stream, &vips).await {
                                let _ = self.events.send(BgpEvent::WithdrawFailed {
                                    peer_ip: self.peer.peer_ip,
                                });
                                return Disconnect::transient(format!("withdraw: {e}"));
                            }
                        }
                    }
                }
                _ = ticker.tick() => {
                    let msg = messages::encode_keepalive();
                    if let Err(e) = stream.write_all(&msg).await {
                        return Disconnect::transient(format!("keepalive: {e}"));
                    }
                }
                read = stream.read(&mut read_buf) => {
                    match read {
                        Ok(0) => return Disconnect::transient("peer closed connection".into()),
                        Ok(n) => {
                            // Any byte of inbound traffic — KEEPALIVE, UPDATE,
                            // or even a not-yet-complete message — resets the
                            // hold timer per RFC 4271 §8.
                            last_inbound = Instant::now();
                            incoming.extend_from_slice(&read_buf[..n]);
                            // Parse as many whole messages as we have. If a
                            // NOTIFICATION lands, emit the event and return
                            // a transient disconnect — RFC 4271 §6.3 says
                            // the session MUST be closed afterwards.
                            while let Some(msg) = take_message(&mut incoming) {
                                if let Some((code, subcode)) = messages::parse_notification(&msg) {
                                    let _ = self.events.send(BgpEvent::PeerNotification {
                                        peer_ip: self.peer.peer_ip,
                                        error_code: code,
                                        error_subcode: subcode,
                                    });
                                    tracing::warn!(
                                        peer = %self.peer.peer_ip,
                                        code,
                                        subcode,
                                        name = messages::notification_error_name(code),
                                        "BGP NOTIFICATION received"
                                    );
                                    return Disconnect::transient(format!(
                                        "NOTIFICATION code={code} subcode={subcode}"
                                    ));
                                }
                                // Other peer-initiated messages (KEEPALIVE,
                                // UPDATE): ignored. A strict parser is out
                                // of scope.
                            }
                        }
                        Err(e) => return Disconnect::transient(format!("read: {e}")),
                    }
                }
                _ = &mut hold_sleep, if keepalives_enabled => {
                    // Peer has been silent for `negotiated_hold` seconds.
                    // Send a Hold Timer Expired NOTIFICATION (best effort —
                    // the session is already broken) and tear down.
                    let msg = messages::encode_notification(
                        messages::error_code::HOLD_TIMER_EXPIRED,
                        0,
                    );
                    let _ = stream.write_all(&msg).await;
                    tracing::warn!(
                        peer = %self.peer.peer_ip,
                        hold = negotiated_hold,
                        "BGP hold timer expired; tearing down session"
                    );
                    return Disconnect::transient(format!(
                        "hold timer expired after {negotiated_hold}s of peer silence"
                    ));
                }
            }
        }
    }

    async fn send_announce(
        &self,
        stream: &mut TcpStream,
        vips: &[Ipv4Addr],
    ) -> Result<(), BgpError> {
        for &vip in vips {
            let msg = messages::encode_update_announce(vip, 32, self.router_id, self.local_asn);
            stream.write_all(&msg).await?;
            tracing::debug!(peer = %self.peer.peer_ip, vip = %vip, "announced VIP");
        }
        Ok(())
    }

    async fn send_withdraw(
        &self,
        stream: &mut TcpStream,
        vips: &[Ipv4Addr],
    ) -> Result<(), BgpError> {
        for &vip in vips {
            let msg = messages::encode_update_withdraw(vip, 32);
            stream.write_all(&msg).await?;
            tracing::debug!(peer = %self.peer.peer_ip, vip = %vip, "withdrew VIP");
        }
        Ok(())
    }
}

struct Disconnect {
    reason: String,
    terminal: bool,
}

impl Disconnect {
    fn terminal(reason: &str) -> Self {
        Self {
            reason: reason.into(),
            terminal: true,
        }
    }
    fn transient(reason: String) -> Self {
        Self {
            reason,
            terminal: false,
        }
    }
}

/// Install a TCP-MD5 signature key (RFC 2385) on the socket, so every TCP
/// segment carries an MD5(header + payload + shared_key) digest. Must be
/// called before `connect` — the SYN itself has to be signed or the peer
/// will drop it.
///
/// Linux only: `TCP_MD5SIG` is a Linux-specific option. On other OSes we
/// log a warning and return `Ok(())` so the session still attempts plain
/// TCP; operators who actually need MD5 auth will have already noticed
/// their peer sessions failing to establish.
///
/// Max key length is 80 bytes (Linux `TCP_MD5SIG_MAXKEYLEN`). Longer keys
/// are rejected with `InvalidInput`.
#[cfg(target_os = "linux")]
fn apply_tcp_md5sig(
    sock: &tokio::net::TcpSocket,
    peer: IpAddr,
    password: &str,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    // TCP_MD5SIG = 14 on Linux (include/uapi/linux/tcp.h). `libc` exposes it.
    const MAX_KEYLEN: usize = 80; // TCP_MD5SIG_MAXKEYLEN

    if password.len() > MAX_KEYLEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "TCP_MD5SIG password too long ({} bytes > {MAX_KEYLEN})",
                password.len()
            ),
        ));
    }

    // Layout mirrors `struct tcp_md5sig` from `<linux/tcp.h>`. libc doesn't
    // expose the struct directly (it varies slightly across libc versions)
    // so we define it here. Total size is 216 bytes.
    #[repr(C)]
    struct TcpMd5Sig {
        tcpm_addr: libc::sockaddr_storage,
        tcpm_flags: u8,
        tcpm_prefixlen: u8,
        tcpm_keylen: u16,
        __tcpm_pad: u32,
        tcpm_key: [u8; MAX_KEYLEN],
    }

    let mut sig: TcpMd5Sig = unsafe { std::mem::zeroed() };

    // Populate tcpm_addr with the peer address. IPv4 is the only form we
    // exercise today; the rest of the forwarder is IPv4-only per H5.
    match peer {
        IpAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    &mut sig.tcpm_addr as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
        }
        IpAddr::V6(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TCP_MD5SIG not yet wired for IPv6 peers",
            ));
        }
    }

    sig.tcpm_keylen = password.len() as u16;
    sig.tcpm_key[..password.len()].copy_from_slice(password.as_bytes());

    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &sig as *const _ as *const libc::c_void,
            std::mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    tracing::info!(%peer, "TCP_MD5SIG installed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_tcp_md5sig(
    _sock: &tokio::net::TcpSocket,
    peer: IpAddr,
    _password: &str,
) -> std::io::Result<()> {
    tracing::warn!(
        %peer,
        "TCP_MD5SIG requested but only supported on Linux; peering in plain TCP"
    );
    Ok(())
}

/// Pop one complete BGP message from the byte accumulator, or return `None`
/// if we don't have one yet. Self-healing: if the buffer does not start on a
/// BGP marker, we drop one byte and wait for more data, which keeps us from
/// hanging on a mid-stream desync.
///
/// Bounds: rejects messages whose length header is outside `[19, 4096]`
/// (RFC 4271 §4.1). Anything larger is almost certainly a framing error, not
/// a legitimate UPDATE.
fn take_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 19 {
        return None;
    }
    if buf[..16] != [0xFF; 16] {
        buf.remove(0);
        return None;
    }
    let len = u16::from_be_bytes([buf[16], buf[17]]) as usize;
    if !(19..=4096).contains(&len) {
        // Desync: drop a byte and wait. Returning None without consuming
        // would loop forever.
        buf.remove(0);
        return None;
    }
    if buf.len() < len {
        return None;
    }
    Some(buf.drain(..len).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    fn config_for(ports: &[u16]) -> BgpConfig {
        BgpConfig {
            local_asn: 65000,
            router_id: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            communities: vec![],
            next_hop_self: true,
            peers: ports
                .iter()
                .map(|&p| BgpPeerConfig {
                    peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    peer_asn: 65000,
                    port: p,
                    hold_time_secs: Some(9),
                    communities: None,
                    enabled: true,
                    md5_password: None,
                    md5_password_env: None,
                })
                .collect(),
        }
    }

    /// Accept one BGP handshake and record every subsequent UPDATE body.
    /// Returns all bytes read after the handshake. Stops reading when either
    /// the stop signal arrives or the peer closes the connection.
    async fn mock_peer(listener: TcpListener, mut stop: oneshot::Receiver<()>) -> Vec<u8> {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];

        // Read OPEN
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n >= 19);
        assert_eq!(
            messages::parse_message_type(&buf[..n]),
            Some(messages::BgpMessageType::Open)
        );

        // Reply with OPEN + KEEPALIVE
        let open = messages::encode_open(65000, 90, Ipv4Addr::new(10, 0, 0, 254));
        stream.write_all(&open).await.unwrap();
        let ka = messages::encode_keepalive();
        stream.write_all(&ka).await.unwrap();

        // Read speaker's KEEPALIVE
        let _ = stream.read(&mut buf).await.unwrap();

        // Accumulate everything the speaker sends until stop arrives or the
        // peer closes. Keep captured data across the stop — the caller needs
        // to inspect it.
        let mut captured = Vec::new();
        let mut tmp = vec![0u8; 4096];
        loop {
            tokio::select! {
                r = stream.read(&mut tmp) => {
                    match r {
                        Ok(0) | Err(_) => break,
                        Ok(n) => captured.extend_from_slice(&tmp[..n]),
                    }
                }
                _ = &mut stop => break,
            }
        }
        captured
    }

    #[tokio::test]
    async fn two_peers_handshake_independently() {
        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pa = a.local_addr().unwrap().port();
        let pb = b.local_addr().unwrap().port();

        let (stop_a_tx, stop_a_rx) = oneshot::channel();
        let (stop_b_tx, stop_b_rx) = oneshot::channel();
        let h_a = tokio::spawn(mock_peer(a, stop_a_rx));
        let h_b = tokio::spawn(mock_peer(b, stop_b_rx));

        let mut speaker = BgpSpeaker::new(config_for(&[pa, pb]));
        speaker.spawn(&tokio::runtime::Handle::current());

        wait_for_state(&speaker, PeerState::Established, 2, Duration::from_secs(2)).await;

        let _ = stop_a_tx.send(());
        let _ = stop_b_tx.send(());
        speaker.shutdown().await;
        let _ = h_a.await.unwrap();
        let _ = h_b.await.unwrap();
    }

    #[tokio::test]
    async fn announce_fans_out_to_all_peers() {
        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pa = a.local_addr().unwrap().port();
        let pb = b.local_addr().unwrap().port();

        let (stop_a_tx, stop_a_rx) = oneshot::channel();
        let (stop_b_tx, stop_b_rx) = oneshot::channel();
        let h_a = tokio::spawn(mock_peer(a, stop_a_rx));
        let h_b = tokio::spawn(mock_peer(b, stop_b_rx));

        let mut speaker = BgpSpeaker::new(config_for(&[pa, pb]));
        speaker.spawn(&tokio::runtime::Handle::current());

        wait_for_state(&speaker, PeerState::Established, 2, Duration::from_secs(2)).await;

        let vip = Ipv4Addr::new(188, 184, 100, 10);
        speaker.announce(&[vip]);

        // Let both sessions flush the write.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let _ = stop_a_tx.send(());
        let _ = stop_b_tx.send(());
        speaker.shutdown().await;

        let captured_a = h_a.await.unwrap();
        let captured_b = h_b.await.unwrap();

        assert!(
            contains_update_with_nlri(&captured_a, vip),
            "peer A missed UPDATE: {captured_a:?}"
        );
        assert!(
            contains_update_with_nlri(&captured_b, vip),
            "peer B missed UPDATE: {captured_b:?}"
        );
    }

    #[tokio::test]
    async fn one_peer_down_does_not_block_others() {
        // Peer A never listens; peer B listens normally.
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pb = b.local_addr().unwrap().port();
        // Port 1 is guaranteed to refuse on 127.0.0.1.
        let pa_dead = 1u16;

        let (stop_b_tx, stop_b_rx) = oneshot::channel();
        let h_b = tokio::spawn(mock_peer(b, stop_b_rx));

        let mut speaker = BgpSpeaker::new(config_for(&[pa_dead, pb]));
        speaker.spawn(&tokio::runtime::Handle::current());

        // Wait for *one* peer to be Established (peer B). Peer A will stay in
        // Connecting/Backoff indefinitely.
        wait_for_state(&speaker, PeerState::Established, 1, Duration::from_secs(3)).await;

        let vip = Ipv4Addr::new(10, 1, 2, 3);
        speaker.announce(&[vip]);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let _ = stop_b_tx.send(());
        speaker.shutdown().await;

        let captured_b = h_b.await.unwrap();
        assert!(
            contains_update_with_nlri(&captured_b, vip),
            "peer B missed UPDATE despite peer A being down"
        );
    }

    #[tokio::test]
    async fn withdraw_fans_out() {
        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pa = a.local_addr().unwrap().port();
        let pb = b.local_addr().unwrap().port();

        let (stop_a_tx, stop_a_rx) = oneshot::channel();
        let (stop_b_tx, stop_b_rx) = oneshot::channel();
        let h_a = tokio::spawn(mock_peer(a, stop_a_rx));
        let h_b = tokio::spawn(mock_peer(b, stop_b_rx));

        let mut speaker = BgpSpeaker::new(config_for(&[pa, pb]));
        speaker.spawn(&tokio::runtime::Handle::current());
        wait_for_state(&speaker, PeerState::Established, 2, Duration::from_secs(2)).await;

        let vip = Ipv4Addr::new(1, 2, 3, 4);
        speaker.withdraw(&[vip]);
        tokio::time::sleep(Duration::from_millis(150)).await;

        let _ = stop_a_tx.send(());
        let _ = stop_b_tx.send(());
        speaker.shutdown().await;

        let captured_a = h_a.await.unwrap();
        let captured_b = h_b.await.unwrap();
        assert!(contains_update_with_withdrawn(&captured_a, vip));
        assert!(contains_update_with_withdrawn(&captured_b, vip));
    }

    #[tokio::test]
    async fn disabled_peer_does_not_connect() {
        let mut cfg = config_for(&[9]); // port 9 unused in any case
        cfg.peers[0].enabled = false;

        let mut speaker = BgpSpeaker::new(cfg);
        speaker.spawn(&tokio::runtime::Handle::current());

        tokio::time::sleep(Duration::from_millis(100)).await;
        let states = speaker.peer_states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].1, PeerState::Disabled);

        speaker.announce(&[Ipv4Addr::new(1, 2, 3, 4)]); // must be a no-op
        speaker.shutdown().await;
    }

    async fn wait_for_state(
        speaker: &BgpSpeaker,
        target: PeerState,
        need_count: usize,
        budget: Duration,
    ) {
        let deadline = Instant::now() + budget;
        loop {
            let matches = speaker
                .peer_states()
                .into_iter()
                .filter(|(_, s)| *s == target)
                .count();
            if matches >= need_count {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "timed out waiting for {need_count} peers in {target:?}; observed {:?}",
                    speaker.peer_states()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Scan `data` for an UPDATE containing the given /32 in its NLRI.
    fn contains_update_with_nlri(data: &[u8], vip: Ipv4Addr) -> bool {
        scan_for_prefix(data, vip, /*is_withdraw*/ false)
    }

    fn contains_update_with_withdrawn(data: &[u8], vip: Ipv4Addr) -> bool {
        scan_for_prefix(data, vip, /*is_withdraw*/ true)
    }

    fn scan_for_prefix(data: &[u8], vip: Ipv4Addr, withdraw: bool) -> bool {
        // Walk BGP messages in `data`.
        let mut i = 0;
        while i + 19 <= data.len() {
            // Marker check
            if data[i..i + 16] != [0xFF; 16] {
                i += 1;
                continue;
            }
            let len = u16::from_be_bytes([data[i + 16], data[i + 17]]) as usize;
            if len < 19 || i + len > data.len() {
                break;
            }
            let ty = data[i + 18];
            if ty == 2 {
                // UPDATE. Body at i+19.
                let body = &data[i + 19..i + len];
                if let Some(pos) = find_prefix(body, vip, withdraw) {
                    let _ = pos;
                    return true;
                }
            }
            i += len;
        }
        false
    }

    fn find_prefix(body: &[u8], vip: Ipv4Addr, withdraw: bool) -> Option<usize> {
        if body.len() < 2 {
            return None;
        }
        let wlen = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + wlen {
            return None;
        }
        let withdrawn = &body[2..2 + wlen];

        if body.len() < 2 + wlen + 2 {
            return None;
        }
        let palen_start = 2 + wlen;
        let palen = u16::from_be_bytes([body[palen_start], body[palen_start + 1]]) as usize;
        let nlri_start = palen_start + 2 + palen;
        if body.len() < nlri_start {
            return None;
        }
        let nlri = &body[nlri_start..];

        let target = if withdraw { withdrawn } else { nlri };
        // Each prefix: 1 byte prefix_len + ceil(len/8) bytes.
        let mut j = 0;
        while j < target.len() {
            let plen = target[j] as usize;
            let pbytes = plen.div_ceil(8);
            if j + 1 + pbytes > target.len() {
                return None;
            }
            if plen == 32 {
                let oct = &target[j + 1..j + 1 + pbytes];
                if oct == vip.octets() {
                    return Some(j);
                }
            }
            j += 1 + pbytes;
        }
        None
    }
}
