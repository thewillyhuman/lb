//! Reusable test doubles for driving `BgpSpeaker` against fake BGP peers.
//!
//! `MockRouter` binds a real `TcpListener` on `127.0.0.1:<random>`, performs
//! the OPEN + KEEPALIVE handshake against whatever speaker connects, and then
//! streams decoded BGP events to the test. Tests can `expect_event` with a
//! timeout rather than sleeping on wall-clock durations.
//!
//! The helper is intentionally lenient about timing — tests drive assertions
//! off observed events, not `tokio::time::sleep`, so they don't flake on
//! loaded CI machines.

#![allow(dead_code)] // scenarios only use a subset of helpers

use lb_bgp::messages;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// What the mock router observed on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterEvent {
    /// OPEN handshake completed.
    Connected,
    /// UPDATE with NLRI.
    Announced { vip: Ipv4Addr },
    /// UPDATE with withdrawn routes.
    Withdrawn { vip: Ipv4Addr },
    /// KEEPALIVE received (not the initial one — that's rolled into Connected).
    Keepalive,
    /// NOTIFICATION received from the speaker.
    Notification { code: u8, subcode: u8 },
    /// Peer closed the TCP connection gracefully (EOF).
    Disconnected,
}

pub struct MockRouter {
    pub addr: SocketAddr,
    events: mpsc::UnboundedReceiver<RouterEvent>,
    /// Bytes the test wants the mock router to inject onto the currently-open
    /// session. The accept loop forwards whatever arrives here straight out
    /// the TCP socket. Used for exercising the speaker's response to peer-
    /// initiated NOTIFICATION and similar.
    inject: mpsc::UnboundedSender<Vec<u8>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl MockRouter {
    /// Bind a listener on an ephemeral port and start the accept loop.
    pub async fn start() -> Self {
        Self::start_with(MockRouterOptions::default()).await
    }

    pub async fn start_with(opts: MockRouterOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (inject_tx, inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (stop_tx, stop_rx) = oneshot::channel();

        let task = tokio::spawn(run_router(listener, opts, events_tx, inject_rx, stop_rx));

        MockRouter {
            addr,
            events: events_rx,
            inject: inject_tx,
            stop: Some(stop_tx),
            task: Some(task),
        }
    }

    /// Push raw bytes into the currently-open session. The accept loop
    /// forwards them verbatim to the speaker. Fire-and-forget.
    pub fn inject_bytes(&self, bytes: Vec<u8>) {
        let _ = self.inject.send(bytes);
    }

    /// Await the next event with a per-call timeout. Panics on timeout so the
    /// failing test points at the assertion, not a silently empty channel.
    pub async fn expect_event(&mut self, budget: Duration) -> RouterEvent {
        match tokio::time::timeout(budget, self.events.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => panic!("mock router event channel closed"),
            Err(_) => panic!("timed out after {budget:?} waiting for router event"),
        }
    }

    /// Await the next event matching the predicate, draining events in order.
    /// Returns the matched event or panics on timeout. Non-matching events
    /// before the target are returned in order via `skipped`.
    pub async fn expect_event_matching<F>(
        &mut self,
        budget: Duration,
        skipped: &mut Vec<RouterEvent>,
        pred: F,
    ) -> RouterEvent
    where
        F: Fn(&RouterEvent) -> bool,
    {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!(
                    "timed out after {budget:?} waiting for matching event; skipped: {skipped:?}"
                );
            }
            let ev = match tokio::time::timeout(remaining, self.events.recv()).await {
                Ok(Some(ev)) => ev,
                Ok(None) => panic!("mock router event channel closed; skipped: {skipped:?}"),
                Err(_) => panic!(
                    "timed out after {budget:?} waiting for matching event; skipped: {skipped:?}"
                ),
            };
            if pred(&ev) {
                return ev;
            }
            skipped.push(ev);
        }
    }

    /// Drain whatever events are immediately available, with a small grace
    /// period so in-flight bytes get parsed.
    pub async fn drain(&mut self, grace: Duration) -> Vec<RouterEvent> {
        tokio::time::sleep(grace).await;
        let mut out = Vec::new();
        while let Ok(ev) = self.events.try_recv() {
            out.push(ev);
        }
        out
    }

    /// Stop accepting, close any active connection, and join the task.
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct MockRouterOptions {
    /// Hold time to advertise in the mock router's OPEN reply. The speaker
    /// picks `min(our_hold, peer_hold)` per RFC 4271 §4.2 and derives both
    /// the keepalive cadence (`hold / 3`) and the hold-timer deadline from
    /// that value.
    pub our_hold_time_secs: u16,
    /// If true, send an OPEN reply and KEEPALIVE; if false, accept and hang
    /// (useful for testing the speaker's handshake timeout).
    pub reply_to_open: bool,
    /// Close the TCP connection right after the OPEN handshake — useful for
    /// exercising reconnect/backoff paths.
    pub disconnect_after_handshake: bool,
    /// After the handshake, stop responding on this socket entirely: no
    /// keepalives, no echoes. Used to exercise the speaker's hold-timer
    /// enforcement. The accept loop still listens for `inject_bytes` but
    /// ignores everything the speaker sends.
    pub go_silent_after_handshake: bool,
}

impl Default for MockRouterOptions {
    fn default() -> Self {
        Self {
            our_hold_time_secs: 90,
            reply_to_open: true,
            disconnect_after_handshake: false,
            go_silent_after_handshake: false,
        }
    }
}

async fn run_router(
    listener: TcpListener,
    opts: MockRouterOptions,
    events: mpsc::UnboundedSender<RouterEvent>,
    inject_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut stop: oneshot::Receiver<()>,
) {
    // Share the inject receiver across all connection tasks. Only one
    // connection has it at a time (we lock across accepts); this is fine
    // because every test scenario opens at most one connection per
    // `MockRouter`.
    let inject = std::sync::Arc::new(tokio::sync::Mutex::new(inject_rx));
    loop {
        let accept = tokio::select! {
            r = listener.accept() => r,
            _ = &mut stop => return,
        };
        let (stream, _) = match accept {
            Ok(p) => p,
            Err(_) => continue,
        };

        let ev = events.clone();
        let opts = opts.clone();
        let inject = std::sync::Arc::clone(&inject);
        tokio::spawn(handle_connection(stream, opts, ev, inject));
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    opts: MockRouterOptions,
    events: mpsc::UnboundedSender<RouterEvent>,
    inject: std::sync::Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
) {
    let mut incoming = ByteAccumulator::new();
    let mut buf = [0u8; 4096];

    // Read the speaker's OPEN.
    let first = match stream.read(&mut buf).await {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    incoming.extend(&buf[..first]);

    // Only proceed if we saw an OPEN.
    let Some(msg) = incoming.next_message() else {
        return;
    };
    if messages::parse_message_type(&msg) != Some(messages::BgpMessageType::Open) {
        return;
    }

    if !opts.reply_to_open {
        // Hang — the speaker should hit its handshake read timeout.
        let _ = stream.read(&mut buf).await;
        return;
    }

    // Reply with our OPEN + KEEPALIVE.
    let reply = messages::encode_open(65000, opts.our_hold_time_secs, Ipv4Addr::new(10, 0, 0, 254));
    if stream.write_all(&reply).await.is_err() {
        return;
    }
    let ka = messages::encode_keepalive();
    if stream.write_all(&ka).await.is_err() {
        return;
    }

    // Expect the speaker's confirming KEEPALIVE.
    // (The speaker sends it right after its OPEN round-trips.)
    loop {
        match incoming.next_message() {
            Some(m) => {
                if messages::parse_message_type(&m) == Some(messages::BgpMessageType::Keepalive) {
                    break;
                }
            }
            None => {
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                incoming.extend(&buf[..n]);
            }
        }
    }

    let _ = events.send(RouterEvent::Connected);

    if opts.disconnect_after_handshake {
        // Drop the stream; speaker should observe EOF and enter backoff.
        drop(stream);
        let _ = events.send(RouterEvent::Disconnected);
        return;
    }

    // Main loop: decode any BGP message arriving on the stream *and* forward
    // any bytes the test wants to inject into the session (via
    // `MockRouter::inject_bytes`).
    let mut inject_guard = inject.lock().await;
    loop {
        while let Some(m) = incoming.next_message() {
            emit_message_event(&m, &events);
        }
        tokio::select! {
            read = stream.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        let _ = events.send(RouterEvent::Disconnected);
                        return;
                    }
                    Ok(n) => {
                        incoming.extend(&buf[..n]);
                    }
                    Err(_) => {
                        let _ = events.send(RouterEvent::Disconnected);
                        return;
                    }
                }
            }
            injected = inject_guard.recv() => {
                // Some(bytes): forward to the peer; if the write fails, the
                // session is done.
                // None: inject channel closed — test is tearing down; fall
                // through and let the next `stream.read` observe EOF.
                let write_failed = match injected {
                    Some(bytes) => stream.write_all(&bytes).await.is_err(),
                    None => false,
                };
                if write_failed {
                    let _ = events.send(RouterEvent::Disconnected);
                    return;
                }
            }
        }
    }
}

fn emit_message_event(msg: &[u8], events: &mpsc::UnboundedSender<RouterEvent>) {
    match messages::parse_message_type(msg) {
        Some(messages::BgpMessageType::Keepalive) => {
            let _ = events.send(RouterEvent::Keepalive);
        }
        Some(messages::BgpMessageType::Notification) => {
            if let Some((code, subcode)) = messages::parse_notification(msg) {
                let _ = events.send(RouterEvent::Notification { code, subcode });
            }
        }
        Some(messages::BgpMessageType::Update) => {
            // Body starts at byte 19 (marker + length + type = 19 bytes).
            if msg.len() < 19 {
                return;
            }
            let body = &msg[19..];
            let (announced, withdrawn) = parse_update_body(body);
            for v in withdrawn {
                let _ = events.send(RouterEvent::Withdrawn { vip: v });
            }
            for v in announced {
                let _ = events.send(RouterEvent::Announced { vip: v });
            }
        }
        _ => {}
    }
}

/// Parse a BGP UPDATE body (after the 19-byte header), returning
/// `(announced, withdrawn)` /32 prefixes. Anything shorter than /32 is
/// ignored since the speaker only emits host routes.
fn parse_update_body(body: &[u8]) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    if body.len() < 2 {
        return (vec![], vec![]);
    }
    let wlen = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + wlen + 2 {
        return (vec![], vec![]);
    }
    let withdrawn = parse_host_prefixes(&body[2..2 + wlen]);

    let palen_start = 2 + wlen;
    let palen = u16::from_be_bytes([body[palen_start], body[palen_start + 1]]) as usize;
    let nlri_start = palen_start + 2 + palen;
    if body.len() < nlri_start {
        return (vec![], withdrawn);
    }
    let announced = parse_host_prefixes(&body[nlri_start..]);
    (announced, withdrawn)
}

fn parse_host_prefixes(data: &[u8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let plen = data[i] as usize;
        let pbytes = plen.div_ceil(8);
        if i + 1 + pbytes > data.len() {
            return out;
        }
        if plen == 32 && pbytes == 4 {
            let oct = &data[i + 1..i + 5];
            out.push(Ipv4Addr::new(oct[0], oct[1], oct[2], oct[3]));
        }
        i += 1 + pbytes;
    }
    out
}

/// Accumulates incoming TCP bytes and yields complete BGP messages.
/// BGP messages start with a 16-byte marker (0xFF * 16), then a 2-byte
/// length field (including header) at offset 16..18, then the type at 18.
struct ByteAccumulator {
    buf: Vec<u8>,
}

impl ByteAccumulator {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    /// Pop the next complete message, or `None` if we don't have one yet.
    fn next_message(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 19 {
            return None;
        }
        // Sanity: marker.
        if self.buf[..16] != [0xFF; 16] {
            // Desync — drop a byte and retry (keeps the parser self-healing
            // on garbage without looping forever).
            self.buf.remove(0);
            return None;
        }
        let len = u16::from_be_bytes([self.buf[16], self.buf[17]]) as usize;
        if !(19..=4096).contains(&len) {
            self.buf.remove(0);
            return None;
        }
        if self.buf.len() < len {
            return None;
        }
        let msg: Vec<u8> = self.buf.drain(..len).collect();
        Some(msg)
    }
}
