//! Integration tests for `BgpSpeaker` driven against live TCP mock routers.
//!
//! These go beyond the speaker's in-module unit tests by exercising:
//!   * burst announce/withdraw sequences observed *in order* at the peer
//!   * reconnect after a peer drops the TCP connection mid-session
//!   * fan-out at realistic scale (3 peers × 20 VIPs)
//!   * supervisor resilience when one peer's endpoint is unreachable
//!   * graceful shutdown
//!
//! The tests share a `MockRouter` helper (see `common/mod.rs`) that binds a
//! real `TcpListener` and emits decoded `RouterEvent`s, so assertions are
//! driven off observed on-the-wire behaviour rather than wall-clock sleeps.

mod common;

use common::{MockRouter, MockRouterOptions, RouterEvent};
use lb_bgp::{BgpAnnouncer, BgpSpeaker, PeerState};
use lb_types::{BgpConfig, BgpPeerConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const EVENT_BUDGET: Duration = Duration::from_secs(3);
const RECONNECT_BUDGET: Duration = Duration::from_secs(5);

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
            })
            .collect(),
    }
}

async fn wait_for_state_count(
    speaker: &BgpSpeaker,
    target: PeerState,
    need: usize,
    budget: Duration,
) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let hit = speaker
            .peer_states()
            .into_iter()
            .filter(|(_, s)| *s == target)
            .count();
        if hit >= need {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "timed out after {budget:?}: {need} peers expected in {target:?}, got {:?}",
                speaker.peer_states()
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn burst_announce_and_withdraw_preserves_order() {
    // Announce 10 VIPs and then withdraw half of them — every event should
    // land at the peer and the per-peer event stream should reflect the
    // supervisor's call order.
    let mut router = MockRouter::start().await;
    let mut speaker = BgpSpeaker::new(config_for(&[router.addr.port()]));
    speaker.spawn(&tokio::runtime::Handle::current());

    wait_for_state_count(&speaker, PeerState::Established, 1, EVENT_BUDGET).await;
    assert_eq!(
        router.expect_event(EVENT_BUDGET).await,
        RouterEvent::Connected
    );

    let announced: Vec<Ipv4Addr> = (1..=10).map(|i| Ipv4Addr::new(203, 0, 113, i)).collect();
    speaker.announce(&announced);

    for vip in &announced {
        let mut skipped = Vec::new();
        let ev = router
            .expect_event_matching(
                EVENT_BUDGET,
                &mut skipped,
                |e| matches!(e, RouterEvent::Announced { vip: v } if v == vip),
            )
            .await;
        assert_eq!(ev, RouterEvent::Announced { vip: *vip });
    }

    let withdraw_half: Vec<Ipv4Addr> = announced.iter().copied().take(5).collect();
    speaker.withdraw(&withdraw_half);

    for vip in &withdraw_half {
        let mut skipped = Vec::new();
        let ev = router
            .expect_event_matching(
                EVENT_BUDGET,
                &mut skipped,
                |e| matches!(e, RouterEvent::Withdrawn { vip: v } if v == vip),
            )
            .await;
        assert_eq!(ev, RouterEvent::Withdrawn { vip: *vip });
    }

    speaker.shutdown().await;
    router.stop().await;
}

#[tokio::test]
async fn fanout_across_three_peers_at_scale() {
    // 3 peers, 20 VIPs announced in one call. Every peer must see every VIP.
    let r1 = MockRouter::start().await;
    let r2 = MockRouter::start().await;
    let r3 = MockRouter::start().await;
    let ports = [r1.addr.port(), r2.addr.port(), r3.addr.port()];
    let mut routers = [r1, r2, r3];

    let mut speaker = BgpSpeaker::new(config_for(&ports));
    speaker.spawn(&tokio::runtime::Handle::current());

    wait_for_state_count(&speaker, PeerState::Established, 3, EVENT_BUDGET).await;
    for r in routers.iter_mut() {
        assert_eq!(r.expect_event(EVENT_BUDGET).await, RouterEvent::Connected);
    }

    let vips: Vec<Ipv4Addr> = (1..=20).map(|i| Ipv4Addr::new(198, 51, 100, i)).collect();
    speaker.announce(&vips);

    for (idx, router) in routers.iter_mut().enumerate() {
        let mut seen: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
        while seen.len() < vips.len() {
            let mut skipped = Vec::new();
            let ev = router
                .expect_event_matching(EVENT_BUDGET, &mut skipped, |e| {
                    matches!(e, RouterEvent::Announced { .. })
                })
                .await;
            if let RouterEvent::Announced { vip } = ev {
                seen.insert(vip);
            }
            assert!(
                skipped
                    .iter()
                    .all(|e| matches!(e, RouterEvent::Keepalive | RouterEvent::Announced { .. })),
                "peer {idx} saw unexpected events before completion: {skipped:?}"
            );
        }
        for v in &vips {
            assert!(seen.contains(v), "peer {idx} missing VIP {v}");
        }
    }

    speaker.shutdown().await;
    for r in routers {
        r.stop().await;
    }
}

#[tokio::test]
async fn one_unreachable_peer_does_not_block_others() {
    // Two peers: one real, one on port 1 (guaranteed refused on 127.0.0.1).
    // Announces to the real peer must succeed even while the other is in
    // permanent backoff.
    let real = MockRouter::start().await;
    let mut speaker = BgpSpeaker::new(config_for(&[1u16, real.addr.port()]));
    speaker.spawn(&tokio::runtime::Handle::current());

    wait_for_state_count(&speaker, PeerState::Established, 1, EVENT_BUDGET).await;

    let vip = Ipv4Addr::new(192, 0, 2, 77);
    speaker.announce(&[vip]);

    let mut router = real;
    let mut skipped = Vec::new();
    let ev = router
        .expect_event_matching(
            EVENT_BUDGET,
            &mut skipped,
            |e| matches!(e, RouterEvent::Announced { vip: v } if v == &vip),
        )
        .await;
    assert_eq!(ev, RouterEvent::Announced { vip });

    // Both peers are configured on localhost; we can't distinguish them by
    // IP alone. What matters is that exactly one reached Established and the
    // other stayed in a non-Established state (Connecting/Backoff).
    let states = speaker.peer_states();
    let established = states
        .iter()
        .filter(|(_, s)| *s == PeerState::Established)
        .count();
    assert_eq!(
        established, 1,
        "expected exactly one Established peer, got {states:?}"
    );
    assert_eq!(
        states.len() - established,
        1,
        "unreachable peer should stay non-Established: {states:?}"
    );

    speaker.shutdown().await;
    router.stop().await;
}

#[tokio::test]
async fn reconnect_after_peer_drops_mid_session() {
    // Peer hangs up immediately after the OPEN handshake. The speaker should
    // observe EOF, enter backoff, and retry within the backoff window.
    // After the first drop we bind a fresh listener on the *same* port so
    // the speaker reconnects to the new incarnation.
    let flaky = MockRouter::start_with(MockRouterOptions {
        disconnect_after_handshake: true,
        ..Default::default()
    })
    .await;
    let port = flaky.addr.port();

    let mut speaker = BgpSpeaker::new(config_for(&[port]));
    speaker.spawn(&tokio::runtime::Handle::current());

    // First connect: handshake, then disconnect.
    let mut r1 = flaky;
    assert_eq!(r1.expect_event(EVENT_BUDGET).await, RouterEvent::Connected);
    assert_eq!(
        r1.expect_event(EVENT_BUDGET).await,
        RouterEvent::Disconnected
    );
    r1.stop().await;

    // Supervisor should fall back to Backoff → Connecting. We don't assert on
    // the transient state (race-prone) but on the eventual re-Establishment
    // once we bring the listener back up. Bind on the same port *before* the
    // backoff timer fires so the retry finds an open socket.
    let listener = loop {
        match tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await {
            Ok(l) => break l,
            // Port might still be in TIME_WAIT — small backoff and retry.
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    // Stand up a new MockRouter on the already-bound listener by mimicking
    // the same handshake logic. Simplest path: re-use the common helper by
    // dropping the listener we just bound and letting `start_with` bind —
    // but then we might lose the port. Instead, directly accept once here.
    let accept = tokio::spawn(async move {
        use lb_bgp::messages;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await; // OPEN
        let reply = messages::encode_open(65000, 90, Ipv4Addr::new(10, 0, 0, 254));
        stream.write_all(&reply).await.unwrap();
        stream
            .write_all(&messages::encode_keepalive())
            .await
            .unwrap();
        // Read speaker's confirming KEEPALIVE before returning.
        let _ = stream.read(&mut buf).await;
        stream
    });

    // Observe re-Establishment via speaker state.
    wait_for_state_count(&speaker, PeerState::Established, 1, RECONNECT_BUDGET).await;
    let _ = accept.await.unwrap();

    speaker.shutdown().await;
}

#[tokio::test]
async fn graceful_shutdown_closes_all_sessions() {
    let r1 = MockRouter::start().await;
    let r2 = MockRouter::start().await;
    let ports = [r1.addr.port(), r2.addr.port()];
    let mut routers = [r1, r2];

    let mut speaker = BgpSpeaker::new(config_for(&ports));
    speaker.spawn(&tokio::runtime::Handle::current());
    wait_for_state_count(&speaker, PeerState::Established, 2, EVENT_BUDGET).await;
    for r in routers.iter_mut() {
        assert_eq!(r.expect_event(EVENT_BUDGET).await, RouterEvent::Connected);
    }

    speaker.shutdown().await;

    // After shutdown, every peer should observe a TCP EOF (Disconnected).
    for (idx, r) in routers.iter_mut().enumerate() {
        let mut skipped = Vec::new();
        let ev = r
            .expect_event_matching(EVENT_BUDGET, &mut skipped, |e| {
                matches!(e, RouterEvent::Disconnected)
            })
            .await;
        assert_eq!(ev, RouterEvent::Disconnected, "peer {idx} never closed");
    }

    for r in routers {
        r.stop().await;
    }
}

#[tokio::test]
async fn interleaved_announce_withdraw_preserves_sequence() {
    // Exercise a realistic pattern: announce A, B; withdraw A; announce C.
    // Peer should see the exact sequence in order.
    let mut router = MockRouter::start().await;
    let mut speaker = BgpSpeaker::new(config_for(&[router.addr.port()]));
    speaker.spawn(&tokio::runtime::Handle::current());

    wait_for_state_count(&speaker, PeerState::Established, 1, EVENT_BUDGET).await;
    assert_eq!(
        router.expect_event(EVENT_BUDGET).await,
        RouterEvent::Connected
    );

    let a = Ipv4Addr::new(203, 0, 113, 1);
    let b = Ipv4Addr::new(203, 0, 113, 2);
    let c = Ipv4Addr::new(203, 0, 113, 3);

    speaker.announce(&[a, b]);
    speaker.withdraw(&[a]);
    speaker.announce(&[c]);

    let want = [
        RouterEvent::Announced { vip: a },
        RouterEvent::Announced { vip: b },
        RouterEvent::Withdrawn { vip: a },
        RouterEvent::Announced { vip: c },
    ];
    let mut seen = Vec::new();
    while seen.len() < want.len() {
        let ev = router.expect_event(EVENT_BUDGET).await;
        // Ignore keepalives — the hold time in this test is 9s so none should
        // fire, but be robust if the scheduler is slow.
        if matches!(ev, RouterEvent::Keepalive) {
            continue;
        }
        seen.push(ev);
    }
    assert_eq!(seen, want);

    speaker.shutdown().await;
    router.stop().await;
}
