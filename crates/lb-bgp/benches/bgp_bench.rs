use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use lb_bgp::{BgpAnnouncer, BgpSpeaker};
use lb_types::{BgpConfig, BgpPeerConfig};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

fn build_config(ports: &[u16]) -> BgpConfig {
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
                hold_time_secs: Some(90),
                communities: None,
                enabled: true,
                md5_password: None,
            })
            .collect(),
    }
}

/// Drain TCP connections: accept + consume. Used so `announce` doesn't block
/// on socket buffer fill — we want to measure the supervisor's fan-out cost,
/// not the kernel's TCP pacing.
async fn spawn_sink(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            // OPEN handshake so the session reaches Established.
            let _ = stream.read(&mut buf).await;
            let open = lb_bgp::messages::encode_open(65000, 90, Ipv4Addr::new(10, 0, 0, 254));
            let _ = stream.write_all(&open).await;
            let ka = lb_bgp::messages::encode_keepalive();
            let _ = stream.write_all(&ka).await;
            // Drain forever.
            loop {
                if stream.read(&mut buf).await.unwrap_or(0) == 0 {
                    return;
                }
            }
        });
    }
}

fn bench_announce_fanout(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("announce_fanout");

    for &n_peers in &[1usize, 2, 4] {
        let (speaker, _listeners) = rt.block_on(async {
            let mut listeners = Vec::with_capacity(n_peers);
            let mut ports = Vec::with_capacity(n_peers);
            for _ in 0..n_peers {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                ports.push(l.local_addr().unwrap().port());
                listeners.push(l);
            }
            for l in listeners.drain(..) {
                tokio::spawn(spawn_sink(l));
            }
            let mut speaker = BgpSpeaker::new(build_config(&ports));
            speaker.spawn(&tokio::runtime::Handle::current());
            // Wait briefly for sessions to establish.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            (speaker, ports)
        });

        let vips: Vec<Ipv4Addr> = (0..10)
            .map(|i| Ipv4Addr::new(203, 0, 113, i as u8))
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(n_peers), &n_peers, |b, _| {
            b.iter(|| {
                speaker.announce(black_box(&vips));
            });
        });
    }

    group.finish();
}

fn bench_update_encoding(c: &mut Criterion) {
    let vip = Ipv4Addr::new(188, 184, 100, 10);
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);

    c.bench_function("encode_update_announce", |b| {
        b.iter(|| {
            let msg = lb_bgp::messages::encode_update_announce(
                black_box(vip),
                32,
                black_box(next_hop),
                65000,
            );
            black_box(msg);
        })
    });

    c.bench_function("encode_update_withdraw", |b| {
        b.iter(|| {
            let msg = lb_bgp::messages::encode_update_withdraw(black_box(vip), 32);
            black_box(msg);
        })
    });
}

criterion_group!(benches, bench_announce_fanout, bench_update_encoding);
criterion_main!(benches);
