use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use crossbeam::queue::ArrayQueue;
use lb_forwarder::conn_table::ConnTable;
use lb_forwarder::gre;
use lb_forwarder::threading::{ForwarderSharedState, MultiThreadedForwarder};
use lb_forwarder::vip_matcher::VipMatcher;
use lb_forwarder::ForwarderConfig;
use lb_hashing::LookupTable;
use lb_io::mock::{mock_io, mock_io_lockfree};
use lb_io::PacketBuf;
use lb_metrics::ForwarderMetrics;
use lb_types::{Backend, BackendPoolId, ConnTtls, FlowProto, PacketMeta, Protocol, TcpFlowState};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;

fn pin_to_core() {
    if let Some(core_ids) = core_affinity::get_core_ids() {
        let core = if core_ids.len() > 1 {
            core_ids[1]
        } else {
            core_ids[0]
        };
        core_affinity::set_for_current(core);
    }
}

fn build_tcp_packet_to_vip(src_last: u8, src_port: u16) -> PacketBuf {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[10, 0, 0, src_last]);
    pkt[16..20].copy_from_slice(&[188, 184, 100, 10]); // VIP address
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
    PacketBuf::from_slice(&pkt)
}

/// Generate a skewed key distribution: 20% of keys account for 80% of lookups.
fn skewed_keys(capacity: usize, fill_pct: u64) -> (Vec<u64>, Vec<u64>) {
    let fill_count = (capacity as u64 * fill_pct) / 100;

    let insert_keys: Vec<u64> = (0..fill_count)
        .map(|i| {
            let mut buf = [0u8; 16];
            buf[0..8].copy_from_slice(&i.to_le_bytes());
            buf[8..16].copy_from_slice(&(i ^ 0xDEAD_BEEF_CAFE_BABE).to_le_bytes());
            xxhash_rust::xxh3::xxh3_64(&buf)
        })
        .collect();

    let hot_count = (fill_count as usize) / 5;
    let mut lookup_keys = Vec::with_capacity(1000);
    for i in 0..1000 {
        if i % 5 < 4 {
            lookup_keys.push(insert_keys[i % hot_count.max(1)]);
        } else {
            lookup_keys.push(insert_keys[hot_count + (i % (insert_keys.len() - hot_count).max(1))]);
        }
    }

    (insert_keys, lookup_keys)
}

// ---------------------------------------------------------------------------
// GRE encapsulation
// ---------------------------------------------------------------------------

fn bench_gre_encapsulate(c: &mut Criterion) {
    pin_to_core();
    let pkt_template = build_tcp_packet_to_vip(1, 12345);
    c.bench_function("gre_encapsulate_ipv4", |b| {
        b.iter_batched(
            || pkt_template.clone(),
            |mut pkt| {
                gre::encapsulate_ipv4(
                    black_box(&mut pkt),
                    Ipv4Addr::new(172, 16, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 5),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// Connection table at various fill ratios (skewed distribution, Robin Hood)
// ---------------------------------------------------------------------------

fn bench_conn_table_lookup(c: &mut Criterion) {
    pin_to_core();
    let now = Instant::now();
    let mut table = ConnTable::new(65536, ConnTtls::with_established(Duration::from_secs(60)));
    for i in 0..10000u64 {
        table.insert(
            i * 7 + 13,
            IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
            FlowProto::Tcp,
            TcpFlowState::Established,
            now,
        );
    }

    let hashes: Vec<u64> = (0..10000).map(|i| i * 7 + 13).collect();
    c.bench_function("conn_table_lookup_10k", |b| {
        b.iter(|| {
            let now = Instant::now();
            for &h in &hashes {
                black_box(table.get(h, now));
            }
        })
    });
}

fn bench_conn_table_high_fill(c: &mut Criterion) {
    pin_to_core();
    let capacity: usize = 65536;

    let mut group = c.benchmark_group("conn_table_high_fill_skewed");
    for fill_pct in [70u64, 90, 95] {
        let (insert_keys, lookup_keys) = skewed_keys(capacity, fill_pct);

        let now = Instant::now();
        let mut table = ConnTable::new(
            capacity,
            ConnTtls::with_established(Duration::from_secs(60)),
        );
        for (i, &key) in insert_keys.iter().enumerate() {
            table.insert(
                key,
                IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
                FlowProto::Tcp,
                TcpFlowState::Established,
                now,
            );
        }

        group.bench_with_input(
            BenchmarkId::new("lookup_skewed_hit", format!("{fill_pct}%")),
            &fill_pct,
            |b, _| {
                b.iter(|| {
                    let now = Instant::now();
                    for &h in &lookup_keys {
                        black_box(table.get(h, now));
                    }
                })
            },
        );

        let miss_keys: Vec<u64> = (0..1000u64)
            .map(|i| {
                let mut buf = [0u8; 16];
                buf[0..8].copy_from_slice(&(i + 999_999).to_le_bytes());
                buf[8..16].copy_from_slice(&0xBAD_F00D_u64.to_le_bytes());
                xxhash_rust::xxh3::xxh3_64(&buf)
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("lookup_miss", format!("{fill_pct}%")),
            &fill_pct,
            |b, _| {
                b.iter(|| {
                    let now = Instant::now();
                    for &h in &miss_keys {
                        black_box(table.get(h, now));
                    }
                })
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Full pipeline: parse → VIP match → conn_table miss → Maglev → insert → GRE
// ---------------------------------------------------------------------------

fn bench_full_pipeline(c: &mut Criterion) {
    pin_to_core();

    let vip_ip = IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10));
    let pool_id = BackendPoolId("web".into());

    let vip_matcher = VipMatcher::from_entries(vec![(vip_ip, Protocol::Tcp, 443, pool_id.clone())]);

    let backends: Vec<Backend> = (0..10)
        .map(|i| Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)), 443))
        .collect();
    let lookup_table = LookupTable::build(&backends, lb_hashing::DEFAULT_TABLE_SIZE).unwrap();
    let lookup_table = Arc::new(ArcSwap::from_pointee(lookup_table));

    let mut tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>> = HashMap::new();
    tables.insert(pool_id.clone(), lookup_table);

    let src_ip = Ipv4Addr::new(172, 16, 0, 1);

    let packets: Vec<PacketBuf> = (0..1000u16)
        .map(|i| build_tcp_packet_to_vip((i / 256) as u8 + 1, 10000 + i))
        .collect();

    c.bench_function("full_pipeline_per_packet", |b| {
        b.iter(|| {
            let mut conn_table =
                ConnTable::new(65536, ConnTtls::with_established(Duration::from_secs(60)));
            let now = Instant::now();

            for pkt in &packets {
                let meta = PacketMeta::from_ipv4_bytes(pkt.as_slice()).unwrap();
                let matched_pool = vip_matcher
                    .match_packet(meta.dst_ip, meta.protocol, meta.dst_port)
                    .unwrap();
                let flow_hash = meta.flow_hash();
                let proto = FlowProto::from(meta.protocol);
                let backend_ip = if let Some(cached) = conn_table.get(flow_hash, now) {
                    cached
                } else {
                    let lt = tables.get(matched_pool).unwrap().load();
                    let backend = lt.lookup(flow_hash);
                    conn_table.insert(flow_hash, backend.ip, proto, TcpFlowState::Handshake, now);
                    backend.ip
                };

                let dst_ip = match backend_ip {
                    IpAddr::V4(v4) => v4,
                    _ => unreachable!(),
                };

                let mut out = pkt.clone();
                black_box(gre::encapsulate_ipv4(&mut out, src_ip, dst_ip));
            }
        })
    });
}

// ---------------------------------------------------------------------------
// TCP state transitions and mixed-protocol fill (Commit B additions)
// ---------------------------------------------------------------------------

fn bench_conn_table_tcp_transitions(c: &mut Criterion) {
    pin_to_core();
    let now = Instant::now();
    let mut table = ConnTable::new(65536, ConnTtls::with_established(Duration::from_secs(60)));
    // Pre-populate with Established entries so every transition targets a
    // real slot — reflects the steady-state cost in production.
    for i in 0..10_000u64 {
        table.insert(
            i * 7 + 13,
            IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
            FlowProto::Tcp,
            TcpFlowState::Established,
            now,
        );
    }
    let hashes: Vec<u64> = (0..10_000u64).map(|i| i * 7 + 13).collect();

    c.bench_function("conn_table_mark_established_10k", |b| {
        b.iter(|| {
            let now = Instant::now();
            for &h in &hashes {
                table.mark_established(black_box(h), now);
            }
        })
    });

    c.bench_function("conn_table_mark_closing_10k", |b| {
        b.iter(|| {
            let now = Instant::now();
            for &h in &hashes {
                table.mark_closing(black_box(h), now);
            }
        })
    });
}

fn bench_conn_table_mixed_protocol(c: &mut Criterion) {
    pin_to_core();
    let now = Instant::now();
    let capacity: usize = 65536;
    let fill = capacity * 70 / 100;

    let mut table = ConnTable::new(
        capacity,
        ConnTtls::with_established(Duration::from_secs(60)),
    );
    for i in 0..fill as u64 {
        let proto = match i % 3 {
            0 => FlowProto::Tcp,
            1 => FlowProto::Udp,
            _ => FlowProto::Other,
        };
        let state = if proto == FlowProto::Tcp {
            TcpFlowState::Established
        } else {
            TcpFlowState::NotTcp
        };
        table.insert(
            i * 31 + 7,
            IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
            proto,
            state,
            now,
        );
    }
    let hashes: Vec<u64> = (0..10_000u64).map(|i| i * 31 + 7).collect();

    c.bench_function("conn_table_mixed_protocol_70pct_fill", |b| {
        b.iter(|| {
            let now = Instant::now();
            for &h in &hashes {
                black_box(table.get(h, now));
            }
        })
    });
}

// ---------------------------------------------------------------------------
// SPSC queue microbenchmarks: isolate the handoff cost
// ---------------------------------------------------------------------------

/// Raw SPSC with a small descriptor (simulates AF_XDP UMEM frame index).
/// Isolates the queue mechanism cost from the 2KB PacketBuf memcpy.
fn bench_spsc_descriptor(c: &mut Criterion) {
    pin_to_core();

    c.bench_function("spsc_descriptor_handoff", |b| {
        b.iter_custom(|iters| {
            let total_packets = (iters as usize) * 1000;
            let q = Arc::new(ArrayQueue::<u32>::new(4096));
            let done = Arc::new(AtomicBool::new(false));

            let q_c = Arc::clone(&q);
            let done_c = Arc::clone(&done);
            let consumer = std::thread::Builder::new()
                .name("bench-consumer".into())
                .spawn(move || {
                    if let Some(core_ids) = core_affinity::get_core_ids() {
                        if core_ids.len() > 2 {
                            core_affinity::set_for_current(core_ids[2]);
                        }
                    }
                    let mut received = 0usize;
                    while received < total_packets {
                        if let Some(v) = q_c.pop() {
                            black_box(v);
                            received += 1;
                        } else if done_c.load(Ordering::Relaxed) {
                            break;
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                })
                .unwrap();

            let start = Instant::now();
            for i in 0..total_packets {
                while q.push(i as u32).is_err() {
                    std::hint::spin_loop();
                }
            }
            done.store(true, Ordering::Relaxed);
            consumer.join().unwrap();

            start.elapsed()
        })
    });
}

/// Raw SPSC: push/pop a PacketBuf (2048 bytes) between two pinned threads.
/// Measures crossbeam ArrayQueue cost including the 2KB memcpy on clone.
fn bench_spsc_raw(c: &mut Criterion) {
    pin_to_core();

    c.bench_function("spsc_packetbuf_handoff", |b| {
        b.iter_custom(|iters| {
            let total_packets = (iters as usize) * 1000;
            let q = Arc::new(ArrayQueue::<PacketBuf>::new(4096));
            let done = Arc::new(AtomicBool::new(false));

            let q_producer = Arc::clone(&q);
            let done_producer = Arc::clone(&done);
            let pkt = PacketBuf::from_slice(&[0x45; 40]);

            // Consumer thread: pop packets
            let q_consumer = Arc::clone(&q);
            let done_consumer = Arc::clone(&done);
            let consumer = std::thread::Builder::new()
                .name("bench-consumer".into())
                .spawn(move || {
                    // Pin consumer to a different core than producer
                    if let Some(core_ids) = core_affinity::get_core_ids() {
                        let core = if core_ids.len() > 2 {
                            core_ids[2]
                        } else {
                            core_ids[0]
                        };
                        core_affinity::set_for_current(core);
                    }
                    let mut received = 0usize;
                    while received < total_packets {
                        if let Some(p) = q_consumer.pop() {
                            black_box(&p);
                            received += 1;
                        } else if done_consumer.load(Ordering::Relaxed) {
                            break;
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                })
                .unwrap();

            // Producer: push packets, measure time
            let start = Instant::now();
            let mut sent = 0usize;
            while sent < total_packets {
                if q_producer.push(pkt.clone()).is_ok() {
                    sent += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
            done_producer.store(true, Ordering::Relaxed);
            consumer.join().unwrap();

            start.elapsed()
        })
    });
}

/// Steering → rewriter hop: one SPSC crossing with real hash + queue assignment.
fn bench_steering_to_rewriter_hop(c: &mut Criterion) {
    pin_to_core();

    let packets: Vec<PacketBuf> = (0..1000u16)
        .map(|i| build_tcp_packet_to_vip((i / 256) as u8 + 1, 10000 + i))
        .collect();

    c.bench_function("hop_steering_to_rewriter", |b| {
        b.iter_custom(|iters| {
            let total_packets = (iters as usize) * 1000;
            let q = Arc::new(ArrayQueue::<PacketBuf>::new(4096));
            let done = Arc::new(AtomicBool::new(false));

            // Consumer (rewriter side): just drain
            let q_c = Arc::clone(&q);
            let done_c = Arc::clone(&done);
            let consumer = std::thread::Builder::new()
                .name("bench-rewriter".into())
                .spawn(move || {
                    if let Some(core_ids) = core_affinity::get_core_ids() {
                        if core_ids.len() > 2 {
                            core_affinity::set_for_current(core_ids[2]);
                        }
                    }
                    let mut received = 0usize;
                    while received < total_packets {
                        if let Some(p) = q_c.pop() {
                            black_box(&p);
                            received += 1;
                        } else if done_c.load(Ordering::Relaxed) {
                            break;
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                })
                .unwrap();

            // Producer (steering side): parse 5-tuple, assign queue, push
            let start = Instant::now();
            let mut sent = 0usize;
            while sent < total_packets {
                let pkt = &packets[sent % packets.len()];
                // Real steering work: parse + queue assignment
                let _meta = PacketMeta::from_ip_bytes(pkt.as_slice());
                // In real code: steering::assign_queue(&meta, num_queues)
                // Here we have 1 queue, so we skip the modulo

                if q.push(pkt.clone()).is_ok() {
                    sent += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
            done.store(true, Ordering::Relaxed);
            consumer.join().unwrap();

            start.elapsed()
        })
    });
}

/// Rewriter → muxer hop: one SPSC crossing with GRE-encapsulated packets.
fn bench_rewriter_to_muxer_hop(c: &mut Criterion) {
    pin_to_core();

    // Pre-build GRE-encapsulated packets
    let encapped_packets: Vec<PacketBuf> = (0..1000u16)
        .map(|i| {
            let mut pkt = build_tcp_packet_to_vip((i / 256) as u8 + 1, 10000 + i);
            gre::encapsulate_ipv4(
                &mut pkt,
                Ipv4Addr::new(172, 16, 0, 1),
                Ipv4Addr::new(10, 0, 0, 1),
            );
            pkt
        })
        .collect();

    c.bench_function("hop_rewriter_to_muxer", |b| {
        b.iter_custom(|iters| {
            let total_packets = (iters as usize) * 1000;
            let q = Arc::new(ArrayQueue::<PacketBuf>::new(4096));
            let done = Arc::new(AtomicBool::new(false));

            // Consumer (muxer side): drain
            let q_c = Arc::clone(&q);
            let done_c = Arc::clone(&done);
            let consumer = std::thread::Builder::new()
                .name("bench-muxer".into())
                .spawn(move || {
                    if let Some(core_ids) = core_affinity::get_core_ids() {
                        if core_ids.len() > 2 {
                            core_affinity::set_for_current(core_ids[2]);
                        }
                    }
                    let mut received = 0usize;
                    while received < total_packets {
                        if let Some(p) = q_c.pop() {
                            black_box(&p);
                            received += 1;
                        } else if done_c.load(Ordering::Relaxed) {
                            break;
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                })
                .unwrap();

            // Producer (rewriter side): push GRE-encapsulated packets
            let start = Instant::now();
            let mut sent = 0usize;
            while sent < total_packets {
                let pkt = &encapped_packets[sent % encapped_packets.len()];
                if q.push(pkt.clone()).is_ok() {
                    sent += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
            done.store(true, Ordering::Relaxed);
            consumer.join().unwrap();

            start.elapsed()
        })
    });
}

// ---------------------------------------------------------------------------
// Thread-to-thread: full pipeline with MockIo (Mutex) and MockIoLockFree
// ---------------------------------------------------------------------------

fn make_shared_state() -> (
    HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
    VipMatcher,
) {
    let vip_ip = IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10));
    let pool_id = BackendPoolId("web".into());

    let backends: Vec<Backend> = (0..10)
        .map(|i| Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)), 443))
        .collect();
    let lookup_table = LookupTable::build(&backends, lb_hashing::DEFAULT_TABLE_SIZE).unwrap();

    let mut tables = HashMap::new();
    tables.insert(
        pool_id.clone(),
        Arc::new(ArcSwap::from_pointee(lookup_table)),
    );

    let vip_matcher = VipMatcher::from_entries(vec![(vip_ip, Protocol::Tcp, 443, pool_id)]);

    (tables, vip_matcher)
}

fn inject_packets(count: u16, injector: impl Fn(&[u8])) {
    for i in 0..count {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, (i >> 8) as u8, i as u8]);
        pkt[16..20].copy_from_slice(&[188, 184, 100, 10]);
        pkt[20..22].copy_from_slice(&(10000 + i).to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        injector(&pkt);
    }
}

/// Thread-to-thread with Mutex-based MockIo (baseline for comparison).
///
/// Measures only packet processing time — forwarder construction (pool allocation)
/// is excluded from the timed region since it's a one-time startup cost.
fn bench_thread_to_thread_mutex(c: &mut Criterion) {
    pin_to_core();
    let (tables, vip_matcher) = make_shared_state();

    c.bench_function("thread_to_thread_mutex_1000pkt", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;

            for _ in 0..iters {
                let (rx_io, rx_handle) = mock_io();
                let (tx_io, tx_handle) = mock_io();

                let mut registry = prometheus_client::registry::Registry::default();
                let metrics = ForwarderMetrics::register(&mut registry);

                let config = ForwarderConfig {
                    src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
                    connection_table_size: 65536,
                    conn_ttls: ConnTtls::with_established(Duration::from_secs(60)),
                    batch_size: 64,
                    mtu_config: lb_types::MtuConfig::new(1500).unwrap(),
                    icmp_rate_limit: 100,
                };

                // Start forwarder (includes pool allocation) BEFORE timing
                let forwarder = MultiThreadedForwarder::start(
                    rx_io,
                    tx_io,
                    config,
                    2,
                    ForwarderSharedState {
                        lookup_tables: tables.clone(),
                        vip_matcher: Arc::new(ArcSwap::from_pointee(vip_matcher.clone())),
                        health_status: Arc::new(DashMap::new()),
                        metrics,
                    },
                );

                // Inject packets and measure processing time
                inject_packets(1000, |pkt| rx_handle.inject_packet(pkt));
                let start = Instant::now();

                let deadline = Instant::now() + Duration::from_secs(5);
                while tx_handle.tx_count() < 1000 && Instant::now() < deadline {
                    std::hint::spin_loop();
                }

                total += start.elapsed();
                forwarder.shutdown();
            }

            total
        })
    });
}

/// Thread-to-thread with lock-free MockIo (reflects production AF_XDP topology).
///
/// Measures only packet processing time — forwarder construction (pool allocation)
/// is excluded from the timed region since it's a one-time startup cost.
fn bench_thread_to_thread_lockfree(c: &mut Criterion) {
    pin_to_core();
    let (tables, vip_matcher) = make_shared_state();

    c.bench_function("thread_to_thread_lockfree_1000pkt", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;

            for _ in 0..iters {
                let (rx_io, rx_handle) = mock_io_lockfree();
                let (tx_io, tx_handle) = mock_io_lockfree();

                let mut registry = prometheus_client::registry::Registry::default();
                let metrics = ForwarderMetrics::register(&mut registry);

                let config = ForwarderConfig {
                    src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
                    connection_table_size: 65536,
                    conn_ttls: ConnTtls::with_established(Duration::from_secs(60)),
                    batch_size: 64,
                    mtu_config: lb_types::MtuConfig::new(1500).unwrap(),
                    icmp_rate_limit: 100,
                };

                // Start forwarder (includes pool allocation) BEFORE timing
                let forwarder = MultiThreadedForwarder::start(
                    rx_io,
                    tx_io,
                    config,
                    2,
                    ForwarderSharedState {
                        lookup_tables: tables.clone(),
                        vip_matcher: Arc::new(ArcSwap::from_pointee(vip_matcher.clone())),
                        health_status: Arc::new(DashMap::new()),
                        metrics,
                    },
                );

                // Inject packets and measure processing time
                inject_packets(1000, |pkt| rx_handle.inject_packet(pkt));
                let start = Instant::now();

                let deadline = Instant::now() + Duration::from_secs(5);
                while tx_handle.tx_count() < 1000 && Instant::now() < deadline {
                    std::hint::spin_loop();
                }

                total += start.elapsed();
                forwarder.shutdown();
            }

            total
        })
    });
}

// ---------------------------------------------------------------------------
// MTU handling benchmarks
// ---------------------------------------------------------------------------

fn bench_mss_clamp_syn(c: &mut Criterion) {
    pin_to_core();

    // Build a TCP SYN with MSS=1460 (will be clamped to 1436)
    let mut syn_template = vec![0u8; 44]; // 20 IP + 24 TCP (base 20 + MSS option 4)
    syn_template[0] = 0x45;
    syn_template[2..4].copy_from_slice(&44u16.to_be_bytes());
    syn_template[8] = 64;
    syn_template[9] = 6; // TCP
    syn_template[12..16].copy_from_slice(&[10, 0, 0, 1]);
    syn_template[16..20].copy_from_slice(&[188, 184, 100, 10]);
    syn_template[20..22].copy_from_slice(&12345u16.to_be_bytes());
    syn_template[22..24].copy_from_slice(&443u16.to_be_bytes());
    syn_template[32] = (24 / 4) << 4; // data offset = 6 words
    syn_template[33] = 0x02; // SYN
    syn_template[40] = 2; // MSS kind
    syn_template[41] = 4; // MSS len
    syn_template[42..44].copy_from_slice(&1460u16.to_be_bytes());

    c.bench_function("mss_clamp_syn_packet", |b| {
        b.iter_batched(
            || syn_template.clone(),
            |mut pkt| {
                black_box(lb_forwarder::mss_clamp::clamp_mss(&mut pkt, 1436));
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_mss_clamp_noop(c: &mut Criterion) {
    pin_to_core();

    // Non-SYN TCP packet — clamp_mss returns NotSyn quickly
    let mut pkt_template = vec![0u8; 40];
    pkt_template[0] = 0x45;
    pkt_template[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt_template[9] = 6; // TCP
    pkt_template[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt_template[16..20].copy_from_slice(&[188, 184, 100, 10]);
    pkt_template[32] = (20 / 4) << 4; // data offset = 5 words
    pkt_template[33] = 0x10; // ACK (not SYN)

    c.bench_function("mss_clamp_noop_not_syn", |b| {
        b.iter_batched(
            || pkt_template.clone(),
            |mut pkt| {
                black_box(lb_forwarder::mss_clamp::clamp_mss(&mut pkt, 1436));
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_icmp_generation(c: &mut Criterion) {
    pin_to_core();

    // Build an oversized UDP packet with DF set
    let mut oversized = vec![0u8; 1500];
    oversized[0] = 0x45;
    oversized[2..4].copy_from_slice(&1500u16.to_be_bytes());
    oversized[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    oversized[8] = 64;
    oversized[9] = 17; // UDP
    oversized[12..16].copy_from_slice(&[10, 0, 0, 1]);
    oversized[16..20].copy_from_slice(&[188, 184, 100, 10]);

    let vip = Ipv4Addr::new(188, 184, 100, 10);

    // Packet generation only (no rate limiter)
    c.bench_function("icmp_frag_needed_generation", |b| {
        b.iter(|| {
            black_box(lb_forwarder::icmp::generate_icmp_frag_needed(
                &oversized, vip, 1476,
            ));
        })
    });

    // Full ICMP path: oversized check + rate limiter + packet generation
    c.bench_function("icmp_full_path_allowed", |b| {
        b.iter_batched(
            || lb_forwarder::icmp::IcmpRateLimiter::new(u32::MAX),
            |mut limiter| {
                let now = Instant::now();
                if lb_forwarder::icmp::should_generate_icmp(&oversized, 1500) && limiter.allow(now)
                {
                    black_box(lb_forwarder::icmp::generate_icmp_frag_needed(
                        &oversized, vip, 1476,
                    ));
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Rate limiter: allow path (within budget)
    c.bench_function("icmp_rate_limiter_allow", |b| {
        let mut limiter = lb_forwarder::icmp::IcmpRateLimiter::new(u32::MAX);
        b.iter(|| {
            let now = Instant::now();
            black_box(limiter.allow(now));
        })
    });

    // Rate limiter: deny path (budget exhausted)
    c.bench_function("icmp_rate_limiter_deny", |b| {
        let mut limiter = lb_forwarder::icmp::IcmpRateLimiter::new(100);
        let now = Instant::now();
        for _ in 0..100 {
            limiter.allow(now);
        }
        // Now exhausted — every call returns false
        b.iter(|| {
            black_box(limiter.allow(now));
        })
    });
}

/// Sweep MSS clamping and ICMP generation across different MTU sizes.
fn bench_mtu_sweep(c: &mut Criterion) {
    pin_to_core();

    let vip = Ipv4Addr::new(188, 184, 100, 10);

    // MSS clamp sweep: SYN packet with MSS=8960 (jumbo) clamped to each MTU's max
    let mut group = c.benchmark_group("mtu_sweep_mss_clamp");
    for mtu in [1280u16, 1500, 4000, 9000] {
        let mtu_config = lb_types::MtuConfig::new(mtu).unwrap();

        let mut syn = vec![0u8; 44];
        syn[0] = 0x45;
        syn[2..4].copy_from_slice(&44u16.to_be_bytes());
        syn[8] = 64;
        syn[9] = 6;
        syn[12..16].copy_from_slice(&[10, 0, 0, 1]);
        syn[16..20].copy_from_slice(&[188, 184, 100, 10]);
        syn[20..22].copy_from_slice(&12345u16.to_be_bytes());
        syn[22..24].copy_from_slice(&443u16.to_be_bytes());
        syn[32] = (24 / 4) << 4;
        syn[33] = 0x02;
        syn[40] = 2;
        syn[41] = 4;
        syn[42..44].copy_from_slice(&8960u16.to_be_bytes());

        group.bench_with_input(
            BenchmarkId::new("clamp", format!("mtu_{mtu}")),
            &mtu,
            |b, _| {
                b.iter_batched(
                    || syn.clone(),
                    |mut pkt| {
                        black_box(lb_forwarder::mss_clamp::clamp_mss(
                            &mut pkt,
                            mtu_config.tcp_mss_clamp,
                        ));
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();

    // ICMP generation sweep: oversized packet at each MTU
    let mut group = c.benchmark_group("mtu_sweep_icmp");
    for mtu in [1280u16, 1500, 4000, 9000] {
        let mtu_config = lb_types::MtuConfig::new(mtu).unwrap();
        // Packet that is exactly 1 byte over the effective inner MTU
        let pkt_len = (mtu_config.effective_inner_mtu + 1) as usize;
        let mut oversized = vec![0u8; pkt_len];
        oversized[0] = 0x45;
        oversized[2..4].copy_from_slice(&(pkt_len as u16).to_be_bytes());
        oversized[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        oversized[8] = 64;
        oversized[9] = 17;
        oversized[12..16].copy_from_slice(&[10, 0, 0, 1]);
        oversized[16..20].copy_from_slice(&[188, 184, 100, 10]);

        group.bench_with_input(
            BenchmarkId::new("icmp_gen", format!("mtu_{mtu}")),
            &mtu,
            |b, _| {
                b.iter(|| {
                    black_box(lb_forwarder::icmp::generate_icmp_frag_needed(
                        &oversized,
                        vip,
                        mtu_config.effective_inner_mtu,
                    ));
                })
            },
        );
    }
    group.finish();

    // should_generate_icmp check sweep
    let mut group = c.benchmark_group("mtu_sweep_oversized_check");
    for mtu in [1280u16, 1500, 4000, 9000] {
        let mtu_config = lb_types::MtuConfig::new(mtu).unwrap();
        let pkt_len = (mtu_config.effective_inner_mtu + 1) as usize;
        let mut oversized = vec![0u8; pkt_len];
        oversized[0] = 0x45;
        oversized[2..4].copy_from_slice(&(pkt_len as u16).to_be_bytes());
        oversized[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        oversized[8] = 64;
        oversized[9] = 17;

        group.bench_with_input(
            BenchmarkId::new("check", format!("mtu_{mtu}")),
            &mtu,
            |b, _| {
                b.iter(|| {
                    black_box(lb_forwarder::icmp::should_generate_icmp(&oversized, mtu));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_gre_encapsulate,
    bench_conn_table_lookup,
    bench_conn_table_high_fill,
    bench_conn_table_tcp_transitions,
    bench_conn_table_mixed_protocol,
    bench_full_pipeline,
    bench_spsc_descriptor,
    bench_spsc_raw,
    bench_steering_to_rewriter_hop,
    bench_rewriter_to_muxer_hop,
    bench_thread_to_thread_mutex,
    bench_thread_to_thread_lockfree,
    bench_mss_clamp_syn,
    bench_mss_clamp_noop,
    bench_icmp_generation,
    bench_mtu_sweep,
);
criterion_main!(benches);
