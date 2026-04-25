//! Multi-threaded forwarder with steering + rewriter + muxer architecture.
//!
//! Architecture (Maglev-style, zero-copy):
//! ```text
//!   NIC RX → [Steering] → SPSC queues (u32 index) → [Rewriter 0..N] → SPSC queues → [Muxer] → NIC TX
//!                ↑                                                                       |
//!                └──────────── completion queue (u32 index) ─────────────────────────────┘
//! ```
//!
//! Packets live in a shared `PacketPool` (pre-allocated frame arena). Only frame
//! indices (u32) flow through the SPSC queues — no 2KB copies between threads.
//! After the muxer sends a frame, it returns the index to the completion queue
//! so steering can reuse it. This mirrors AF_XDP's UMEM model.

use crate::conn_table::{ConnTable, InsertResult};
use crate::fragment_table::FragmentTable;
use crate::gre;
use crate::packet_pool::{FrameIndex, PacketPool};
use crate::steering;
use crate::vip_matcher::VipMatcher;
use crate::ForwarderConfig;
use crossbeam::queue::ArrayQueue;
use lb_config_manager::applier::LookupTables;
use lb_io::{PacketBuf, PacketIo};
use lb_metrics::ForwarderMetrics;
use lb_types::packet;
use lb_types::{ConnTtls, FlowProto, FragmentId, HealthStatus, PacketMeta, TcpFlags, TcpFlowState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;

/// Capacity of each SPSC queue between steering→rewriter and rewriter→muxer.
const QUEUE_CAPACITY: usize = 4096;

/// Maximum packets to drain from a queue per iteration.
const BATCH_DRAIN_SIZE: usize = 64;

/// Spin iterations before parking. One batch-worth (64) keeps the thread hot
/// for approximately 1µs on modern hardware, avoiding the ~1-2µs kernel
/// round-trip of thread::park/unpark during bursty traffic.
const SPIN_BEFORE_PARK: u32 = 64;

/// Park timeout for idle threads.
const PARK_TIMEOUT: std::time::Duration = std::time::Duration::from_micros(100);

/// Shared state passed to the multi-threaded forwarder.
pub struct ForwarderSharedState {
    pub lookup_tables: LookupTables,
    pub vip_matcher: Arc<ArcSwap<VipMatcher>>,
    pub health_status: Arc<DashMap<IpAddr, HealthStatus>>,
    pub metrics: ForwarderMetrics,
}

/// Multi-threaded forwarder engine.
pub struct MultiThreadedForwarder {
    /// Thread handles wrapped in a Mutex so `shutdown` can `join` them from
    /// `&self`, letting the forwarder live behind `Arc` (e.g. when a signal
    /// handler needs to drive shutdown alongside other owners like the ops
    /// HTTP server's liveness check).
    handles: parking_lot::Mutex<Vec<JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
}

impl MultiThreadedForwarder {
    /// Build and start the multi-threaded forwarder.
    ///
    /// `num_rewriters` controls how many rewriter threads are spawned.
    /// The steering and muxer threads are always 1 each.
    pub fn start<T: PacketIo>(
        mut rx_io: T,
        mut tx_io: T,
        config: ForwarderConfig,
        num_rewriters: usize,
        shared: ForwarderSharedState,
    ) -> Self {
        let ForwarderSharedState {
            lookup_tables,
            vip_matcher,
            health_status,
            metrics,
        } = shared;
        let shutdown = Arc::new(AtomicBool::new(false));
        let num_rewriters = num_rewriters.max(1);

        // Shared packet pool — sized to cover all in-flight frames:
        // queue capacity × (rx + tx per rewriter) + batch headroom
        let pool_size = QUEUE_CAPACITY * num_rewriters * 2 + config.batch_size * 2;
        let pool = Arc::new(PacketPool::new(pool_size));

        // Per-rewriter queues carry FrameIndex (u32), not PacketBuf
        let mut rx_queues = Vec::with_capacity(num_rewriters);
        let mut tx_queues = Vec::with_capacity(num_rewriters);
        for _ in 0..num_rewriters {
            rx_queues.push(Arc::new(ArrayQueue::<FrameIndex>::new(QUEUE_CAPACITY)));
            tx_queues.push(Arc::new(ArrayQueue::<FrameIndex>::new(QUEUE_CAPACITY)));
        }

        let mut handles = Vec::with_capacity(num_rewriters + 2);
        let batch_size = config.batch_size;

        // --- Steering thread ---
        {
            let rx_queues = rx_queues.clone();
            let shutdown = Arc::clone(&shutdown);
            let vip_matcher = Arc::clone(&vip_matcher);
            let pool = Arc::clone(&pool);

            handles.push(
                thread::Builder::new()
                    .name("lb-steering".into())
                    .spawn(move || {
                        run_steering(
                            &mut rx_io,
                            &rx_queues,
                            &vip_matcher,
                            &pool,
                            batch_size,
                            &shutdown,
                        );
                    })
                    .expect("failed to spawn steering thread"),
            );
        }

        // --- Rewriter threads ---
        for i in 0..num_rewriters {
            let shutdown = Arc::clone(&shutdown);
            let ctx = RewriterContext {
                rx_q: Arc::clone(&rx_queues[i]),
                tx_q: Arc::clone(&tx_queues[i]),
                pool: Arc::clone(&pool),
                src_ip: config.src_ip,
                conn_table_size: config.connection_table_size,
                conn_ttls: config.conn_ttls,
                fragment_table_size: config.fragment_table_size,
                fragment_ttl: config.fragment_ttl,
                lookup_tables: lookup_tables.clone(),
                vip_matcher: Arc::clone(&vip_matcher),
                health_status: Arc::clone(&health_status),
                metrics: metrics.clone(),
            };

            handles.push(
                thread::Builder::new()
                    .name(format!("lb-rewriter-{i}"))
                    .spawn(move || {
                        run_rewriter(ctx, &shutdown);
                    })
                    .expect("failed to spawn rewriter thread"),
            );
        }

        // --- Muxer thread ---
        {
            let tx_queues = tx_queues.clone();
            let shutdown = Arc::clone(&shutdown);
            let pool = Arc::clone(&pool);

            handles.push(
                thread::Builder::new()
                    .name("lb-muxer".into())
                    .spawn(move || {
                        run_muxer(&mut tx_io, &tx_queues, &pool, batch_size, &shutdown);
                    })
                    .expect("failed to spawn muxer thread"),
            );
        }

        Self {
            handles: parking_lot::Mutex::new(handles),
            shutdown,
        }
    }

    /// Signal all threads to shut down and wait for them to finish.
    ///
    /// Idempotent: calling twice is a no-op (the second call finds an empty
    /// handles vec). Blocks until every worker thread has joined.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let handles = std::mem::take(&mut *self.handles.lock());
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// Check if the forwarder is still running (no thread has panicked).
    pub fn is_running(&self) -> bool {
        let handles = self.handles.lock();
        !handles.is_empty() && handles.iter().all(|h| !h.is_finished())
    }
}

/// Steering loop: receive packets into pool frames, distribute indices to rewriter queues.
fn run_steering<T: PacketIo>(
    io: &mut T,
    rx_queues: &[Arc<ArrayQueue<FrameIndex>>],
    _vip_matcher: &Arc<ArcSwap<VipMatcher>>,
    pool: &PacketPool,
    batch_size: usize,
    shutdown: &AtomicBool,
) {
    let num_queues = rx_queues.len();
    let mut rx_buf = vec![PacketBuf::new(); batch_size];

    while !shutdown.load(Ordering::Relaxed) {
        let received = match io.recv_batch(&mut rx_buf) {
            Ok(n) => n,
            Err(_) => continue,
        };

        for pkt in &rx_buf[..received] {
            // Allocate a frame from the pool
            let idx = match pool.alloc() {
                Some(idx) => idx,
                None => continue, // pool exhausted, drop packet (back-pressure)
            };

            // Copy packet data into the pool frame (one copy: NIC → pool)
            let frame = pool.get_mut(idx);
            frame.write_from(pkt.as_slice());

            // Parse 5-tuple from the pool frame for queue assignment
            let queue_idx = match PacketMeta::from_ip_bytes(frame.as_slice()) {
                Some(meta) => steering::assign_queue(&meta, num_queues),
                None => 0,
            };

            // Push frame index; free the frame if queue is full
            if rx_queues[queue_idx].push(idx).is_err() {
                pool.free(idx);
            }
        }
    }
}

/// All shared state a rewriter thread needs.
struct RewriterContext {
    rx_q: Arc<ArrayQueue<FrameIndex>>,
    tx_q: Arc<ArrayQueue<FrameIndex>>,
    pool: Arc<PacketPool>,
    src_ip: IpAddr,
    conn_table_size: usize,
    conn_ttls: ConnTtls,
    fragment_table_size: usize,
    fragment_ttl: Duration,
    lookup_tables: LookupTables,
    vip_matcher: Arc<ArcSwap<VipMatcher>>,
    health_status: Arc<DashMap<IpAddr, HealthStatus>>,
    metrics: ForwarderMetrics,
}

/// Rewriter loop: drain frame indices from RX queue, process in-place, push to TX queue.
fn run_rewriter(ctx: RewriterContext, shutdown: &AtomicBool) {
    let mut conn_table = ConnTable::new(ctx.conn_table_size, ctx.conn_ttls);
    let mut fragment_table = FragmentTable::new(ctx.fragment_table_size, ctx.fragment_ttl);
    let mut indices = Vec::with_capacity(BATCH_DRAIN_SIZE);
    let mut spin_count = 0u32;

    let src_ipv4 = match ctx.src_ip {
        IpAddr::V4(v4) => v4,
        _ => return, // IPv6 source not supported yet
    };

    while !shutdown.load(Ordering::Relaxed) {
        indices.clear();
        for _ in 0..BATCH_DRAIN_SIZE {
            match ctx.rx_q.pop() {
                Some(idx) => indices.push(idx),
                None => break,
            }
        }

        if indices.is_empty() {
            spin_count += 1;
            if spin_count < SPIN_BEFORE_PARK {
                std::hint::spin_loop();
            } else {
                std::thread::park_timeout(PARK_TIMEOUT);
                spin_count = 0;
            }
            continue;
        }
        spin_count = 0;

        let vip_matcher = ctx.vip_matcher.load();
        // Snapshot the pool→table map once per batch. Cheap inner-`Arc`
        // clones at the lookup site keep references valid even if the
        // controller swaps the map mid-batch.
        let lookup_tables = ctx.lookup_tables.load();
        let now = std::time::Instant::now();

        for &idx in &indices {
            ctx.metrics.packets_received.inc();

            let frame = ctx.pool.get_mut(idx);

            // Non-first fragment fast path: no L4 header present, so pin the
            // backend by looking up the 3-tuple in the fragment table. If the
            // first fragment's entry has expired or was dropped, we have no
            // way to reassemble — drop.
            if packet::is_non_first_fragment(frame.as_slice()) {
                let backend_ip = match FragmentId::from_ipv4_bytes(frame.as_slice())
                    .and_then(|fid| fragment_table.get(fid.fragment_hash(), now))
                {
                    Some(ip) => ip,
                    None => {
                        ctx.metrics.fragment_drop_no_mapping_total.inc();
                        ctx.metrics.packets_dropped.inc();
                        ctx.pool.free(idx);
                        continue;
                    }
                };
                let dst_ipv4 = match backend_ip {
                    IpAddr::V4(v4) => v4,
                    _ => {
                        ctx.metrics.packets_dropped.inc();
                        ctx.pool.free(idx);
                        continue;
                    }
                };
                if let Some(new_len) =
                    gre::encapsulate_ipv4_buf(&mut frame.data, frame.len, src_ipv4, dst_ipv4)
                {
                    frame.len = new_len;
                    ctx.metrics.fragment_subsequent_forwarded_total.inc();
                    ctx.metrics.packets_forwarded.inc();
                    if ctx.tx_q.push(idx).is_err() {
                        ctx.pool.free(idx);
                    }
                } else {
                    ctx.metrics.packets_dropped.inc();
                    ctx.pool.free(idx);
                }
                continue;
            }

            // Parse 5-tuple
            let meta = match PacketMeta::from_ipv4_bytes(frame.as_slice()) {
                Some(m) => m,
                None => {
                    ctx.metrics.packets_dropped.inc();
                    ctx.pool.free(idx);
                    continue;
                }
            };

            // VIP match
            let pool_id = match vip_matcher.match_packet(meta.dst_ip, meta.protocol, meta.dst_port)
            {
                Some(id) => id,
                None => {
                    ctx.metrics.packets_dropped.inc();
                    ctx.pool.free(idx);
                    continue;
                }
            };

            // Get lookup table
            let lookup_table = match lookup_tables.get(pool_id) {
                Some(lt) => lt.clone(),
                None => {
                    ctx.metrics.packets_dropped.inc();
                    ctx.pool.free(idx);
                    continue;
                }
            };

            let flow_hash = meta.flow_hash();
            let proto = FlowProto::from(meta.protocol);
            let initial_state = initial_tcp_state(meta.tcp_flags);

            // Connection table lookup
            let backend_ip = if let Some(cached_ip) = conn_table.get(flow_hash, now) {
                let healthy = ctx
                    .health_status
                    .get(&cached_ip)
                    .map(|s| *s != HealthStatus::Unhealthy)
                    .unwrap_or(true);

                if healthy {
                    ctx.metrics.conn_table_hits.inc();
                    conn_table.touch(flow_hash, now);
                    cached_ip
                } else {
                    ctx.metrics.conn_table_fallback_to_maglev_total.inc();
                    let backend = lookup_table.lookup(flow_hash);
                    insert_tracked(
                        &mut conn_table,
                        &ctx.metrics,
                        flow_hash,
                        backend.ip,
                        proto,
                        initial_state,
                        now,
                    );
                    backend.ip
                }
            } else {
                ctx.metrics.conn_table_misses.inc();
                let backend = lookup_table.lookup(flow_hash);
                insert_tracked(
                    &mut conn_table,
                    &ctx.metrics,
                    flow_hash,
                    backend.ip,
                    proto,
                    initial_state,
                    now,
                );
                backend.ip
            };

            if let Some(flags) = meta.tcp_flags {
                apply_tcp_transitions(&mut conn_table, &ctx.metrics, flow_hash, flags, now);
            }

            // First fragment (MF=1, offset=0): record the 3-tuple → backend
            // mapping so subsequent fragments reach the same pool member.
            // `is_fragment` would also match non-first fragments, but those
            // took the short-circuit branch above.
            if packet::is_fragment(frame.as_slice()) {
                if let Some(fid) = FragmentId::from_ipv4_bytes(frame.as_slice()) {
                    fragment_table.insert(fid.fragment_hash(), backend_ip, now);
                    ctx.metrics.fragment_first_total.inc();
                }
            }

            let dst_ipv4 = match backend_ip {
                IpAddr::V4(v4) => v4,
                _ => {
                    ctx.metrics.packets_dropped.inc();
                    ctx.pool.free(idx);
                    continue;
                }
            };

            // GRE encapsulation in-place on the pool frame (zero-copy)
            if let Some(new_len) =
                gre::encapsulate_ipv4_buf(&mut frame.data, frame.len, src_ipv4, dst_ipv4)
            {
                frame.len = new_len;
                ctx.metrics.packets_forwarded.inc();
                // Push index to TX queue; free if full
                if ctx.tx_q.push(idx).is_err() {
                    ctx.pool.free(idx);
                }
            } else {
                ctx.metrics.packets_dropped.inc();
                ctx.pool.free(idx);
            }
        }

        ctx.metrics.conn_table_size.set(conn_table.len() as i64);
        ctx.metrics.conn_table_fill_bp.set(conn_table.fill_bp());
    }
}

#[inline(always)]
fn initial_tcp_state(flags: Option<TcpFlags>) -> TcpFlowState {
    match flags {
        None => TcpFlowState::NotTcp,
        Some(f) if f.rst() || f.fin() => TcpFlowState::Closing,
        Some(f) if f.syn() && !f.ack() => TcpFlowState::Handshake,
        Some(f) if f.ack() => TcpFlowState::Established,
        Some(_) => TcpFlowState::Handshake,
    }
}

#[inline(always)]
fn insert_tracked(
    conn_table: &mut ConnTable,
    metrics: &ForwarderMetrics,
    hash: u64,
    backend_ip: IpAddr,
    proto: FlowProto,
    tcp_state: TcpFlowState,
    now: std::time::Instant,
) {
    match conn_table.insert(hash, backend_ip, proto, tcp_state, now) {
        InsertResult::Inserted | InsertResult::Updated => {
            metrics.conn_table_inserts_total.inc();
        }
        InsertResult::EvictedExpired => {
            metrics.conn_table_inserts_total.inc();
            metrics.eviction_expired_on_insert.inc();
        }
        InsertResult::DroppedFull => {
            metrics.eviction_dropped_full.inc();
        }
    }
}

#[inline(always)]
fn apply_tcp_transitions(
    conn_table: &mut ConnTable,
    metrics: &ForwarderMetrics,
    hash: u64,
    flags: TcpFlags,
    now: std::time::Instant,
) {
    if flags.rst() {
        conn_table.mark_closing(hash, now);
        metrics.tcp_transition_closing_rst.inc();
        return;
    }
    if flags.fin() {
        conn_table.mark_closing(hash, now);
        metrics.tcp_transition_closing_fin.inc();
        return;
    }
    if flags.ack() && !flags.syn() {
        conn_table.mark_established(hash, now);
        metrics.tcp_transition_established.inc();
    }
}

/// Muxer loop: drain frame indices from TX queues, send via PacketIo, return frames to pool.
fn run_muxer<T: PacketIo>(
    io: &mut T,
    tx_queues: &[Arc<ArrayQueue<FrameIndex>>],
    pool: &PacketPool,
    batch_size: usize,
    shutdown: &AtomicBool,
) {
    let mut send_buf = vec![PacketBuf::new(); batch_size];
    let mut send_indices = Vec::with_capacity(batch_size);
    let mut spin_count = 0u32;

    while !shutdown.load(Ordering::Relaxed) {
        send_indices.clear();

        // Round-robin drain from all TX queues
        for q in tx_queues {
            while send_indices.len() < batch_size {
                match q.pop() {
                    Some(idx) => send_indices.push(idx),
                    None => break,
                }
            }
            if send_indices.len() >= batch_size {
                break;
            }
        }

        if send_indices.is_empty() {
            spin_count += 1;
            if spin_count < SPIN_BEFORE_PARK {
                std::hint::spin_loop();
            } else {
                std::thread::park_timeout(PARK_TIMEOUT);
                spin_count = 0;
            }
            continue;
        }
        spin_count = 0;

        // Copy frames into send buffer for PacketIo (the last copy: pool → NIC).
        // With AF_XDP zero-copy, this would be a descriptor submission instead.
        for (i, &idx) in send_indices.iter().enumerate() {
            let frame = pool.get(idx);
            send_buf[i].data[..frame.len].copy_from_slice(&frame.data[..frame.len]);
            send_buf[i].len = frame.len;
        }

        let _ = io.send_batch(&send_buf[..send_indices.len()]);

        // Return frames to the pool (completion queue)
        for &idx in &send_indices {
            pool.free(idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_hashing::LookupTable;
    use lb_io::mock::mock_io;
    use lb_types::{Backend, BackendPoolId, Protocol};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn build_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn multi_threaded_end_to_end() {
        let (rx_io, rx_handle) = mock_io();
        let (tx_io, tx_handle) = mock_io();

        let backends = vec![
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        ];

        let lookup_table = LookupTable::build(&backends, 17).unwrap();
        let pool_id = BackendPoolId("web".into());

        let mut tables_map: HashMap<BackendPoolId, Arc<LookupTable>> = HashMap::new();
        tables_map.insert(pool_id.clone(), Arc::new(lookup_table));
        let tables: LookupTables = Arc::new(ArcSwap::from_pointee(tables_map));

        let vip_matcher = crate::vip_matcher::VipMatcher::from_entries(vec![(
            IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            Protocol::Tcp,
            443,
            pool_id,
        )]);

        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);

        let config = ForwarderConfig {
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            connection_table_size: 64,
            conn_ttls: ConnTtls::with_established(Duration::from_secs(60)),
            fragment_table_size: 64,
            fragment_ttl: Duration::from_secs(10),
            batch_size: 64,
            mtu_config: lb_types::MtuConfig::new(1500).unwrap(),
            icmp_rate_limit: 100,
        };

        // Inject packets before starting
        for i in 0..100u16 {
            let pkt = build_tcp_packet(
                [10, 0, (i >> 8) as u8, i as u8],
                [188, 184, 100, 10],
                12345 + i,
                443,
            );
            rx_handle.inject_packet(&pkt);
        }

        let forwarder = MultiThreadedForwarder::start(
            rx_io,
            tx_io,
            config,
            2, // 2 rewriter threads
            ForwarderSharedState {
                lookup_tables: tables,
                vip_matcher: Arc::new(ArcSwap::from_pointee(vip_matcher)),
                health_status: Arc::new(DashMap::new()),
                metrics,
            },
        );

        // Wait for packets to be processed
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while tx_handle.tx_count() < 100 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(forwarder.is_running());

        let count = tx_handle.tx_count();
        assert_eq!(count, 100, "expected 100 forwarded packets, got {count}");

        // Verify GRE encapsulation
        let pkt = tx_handle.read_transmitted().unwrap();
        assert_eq!(pkt.len(), 40 + crate::gre::ENCAP_OVERHEAD);
        assert_eq!(pkt[0], 0x45); // outer IPv4
        assert_eq!(pkt[9], 47); // GRE protocol

        forwarder.shutdown();
    }

    #[test]
    fn same_flow_same_rewriter() {
        let (rx_io, rx_handle) = mock_io();
        let (tx_io, tx_handle) = mock_io();

        let backends = vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)];

        let lookup_table = LookupTable::build(&backends, 17).unwrap();
        let pool_id = BackendPoolId("web".into());

        let mut tables_map: HashMap<BackendPoolId, Arc<LookupTable>> = HashMap::new();
        tables_map.insert(pool_id.clone(), Arc::new(lookup_table));
        let tables: LookupTables = Arc::new(ArcSwap::from_pointee(tables_map));

        let vip_matcher = crate::vip_matcher::VipMatcher::from_entries(vec![(
            IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
            Protocol::Tcp,
            443,
            pool_id,
        )]);

        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = ForwarderMetrics::register(&mut registry);

        let config = ForwarderConfig {
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            connection_table_size: 64,
            conn_ttls: ConnTtls::with_established(Duration::from_secs(60)),
            fragment_table_size: 64,
            fragment_ttl: Duration::from_secs(10),
            batch_size: 64,
            mtu_config: lb_types::MtuConfig::new(1500).unwrap(),
            icmp_rate_limit: 100,
        };

        // Inject 50 packets from the SAME flow
        for _ in 0..50 {
            let pkt = build_tcp_packet([10, 0, 0, 1], [188, 184, 100, 10], 12345, 443);
            rx_handle.inject_packet(&pkt);
        }

        let forwarder = MultiThreadedForwarder::start(
            rx_io,
            tx_io,
            config,
            4, // 4 rewriter threads
            ForwarderSharedState {
                lookup_tables: tables,
                vip_matcher: Arc::new(ArcSwap::from_pointee(vip_matcher)),
                health_status: Arc::new(DashMap::new()),
                metrics,
            },
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while tx_handle.tx_count() < 50 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(tx_handle.tx_count(), 50);

        // All packets should go to the same backend (same flow → same rewriter → same conn entry)
        let mut dst_ips = std::collections::HashSet::new();
        while let Some(pkt) = tx_handle.read_transmitted() {
            // Outer IP dst is at bytes 16..20
            let dst = &pkt[16..20];
            dst_ips.insert([dst[0], dst[1], dst[2], dst[3]]);
        }
        assert_eq!(
            dst_ips.len(),
            1,
            "all same-flow packets should go to same backend"
        );

        forwarder.shutdown();
    }
}
