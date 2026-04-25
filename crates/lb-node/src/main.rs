mod ops_server;

use clap::Parser;
use lb_bgp::{BgpAnnouncer, BgpEvent, BgpSpeaker};
use lb_config_manager::loader::LbConfig;
use lb_config_manager::watcher::ConfigWatcher;
use lb_controller::Controller;
use lb_forwarder::threading::{ForwarderSharedState, MultiThreadedForwarder};
use lb_forwarder::vip_matcher::VipMatcher;
use lb_forwarder::ForwarderConfig;
use lb_hashing::LookupTable;
use lb_io::af_xdp::{AfXdpConfig, AfXdpIo};
use lb_io::mock::mock_io;
use lb_metrics::{LbMetrics, PeerLabels, PeerNotificationLabels};
use lb_types::{BackendPoolId, HealthStatus, IoBackend, NodeConfig};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use crate::ops_server::OpsState;

#[derive(Parser)]
#[command(name = "lb-node", version, about = "LB node: forwarder + controller")]
struct Cli {
    /// Path to the node configuration file (TOML)
    #[arg(long, default_value = "/etc/lb/config.toml")]
    config: PathBuf,

    /// Validate config and exit
    #[arg(long)]
    check_config: bool,
}

fn main() {
    let cli = Cli::parse();

    // Load node config (TOML)
    let config_str = std::fs::read_to_string(&cli.config).unwrap_or_else(|e| {
        eprintln!("failed to read config file {:?}: {e}", cli.config);
        std::process::exit(1);
    });

    let config: NodeConfig = toml::from_str(&config_str).unwrap_or_else(|e| {
        eprintln!("failed to parse config: {e}");
        std::process::exit(1);
    });

    if cli.check_config {
        // Also validate the LB config file if it exists
        if config.control_plane.config_file.exists() {
            match lb_config_manager::loader::load_from_file(&config.control_plane.config_file) {
                Ok(_) => println!("Configuration is valid (node + LB config)"),
                Err(e) => {
                    eprintln!("LB config file is invalid: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            println!("Configuration is valid (node config only, LB config file not found)");
        }
        return;
    }

    // Initialize tracing. Default to the JSON formatter — structured logs
    // round-trip cleanly through `journald` → `journalctl -o cat` / `jq` /
    // Loki, and the per-call `tracing::info!(field = %value, "msg")` sites
    // already scattered through the binary all become first-class indexable
    // fields. Operators who prefer pretty console output for local dev can
    // set `LB_LOG_FORMAT=pretty`. Log level is driven by `RUST_LOG` as
    // usual, defaulting to `info`.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match std::env::var("LB_LOG_FORMAT").as_deref() {
        Ok("pretty") => tracing_subscriber::fmt().with_env_filter(env_filter).init(),
        _ => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init(),
    }

    tracing::info!(
        node_id = %config.node.id,
        threads = config.node.num_threads,
        config_file = %config.control_plane.config_file.display(),
        "starting lb-node"
    );

    // Shared state between forwarder (data plane) and controller (control plane)
    let health_status: Arc<DashMap<IpAddr, HealthStatus>> = Arc::new(DashMap::new());
    let vip_matcher = Arc::new(ArcSwap::from_pointee(VipMatcher::new()));

    // Metrics. Wrapped in an Arc so the ops HTTP server and the BGP event
    // pump share a single registry.
    let metrics = Arc::new(LbMetrics::new());

    // Readiness flag flipped after the initial config has been applied.
    // The `/readyz` endpoint consults it along with the forwarder's liveness
    // flag, so load balancers / systemd notify can steer traffic only when
    // the node is fully primed.
    let ready = Arc::new(AtomicBool::new(false));

    // Shared shutdown signal. The SIGTERM/SIGINT handler flips this so
    // long-running blocking threads (e.g. the config watcher) can exit
    // cleanly instead of being torn down mid-syscall by `process::exit`.
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Try to load initial LB config (per ADR-001: from local file)
    let initial_lb_config = if config.control_plane.config_file.exists() {
        match ConfigWatcher::new(&config.control_plane.config_file) {
            Ok((watcher, lb_config)) => {
                tracing::info!(
                    vips = lb_config.vips.len(),
                    pools = lb_config.pools.len(),
                    "loaded initial LB config"
                );
                Some((watcher, lb_config))
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to load LB config, starting with empty config");
                None
            }
        }
    } else {
        tracing::warn!(
            path = %config.control_plane.config_file.display(),
            "LB config file not found, starting with empty config"
        );
        None
    };

    // Build initial lookup tables from LB config
    let mut lookup_tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>> = HashMap::new();

    if let Some((_, ref lb_config)) = initial_lb_config {
        apply_lb_config(lb_config, &mut lookup_tables, &vip_matcher);
    }

    // BGP speaker — one session per configured peer. Spawned on a dedicated
    // tokio runtime so the sync control-plane thread can use `announce` /
    // `withdraw` without needing to be async itself.
    let bgp_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("lb-bgp")
        .enable_all()
        .build()
        .expect("failed to build BGP runtime");
    let mut bgp_speaker = BgpSpeaker::new(config.bgp.clone());
    let bgp_events = bgp_speaker.take_event_rx();
    bgp_speaker.spawn(bgp_runtime.handle());
    // Keep a concrete `Arc<BgpSpeaker>` so the signal handler can call
    // `shutdown`; the controller holds the same data through the trait object
    // via an unsizing coercion (`Arc<BgpSpeaker>` → `Arc<dyn BgpAnnouncer>`).
    let bgp_speaker: Arc<BgpSpeaker> = Arc::new(bgp_speaker);
    let bgp_announcer: Arc<dyn BgpAnnouncer> = bgp_speaker.clone();

    // Controller
    let mut controller = Controller::new(
        lookup_tables.clone(),
        health_status.clone(),
        lb_hashing::DEFAULT_TABLE_SIZE,
    );
    if let Some(parent) = config.control_plane.local_cache.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    controller = controller
        .with_cache_path(config.control_plane.local_cache.clone())
        .with_bgp(Arc::clone(&bgp_announcer));

    if let Some((_, ref lb_config)) = initial_lb_config {
        controller.apply_config(lb_config.clone());
    }

    // BGP event pump: drive per-peer metrics and re-announce the full VIP
    // set whenever a peer (re)connects. Controller is wrapped in Arc<Mutex>
    // for the event loop. We use a blocking Mutex because event bursts are
    // infrequent and the critical section is tiny (flip a set of VIPs).
    let controller = Arc::new(parking_lot::Mutex::new(controller));
    let bgp_handle = bgp_runtime.handle().clone();
    if let Some(mut rx) = bgp_events {
        let controller_for_events = Arc::clone(&controller);
        let bgp_metrics = metrics.controller.bgp.clone();
        bgp_handle.spawn(async move {
            while let Some(evt) = rx.recv().await {
                match evt {
                    BgpEvent::PeerConnected { peer_ip } => {
                        let labels = PeerLabels {
                            peer_ip: peer_ip.to_string(),
                        };
                        bgp_metrics.peer_state.get_or_create(&labels).set(1);
                        bgp_metrics.peer_connects.get_or_create(&labels).inc();
                        // Push the full announced-set to the newly-connected peer
                        // to recover any updates dropped while it was down.
                        controller_for_events.lock().reannounce_all();
                    }
                    BgpEvent::PeerDisconnected { peer_ip, reason } => {
                        let labels = PeerLabels {
                            peer_ip: peer_ip.to_string(),
                        };
                        bgp_metrics.peer_state.get_or_create(&labels).set(0);
                        bgp_metrics.peer_disconnects.get_or_create(&labels).inc();
                        tracing::info!(%peer_ip, %reason, "BGP peer disconnected");
                    }
                    BgpEvent::AnnounceFailed { peer_ip } => {
                        bgp_metrics
                            .announce_failures
                            .get_or_create(&PeerLabels {
                                peer_ip: peer_ip.to_string(),
                            })
                            .inc();
                    }
                    BgpEvent::WithdrawFailed { peer_ip } => {
                        bgp_metrics
                            .withdraw_failures
                            .get_or_create(&PeerLabels {
                                peer_ip: peer_ip.to_string(),
                            })
                            .inc();
                    }
                    BgpEvent::PeerNotification {
                        peer_ip,
                        error_code,
                        error_subcode,
                    } => {
                        bgp_metrics
                            .peer_notifications
                            .get_or_create(&PeerNotificationLabels {
                                peer_ip: peer_ip.to_string(),
                                code: error_code,
                                subcode: error_subcode,
                            })
                            .inc();
                    }
                }
            }
        });
    }
    // Retain the runtime for the lifetime of the process.
    std::mem::forget(bgp_runtime);

    // Forwarder config
    let mtu_config = lb_types::MtuConfig::new(config.forwarder.network_mtu).unwrap_or_else(|e| {
        eprintln!("invalid MTU config: {e}");
        std::process::exit(1);
    });
    let fwd_config = ForwarderConfig {
        src_ip: config.node.loopback_ip,
        connection_table_size: config.forwarder.connection_table_size,
        conn_ttls: config.forwarder.resolved_conn_ttls(),
        fragment_table_size: config.forwarder.fragment_table_size,
        fragment_ttl: config.forwarder.fragment_ttl,
        batch_size: config.forwarder.batch_size,
        mtu_config,
        icmp_rate_limit: config.forwarder.icmp_rate_limit,
        cpu_affinity: config
            .node
            .cpu_affinity
            .as_ref()
            .map(|c| lb_forwarder::CpuAffinity {
                steering: c.steering.clone(),
                rewriters: c.rewriters.clone(),
                muxer: c.muxer.clone(),
            }),
    };

    // Start the multi-threaded forwarder against the configured I/O backend.
    // Each backend arm constructs RX and TX handles and then dispatches to
    // the same shared-state shape, which is why `MultiThreadedForwarder` is
    // generic over `T: PacketIo`.
    let num_rewriters = config.node.num_threads;
    tracing::info!(
        num_rewriters = num_rewriters,
        io_backend = ?config.node.io_backend,
        "starting multi-threaded forwarder"
    );
    // Clone the lookup-table map before handing it to the forwarder: the
    // ops HTTP server's `/v1/trace` endpoint also needs read access, and
    // the forwarder consumes its copy.
    let lookup_tables_for_ops = Arc::new(lookup_tables.clone());
    let shared = ForwarderSharedState {
        lookup_tables,
        vip_matcher: vip_matcher.clone(),
        health_status: health_status.clone(),
        metrics: metrics.forwarder.clone(),
    };
    let forwarder = match config.node.io_backend {
        IoBackend::Mock => {
            let (rx_io, _rx_handle) = mock_io();
            let (tx_io, _tx_handle) = mock_io();
            MultiThreadedForwarder::start(rx_io, tx_io, fwd_config, num_rewriters, shared)
        }
        IoBackend::AfXdp => {
            let xdp_cfg = AfXdpConfig {
                iface: config.node.data_iface.clone(),
                ..AfXdpConfig::default()
            };
            // Fail fast with a clear message — the scaffold returns
            // `Unsupported` today, so exiting here is the honest response.
            // When a real implementation lands the same code path will
            // succeed without further changes.
            let rx_io = AfXdpIo::new(&xdp_cfg).unwrap_or_else(|e| {
                eprintln!(
                    "failed to initialize AF_XDP RX socket on {:?}: {e}",
                    xdp_cfg.iface
                );
                std::process::exit(1);
            });
            let tx_io = AfXdpIo::new(&xdp_cfg).unwrap_or_else(|e| {
                eprintln!(
                    "failed to initialize AF_XDP TX socket on {:?}: {e}",
                    xdp_cfg.iface
                );
                std::process::exit(1);
            });
            MultiThreadedForwarder::start(rx_io, tx_io, fwd_config, num_rewriters, shared)
        }
    };
    let forwarder = Arc::new(forwarder);

    // Spawn the operations HTTP server (`/healthz`, `/readyz`, `/metrics`).
    // Binds lazily so the process comes up even if the port is taken; errors
    // are logged but non-fatal — the forwarder is still running without it.
    {
        let ops_state = OpsState {
            metrics: Arc::clone(&metrics),
            ready: Arc::clone(&ready),
            forwarder_running: {
                let f = Arc::clone(&forwarder);
                Arc::new(move || f.is_running())
            },
            node_id: Arc::from(config.node.id.as_str()),
            vip_matcher: Arc::clone(&vip_matcher),
            lookup_tables: Arc::clone(&lookup_tables_for_ops),
            health_status: Arc::clone(&health_status),
        };
        let ops_addr = config.node.metrics_addr;
        bgp_handle.spawn(async move {
            match ops_server::serve(ops_addr, ops_state).await {
                Ok((_, fut)) => {
                    if let Err(e) = fut.await {
                        tracing::error!(%ops_addr, error = %e, "ops HTTP server exited");
                    }
                }
                Err(e) => {
                    tracing::error!(%ops_addr, error = %e, "ops HTTP server failed to bind");
                }
            }
        });
    }

    // Initial config has been applied (or we've decided to run empty).
    // Flip readiness now so `/readyz` starts returning 200 and load balancers
    // / systemd notify can start steering traffic at the forwarder.
    ready.store(true, std::sync::atomic::Ordering::Relaxed);

    // Config file watcher (per ADR-001: inotify-based reload).
    //
    // Reload flow: the watcher thread (sync, blocks on inotify) forwards each
    // new `LbConfig` over an `mpsc::channel` to an apply-task on the BGP
    // runtime. The apply-task rebuilds the VIP matcher *and* calls
    // `Controller::apply_config`, which rebuilds lookup tables and diffs BGP
    // announcements. Previously only the VIP matcher was rebuilt — lookup
    // tables stayed stale and BGP announces didn't track config changes.
    //
    // Known limitation: `apply_tables` only updates *existing* pool IDs in the
    // shared HashMap. Adding a brand-new pool at runtime still requires a
    // restart; membership changes within existing pools and VIP->pool
    // remapping both work.
    if let Some((watcher, _)) = initial_lb_config {
        let (config_tx, mut config_rx) = tokio::sync::mpsc::unbounded_channel::<LbConfig>();

        // Apply-task: runs on the BGP runtime, receives new configs, rebuilds
        // VIP matcher + calls controller.apply_config under the controller's
        // Mutex.
        {
            let controller = Arc::clone(&controller);
            let vip_matcher = vip_matcher.clone();
            bgp_handle.spawn(async move {
                while let Some(new_config) = config_rx.recv().await {
                    tracing::info!(
                        vips = new_config.vips.len(),
                        pools = new_config.pools.len(),
                        "applying reloaded config"
                    );
                    // Rebuild and swap the VIP matcher atomically so the
                    // forwarder sees either the old or new state, never a
                    // torn read.
                    let new_matcher = build_vip_matcher(&new_config);
                    vip_matcher.store(Arc::new(new_matcher));
                    // Let the controller rebuild lookup tables and
                    // reconcile BGP announcements. `apply_config` also
                    // caches the validated config to disk.
                    controller.lock().apply_config(new_config);
                }
            });
        }

        // Watcher thread: sync, inotify-driven. Feeds `config_tx`. Stops on
        // either an explicit shutdown signal or the apply-task channel
        // closing.
        let watcher_shutdown = Arc::clone(&shutdown_flag);
        std::thread::Builder::new()
            .name("lb-config-watcher".into())
            .spawn(move || {
                tracing::info!("config file watcher started");
                while let Some(new_config) = watcher.wait_for_change(&watcher_shutdown) {
                    if config_tx.send(new_config).is_err() {
                        tracing::info!("config apply-task gone, watcher exiting");
                        return;
                    }
                }
                tracing::info!("config watcher stopping (shutdown or channel closed)");
            })
            .expect("failed to spawn config watcher thread");
    }

    tracing::info!("lb-node started");

    // Graceful shutdown: on SIGTERM or SIGINT, withdraw every announced VIP
    // (so the upstream router removes us from ECMP *before* we stop
    // forwarding, not after its BGP hold timer has elapsed), then tear down
    // BGP sessions, then join the forwarder threads. Exiting without
    // withdrawing would cause a ~90-second traffic blackhole at the router.
    {
        let controller_for_signal = Arc::clone(&controller);
        let bgp_speaker_for_signal = Arc::clone(&bgp_speaker);
        let forwarder_for_signal = Arc::clone(&forwarder);
        let shutdown_for_signal = Arc::clone(&shutdown_flag);
        bgp_handle.spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
            let signame = tokio::select! {
                _ = sigterm.recv() => "SIGTERM",
                _ = sigint.recv() => "SIGINT",
            };
            tracing::info!(%signame, "received shutdown signal, draining");

            // Tell the config watcher (and any other thread polling this
            // flag) to stop. They unwind cleanly before `process::exit`
            // pulls the rug.
            shutdown_for_signal.store(true, std::sync::atomic::Ordering::Relaxed);

            // 1. Withdraw VIPs. Best-effort; the speaker writes to each peer
            //    session's mpsc channel and returns immediately.
            controller_for_signal.lock().withdraw_all();

            // 2. Give BGP peers a brief moment to receive and ACK the
            //    UPDATEs. 2s is plenty on a healthy network.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // 3. Close BGP sessions. Each session sees a `Shutdown` command,
            //    drops its TCP stream, and the JoinHandle resolves.
            bgp_speaker_for_signal.shutdown().await;

            // 4. Join forwarder threads.
            forwarder_for_signal.shutdown();

            tracing::info!("shutdown complete");
            std::process::exit(0);
        });
    }

    // Main thread: wait for forwarder to finish (or panic). The signal handler
    // calls `std::process::exit` directly on graceful shutdown, so we only
    // reach the `exit(1)` branch on an *unexpected* thread panic.
    loop {
        if !forwarder.is_running() {
            tracing::error!("forwarder thread(s) exited unexpectedly");
            std::process::exit(1);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Build VIP matcher entries from LB config.
fn build_vip_matcher(config: &LbConfig) -> VipMatcher {
    let mut entries = Vec::new();
    for vip in &config.vips {
        for svc in &vip.services {
            entries.push((
                vip.address,
                svc.protocol,
                svc.port,
                BackendPoolId(svc.backend_pool.clone()),
            ));
        }
    }
    VipMatcher::from_entries(entries)
}

/// Apply an LB config: build lookup tables and update VIP matcher.
fn apply_lb_config(
    config: &LbConfig,
    lookup_tables: &mut HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
    vip_matcher: &Arc<ArcSwap<VipMatcher>>,
) {
    // Build lookup tables for each pool
    for pool in &config.pools {
        if !pool.backends.is_empty() {
            if let Ok(table) = LookupTable::build(&pool.backends, lb_hashing::DEFAULT_TABLE_SIZE) {
                lookup_tables.insert(pool.id.clone(), Arc::new(ArcSwap::from_pointee(table)));
            }
        }
    }

    // Build and swap VIP matcher
    let new_matcher = build_vip_matcher(config);
    vip_matcher.store(Arc::new(new_matcher));
}
