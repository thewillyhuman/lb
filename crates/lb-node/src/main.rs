use clap::Parser;
use lb_config_manager::loader::LbConfig;
use lb_config_manager::watcher::ConfigWatcher;
use lb_controller::Controller;
use lb_forwarder::threading::{ForwarderSharedState, MultiThreadedForwarder};
use lb_forwarder::vip_matcher::VipMatcher;
use lb_forwarder::ForwarderConfig;
use lb_hashing::LookupTable;
use lb_io::mock::mock_io;
use lb_metrics::LbMetrics;
use lb_types::{BackendPoolId, HealthStatus, NodeConfig};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

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

    // Initialize tracing
    tracing_subscriber::fmt::init();

    tracing::info!(
        node_id = %config.node.id,
        threads = config.node.num_threads,
        config_file = %config.control_plane.config_file.display(),
        "starting lb-node"
    );

    // Shared state between forwarder (data plane) and controller (control plane)
    let health_status: Arc<DashMap<IpAddr, HealthStatus>> = Arc::new(DashMap::new());
    let vip_matcher = Arc::new(ArcSwap::from_pointee(VipMatcher::new()));

    // Metrics
    let metrics = LbMetrics::new();

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
        apply_lb_config(
            lb_config,
            &mut lookup_tables,
            &vip_matcher,
        );
    }

    // Controller
    let mut controller = Controller::new(
        lookup_tables.clone(),
        health_status.clone(),
        lb_hashing::DEFAULT_TABLE_SIZE,
    );
    if let Some(parent) = config.control_plane.local_cache.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    controller = controller.with_cache_path(config.control_plane.local_cache.clone());

    if let Some((_, ref lb_config)) = initial_lb_config {
        controller.apply_config(lb_config.clone());
    }

    // Forwarder config
    let mtu_config = lb_types::MtuConfig::new(config.forwarder.network_mtu).unwrap_or_else(|e| {
        eprintln!("invalid MTU config: {e}");
        std::process::exit(1);
    });
    let fwd_config = ForwarderConfig {
        src_ip: config.node.loopback_ip,
        connection_table_size: config.forwarder.connection_table_size,
        connection_ttl: config.forwarder.connection_ttl,
        batch_size: config.forwarder.batch_size,
        mtu_config,
        icmp_rate_limit: config.forwarder.icmp_rate_limit,
    };

    // Start multi-threaded forwarder
    // In production, replace mock_io with AfXdpIo or DpdkIo per NIC config.
    let (rx_io, _rx_handle) = mock_io();
    let (tx_io, _tx_handle) = mock_io();

    let num_rewriters = config.node.num_threads;

    tracing::info!(
        num_rewriters = num_rewriters,
        "starting multi-threaded forwarder"
    );

    let forwarder = MultiThreadedForwarder::start(
        rx_io,
        tx_io,
        fwd_config,
        num_rewriters,
        ForwarderSharedState {
            lookup_tables,
            vip_matcher: vip_matcher.clone(),
            health_status: health_status.clone(),
            metrics: metrics.forwarder.clone(),
        },
    );

    // Config file watcher thread (per ADR-001: inotify-based reload)
    if let Some((watcher, _)) = initial_lb_config {
        let vip_matcher_clone = vip_matcher.clone();

        std::thread::Builder::new()
            .name("lb-config-watcher".into())
            .spawn(move || {
                tracing::info!("config file watcher started");
                loop {
                    let new_config = watcher.wait_for_change();
                    tracing::info!(
                        vips = new_config.vips.len(),
                        pools = new_config.pools.len(),
                        "applying reloaded config"
                    );

                    // Rebuild VIP matcher
                    let new_matcher = build_vip_matcher(&new_config);
                    vip_matcher_clone.store(Arc::new(new_matcher));

                    // Note: controller.apply_config() would also need to be
                    // called here in a full implementation. For now, the VIP
                    // matcher is updated directly. A production setup would
                    // use a channel to send the new config to the controller.
                }
            })
            .expect("failed to spawn config watcher thread");
    }

    tracing::info!("lb-node started");

    // Main thread: wait for forwarder to finish (or panic)
    // In production, this would also handle signal handling (SIGTERM, SIGHUP).
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
                lookup_tables.insert(
                    pool.id.clone(),
                    Arc::new(ArcSwap::from_pointee(table)),
                );
            }
        }
    }

    // Build and swap VIP matcher
    let new_matcher = build_vip_matcher(config);
    vip_matcher.store(Arc::new(new_matcher));
}
