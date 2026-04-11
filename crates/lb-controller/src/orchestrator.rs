use lb_config_manager::applier;
use lb_config_manager::cache;
use lb_config_manager::loader::LbConfig;
use lb_hashing::LookupTable;
use lb_types::{BackendPoolId, HealthStatus};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;

/// Health change events within this window are batched into a single rebuild
/// per affected pool. Limits redundant work when correlated failures (e.g., a
/// rack switch dying) take multiple backends offline simultaneously.
const DEBOUNCE_WINDOW: Duration = Duration::from_millis(50);

/// The control-plane orchestrator. Coordinates health checking, BGP, and config.
pub struct Controller {
    /// Shared lookup tables (controller writes, forwarder reads).
    lookup_tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
    /// Shared health status (health checker writes, forwarder reads).
    health_status: Arc<DashMap<IpAddr, HealthStatus>>,
    /// Current config.
    config: Option<LbConfig>,
    /// Reverse index: backend IP -> pool IDs that contain it.
    /// Rebuilt on config change so health flaps only rebuild affected pools.
    backend_pool_index: HashMap<IpAddr, HashSet<BackendPoolId>>,
    /// Pool IDs that need a lookup table rebuild. Accumulated across multiple
    /// `on_health_change` calls and flushed after the debounce window.
    pending_pools: HashSet<BackendPoolId>,
    /// When the first change in the current debounce window arrived.
    /// `None` means no pending changes.
    pending_since: Option<Instant>,
    /// Local cache path.
    cache_path: Option<PathBuf>,
    /// Maglev table size.
    table_size: usize,
}

impl Controller {
    pub fn new(
        lookup_tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
        health_status: Arc<DashMap<IpAddr, HealthStatus>>,
        table_size: usize,
    ) -> Self {
        Self {
            lookup_tables,
            health_status,
            config: None,
            backend_pool_index: HashMap::new(),
            pending_pools: HashSet::new(),
            pending_since: None,
            cache_path: None,
            table_size,
        }
    }

    pub fn with_cache_path(mut self, path: PathBuf) -> Self {
        self.cache_path = Some(path);
        self
    }

    /// Apply a new configuration. Rebuilds all lookup tables and swaps them atomically.
    ///
    /// Any pending debounced rebuilds are discarded since we're rebuilding everything.
    pub fn apply_config(&mut self, config: LbConfig) {
        // A full config apply supersedes any pending health-based rebuilds
        self.pending_pools.clear();
        self.pending_since = None;

        // Collect current health status
        let health: HashMap<IpAddr, HealthStatus> = self
            .health_status
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();

        // Build new lookup tables for all pools
        let new_tables = applier::build_lookup_tables(&config, &health, self.table_size);

        // Swap them in
        applier::apply_tables(new_tables, &self.lookup_tables);

        // Rebuild the reverse index (backend IP -> pool IDs)
        self.backend_pool_index = applier::build_backend_pool_index(&config);

        // Cache the config
        if let Some(ref path) = self.cache_path {
            if let Err(e) = cache::save_cache(path, &config) {
                tracing::warn!(error = %e, "failed to save config cache");
            }
        }

        self.config = Some(config);
        tracing::info!("config applied successfully");
    }

    /// Record a backend health status change.
    ///
    /// The health status in `DashMap` is updated immediately so the rewriter's
    /// per-packet health check sees it right away (falling back to a fresh
    /// Maglev lookup for flows pinned to the dead backend). The lookup table
    /// rebuild is debounced: affected pool IDs are accumulated and flushed
    /// after [`DEBOUNCE_WINDOW`] (50ms) has elapsed since the first pending
    /// change. This coalesces correlated failures (e.g., a rack switch dying
    /// takes 20 backends offline) into a single rebuild per affected pool.
    ///
    /// Call [`tick`] periodically (or after the last health event in a batch)
    /// to flush pending rebuilds if no further `on_health_change` calls arrive.
    pub fn on_health_change(&mut self, backend_ip: IpAddr, status: HealthStatus) {
        // Always update the shared health map immediately — the rewriter
        // checks this per-packet and will fall back to Maglev for flows
        // pinned to a now-unhealthy backend, even before the table rebuild.
        self.health_status.insert(backend_ip, status);

        // Accumulate affected pools for debounced rebuild
        if let Some(pool_ids) = self.backend_pool_index.get(&backend_ip) {
            self.pending_pools.extend(pool_ids.iter().cloned());
            if self.pending_since.is_none() {
                self.pending_since = Some(Instant::now());
            }
        }

        // Flush if the debounce window has elapsed
        self.maybe_flush();
    }

    /// Drive pending debounced rebuilds. Call this periodically from the
    /// control-plane event loop so that changes are flushed even if no further
    /// `on_health_change` calls arrive after a burst.
    pub fn tick(&mut self) {
        self.maybe_flush();
    }

    /// Returns true if there are pending pool rebuilds waiting for the
    /// debounce window to elapse.
    pub fn has_pending_rebuilds(&self) -> bool {
        self.pending_since.is_some()
    }

    /// Flush all pending pool rebuilds immediately, ignoring the debounce window.
    /// Useful for shutdown or testing.
    pub fn flush_pending(&mut self) {
        self.flush();
    }

    /// Get the current config.
    pub fn config(&self) -> Option<&LbConfig> {
        self.config.as_ref()
    }

    fn maybe_flush(&mut self) {
        if let Some(since) = self.pending_since {
            if since.elapsed() >= DEBOUNCE_WINDOW {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        if self.pending_pools.is_empty() {
            self.pending_since = None;
            return;
        }

        let config = match self.config {
            Some(ref c) => c,
            None => {
                self.pending_pools.clear();
                self.pending_since = None;
                return;
            }
        };

        let affected_pools: Vec<_> = config
            .pools
            .iter()
            .filter(|p| self.pending_pools.contains(&p.id))
            .cloned()
            .collect();

        if !affected_pools.is_empty() {
            let health: HashMap<IpAddr, HealthStatus> = self
                .health_status
                .iter()
                .map(|entry| (*entry.key(), *entry.value()))
                .collect();

            let new_tables = applier::build_lookup_tables_for_pools(
                &affected_pools,
                &health,
                self.table_size,
            );

            tracing::info!(
                affected_pools = affected_pools.len(),
                total_pools = config.pools.len(),
                pending_changes = self.pending_pools.len(),
                debounce_ms = self.pending_since.map(|s| s.elapsed().as_millis()).unwrap_or(0),
                "flushing debounced lookup table rebuilds"
            );

            applier::apply_tables(new_tables, &self.lookup_tables);
        }

        self.pending_pools.clear();
        self.pending_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_types::*;
    use std::net::Ipv4Addr;

    fn make_config() -> LbConfig {
        LbConfig {
            vips: vec![Vip {
                id: VipId("web".into()),
                address: IpAddr::V4(Ipv4Addr::new(188, 184, 100, 10)),
                services: vec![VipService {
                    protocol: Protocol::Tcp,
                    port: 443,
                    backend_pool: "web-pool".into(),
                }],
                owner: "test".into(),
                description: "".into(),
            }],
            pools: vec![BackendPool {
                id: BackendPoolId("web-pool".into()),
                backends: vec![
                    Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                    Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
                ],
                health_check: None,
            }],
        }
    }

    fn make_multi_pool_config() -> LbConfig {
        LbConfig {
            vips: vec![],
            pools: vec![
                BackendPool {
                    id: BackendPoolId("pool-a".into()),
                    backends: vec![
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 443),
                    ],
                    health_check: None,
                },
                BackendPool {
                    id: BackendPoolId("pool-b".into()),
                    backends: vec![
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080),
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8080),
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), 8080),
                    ],
                    health_check: None,
                },
                BackendPool {
                    id: BackendPoolId("pool-c".into()),
                    backends: vec![
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 9090),
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)), 9090),
                    ],
                    health_check: None,
                },
            ],
        }
    }

    fn setup_controller(
        config: &LbConfig,
    ) -> (Controller, HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>) {
        let mut tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>> = HashMap::new();
        for pool in &config.pools {
            let table = LookupTable::build(&pool.backends, 17).unwrap();
            tables.insert(pool.id.clone(), Arc::new(ArcSwap::from_pointee(table)));
        }
        let health_status = Arc::new(DashMap::new());
        let mut controller = Controller::new(tables.clone(), health_status, 17);
        controller.apply_config(config.clone());
        (controller, tables)
    }

    #[test]
    fn apply_config_updates_lookup_tables() {
        let pool_id = BackendPoolId("web-pool".into());
        let initial_table = LookupTable::build(
            &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 80)],
            17,
        )
        .unwrap();

        let mut tables = HashMap::new();
        tables.insert(
            pool_id.clone(),
            Arc::new(ArcSwap::from_pointee(initial_table)),
        );

        let health_status = Arc::new(DashMap::new());
        let mut controller = Controller::new(tables.clone(), health_status, 17);

        controller.apply_config(make_config());

        // Table should now have 2 backends
        assert_eq!(tables[&pool_id].load().num_backends(), 2);
    }

    #[test]
    fn health_change_is_debounced() {
        let (mut controller, tables) = setup_controller(&make_config());
        let pool_id = BackendPoolId("web-pool".into());

        assert_eq!(tables[&pool_id].load().num_backends(), 2);

        // Mark one backend unhealthy — should NOT rebuild immediately
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            HealthStatus::Unhealthy,
        );

        // Health status is updated immediately in DashMap
        assert_eq!(
            *controller
                .health_status
                .get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
                .unwrap(),
            HealthStatus::Unhealthy,
        );

        // But the lookup table hasn't been rebuilt yet (within debounce window)
        assert!(controller.has_pending_rebuilds());
        assert_eq!(tables[&pool_id].load().num_backends(), 2);
    }

    #[test]
    fn flush_pending_forces_rebuild() {
        let (mut controller, tables) = setup_controller(&make_config());
        let pool_id = BackendPoolId("web-pool".into());

        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            HealthStatus::Unhealthy,
        );

        // Force flush
        controller.flush_pending();

        assert!(!controller.has_pending_rebuilds());
        assert_eq!(tables[&pool_id].load().num_backends(), 1);
    }

    #[test]
    fn debounce_coalesces_correlated_failures() {
        let config = make_multi_pool_config();
        let (mut controller, tables) = setup_controller(&config);

        let pool_a = BackendPoolId("pool-a".into());
        let pool_b = BackendPoolId("pool-b".into());
        let pool_c = BackendPoolId("pool-c".into());

        assert_eq!(tables[&pool_a].load().num_backends(), 3);
        assert_eq!(tables[&pool_b].load().num_backends(), 3);
        assert_eq!(tables[&pool_c].load().num_backends(), 2);

        // Simulate a rack switch failure: backends 10.0.0.2 and 10.0.0.3 go
        // down simultaneously. Both appear in pool-a and pool-b.
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            HealthStatus::Unhealthy,
        );
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            HealthStatus::Unhealthy,
        );

        // Tables haven't been rebuilt yet (debounce window)
        assert_eq!(tables[&pool_a].load().num_backends(), 3);
        assert_eq!(tables[&pool_b].load().num_backends(), 3);

        // Flush — pool-a and pool-b are rebuilt ONCE each, with both changes applied
        controller.flush_pending();

        assert_eq!(tables[&pool_a].load().num_backends(), 1); // only 10.0.0.1 left
        assert_eq!(tables[&pool_b].load().num_backends(), 1); // only 10.0.0.4 left
        assert_eq!(tables[&pool_c].load().num_backends(), 2); // unaffected
    }

    #[test]
    fn tick_flushes_after_debounce_window() {
        let (mut controller, tables) = setup_controller(&make_config());
        let pool_id = BackendPoolId("web-pool".into());

        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            HealthStatus::Unhealthy,
        );

        // tick() right away — still within debounce window, no flush
        controller.tick();
        assert_eq!(tables[&pool_id].load().num_backends(), 2);

        // Wait for the debounce window to elapse
        std::thread::sleep(DEBOUNCE_WINDOW + Duration::from_millis(10));

        // Now tick() should flush
        controller.tick();
        assert!(!controller.has_pending_rebuilds());
        assert_eq!(tables[&pool_id].load().num_backends(), 1);
    }

    #[test]
    fn health_change_after_debounce_window_triggers_flush() {
        let config = make_multi_pool_config();
        let (mut controller, tables) = setup_controller(&config);

        let pool_a = BackendPoolId("pool-a".into());
        let pool_b = BackendPoolId("pool-b".into());

        // First change: starts the debounce window
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            HealthStatus::Unhealthy,
        );
        assert!(controller.has_pending_rebuilds());

        // Wait past the debounce window
        std::thread::sleep(DEBOUNCE_WINDOW + Duration::from_millis(10));

        // Second change: on_health_change accumulates the new pools into
        // pending_pools, then maybe_flush sees the window has elapsed and
        // flushes everything in one batch. The rebuild uses the current
        // DashMap state, which already includes both changes.
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            HealthStatus::Unhealthy,
        );

        // Both changes flushed together — no pending work remains
        assert!(!controller.has_pending_rebuilds());
        assert_eq!(tables[&pool_a].load().num_backends(), 1); // only 10.0.0.1
        assert_eq!(tables[&pool_b].load().num_backends(), 1); // only 10.0.0.4
    }

    #[test]
    fn health_change_unknown_backend_is_noop() {
        let (mut controller, tables) = setup_controller(&make_config());
        let pool_id = BackendPoolId("web-pool".into());

        // Health change for a backend that's not in any pool
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 99, 99, 99)),
            HealthStatus::Unhealthy,
        );

        assert!(!controller.has_pending_rebuilds());
        assert_eq!(tables[&pool_id].load().num_backends(), 2);
    }

    #[test]
    fn apply_config_clears_pending_rebuilds() {
        let (mut controller, tables) = setup_controller(&make_config());
        let pool_id = BackendPoolId("web-pool".into());

        // Accumulate a pending change
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            HealthStatus::Unhealthy,
        );
        assert!(controller.has_pending_rebuilds());

        // A full config apply supersedes pending changes
        controller.apply_config(make_config());

        assert!(!controller.has_pending_rebuilds());
        // apply_config rebuilt with current health, so 10.0.0.2 is excluded
        assert_eq!(tables[&pool_id].load().num_backends(), 1);
    }

    #[test]
    fn health_change_only_rebuilds_affected_pools() {
        let config = make_multi_pool_config();
        let (mut controller, tables) = setup_controller(&config);

        let pool_a = BackendPoolId("pool-a".into());
        let pool_b = BackendPoolId("pool-b".into());
        let pool_c = BackendPoolId("pool-c".into());

        // Mark 10.0.0.1 unhealthy — only in pool-a
        controller.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            HealthStatus::Unhealthy,
        );
        controller.flush_pending();

        assert_eq!(tables[&pool_a].load().num_backends(), 2); // 10.0.0.2, 10.0.0.3
        assert_eq!(tables[&pool_b].load().num_backends(), 3); // unchanged
        assert_eq!(tables[&pool_c].load().num_backends(), 2); // unchanged
    }
}
