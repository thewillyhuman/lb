use lb_bgp::BgpAnnouncer;
use lb_config_manager::applier::{self, LookupTables};
use lb_config_manager::cache;
use lb_config_manager::loader::LbConfig;
use lb_types::{BackendPoolId, HealthStatus};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Health change events within this window are batched into a single rebuild
/// per affected pool. Limits redundant work when correlated failures (e.g., a
/// rack switch dying) take multiple backends offline simultaneously.
const DEBOUNCE_WINDOW: Duration = Duration::from_millis(50);

/// The control-plane orchestrator. Coordinates health checking, BGP, and config.
pub struct Controller {
    /// Shared lookup tables (controller writes, forwarder reads). Wrapped
    /// as `Arc<ArcSwap<HashMap<…>>>` so adding/removing a pool at runtime
    /// reaches the data plane atomically — the forwarder loads the map
    /// once per batch.
    lookup_tables: LookupTables,
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
    /// Optional BGP announcer. When set, the controller keeps the set of
    /// announced VIPs in sync with the set of VIPs whose backing pool has at
    /// least one healthy backend.
    bgp: Option<Arc<dyn BgpAnnouncer>>,
    /// VIPs the controller believes are currently announced. Used to compute
    /// announce/withdraw diffs on health or config changes. Only IPv4 VIPs
    /// are tracked — IPv6 BGP announcement is out of scope.
    vips_announced: BTreeSet<Ipv4Addr>,
}

impl Controller {
    pub fn new(
        lookup_tables: LookupTables,
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
            bgp: None,
            vips_announced: BTreeSet::new(),
        }
    }

    pub fn with_cache_path(mut self, path: PathBuf) -> Self {
        self.cache_path = Some(path);
        self
    }

    /// Attach a BGP announcer. Every subsequent config or health change will
    /// diff the set of VIPs-with-healthy-pool against `vips_announced` and
    /// call `announce`/`withdraw` accordingly.
    pub fn with_bgp(mut self, bgp: Arc<dyn BgpAnnouncer>) -> Self {
        self.bgp = Some(bgp);
        self
    }

    /// Re-announce every VIP in the current desired set. Call after the BGP
    /// speaker reports a peer has (re)connected, so that peer gets the full
    /// announcement state even if individual commands were dropped while it
    /// was down.
    pub fn reannounce_all(&self) {
        if let Some(bgp) = &self.bgp {
            let vips: Vec<Ipv4Addr> = self.vips_announced.iter().copied().collect();
            if !vips.is_empty() {
                bgp.announce(&vips);
            }
        }
    }

    /// Withdraw every VIP currently believed-announced. Call this on graceful
    /// shutdown so the upstream router removes this node from ECMP *before*
    /// the process exits — otherwise traffic keeps arriving for up to the
    /// BGP hold-timer (90s default) at the router and blackholes.
    ///
    /// Clears `vips_announced`; any later re-announce path (e.g.
    /// `reannounce_all`) therefore has nothing to fire.
    pub fn withdraw_all(&mut self) {
        if let Some(bgp) = &self.bgp {
            let vips: Vec<Ipv4Addr> = std::mem::take(&mut self.vips_announced)
                .into_iter()
                .collect();
            if !vips.is_empty() {
                bgp.withdraw(&vips);
            }
        } else {
            self.vips_announced.clear();
        }
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

        // Full-config apply: drop pools that the new config no longer
        // mentions. Uses replace_tables (not apply_tables) so removed
        // pools don't linger in the shared map.
        applier::replace_tables(new_tables, &self.lookup_tables);

        // Rebuild the reverse index (backend IP -> pool IDs)
        self.backend_pool_index = applier::build_backend_pool_index(&config);

        // Cache the config
        if let Some(ref path) = self.cache_path {
            if let Err(e) = cache::save_cache(path, &config) {
                tracing::warn!(error = %e, "failed to save config cache");
            }
        }

        self.config = Some(config);

        // Recompute announced VIP set from the fresh config + health state.
        self.sync_bgp_announcements();

        tracing::info!("config applied successfully");
    }

    /// Compute the set of VIPs that currently have at least one healthy
    /// backend in their pool. Only IPv4 VIPs are considered for BGP.
    fn desired_announced_vips(&self) -> BTreeSet<Ipv4Addr> {
        let Some(config) = &self.config else {
            return BTreeSet::new();
        };

        // Map pool id -> has_any_healthy_backend.
        let mut pool_healthy: HashMap<&BackendPoolId, bool> = HashMap::new();
        for pool in &config.pools {
            let any_healthy = pool.backends.iter().any(|b| {
                self.health_status
                    .get(&b.ip)
                    .map(|s| *s != HealthStatus::Unhealthy)
                    .unwrap_or(true) // unknown == healthy-by-default (matches rewriter)
            });
            pool_healthy.insert(&pool.id, any_healthy);
        }

        let mut out = BTreeSet::new();
        for vip in &config.vips {
            let IpAddr::V4(v4) = vip.address else {
                continue;
            };
            let any_service_healthy = vip.services.iter().any(|svc| {
                pool_healthy
                    .get(&BackendPoolId(svc.backend_pool.clone()))
                    .copied()
                    .unwrap_or(false)
            });
            if any_service_healthy {
                out.insert(v4);
            }
        }
        out
    }

    /// Diff desired VIPs against currently-announced VIPs and emit
    /// announce/withdraw calls to the BGP speaker. No-op if no BGP speaker
    /// is attached.
    fn sync_bgp_announcements(&mut self) {
        let Some(bgp) = &self.bgp else {
            return;
        };

        let desired = self.desired_announced_vips();

        let to_announce: Vec<Ipv4Addr> =
            desired.difference(&self.vips_announced).copied().collect();
        let to_withdraw: Vec<Ipv4Addr> =
            self.vips_announced.difference(&desired).copied().collect();

        if !to_announce.is_empty() {
            tracing::info!(count = to_announce.len(), "announcing VIPs");
            bgp.announce(&to_announce);
        }
        if !to_withdraw.is_empty() {
            tracing::info!(count = to_withdraw.len(), "withdrawing VIPs");
            bgp.withdraw(&to_withdraw);
        }

        self.vips_announced = desired;
    }

    /// Record a backend health status change.
    ///
    /// The health status in `DashMap` is updated immediately so the rewriter's
    /// per-packet health check sees it right away (falling back to a fresh
    /// Maglev lookup for flows pinned to the dead backend). The lookup table
    /// rebuild is debounced: affected pool IDs are accumulated and flushed
    /// after the debounce window (50ms) has elapsed since the first pending
    /// change. This coalesces correlated failures (e.g., a rack switch dying
    /// takes 20 backends offline) into a single rebuild per affected pool.
    ///
    /// Call [`Self::tick`] periodically (or after the last health event in a
    /// batch) to flush pending rebuilds if no further `on_health_change`
    /// calls arrive.
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

        // BGP announcements are reconciled eagerly (not debounced): a VIP
        // with zero healthy backends must be withdrawn immediately so the
        // router stops sending it traffic. The announced-set is small, so
        // recomputing on every health event is cheap.
        self.sync_bgp_announcements();

        // Flush lookup-table rebuilds if the debounce window has elapsed.
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

            let new_tables =
                applier::build_lookup_tables_for_pools(&affected_pools, &health, self.table_size);

            tracing::info!(
                affected_pools = affected_pools.len(),
                total_pools = config.pools.len(),
                pending_changes = self.pending_pools.len(),
                debounce_ms = self
                    .pending_since
                    .map(|s| s.elapsed().as_millis())
                    .unwrap_or(0),
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
    use arc_swap::ArcSwap;
    use lb_hashing::LookupTable;
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

    fn setup_controller(config: &LbConfig) -> (Controller, LookupTables) {
        let mut tables_map: HashMap<BackendPoolId, Arc<LookupTable>> = HashMap::new();
        for pool in &config.pools {
            let table = LookupTable::build(&pool.backends, 17).unwrap();
            tables_map.insert(pool.id.clone(), Arc::new(table));
        }
        let tables: LookupTables = Arc::new(ArcSwap::from_pointee(tables_map));
        let health_status = Arc::new(DashMap::new());
        let mut controller = Controller::new(Arc::clone(&tables), health_status, 17);
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

        let mut tables_map: HashMap<BackendPoolId, Arc<LookupTable>> = HashMap::new();
        tables_map.insert(pool_id.clone(), Arc::new(initial_table));
        let tables: LookupTables = Arc::new(ArcSwap::from_pointee(tables_map));

        let health_status = Arc::new(DashMap::new());
        let mut controller = Controller::new(Arc::clone(&tables), health_status, 17);

        controller.apply_config(make_config());

        // Table should now have 2 backends
        assert_eq!(tables.load()[&pool_id].num_backends(), 2);
    }

    #[test]
    fn apply_config_drops_pools_no_longer_in_config() {
        // Closes the "removed pool stays in shared map" gap.
        let mut config = make_config();
        config.pools.push(BackendPool {
            id: BackendPoolId("legacy-pool".into()),
            backends: vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), 80)],
            health_check: None,
        });
        let (mut controller, tables) = setup_controller(&config);
        assert!(tables
            .load()
            .contains_key(&BackendPoolId("legacy-pool".into())));

        controller.apply_config(make_config()); // legacy-pool removed

        let snap = tables.load();
        assert!(snap.contains_key(&BackendPoolId("web-pool".into())));
        assert!(
            !snap.contains_key(&BackendPoolId("legacy-pool".into())),
            "legacy-pool should have been dropped from the shared map"
        );
    }

    #[test]
    fn apply_config_inserts_new_pool_at_runtime() {
        // Closes the audit's "adding a new pool requires a restart" finding.
        let (mut controller, tables) = setup_controller(&make_config());
        assert!(!tables.load().contains_key(&BackendPoolId("api".into())));

        let mut extended = make_config();
        extended.pools.push(BackendPool {
            id: BackendPoolId("api".into()),
            backends: vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), 8080)],
            health_check: None,
        });
        controller.apply_config(extended);

        assert!(
            tables.load().contains_key(&BackendPoolId("api".into())),
            "newly added pool should be in the shared map without a restart"
        );
    }

    #[test]
    fn health_change_is_debounced() {
        let (mut controller, tables) = setup_controller(&make_config());
        let pool_id = BackendPoolId("web-pool".into());

        assert_eq!(tables.load()[&pool_id].num_backends(), 2);

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
        assert_eq!(tables.load()[&pool_id].num_backends(), 2);
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
        assert_eq!(tables.load()[&pool_id].num_backends(), 1);
    }

    #[test]
    fn debounce_coalesces_correlated_failures() {
        let config = make_multi_pool_config();
        let (mut controller, tables) = setup_controller(&config);

        let pool_a = BackendPoolId("pool-a".into());
        let pool_b = BackendPoolId("pool-b".into());
        let pool_c = BackendPoolId("pool-c".into());

        assert_eq!(tables.load()[&pool_a].num_backends(), 3);
        assert_eq!(tables.load()[&pool_b].num_backends(), 3);
        assert_eq!(tables.load()[&pool_c].num_backends(), 2);

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
        assert_eq!(tables.load()[&pool_a].num_backends(), 3);
        assert_eq!(tables.load()[&pool_b].num_backends(), 3);

        // Flush — pool-a and pool-b are rebuilt ONCE each, with both changes applied
        controller.flush_pending();

        assert_eq!(tables.load()[&pool_a].num_backends(), 1); // only 10.0.0.1 left
        assert_eq!(tables.load()[&pool_b].num_backends(), 1); // only 10.0.0.4 left
        assert_eq!(tables.load()[&pool_c].num_backends(), 2); // unaffected
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
        assert_eq!(tables.load()[&pool_id].num_backends(), 2);

        // Wait for the debounce window to elapse
        std::thread::sleep(DEBOUNCE_WINDOW + Duration::from_millis(10));

        // Now tick() should flush
        controller.tick();
        assert!(!controller.has_pending_rebuilds());
        assert_eq!(tables.load()[&pool_id].num_backends(), 1);
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
        assert_eq!(tables.load()[&pool_a].num_backends(), 1); // only 10.0.0.1
        assert_eq!(tables.load()[&pool_b].num_backends(), 1); // only 10.0.0.4
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
        assert_eq!(tables.load()[&pool_id].num_backends(), 2);
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
        assert_eq!(tables.load()[&pool_id].num_backends(), 1);
    }

    /// In-memory BGP announcer that records every call. Lets us test the
    /// controller's VIP-diff logic without touching real TCP sockets.
    #[derive(Default)]
    struct MockAnnouncer {
        events: parking_lot::Mutex<Vec<AnnouncerEvent>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum AnnouncerEvent {
        Announce(Vec<Ipv4Addr>),
        Withdraw(Vec<Ipv4Addr>),
    }

    impl BgpAnnouncer for MockAnnouncer {
        fn announce(&self, vips: &[Ipv4Addr]) {
            self.events
                .lock()
                .push(AnnouncerEvent::Announce(vips.to_vec()));
        }
        fn withdraw(&self, vips: &[Ipv4Addr]) {
            self.events
                .lock()
                .push(AnnouncerEvent::Withdraw(vips.to_vec()));
        }
    }

    impl MockAnnouncer {
        fn drain(&self) -> Vec<AnnouncerEvent> {
            std::mem::take(&mut *self.events.lock())
        }
    }

    fn vip_v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn make_bgp_config() -> (LbConfig, Ipv4Addr, Ipv4Addr) {
        let vip_a = vip_v4(188, 184, 100, 10);
        let vip_b = vip_v4(188, 184, 100, 11);
        let cfg = LbConfig {
            vips: vec![
                Vip {
                    id: VipId("web".into()),
                    address: IpAddr::V4(vip_a),
                    services: vec![VipService {
                        protocol: Protocol::Tcp,
                        port: 443,
                        backend_pool: "pool-a".into(),
                    }],
                    owner: "test".into(),
                    description: "".into(),
                },
                Vip {
                    id: VipId("api".into()),
                    address: IpAddr::V4(vip_b),
                    services: vec![VipService {
                        protocol: Protocol::Tcp,
                        port: 443,
                        backend_pool: "pool-b".into(),
                    }],
                    owner: "test".into(),
                    description: "".into(),
                },
            ],
            pools: vec![
                BackendPool {
                    id: BackendPoolId("pool-a".into()),
                    backends: vec![
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
                    ],
                    health_check: None,
                },
                BackendPool {
                    id: BackendPoolId("pool-b".into()),
                    backends: vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 443)],
                    health_check: None,
                },
            ],
        };
        (cfg, vip_a, vip_b)
    }

    fn setup_with_bgp() -> (Controller, Arc<MockAnnouncer>, Ipv4Addr, Ipv4Addr) {
        let (cfg, vip_a, vip_b) = make_bgp_config();
        let mut tables_map: HashMap<BackendPoolId, Arc<LookupTable>> = HashMap::new();
        for pool in &cfg.pools {
            let t = LookupTable::build(&pool.backends, 17).unwrap();
            tables_map.insert(pool.id.clone(), Arc::new(t));
        }
        let tables: LookupTables = Arc::new(ArcSwap::from_pointee(tables_map));
        let health = Arc::new(DashMap::new());
        let mock = Arc::new(MockAnnouncer::default());
        let mut ctl =
            Controller::new(tables, health, 17).with_bgp(mock.clone() as Arc<dyn BgpAnnouncer>);
        ctl.apply_config(cfg);
        (ctl, mock, vip_a, vip_b)
    }

    #[test]
    fn apply_config_announces_vips_with_healthy_pools() {
        let (_ctl, mock, vip_a, vip_b) = setup_with_bgp();

        // Both pools have no explicit health = treated as healthy by default,
        // so both VIPs should be announced.
        let events = mock.drain();
        let announced: Vec<Ipv4Addr> = events
            .iter()
            .filter_map(|e| match e {
                AnnouncerEvent::Announce(v) => Some(v.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(announced.contains(&vip_a));
        assert!(announced.contains(&vip_b));
    }

    #[test]
    fn withdraw_when_all_pool_backends_unhealthy() {
        let (mut ctl, mock, _vip_a, vip_b) = setup_with_bgp();
        mock.drain(); // clear initial announcements

        // pool-b has exactly one backend (10.0.1.1). Take it down.
        ctl.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            HealthStatus::Unhealthy,
        );

        let events = mock.drain();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, AnnouncerEvent::Withdraw(v) if v.contains(&vip_b))),
            "expected withdraw of {vip_b}, got {events:?}"
        );
    }

    #[test]
    fn reannounce_when_pool_recovers() {
        let (mut ctl, mock, _vip_a, vip_b) = setup_with_bgp();
        mock.drain();

        // Take down, then bring back up.
        ctl.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            HealthStatus::Unhealthy,
        );
        mock.drain();
        ctl.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            HealthStatus::Healthy,
        );

        let events = mock.drain();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, AnnouncerEvent::Announce(v) if v.contains(&vip_b))),
            "expected re-announce of {vip_b}, got {events:?}"
        );
    }

    #[test]
    fn partially_healthy_pool_keeps_vip_announced() {
        let (mut ctl, mock, vip_a, _) = setup_with_bgp();
        mock.drain();

        // pool-a has two backends — take only one down. The VIP must stay up.
        ctl.on_health_change(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            HealthStatus::Unhealthy,
        );

        let events = mock.drain();
        for e in &events {
            if let AnnouncerEvent::Withdraw(v) = e {
                assert!(!v.contains(&vip_a), "vip_a withdrawn too early: {events:?}");
            }
        }
    }

    #[test]
    fn apply_config_rediff_announces_only_new_vips() {
        let (mut ctl, mock, vip_a, vip_b) = setup_with_bgp();
        mock.drain();

        // Reapply the same config — no diff, nothing should fire.
        let (cfg, _, _) = make_bgp_config();
        ctl.apply_config(cfg);

        let events = mock.drain();
        let any_nonempty = events.iter().any(|e| match e {
            AnnouncerEvent::Announce(v) | AnnouncerEvent::Withdraw(v) => !v.is_empty(),
        });
        assert!(!any_nonempty, "reapply fired unexpected events: {events:?}");
        // Silence unused
        let _ = (vip_a, vip_b);
    }

    #[test]
    fn reannounce_all_emits_full_set() {
        let (ctl, mock, vip_a, vip_b) = setup_with_bgp();
        mock.drain();

        ctl.reannounce_all();

        let events = mock.drain();
        assert_eq!(events.len(), 1);
        match &events[0] {
            AnnouncerEvent::Announce(v) => {
                assert!(v.contains(&vip_a));
                assert!(v.contains(&vip_b));
            }
            _ => panic!("expected single Announce, got {events:?}"),
        }
    }

    #[test]
    fn withdraw_all_emits_withdraw_and_clears_announced_set() {
        let (mut ctl, mock, vip_a, vip_b) = setup_with_bgp();
        mock.drain();

        ctl.withdraw_all();

        let events = mock.drain();
        assert_eq!(events.len(), 1);
        match &events[0] {
            AnnouncerEvent::Withdraw(v) => {
                assert!(v.contains(&vip_a));
                assert!(v.contains(&vip_b));
            }
            _ => panic!("expected single Withdraw, got {events:?}"),
        }

        // Idempotent: a second call must not fire anything.
        ctl.withdraw_all();
        let events = mock.drain();
        assert!(
            events.is_empty(),
            "withdraw_all fired after the set was already empty: {events:?}"
        );

        // `reannounce_all` must not fire either — the announced set is empty.
        ctl.reannounce_all();
        assert!(mock.drain().is_empty());
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

        assert_eq!(tables.load()[&pool_a].num_backends(), 2); // 10.0.0.2, 10.0.0.3
        assert_eq!(tables.load()[&pool_b].num_backends(), 3); // unchanged
        assert_eq!(tables.load()[&pool_c].num_backends(), 2); // unchanged
    }
}
