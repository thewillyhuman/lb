use crate::loader::LbConfig;
use lb_hashing::LookupTable;
use lb_types::{Backend, BackendPool, BackendPoolId, HealthStatus};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

/// Build new lookup tables from config, filtering out unhealthy backends.
pub fn build_lookup_tables(
    config: &LbConfig,
    health_status: &HashMap<IpAddr, HealthStatus>,
    table_size: usize,
) -> HashMap<BackendPoolId, Arc<LookupTable>> {
    build_lookup_tables_for_pools(&config.pools, health_status, table_size)
}

/// Build lookup tables for only the specified pools.
///
/// Used by `on_health_change` to rebuild only the pools affected by a backend
/// status change, avoiding O(total_pools) work when only a subset are affected.
pub fn build_lookup_tables_for_pools(
    pools: &[BackendPool],
    health_status: &HashMap<IpAddr, HealthStatus>,
    table_size: usize,
) -> HashMap<BackendPoolId, Arc<LookupTable>> {
    let mut tables = HashMap::new();

    for pool in pools {
        // Two reasons to exclude a backend from the new lookup table:
        //  1. Health checker has marked it `Unhealthy` (automatic).
        //  2. Operator has set `drain = true` in the config (manual).
        // The "assume healthy unless explicitly Unhealthy" default for
        // never-probed backends is preserved.
        let active_backends: Vec<Backend> = pool
            .backends
            .iter()
            .filter(|b| {
                if b.drain {
                    return false;
                }
                health_status
                    .get(&b.ip)
                    .map(|s| *s != HealthStatus::Unhealthy)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        if active_backends.is_empty() {
            // No usable backends — fall back to *all* of them, including
            // unhealthy/drained, so traffic still has somewhere to go.
            // This matches the existing "all-unhealthy fallback" behaviour
            // and keeps the safety property: a misconfigured pool prefers
            // best-effort routing over total drop.
            if let Ok(table) = LookupTable::build(&pool.backends, table_size) {
                tables.insert(pool.id.clone(), Arc::new(table));
            }
        } else if let Ok(table) = LookupTable::build(&active_backends, table_size) {
            tables.insert(pool.id.clone(), Arc::new(table));
        }
    }

    tables
}

/// Build a reverse index: backend IP -> set of pool IDs that contain it.
///
/// At CERN scale (hundreds of pools), a single health flap should only rebuild
/// the pools that actually contain the flapping backend, not all pools.
pub fn build_backend_pool_index(config: &LbConfig) -> HashMap<IpAddr, HashSet<BackendPoolId>> {
    let mut index: HashMap<IpAddr, HashSet<BackendPoolId>> = HashMap::new();
    for pool in &config.pools {
        for backend in &pool.backends {
            index.entry(backend.ip).or_default().insert(pool.id.clone());
        }
    }
    index
}

/// Type alias for the shared map of pool id → lookup table.
///
/// Wrapped in `Arc<ArcSwap<HashMap<…>>>` (rather than the older shape of
/// `HashMap<…, Arc<ArcSwap<…>>>`) so the controller can add and remove
/// pool entries at runtime atomically. The forwarder reads via
/// `lookup_tables.load()` once per batch.
pub type LookupTables = Arc<ArcSwap<HashMap<BackendPoolId, Arc<LookupTable>>>>;

/// Merge `updates` into the shared lookup-table map. Any existing pool not
/// mentioned in `updates` is preserved — this is the path used by health-
/// driven rebuilds where we only have entries for the affected pools.
/// Use [`replace_tables`] when applying a fresh full config.
pub fn apply_tables(updates: HashMap<BackendPoolId, Arc<LookupTable>>, shared: &LookupTables) {
    let current = shared.load_full();
    let mut next: HashMap<BackendPoolId, Arc<LookupTable>> = (*current).clone();
    next.extend(updates);
    shared.store(Arc::new(next));
}

/// Atomically replace the entire lookup-table map. Used on full
/// `apply_config` calls where the operator's intent is "every pool now
/// looks like this and removed pools should disappear". Pools present in
/// the previous state but missing from `new_tables` are dropped, freeing
/// their `Arc<LookupTable>` once outstanding readers finish.
pub fn replace_tables(new_tables: HashMap<BackendPoolId, Arc<LookupTable>>, shared: &LookupTables) {
    shared.store(Arc::new(new_tables));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_config() -> LbConfig {
        LbConfig {
            vips: vec![],
            pools: vec![BackendPool {
                id: BackendPoolId("web".into()),
                backends: vec![
                    Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                    Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
                    Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 443),
                ],
                health_check: None,
            }],
        }
    }

    #[test]
    fn build_tables_all_healthy() {
        let config = make_config();
        let health = HashMap::new(); // no status = assume healthy
        let tables = build_lookup_tables(&config, &health, 17);
        assert!(tables.contains_key(&BackendPoolId("web".into())));
        assert_eq!(tables[&BackendPoolId("web".into())].num_backends(), 3);
    }

    #[test]
    fn drained_backend_is_excluded_from_lookup_table() {
        let mut config = make_config();
        // Mark 10.0.0.2 as drained.
        config.pools[0].backends[1].drain = true;
        let health = HashMap::new();
        let tables = build_lookup_tables(&config, &health, 65537);
        let table = &tables[&BackendPoolId("web".into())];
        assert_eq!(table.num_backends(), 2);
        // The drained IP must not appear in the lookup output.
        let drained = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for hash in 0..1000u64 {
            assert_ne!(table.lookup(hash).ip, drained);
        }
    }

    #[test]
    fn all_drained_falls_back_to_all_backends() {
        let mut config = make_config();
        for b in &mut config.pools[0].backends {
            b.drain = true;
        }
        let health = HashMap::new();
        let tables = build_lookup_tables(&config, &health, 17);
        // Same fallback semantics as all-unhealthy: serve traffic, the
        // operator clearly didn't intend the LB to black-hole the VIP.
        // We have to clear the drain bit on the fallback build because
        // `LookupTable::build` filters weight=0 too — drain doesn't
        // affect weight today, so this works without further coupling.
        let table = &tables[&BackendPoolId("web".into())];
        assert_eq!(table.num_backends(), 3);
    }

    #[test]
    fn build_tables_one_unhealthy() {
        let config = make_config();
        let mut health = HashMap::new();
        health.insert(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            HealthStatus::Unhealthy,
        );
        let tables = build_lookup_tables(&config, &health, 17);
        assert_eq!(tables[&BackendPoolId("web".into())].num_backends(), 2);
    }

    #[test]
    fn build_tables_all_unhealthy_fallback() {
        let config = make_config();
        let mut health = HashMap::new();
        for i in 1..=3 {
            health.insert(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                HealthStatus::Unhealthy,
            );
        }
        let tables = build_lookup_tables(&config, &health, 17);
        // Fallback: use all backends
        assert_eq!(tables[&BackendPoolId("web".into())].num_backends(), 3);
    }

    #[test]
    fn apply_tables_merges_into_shared_map() {
        let config = make_config();
        let health = HashMap::new();
        let tables = build_lookup_tables(&config, &health, 17);

        let pool_id = BackendPoolId("web".into());
        let initial = LookupTable::build(
            &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 80)],
            17,
        )
        .unwrap();
        let mut initial_map: HashMap<_, _> = HashMap::new();
        initial_map.insert(pool_id.clone(), Arc::new(initial));
        let shared: LookupTables = Arc::new(ArcSwap::from_pointee(initial_map));

        assert_eq!(shared.load()[&pool_id].num_backends(), 1);

        apply_tables(tables, &shared);

        assert_eq!(shared.load()[&pool_id].num_backends(), 3);
    }

    #[test]
    fn apply_tables_inserts_new_pool_at_runtime() {
        // Closes the "adding a new pool requires a restart" gap from the
        // production-readiness audit. The shared map starts with `web`;
        // a config reload that introduces `api` must reach the data plane.
        let initial = LookupTable::build(
            &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)],
            17,
        )
        .unwrap();
        let mut initial_map: HashMap<_, _> = HashMap::new();
        initial_map.insert(BackendPoolId("web".into()), Arc::new(initial));
        let shared: LookupTables = Arc::new(ArcSwap::from_pointee(initial_map));

        let new_pool = LookupTable::build(
            &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), 8080)],
            17,
        )
        .unwrap();
        let mut updates = HashMap::new();
        updates.insert(BackendPoolId("api".into()), Arc::new(new_pool));

        apply_tables(updates, &shared);

        let snap = shared.load();
        assert!(snap.contains_key(&BackendPoolId("web".into())));
        assert!(snap.contains_key(&BackendPoolId("api".into())));
    }

    #[test]
    fn replace_tables_drops_pools_not_in_new_set() {
        // Full-config-apply path: a pool removed from the JSON should
        // disappear from the shared map.
        let mut initial_map: HashMap<_, _> = HashMap::new();
        initial_map.insert(
            BackendPoolId("web".into()),
            Arc::new(
                LookupTable::build(
                    &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)],
                    17,
                )
                .unwrap(),
            ),
        );
        initial_map.insert(
            BackendPoolId("legacy".into()),
            Arc::new(
                LookupTable::build(
                    &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 80)],
                    17,
                )
                .unwrap(),
            ),
        );
        let shared: LookupTables = Arc::new(ArcSwap::from_pointee(initial_map));

        let mut new_state = HashMap::new();
        new_state.insert(
            BackendPoolId("web".into()),
            Arc::new(
                LookupTable::build(
                    &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)],
                    17,
                )
                .unwrap(),
            ),
        );
        replace_tables(new_state, &shared);

        let snap = shared.load();
        assert!(snap.contains_key(&BackendPoolId("web".into())));
        assert!(
            !snap.contains_key(&BackendPoolId("legacy".into())),
            "replace_tables must drop pools no longer in the config"
        );
    }

    #[test]
    fn backend_pool_index_maps_ips_to_pools() {
        let config = LbConfig {
            vips: vec![],
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
                    backends: vec![
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080),
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8080),
                    ],
                    health_check: None,
                },
            ],
        };

        let index = build_backend_pool_index(&config);

        // 10.0.0.1 is only in pool-a
        let pools_1 = &index[&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        assert_eq!(pools_1.len(), 1);
        assert!(pools_1.contains(&BackendPoolId("pool-a".into())));

        // 10.0.0.2 is in both pools
        let pools_2 = &index[&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))];
        assert_eq!(pools_2.len(), 2);
        assert!(pools_2.contains(&BackendPoolId("pool-a".into())));
        assert!(pools_2.contains(&BackendPoolId("pool-b".into())));

        // 10.0.0.3 is only in pool-b
        let pools_3 = &index[&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))];
        assert_eq!(pools_3.len(), 1);
        assert!(pools_3.contains(&BackendPoolId("pool-b".into())));
    }

    #[test]
    fn build_for_subset_of_pools() {
        let config = LbConfig {
            vips: vec![],
            pools: vec![
                BackendPool {
                    id: BackendPoolId("pool-a".into()),
                    backends: vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)],
                    health_check: None,
                },
                BackendPool {
                    id: BackendPoolId("pool-b".into()),
                    backends: vec![Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080)],
                    health_check: None,
                },
            ],
        };

        // Build only pool-a
        let health = HashMap::new();
        let tables = build_lookup_tables_for_pools(&config.pools[..1], &health, 17);
        assert_eq!(tables.len(), 1);
        assert!(tables.contains_key(&BackendPoolId("pool-a".into())));
    }
}
