use crate::loader::LbConfig;
use lb_hashing::LookupTable;
use lb_types::{Backend, BackendPoolId, BackendPool, HealthStatus};
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
        let healthy_backends: Vec<Backend> = pool
            .backends
            .iter()
            .filter(|b| {
                health_status
                    .get(&b.ip)
                    .map(|s| *s != HealthStatus::Unhealthy)
                    .unwrap_or(true) // assume healthy if no status yet
            })
            .cloned()
            .collect();

        if healthy_backends.is_empty() {
            // If all backends are unhealthy, use all backends as fallback
            if let Ok(table) = LookupTable::build(&pool.backends, table_size) {
                tables.insert(pool.id.clone(), Arc::new(table));
            }
        } else if let Ok(table) = LookupTable::build(&healthy_backends, table_size) {
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
            index
                .entry(backend.ip)
                .or_default()
                .insert(pool.id.clone());
        }
    }
    index
}

/// Atomically swap lookup tables into the shared state.
pub fn apply_tables(
    new_tables: HashMap<BackendPoolId, Arc<LookupTable>>,
    shared_tables: &HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
) {
    for (pool_id, new_table) in new_tables {
        if let Some(swap) = shared_tables.get(&pool_id) {
            swap.store(new_table);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_types::*;
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
    fn apply_tables_swaps_atomically() {
        let config = make_config();
        let health = HashMap::new();
        let tables = build_lookup_tables(&config, &health, 17);

        // Set up shared state
        let pool_id = BackendPoolId("web".into());
        let initial_table = LookupTable::build(
            &[Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 80)],
            17,
        )
        .unwrap();
        let mut shared = HashMap::new();
        shared.insert(pool_id.clone(), Arc::new(ArcSwap::from_pointee(initial_table)));

        // Verify initial state
        assert_eq!(shared[&pool_id].load().num_backends(), 1);

        // Apply new tables
        apply_tables(tables, &shared);

        // Verify swapped
        assert_eq!(shared[&pool_id].load().num_backends(), 3);
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
                    backends: vec![
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                    ],
                    health_check: None,
                },
                BackendPool {
                    id: BackendPoolId("pool-b".into()),
                    backends: vec![
                        Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080),
                    ],
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
