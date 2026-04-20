use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use lb_config_manager::loader::LbConfig;
use lb_controller::Controller;
use lb_hashing::LookupTable;
use lb_types::*;

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

/// Build a config with `num_pools` pools, each having `backends_per_pool`
/// backends. A single "shared" backend (10.255.255.1) appears in every pool
/// to simulate a backend that triggers cascading rebuilds on health flap.
fn make_config(num_pools: usize, backends_per_pool: usize) -> LbConfig {
    let shared_backend = Backend::new(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1)), 443);

    let pools: Vec<BackendPool> = (0..num_pools)
        .map(|pool_idx| {
            let mut backends: Vec<Backend> = (0..(backends_per_pool - 1))
                .map(|b| {
                    let unique = pool_idx * (backends_per_pool - 1) + b;
                    Backend::new(
                        IpAddr::V4(Ipv4Addr::new(
                            10,
                            (unique / 65536) as u8,
                            ((unique / 256) % 256) as u8,
                            (unique % 256) as u8,
                        )),
                        443,
                    )
                })
                .collect();
            backends.push(shared_backend.clone());
            BackendPool {
                id: BackendPoolId(format!("pool-{pool_idx}")),
                backends,
                health_check: None,
            }
        })
        .collect();

    let vips: Vec<Vip> = pools
        .iter()
        .enumerate()
        .map(|(i, pool)| Vip {
            id: VipId(format!("vip-{i}")),
            address: IpAddr::V4(Ipv4Addr::new(188, 184, (i / 256) as u8, (i % 256) as u8)),
            services: vec![VipService {
                protocol: Protocol::Tcp,
                port: 443,
                backend_pool: pool.id.0.clone(),
            }],
            owner: "bench".into(),
            description: "".into(),
        })
        .collect();

    LbConfig { vips, pools }
}

/// Build a config where `num_failing` backends each appear in `pools_per_backend`
/// pools. Simulates a rack switch failure taking multiple backends offline.
fn make_correlated_config(
    num_failing: usize,
    pools_per_backend: usize,
    extra_backends: usize,
) -> (LbConfig, Vec<IpAddr>) {
    let failing_ips: Vec<IpAddr> = (0..num_failing)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 255, (i / 256) as u8, (i % 256) as u8)))
        .collect();

    let total_pools = pools_per_backend;
    let pools: Vec<BackendPool> = (0..total_pools)
        .map(|pool_idx| {
            let mut backends: Vec<Backend> = (0..extra_backends)
                .map(|b| {
                    let unique = pool_idx * extra_backends + b;
                    Backend::new(
                        IpAddr::V4(Ipv4Addr::new(
                            10,
                            0,
                            ((unique / 256) % 256) as u8,
                            (unique % 256) as u8,
                        )),
                        443,
                    )
                })
                .collect();
            // Add all failing backends to every pool
            for ip in &failing_ips {
                backends.push(Backend::new(*ip, 443));
            }
            BackendPool {
                id: BackendPoolId(format!("pool-{pool_idx}")),
                backends,
                health_check: None,
            }
        })
        .collect();

    let vips = vec![];
    (LbConfig { vips, pools }, failing_ips)
}

fn setup_controller(
    config: &LbConfig,
    table_size: usize,
) -> (
    Controller,
    HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>>,
) {
    let mut tables: HashMap<BackendPoolId, Arc<ArcSwap<LookupTable>>> = HashMap::new();
    for pool in &config.pools {
        let table = LookupTable::build(&pool.backends, table_size).unwrap();
        tables.insert(pool.id.clone(), Arc::new(ArcSwap::from_pointee(table)));
    }
    let health_status = Arc::new(DashMap::new());
    let mut controller = Controller::new(tables.clone(), health_status, table_size);
    controller.apply_config(config.clone());
    (controller, tables)
}

/// Benchmark: single backend flap affecting N pools.
///
/// Compares without-debounce (flush after each change) vs with-debounce
/// (accumulate, flush once). With a single flapping backend this measures
/// the overhead of Controller machinery vs raw Maglev rebuilds.
fn bench_single_backend_flap(c: &mut Criterion) {
    pin_to_core();
    let mut group = c.benchmark_group("single_backend_flap");
    group.warm_up_time(Duration::from_secs(2));

    let table_size = 65537;

    for num_pools in [10, 50, 100, 200] {
        let config = make_config(num_pools, 20);

        // Without debounce: flush after each on_health_change
        group.bench_with_input(
            BenchmarkId::new("no_debounce", num_pools),
            &num_pools,
            |b, _| {
                let (mut controller, _tables) = setup_controller(&config, table_size);
                let flapping_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1));

                b.iter(|| {
                    controller.on_health_change(black_box(flapping_ip), HealthStatus::Unhealthy);
                    controller.flush_pending();
                    // Restore for next iteration
                    controller.on_health_change(black_box(flapping_ip), HealthStatus::Healthy);
                    controller.flush_pending();
                })
            },
        );

        // With debounce: accumulate + single flush
        group.bench_with_input(
            BenchmarkId::new("with_debounce", num_pools),
            &num_pools,
            |b, _| {
                let (mut controller, _tables) = setup_controller(&config, table_size);
                let flapping_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1));

                b.iter(|| {
                    controller.on_health_change(black_box(flapping_ip), HealthStatus::Unhealthy);
                    // Single flush covers all affected pools
                    controller.flush_pending();
                    // Restore
                    controller.on_health_change(black_box(flapping_ip), HealthStatus::Healthy);
                    controller.flush_pending();
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: correlated failure — N backends go down simultaneously,
/// each appearing in M pools. This is the rack-switch-dies scenario.
///
/// Without debounce: each health change triggers a flush, so a pool
/// containing K of the N failing backends gets rebuilt K times.
/// With debounce: all N changes accumulate, each pool rebuilt once.
fn bench_correlated_failure(c: &mut Criterion) {
    pin_to_core();
    let mut group = c.benchmark_group("correlated_failure");
    group.warm_up_time(Duration::from_secs(2));

    let table_size = 65537;

    for num_failing in [5, 10, 20] {
        let pools_per_backend = 50;
        let extra_backends = 15;
        let (config, failing_ips) =
            make_correlated_config(num_failing, pools_per_backend, extra_backends);

        // Without debounce: flush after EACH backend goes unhealthy.
        // Each pool gets rebuilt once per failing backend it contains.
        group.bench_with_input(
            BenchmarkId::new("no_debounce", num_failing),
            &num_failing,
            |b, _| {
                let (mut controller, _tables) = setup_controller(&config, table_size);

                b.iter(|| {
                    for &ip in &failing_ips {
                        controller.on_health_change(black_box(ip), HealthStatus::Unhealthy);
                        controller.flush_pending();
                    }
                    // Restore for next iteration
                    for &ip in &failing_ips {
                        controller.on_health_change(black_box(ip), HealthStatus::Healthy);
                        controller.flush_pending();
                    }
                })
            },
        );

        // With debounce: accumulate all N changes, then flush once.
        // Each pool is rebuilt exactly once with all changes applied.
        group.bench_with_input(
            BenchmarkId::new("with_debounce", num_failing),
            &num_failing,
            |b, _| {
                let (mut controller, _tables) = setup_controller(&config, table_size);

                b.iter(|| {
                    for &ip in &failing_ips {
                        controller.on_health_change(black_box(ip), HealthStatus::Unhealthy);
                    }
                    controller.flush_pending(); // single flush
                                                // Restore
                    for &ip in &failing_ips {
                        controller.on_health_change(black_box(ip), HealthStatus::Healthy);
                    }
                    controller.flush_pending();
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: on_health_change without flush — measures just the DashMap
/// update + reverse index lookup + pending set insertion overhead.
fn bench_health_change_overhead(c: &mut Criterion) {
    pin_to_core();
    let table_size = 65537;
    let config = make_config(100, 20);
    let (mut controller, _tables) = setup_controller(&config, table_size);

    let flapping_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1));

    c.bench_function("health_change_overhead_100_pools", |b| {
        b.iter(|| {
            controller.on_health_change(black_box(flapping_ip), HealthStatus::Unhealthy);
        })
    });
}

/// Benchmark: apply_config (full config reload) at varying scales.
fn bench_apply_config(c: &mut Criterion) {
    pin_to_core();
    let mut group = c.benchmark_group("apply_config");
    group.warm_up_time(Duration::from_secs(2));

    let table_size = 65537;

    for num_pools in [10, 50, 100] {
        let config = make_config(num_pools, 20);

        group.bench_with_input(BenchmarkId::new("pools", num_pools), &num_pools, |b, _| {
            let (mut controller, _tables) = setup_controller(&config, table_size);

            b.iter(|| {
                controller.apply_config(black_box(config.clone()));
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_single_backend_flap,
    bench_correlated_failure,
    bench_health_change_overhead,
    bench_apply_config,
);
criterion_main!(benches);
