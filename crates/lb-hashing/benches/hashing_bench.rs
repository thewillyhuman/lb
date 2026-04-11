use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lb_hashing::{LookupTable, DEFAULT_TABLE_SIZE};
use lb_types::Backend;
use std::net::{IpAddr, Ipv4Addr};

fn pin_to_core() {
    if let Some(core_ids) = core_affinity::get_core_ids() {
        // Pick core 1 if available (avoid core 0 which handles interrupts),
        // otherwise fall back to the first available core.
        let core = if core_ids.len() > 1 {
            core_ids[1]
        } else {
            core_ids[0]
        };
        core_affinity::set_for_current(core);
    }
}

fn make_backends(n: usize) -> Vec<Backend> {
    (0..n)
        .map(|i| Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)), 443))
        .collect()
}

fn bench_table_build(c: &mut Criterion) {
    pin_to_core();
    let backends = make_backends(100);
    c.bench_function("maglev_table_build_100_backends", |b| {
        b.iter(|| LookupTable::build(black_box(&backends), DEFAULT_TABLE_SIZE).unwrap())
    });
}

fn bench_table_build_small(c: &mut Criterion) {
    pin_to_core();
    let backends = make_backends(10);
    c.bench_function("maglev_table_build_10_backends", |b| {
        b.iter(|| LookupTable::build(black_box(&backends), DEFAULT_TABLE_SIZE).unwrap())
    });
}

fn bench_table_lookup(c: &mut Criterion) {
    pin_to_core();
    let backends = make_backends(100);
    let table = LookupTable::build(&backends, DEFAULT_TABLE_SIZE).unwrap();
    let hashes: Vec<u64> = (0..10000).map(|i| i * 7 + 13).collect();

    c.bench_function("maglev_lookup_10k", |b| {
        b.iter(|| {
            for &h in &hashes {
                black_box(table.lookup(h));
            }
        })
    });
}

/// Simulates a health-check flap triggering cascading Maglev table rebuilds.
///
/// At CERN scale: hundreds of VIPs, each with its own backend pool and Maglev
/// lookup table. A single backend IP that appears in N pools goes unhealthy,
/// and all N tables must be rebuilt sequentially on the control plane.
fn bench_cascading_rebuild(c: &mut Criterion) {
    pin_to_core();

    let mut group = c.benchmark_group("cascading_rebuild");

    for num_pools in [10, 50, 100, 200] {
        // Each pool has 20 backends (realistic CERN service size).
        // The "flapping" backend appears in every pool.
        let pools: Vec<Vec<Backend>> = (0..num_pools)
            .map(|pool_idx| {
                let mut backends: Vec<Backend> = (0..19)
                    .map(|b| {
                        let ip_third = ((pool_idx * 19 + b) / 256) as u8;
                        let ip_fourth = ((pool_idx * 19 + b) % 256) as u8;
                        Backend::new(
                            IpAddr::V4(Ipv4Addr::new(10, ip_third, ip_fourth, 1)),
                            443,
                        )
                    })
                    .collect();
                // Shared backend that appears in every pool (the one that flaps)
                backends.push(Backend::new(
                    IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1)),
                    443,
                ));
                backends
            })
            .collect();

        // Benchmark: rebuild ALL affected pools (the flapping backend is removed)
        group.bench_with_input(
            BenchmarkId::new("all_pools", num_pools),
            &num_pools,
            |b, _| {
                b.iter(|| {
                    for pool in &pools {
                        // Simulate removing the unhealthy backend
                        let healthy: Vec<&Backend> = pool
                            .iter()
                            .filter(|b| b.ip != IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1)))
                            .collect();
                        let owned: Vec<Backend> = healthy.into_iter().cloned().collect();
                        black_box(
                            LookupTable::build(&owned, DEFAULT_TABLE_SIZE).unwrap(),
                        );
                    }
                })
            },
        );

        // Benchmark: rebuild only pools that contain the flapping backend
        // (with a pre-computed reverse index)
        group.bench_with_input(
            BenchmarkId::new("affected_only", num_pools),
            &num_pools,
            |b, _| {
                // Pre-compute which pools contain the flapping backend
                let flapping_ip = IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1));
                let affected: Vec<usize> = pools
                    .iter()
                    .enumerate()
                    .filter(|(_, pool)| pool.iter().any(|b| b.ip == flapping_ip))
                    .map(|(i, _)| i)
                    .collect();

                b.iter(|| {
                    for &idx in &affected {
                        let healthy: Vec<Backend> = pools[idx]
                            .iter()
                            .filter(|b| b.ip != flapping_ip)
                            .cloned()
                            .collect();
                        black_box(
                            LookupTable::build(&healthy, DEFAULT_TABLE_SIZE).unwrap(),
                        );
                    }
                })
            },
        );
    }

    group.finish();
}

/// Single table build with varying backend counts (10 to 200).
/// Shows how build time scales with pool size.
fn bench_table_build_scaling(c: &mut Criterion) {
    pin_to_core();
    let mut group = c.benchmark_group("table_build_scaling");

    for n_backends in [5, 10, 20, 50, 100, 200] {
        let backends = make_backends(n_backends);
        group.bench_with_input(
            BenchmarkId::new("backends", n_backends),
            &n_backends,
            |b, _| {
                b.iter(|| LookupTable::build(black_box(&backends), DEFAULT_TABLE_SIZE).unwrap())
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_table_build,
    bench_table_build_small,
    bench_table_lookup,
    bench_cascading_rebuild,
    bench_table_build_scaling,
);
criterion_main!(benches);
