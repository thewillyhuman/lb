use crate::permutation::{offset, skip};
use lb_types::Backend;

/// Maglev consistent hash lookup table.
///
/// Once built, the table is immutable. To update, build a new table
/// and swap it in atomically (e.g., via `ArcSwap`).
#[derive(Debug, Clone)]
pub struct LookupTable {
    entries: Vec<usize>,
    backends: Vec<Backend>,
    table_size: usize,
}

impl LookupTable {
    /// Build a Maglev lookup table from a set of backends.
    ///
    /// `m` must be prime and much larger than `backends.len()`.
    /// Returns `Err` if `backends` is empty *after* dropping zero-weight
    /// entries — `weight = 0` is treated as "this backend does not take
    /// traffic right now" (e.g. drained), the same way `Unhealthy` is
    /// treated by the controller's filter.
    ///
    /// **Weights**: per Maglev §3.4.4 the simplest weighting is to give
    /// backend `i` `weight[i]` chances per outer-loop pass to claim a
    /// slot. A backend with weight 2 fills roughly twice as many entries
    /// as a backend with weight 1, and the minimal-disruption property
    /// holds when weights are scaled uniformly. Asymmetric weight changes
    /// do disrupt some flows — that's inherent to weighted consistent
    /// hashing.
    pub fn build(backends: &[Backend], m: usize) -> Result<Self, &'static str> {
        // Filter zero-weight backends — they exist in config but don't
        // currently take traffic. Caller (the controller's applier) is the
        // one with the operator intent; we just produce a table over
        // whatever non-zero-weight set we're given.
        let active: Vec<&Backend> = backends.iter().filter(|b| b.weight > 0).collect();
        if active.is_empty() {
            return Err("cannot build lookup table: no backends with weight > 0");
        }

        let n = active.len();
        let mut entries = vec![usize::MAX; m];

        // Pre-compute offset/skip pairs instead of materializing full
        // preference lists. O(n*m) (~50 MB for n=100, m=65537) → O(n)
        // (~1.6 KB).
        let params: Vec<(usize, usize)> = active
            .iter()
            .map(|b| {
                let name = b.name();
                let name_bytes = name.as_bytes();
                (offset(name_bytes, m), skip(name_bytes, m))
            })
            .collect();

        // next[i] tracks how far backend i has advanced in its preference list.
        let mut next = vec![0usize; n];

        let mut filled = 0;
        'outer: loop {
            for i in 0..n {
                // Each backend gets `weight` chances per outer pass.
                let chances = active[i].weight as usize;
                for _ in 0..chances {
                    let (o, s) = params[i];
                    // Compute preference list entry on-the-fly:
                    //   (offset + next * skip) % m
                    let mut c = (o + next[i] * s) % m;
                    while entries[c] != usize::MAX {
                        next[i] += 1;
                        c = (o + next[i] * s) % m;
                    }
                    entries[c] = i;
                    next[i] += 1;
                    filled += 1;
                    if filled == m {
                        break 'outer;
                    }
                }
            }
        }

        Ok(LookupTable {
            entries,
            backends: active.into_iter().cloned().collect(),
            table_size: m,
        })
    }

    /// Look up the backend for a given flow hash.
    pub fn lookup(&self, hash: u64) -> &Backend {
        let idx = (hash % self.table_size as u64) as usize;
        let backend_idx = self.entries[idx];
        &self.backends[backend_idx]
    }

    /// Number of backends in this table.
    pub fn num_backends(&self) -> usize {
        self.backends.len()
    }

    /// The table size (M).
    pub fn table_size(&self) -> usize {
        self.table_size
    }

    /// Get the raw entries (for testing/debugging).
    pub fn entries(&self) -> &[usize] {
        &self.entries
    }

    /// Get the backends (for testing/debugging).
    pub fn backends(&self) -> &[Backend] {
        &self.backends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_backends(n: usize) -> Vec<Backend> {
        (0..n)
            .map(|i| Backend::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8 + 1)), 443))
            .collect()
    }

    #[test]
    fn build_fills_all_slots() {
        let backends = make_backends(3);
        let table = LookupTable::build(&backends, 17).unwrap();
        assert!(table.entries().iter().all(|&e| e != usize::MAX));
    }

    #[test]
    fn distribution_is_uniform() {
        let m = 65537;
        let backends = make_backends(5);
        let table = LookupTable::build(&backends, m).unwrap();

        let mut counts = vec![0usize; backends.len()];
        for &entry in table.entries() {
            counts[entry] += 1;
        }

        let expected = m / backends.len();
        for count in &counts {
            // Each backend should get within 1 of m/n
            assert!(
                (*count as isize - expected as isize).unsigned_abs() <= 1,
                "count {count} far from expected {expected}"
            );
        }
    }

    #[test]
    fn deterministic_build() {
        let backends = make_backends(10);
        let t1 = LookupTable::build(&backends, 65537).unwrap();
        let t2 = LookupTable::build(&backends, 65537).unwrap();
        assert_eq!(t1.entries(), t2.entries());
    }

    #[test]
    fn minimal_disruption_on_removal() {
        let m = 65537;
        let backends_full = make_backends(10);
        let backends_minus_one = make_backends(9);

        let t1 = LookupTable::build(&backends_full, m).unwrap();
        let t2 = LookupTable::build(&backends_minus_one, m).unwrap();

        let changed = t1
            .entries()
            .iter()
            .zip(t2.entries())
            .filter(|(&a, &b)| a != b)
            .count();

        // Removing 1 backend from 10 should affect roughly 1/10 of entries
        let max_expected = m / 5; // generous upper bound: 20%
        assert!(
            changed < max_expected,
            "changed {changed} entries, expected < {max_expected}"
        );
    }

    #[test]
    fn single_backend_all_slots() {
        let backends = make_backends(1);
        let table = LookupTable::build(&backends, 17).unwrap();
        assert!(table.entries().iter().all(|&e| e == 0));
    }

    #[test]
    fn empty_backends_returns_error() {
        let result = LookupTable::build(&[], 17);
        assert!(result.is_err());
    }

    #[test]
    fn all_zero_weight_backends_returns_error() {
        let mut backends = make_backends(2);
        for b in &mut backends {
            b.weight = 0;
        }
        let result = LookupTable::build(&backends, 17);
        assert!(result.is_err());
    }

    #[test]
    fn weight_zero_backend_is_excluded() {
        let mut backends = make_backends(3);
        backends[1].weight = 0; // drain the middle one
        let table = LookupTable::build(&backends, 65537).unwrap();
        assert_eq!(table.num_backends(), 2);
        // The zero-weight backend's IP never appears in the lookup result.
        let drained_ip = backends[1].ip;
        for hash in 0..1000u64 {
            assert_ne!(table.lookup(hash).ip, drained_ip);
        }
    }

    #[test]
    fn higher_weight_takes_proportionally_more_slots() {
        let m = 65537;
        let mut backends = make_backends(3);
        backends[0].weight = 1;
        backends[1].weight = 2;
        backends[2].weight = 3;
        let total: u32 = backends.iter().map(|b| b.weight).sum();

        let table = LookupTable::build(&backends, m).unwrap();
        let mut counts = vec![0usize; backends.len()];
        for &entry in table.entries() {
            counts[entry] += 1;
        }

        // Each backend should land within ~5% of its expected share. Maglev's
        // iterative fill never hits the analytic ratio exactly because of
        // collisions, but should be close at m=65537.
        for (i, &count) in counts.iter().enumerate() {
            let expected = (m as u32 * backends[i].weight / total) as usize;
            let tolerance = expected / 20 + 1;
            assert!(
                (count as isize - expected as isize).unsigned_abs() <= tolerance,
                "backend {i}: weight={} got {count} entries, expected ~{expected} (±{tolerance})",
                backends[i].weight
            );
        }
    }

    #[test]
    fn lookup_returns_valid_backend() {
        let backends = make_backends(5);
        let table = LookupTable::build(&backends, 65537).unwrap();
        let b = table.lookup(12345);
        assert!(backends.contains(b));
    }

    #[test]
    fn same_hash_same_backend() {
        let backends = make_backends(5);
        let table = LookupTable::build(&backends, 65537).unwrap();
        let b1 = table.lookup(99999);
        let b2 = table.lookup(99999);
        assert_eq!(b1, b2);
    }
}
