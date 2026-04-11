use xxhash_rust::xxh3::xxh3_64_with_seed;

/// Derive the `offset` for a backend's preference list.
/// Uses xxh3 with seed 0.
pub fn offset(name: &[u8], m: usize) -> usize {
    (xxh3_64_with_seed(name, 0) % m as u64) as usize
}

/// Derive the `skip` for a backend's preference list.
/// Uses xxh3 with seed 1. Result is in [1, M-1].
pub fn skip(name: &[u8], m: usize) -> usize {
    (xxh3_64_with_seed(name, 1) % (m as u64 - 1) + 1) as usize
}

/// Generate the preference list for a backend: an iterator over
/// slot indices the backend prefers, in order.
pub fn preference_list(name: &[u8], m: usize) -> impl Iterator<Item = usize> {
    let o = offset(name, m);
    let s = skip(name, m);
    (0..m).map(move |j| (o + j * s) % m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_within_range() {
        let m = 65537;
        let o = offset(b"10.0.0.1:443", m);
        assert!(o < m);
    }

    #[test]
    fn skip_within_range() {
        let m = 65537;
        let s = skip(b"10.0.0.1:443", m);
        assert!(s >= 1);
        assert!(s < m);
    }

    #[test]
    fn preference_list_covers_all_slots() {
        let m = 17; // small prime for testing
        let prefs: Vec<usize> = preference_list(b"backend-1", m).collect();
        assert_eq!(prefs.len(), m);
        let mut seen = vec![false; m];
        for &p in &prefs {
            seen[p] = true;
        }
        // Since m is prime and skip is in [1, m-1], the permutation visits all slots
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn deterministic() {
        let m = 65537;
        let o1 = offset(b"test", m);
        let o2 = offset(b"test", m);
        assert_eq!(o1, o2);
    }
}
