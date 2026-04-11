use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A single entry in the connection tracking table.
#[derive(Clone)]
struct ConnEntry {
    hash: u64,
    backend_ip: IpAddr,
    last_seen: Instant,
    occupied: bool,
}

/// Fixed-size per-thread connection tracking table.
///
/// Uses open addressing with Robin Hood hashing. Size must be a power of two.
/// Entries expire after a configurable TTL and are lazily reclaimed on collision.
///
/// Robin Hood hashing keeps probe distances balanced: on insert, if the new entry
/// has traveled farther from its home slot than the incumbent, they swap. This
/// bounds worst-case probe length and — critically — allows miss lookups to
/// early-terminate when the current probe distance exceeds the incumbent's,
/// because no matching entry could be further out. At 95% fill, miss cost drops
/// from O(1/(1-α)²) ≈ 400 probes (plain linear) to O(ln n) ≈ 12 probes.
pub struct ConnTable {
    entries: Vec<ConnEntry>,
    mask: usize,
    ttl: Duration,
    size: usize, // current number of occupied entries
}

impl ConnTable {
    /// Create a new connection table. `capacity` must be a power of two.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be power of two");
        let init_time = Instant::now();
        let empty = ConnEntry {
            hash: 0,
            backend_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            last_seen: init_time,
            occupied: false,
        };
        Self {
            entries: vec![empty; capacity],
            mask: capacity - 1,
            ttl,
            size: 0,
        }
    }

    /// Probe distance: how far `idx` is from the home slot for `hash`.
    #[inline(always)]
    fn probe_distance(&self, hash: u64, idx: usize) -> usize {
        let home = (hash as usize) & self.mask;
        (idx.wrapping_sub(home)) & self.mask
    }

    /// Look up a backend for a given flow hash.
    /// Returns `Some(backend_ip)` if found and not expired.
    ///
    /// `now` should be grabbed once per batch (via `Instant::now()`) and reused
    /// for all lookups in that batch to avoid per-packet clock_gettime overhead.
    pub fn get(&self, hash: u64, now: Instant) -> Option<IpAddr> {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.mask + 1;

        for dist in 0..capacity {
            let entry = &self.entries[idx];
            if !entry.occupied {
                return None;
            }
            // Robin Hood early termination: if this entry's probe distance is
            // shorter than ours, our key can't be further along — it would have
            // displaced this entry during insert.
            if self.probe_distance(entry.hash, idx) < dist {
                return None;
            }
            if entry.hash == hash {
                if now.duration_since(entry.last_seen) > self.ttl {
                    return None; // expired
                }
                return Some(entry.backend_ip);
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    /// Insert or update a connection tracking entry.
    /// If the table is full, the entry is not stored (fallback to pure hashing).
    ///
    /// Uses Robin Hood insertion: when the new entry has probed farther than the
    /// incumbent, swap them and continue inserting the displaced entry. This
    /// equalizes probe distances across all entries.
    ///
    /// `now` should be grabbed once per batch and reused for all inserts.
    pub fn insert(&mut self, hash: u64, backend_ip: IpAddr, now: Instant) {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.mask + 1;

        let mut cur_hash = hash;
        let mut cur_ip = backend_ip;
        let mut cur_time = now;
        let mut dist = 0usize;

        for _ in 0..capacity {
            let entry = &self.entries[idx];

            if !entry.occupied || now.duration_since(entry.last_seen) > self.ttl {
                // Empty or expired slot: take it
                let was_occupied = self.entries[idx].occupied;
                self.entries[idx] = ConnEntry {
                    hash: cur_hash,
                    backend_ip: cur_ip,
                    last_seen: cur_time,
                    occupied: true,
                };
                if !was_occupied {
                    self.size += 1;
                }
                return;
            }
            if entry.hash == cur_hash {
                // Update existing entry
                self.entries[idx].backend_ip = cur_ip;
                self.entries[idx].last_seen = cur_time;
                return;
            }

            // Robin Hood: if the incumbent is richer (shorter probe distance), steal its slot
            let incumbent_dist = self.probe_distance(entry.hash, idx);
            if incumbent_dist < dist {
                let displaced_hash = entry.hash;
                let displaced_ip = entry.backend_ip;
                let displaced_time = entry.last_seen;
                self.entries[idx] = ConnEntry {
                    hash: cur_hash,
                    backend_ip: cur_ip,
                    last_seen: cur_time,
                    occupied: true,
                };
                cur_hash = displaced_hash;
                cur_ip = displaced_ip;
                cur_time = displaced_time;
                dist = incumbent_dist;
            }

            idx = (idx + 1) & self.mask;
            dist += 1;
        }
        // Table full, don't insert (spec: fallback to pure consistent hashing)
    }

    /// Touch an entry to refresh its timestamp (on cache hit).
    ///
    /// `now` should be grabbed once per batch and reused.
    pub fn touch(&mut self, hash: u64, now: Instant) {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.mask + 1;

        for dist in 0..capacity {
            let entry = &self.entries[idx];
            if !entry.occupied {
                return;
            }
            if self.probe_distance(entry.hash, idx) < dist {
                return; // Robin Hood early termination
            }
            if entry.hash == hash {
                self.entries[idx].last_seen = now;
                return;
            }
            idx = (idx + 1) & self.mask;
        }
    }

    /// Current number of occupied entries.
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn insert_and_get() {
        let now = Instant::now();
        let mut table = ConnTable::new(64, Duration::from_secs(60));
        table.insert(42, ip(1), now);
        assert_eq!(table.get(42, now), Some(ip(1)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn miss_on_empty() {
        let table = ConnTable::new(64, Duration::from_secs(60));
        assert_eq!(table.get(42, Instant::now()), None);
    }

    #[test]
    fn update_existing() {
        let now = Instant::now();
        let mut table = ConnTable::new(64, Duration::from_secs(60));
        table.insert(42, ip(1), now);
        table.insert(42, ip(2), now);
        assert_eq!(table.get(42, now), Some(ip(2)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn collision_handling() {
        let now = Instant::now();
        // With capacity 4 (mask=3), hashes 0 and 4 collide at index 0
        let mut table = ConnTable::new(4, Duration::from_secs(60));
        table.insert(0, ip(1), now);
        table.insert(4, ip(2), now); // collides, probes to index 1
        assert_eq!(table.get(0, now), Some(ip(1)));
        assert_eq!(table.get(4, now), Some(ip(2)));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn robin_hood_rebalances_probes() {
        let now = Instant::now();
        // With capacity 8 (mask=7):
        // Insert hash=0 → slot 0 (dist 0)
        // Insert hash=8 → collides at slot 0, probes to slot 1 (dist 1)
        // Insert hash=1 → home is slot 1, but hash=8 is there with dist 1.
        //   hash=1 has dist 0 at slot 1, so it doesn't displace (incumbent dist >= ours).
        //   hash=1 probes to slot 2 (dist 1).
        // Insert hash=16 → collides at slot 0, probes to slot 1 (dist 1).
        //   At slot 1: hash=8 has dist 1, we have dist 1 — no swap.
        //   Probes to slot 2 (dist 2): hash=1 has dist 1, we have dist 2 — swap!
        //   Now hash=1 continues from slot 2 with dist 1, probes to slot 3.
        let mut table = ConnTable::new(8, Duration::from_secs(60));
        table.insert(0, ip(1), now);
        table.insert(8, ip(2), now);
        table.insert(1, ip(3), now);
        table.insert(16, ip(4), now);

        // All entries should still be retrievable
        assert_eq!(table.get(0, now), Some(ip(1)));
        assert_eq!(table.get(8, now), Some(ip(2)));
        assert_eq!(table.get(1, now), Some(ip(3)));
        assert_eq!(table.get(16, now), Some(ip(4)));
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn miss_early_terminates() {
        let now = Instant::now();
        // Insert entries that cluster at slot 0
        let mut table = ConnTable::new(16, Duration::from_secs(60));
        table.insert(0, ip(1), now);  // slot 0
        table.insert(16, ip(2), now); // slot 1 (displaced from 0)

        // Lookup a hash that maps to slot 0 but doesn't exist.
        // Robin Hood guarantees it can stop probing early when probe distance
        // exceeds the incumbent's distance.
        assert_eq!(table.get(32, now), None);
    }

    #[test]
    fn ttl_expiry() {
        let mut table = ConnTable::new(64, Duration::from_millis(1));
        table.insert(42, ip(1), Instant::now());
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(table.get(42, Instant::now()), None);
    }

    #[test]
    fn expired_entry_reclaimed_on_insert() {
        let mut table = ConnTable::new(4, Duration::from_millis(1));
        table.insert(0, ip(1), Instant::now());
        std::thread::sleep(Duration::from_millis(5));
        let now = Instant::now();
        // Insert at same slot: should reclaim the expired entry
        table.insert(4, ip(2), now);
        assert_eq!(table.get(4, now), Some(ip(2)));
        assert_eq!(table.get(0, now), None);
    }

    #[test]
    fn full_table_does_not_panic() {
        let now = Instant::now();
        let mut table = ConnTable::new(4, Duration::from_secs(60));
        for i in 0..4 {
            table.insert(i * 7, ip(i as u8 + 1), now); // spread hashes
        }
        // Table is full, this should not panic or insert
        table.insert(999, ip(99), now);
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn high_fill_all_entries_retrievable() {
        let now = Instant::now();
        let capacity = 64;
        let fill = capacity * 90 / 100; // 90% fill
        let mut table = ConnTable::new(capacity, Duration::from_secs(60));

        let keys: Vec<u64> = (0..fill as u64).map(|i| i * 31 + 7).collect();
        for (i, &k) in keys.iter().enumerate() {
            table.insert(k, ip((i % 254) as u8 + 1), now);
        }

        // Every inserted key must be retrievable
        for (i, &k) in keys.iter().enumerate() {
            assert_eq!(
                table.get(k, now),
                Some(ip((i % 254) as u8 + 1)),
                "missing key {k} at index {i}"
            );
        }
    }
}
