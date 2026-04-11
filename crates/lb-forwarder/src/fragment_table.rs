use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Entry in the fragment table mapping a 3-tuple to the backend selected for the first fragment.
#[derive(Clone)]
struct FragmentEntry {
    hash: u64,
    backend_ip: IpAddr,
    inserted_at: Instant,
    occupied: bool,
}

/// Fixed-size table for tracking IP fragment → backend mapping.
///
/// Uses open addressing with Robin Hood hashing, same strategy as ConnTable.
/// Entries expire after a configurable TTL (default: 10 seconds).
pub struct FragmentTable {
    entries: Vec<FragmentEntry>,
    mask: usize,
    ttl: Duration,
}

impl FragmentTable {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity.is_power_of_two());
        let init_time = Instant::now();
        let empty = FragmentEntry {
            hash: 0,
            backend_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            inserted_at: init_time,
            occupied: false,
        };
        Self {
            entries: vec![empty; capacity],
            mask: capacity - 1,
            ttl,
        }
    }

    #[inline(always)]
    fn probe_distance(&self, hash: u64, idx: usize) -> usize {
        let home = (hash as usize) & self.mask;
        (idx.wrapping_sub(home)) & self.mask
    }

    /// Look up the backend for a fragment 3-tuple hash.
    ///
    /// `now` should be grabbed once per batch and reused.
    pub fn get(&self, hash: u64, now: Instant) -> Option<IpAddr> {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.mask + 1;

        for dist in 0..capacity {
            let entry = &self.entries[idx];
            if !entry.occupied {
                return None;
            }
            if self.probe_distance(entry.hash, idx) < dist {
                return None; // Robin Hood early termination
            }
            if entry.hash == hash {
                if now.duration_since(entry.inserted_at) > self.ttl {
                    return None;
                }
                return Some(entry.backend_ip);
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    /// Insert a fragment → backend mapping (for first fragments).
    ///
    /// `now` should be grabbed once per batch and reused.
    pub fn insert(&mut self, hash: u64, backend_ip: IpAddr, now: Instant) {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.mask + 1;

        let mut cur_hash = hash;
        let mut cur_ip = backend_ip;
        let mut cur_time = now;
        let mut dist = 0usize;

        for _ in 0..capacity {
            let entry = &self.entries[idx];

            if !entry.occupied || now.duration_since(entry.inserted_at) > self.ttl || entry.hash == cur_hash {
                self.entries[idx] = FragmentEntry {
                    hash: cur_hash,
                    backend_ip: cur_ip,
                    inserted_at: cur_time,
                    occupied: true,
                };
                return;
            }

            // Robin Hood: steal from richer entries
            let incumbent_dist = self.probe_distance(entry.hash, idx);
            if incumbent_dist < dist {
                let displaced_hash = entry.hash;
                let displaced_ip = entry.backend_ip;
                let displaced_time = entry.inserted_at;
                self.entries[idx] = FragmentEntry {
                    hash: cur_hash,
                    backend_ip: cur_ip,
                    inserted_at: cur_time,
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
        // Table full, don't insert
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
        let mut table = FragmentTable::new(64, Duration::from_secs(10));
        table.insert(42, ip(1), now);
        assert_eq!(table.get(42, now), Some(ip(1)));
    }

    #[test]
    fn miss_on_empty() {
        let table = FragmentTable::new(64, Duration::from_secs(10));
        assert_eq!(table.get(42, Instant::now()), None);
    }

    #[test]
    fn ttl_expiry() {
        let mut table = FragmentTable::new(64, Duration::from_millis(1));
        table.insert(42, ip(1), Instant::now());
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(table.get(42, Instant::now()), None);
    }

    #[test]
    fn same_hash_returns_same_backend() {
        let now = Instant::now();
        let mut table = FragmentTable::new(64, Duration::from_secs(10));
        table.insert(100, ip(5), now);
        assert_eq!(table.get(100, now), Some(ip(5)));
        assert_eq!(table.get(100, now), Some(ip(5)));
    }

    #[test]
    fn robin_hood_rebalances() {
        let now = Instant::now();
        let mut table = FragmentTable::new(8, Duration::from_secs(10));
        table.insert(0, ip(1), now);
        table.insert(8, ip(2), now); // collides at slot 0
        table.insert(16, ip(3), now); // collides at slot 0

        assert_eq!(table.get(0, now), Some(ip(1)));
        assert_eq!(table.get(8, now), Some(ip(2)));
        assert_eq!(table.get(16, now), Some(ip(3)));
    }

    #[test]
    fn miss_early_terminates() {
        let now = Instant::now();
        let mut table = FragmentTable::new(16, Duration::from_secs(10));
        table.insert(0, ip(1), now);
        table.insert(16, ip(2), now);
        // Hash 32 maps to slot 0 but doesn't exist — Robin Hood early terminates
        assert_eq!(table.get(32, now), None);
    }
}
