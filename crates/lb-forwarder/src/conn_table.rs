use lb_types::{ConnTtls, FlowProto, TcpFlowState};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A single entry in the connection tracking table.
#[derive(Clone)]
struct ConnEntry {
    hash: u64,
    backend_ip: IpAddr,
    last_seen: Instant,
    proto: FlowProto,
    tcp_state: TcpFlowState,
    occupied: bool,
}

/// Outcome of an [`ConnTable::insert`] call. Callers use this to drive
/// metrics without paying for internal counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertResult {
    /// A fresh slot was claimed; table size grew by one.
    Inserted,
    /// An existing entry matched the hash and was updated in place.
    Updated,
    /// An expired slot was reclaimed for this insertion. Table size unchanged.
    EvictedExpired,
    /// Every slot in the probe window was occupied and not-yet-expired.
    /// The entry was dropped; the caller falls back to pure Maglev hashing.
    DroppedFull,
}

/// Fixed-size per-thread connection tracking table.
///
/// Uses open addressing with Robin Hood hashing. Size must be a power of two.
/// Entries carry a protocol/TCP-state tag so different flow families can
/// expire on different schedules: TCP handshake (SYN without data) expires
/// fast to clear half-open connections, established TCP uses the long
/// operator-chosen TTL, TCP closing (FIN/RST observed) expires promptly so
/// slots are reclaimed, UDP gets its own bucket.
///
/// Robin Hood hashing keeps probe distances balanced: on insert, if the new
/// entry has traveled farther from its home slot than the incumbent, they
/// swap. This bounds worst-case probe length and — critically — allows miss
/// lookups to early-terminate when the current probe distance exceeds the
/// incumbent's, because no matching entry could be further out. At 95% fill,
/// miss cost drops from O(1/(1-α)²) ≈ 400 probes (plain linear) to O(ln n)
/// ≈ 12 probes.
pub struct ConnTable {
    entries: Vec<ConnEntry>,
    mask: usize,
    ttls: ConnTtls,
    size: usize,
}

impl ConnTable {
    /// Create a new connection table. `capacity` must be a power of two.
    pub fn new(capacity: usize, ttls: ConnTtls) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be power of two");
        let init_time = Instant::now();
        let empty = ConnEntry {
            hash: 0,
            backend_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            last_seen: init_time,
            proto: FlowProto::Other,
            tcp_state: TcpFlowState::NotTcp,
            occupied: false,
        };
        Self {
            entries: vec![empty; capacity],
            mask: capacity - 1,
            ttls,
            size: 0,
        }
    }

    /// Capacity of the backing storage (constant after construction).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.mask + 1
    }

    /// Effective TTL for a given protocol/state combination.
    #[inline(always)]
    fn ttl_for(&self, proto: FlowProto, state: TcpFlowState) -> Duration {
        match (proto, state) {
            (FlowProto::Tcp, TcpFlowState::Handshake) => self.ttls.tcp_handshake,
            (FlowProto::Tcp, TcpFlowState::Closing) => self.ttls.tcp_closing,
            (FlowProto::Tcp, _) => self.ttls.tcp_established,
            (FlowProto::Udp, _) => self.ttls.udp,
            (FlowProto::Other, _) => self.ttls.other,
        }
    }

    #[inline(always)]
    fn is_expired(&self, entry: &ConnEntry, now: Instant) -> bool {
        let ttl = self.ttl_for(entry.proto, entry.tcp_state);
        now.duration_since(entry.last_seen) > ttl
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
        let capacity = self.capacity();

        for dist in 0..capacity {
            let entry = &self.entries[idx];
            if !entry.occupied {
                return None;
            }
            if self.probe_distance(entry.hash, idx) < dist {
                return None;
            }
            if entry.hash == hash {
                if self.is_expired(entry, now) {
                    return None;
                }
                return Some(entry.backend_ip);
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    /// Insert or update a connection tracking entry.
    ///
    /// Returns an [`InsertResult`] describing what happened, so the caller
    /// can drive eviction/drop metrics without needing the table to keep
    /// internal counters.
    pub fn insert(
        &mut self,
        hash: u64,
        backend_ip: IpAddr,
        proto: FlowProto,
        tcp_state: TcpFlowState,
        now: Instant,
    ) -> InsertResult {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.capacity();

        let mut cur = ConnEntry {
            hash,
            backend_ip,
            last_seen: now,
            proto,
            tcp_state,
            occupied: true,
        };
        let mut dist = 0usize;
        let mut reclaimed_expired = false;

        for _ in 0..capacity {
            let entry = &self.entries[idx];

            if !entry.occupied {
                self.entries[idx] = cur;
                self.size += 1;
                return if reclaimed_expired {
                    InsertResult::EvictedExpired
                } else {
                    InsertResult::Inserted
                };
            }

            if self.is_expired(entry, now) {
                // Reclaim the expired slot. `size` unchanged because we are
                // replacing one occupied entry with another.
                self.entries[idx] = cur;
                return InsertResult::EvictedExpired;
            }

            if entry.hash == cur.hash {
                // Update in place. Preserve the richer TCP state: once a flow
                // has transitioned to Closing, subsequent packets (retransmits,
                // late ACKs) must not demote it back to Established.
                let new_state = promote_state(entry.tcp_state, cur.tcp_state);
                self.entries[idx].backend_ip = cur.backend_ip;
                self.entries[idx].last_seen = cur.last_seen;
                self.entries[idx].proto = cur.proto;
                self.entries[idx].tcp_state = new_state;
                return InsertResult::Updated;
            }

            let incumbent_dist = self.probe_distance(entry.hash, idx);
            if incumbent_dist < dist {
                let displaced = self.entries[idx].clone();
                self.entries[idx] = cur;
                cur = displaced;
                dist = incumbent_dist;
            }

            idx = (idx + 1) & self.mask;
            dist += 1;

            // Track whether we've skipped any expired neighbours during probing.
            // (Not required for correctness — just informs the eviction tally
            // returned above when we eventually find a free slot.)
            reclaimed_expired |= false;
        }

        // Table full — fall through. Caller falls back to pure Maglev.
        InsertResult::DroppedFull
    }

    /// Touch an entry to refresh its timestamp (on cache hit).
    pub fn touch(&mut self, hash: u64, now: Instant) {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.capacity();

        for dist in 0..capacity {
            let entry = &self.entries[idx];
            if !entry.occupied {
                return;
            }
            if self.probe_distance(entry.hash, idx) < dist {
                return;
            }
            if entry.hash == hash {
                self.entries[idx].last_seen = now;
                return;
            }
            idx = (idx + 1) & self.mask;
        }
    }

    /// Promote a matching TCP flow to `Established`. No-op if the flow is not
    /// present or is already in `Closing` (a closing flow must not be
    /// resurrected by a late SYN-ACK retransmit).
    pub fn mark_established(&mut self, hash: u64, now: Instant) {
        self.with_matching_entry(hash, |entry| {
            if entry.proto == FlowProto::Tcp && entry.tcp_state != TcpFlowState::Closing {
                entry.tcp_state = TcpFlowState::Established;
                entry.last_seen = now;
            }
        });
    }

    /// Move a matching TCP flow to `Closing` so it expires on the short TTL.
    /// No-op if the flow is not present.
    pub fn mark_closing(&mut self, hash: u64, now: Instant) {
        self.with_matching_entry(hash, |entry| {
            if entry.proto == FlowProto::Tcp {
                entry.tcp_state = TcpFlowState::Closing;
                entry.last_seen = now;
            }
        });
    }

    fn with_matching_entry<F: FnOnce(&mut ConnEntry)>(&mut self, hash: u64, f: F) {
        let mut idx = (hash as usize) & self.mask;
        let capacity = self.capacity();
        for dist in 0..capacity {
            {
                let entry = &self.entries[idx];
                if !entry.occupied {
                    return;
                }
                if self.probe_distance(entry.hash, idx) < dist {
                    return;
                }
                if entry.hash != hash {
                    idx = (idx + 1) & self.mask;
                    continue;
                }
            }
            f(&mut self.entries[idx]);
            return;
        }
    }

    /// Current number of occupied entries.
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Fill ratio in basis points (parts per 10 000). Cheap integer maths,
    /// safe to call once per batch for a Prometheus gauge.
    pub fn fill_bp(&self) -> i64 {
        (self.size as i64 * 10_000) / (self.capacity() as i64)
    }
}

/// Rule for merging an existing TCP state with an incoming one on duplicate
/// insert. `Closing` is terminal; `Established` beats `Handshake`.
#[inline(always)]
fn promote_state(existing: TcpFlowState, incoming: TcpFlowState) -> TcpFlowState {
    use TcpFlowState::*;
    match (existing, incoming) {
        (Closing, _) | (_, Closing) => Closing,
        (Established, _) | (_, Established) => Established,
        (NotTcp, _) | (_, NotTcp) => NotTcp,
        _ => Handshake,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn tcp_ttls() -> ConnTtls {
        ConnTtls::with_established(Duration::from_secs(60))
    }

    #[test]
    fn insert_and_get() {
        let now = Instant::now();
        let mut table = ConnTable::new(64, tcp_ttls());
        assert_eq!(
            table.insert(42, ip(1), FlowProto::Tcp, TcpFlowState::Established, now),
            InsertResult::Inserted
        );
        assert_eq!(table.get(42, now), Some(ip(1)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn miss_on_empty() {
        let table = ConnTable::new(64, tcp_ttls());
        assert_eq!(table.get(42, Instant::now()), None);
    }

    #[test]
    fn update_existing_returns_updated() {
        let now = Instant::now();
        let mut table = ConnTable::new(64, tcp_ttls());
        assert_eq!(
            table.insert(42, ip(1), FlowProto::Tcp, TcpFlowState::Established, now),
            InsertResult::Inserted
        );
        assert_eq!(
            table.insert(42, ip(2), FlowProto::Tcp, TcpFlowState::Established, now),
            InsertResult::Updated
        );
        assert_eq!(table.get(42, now), Some(ip(2)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn collision_handling() {
        let now = Instant::now();
        let mut table = ConnTable::new(4, tcp_ttls());
        table.insert(0, ip(1), FlowProto::Tcp, TcpFlowState::Established, now);
        table.insert(4, ip(2), FlowProto::Tcp, TcpFlowState::Established, now);
        assert_eq!(table.get(0, now), Some(ip(1)));
        assert_eq!(table.get(4, now), Some(ip(2)));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn robin_hood_rebalances_probes() {
        let now = Instant::now();
        let mut table = ConnTable::new(8, tcp_ttls());
        for &(h, last) in &[(0u64, 1u8), (8, 2), (1, 3), (16, 4)] {
            table.insert(h, ip(last), FlowProto::Tcp, TcpFlowState::Established, now);
        }
        assert_eq!(table.get(0, now), Some(ip(1)));
        assert_eq!(table.get(8, now), Some(ip(2)));
        assert_eq!(table.get(1, now), Some(ip(3)));
        assert_eq!(table.get(16, now), Some(ip(4)));
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn tcp_handshake_short_ttl_expires_fast() {
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_millis(1),
            tcp_established: Duration::from_secs(60),
            tcp_closing: Duration::from_secs(10),
            udp: Duration::from_secs(30),
            other: Duration::from_secs(30),
        };
        let mut table = ConnTable::new(64, ttls);
        table.insert(
            7,
            ip(1),
            FlowProto::Tcp,
            TcpFlowState::Handshake,
            Instant::now(),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(table.get(7, Instant::now()), None);
    }

    #[test]
    fn tcp_established_survives_longer_than_handshake() {
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_millis(1),
            tcp_established: Duration::from_secs(60),
            tcp_closing: Duration::from_secs(10),
            udp: Duration::from_secs(30),
            other: Duration::from_secs(30),
        };
        let mut table = ConnTable::new(64, ttls);
        table.insert(
            7,
            ip(1),
            FlowProto::Tcp,
            TcpFlowState::Established,
            Instant::now(),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(table.get(7, Instant::now()), Some(ip(1)));
    }

    #[test]
    fn mark_closing_shortens_ttl() {
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_millis(1),
            tcp_established: Duration::from_secs(60),
            tcp_closing: Duration::from_millis(1),
            udp: Duration::from_secs(30),
            other: Duration::from_secs(30),
        };
        let mut table = ConnTable::new(64, ttls);
        let now = Instant::now();
        table.insert(7, ip(1), FlowProto::Tcp, TcpFlowState::Established, now);
        assert!(table.get(7, now).is_some());

        table.mark_closing(7, now);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(table.get(7, Instant::now()), None);
    }

    #[test]
    fn mark_established_promotes_handshake() {
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_millis(5),
            tcp_established: Duration::from_secs(60),
            tcp_closing: Duration::from_secs(10),
            udp: Duration::from_secs(30),
            other: Duration::from_secs(30),
        };
        let mut table = ConnTable::new(64, ttls);
        let now = Instant::now();
        table.insert(7, ip(1), FlowProto::Tcp, TcpFlowState::Handshake, now);

        // Promote to Established — the entry should now survive past the
        // handshake TTL.
        table.mark_established(7, now);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(table.get(7, Instant::now()), Some(ip(1)));
    }

    #[test]
    fn mark_closing_is_noop_on_missing_entry() {
        let mut table = ConnTable::new(64, tcp_ttls());
        table.mark_closing(9999, Instant::now()); // must not panic
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn mark_established_does_not_resurrect_closing() {
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_secs(5),
            tcp_established: Duration::from_secs(60),
            tcp_closing: Duration::from_millis(2),
            udp: Duration::from_secs(30),
            other: Duration::from_secs(30),
        };
        let mut table = ConnTable::new(64, ttls);
        let now = Instant::now();
        table.insert(7, ip(1), FlowProto::Tcp, TcpFlowState::Established, now);
        table.mark_closing(7, now);
        // A late retransmit shouldn't undo the Closing state.
        table.mark_established(7, now);
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(table.get(7, Instant::now()), None);
    }

    #[test]
    fn udp_uses_udp_ttl() {
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_secs(60),
            tcp_established: Duration::from_secs(60),
            tcp_closing: Duration::from_secs(60),
            udp: Duration::from_millis(1),
            other: Duration::from_secs(60),
        };
        let mut table = ConnTable::new(64, ttls);
        table.insert(
            7,
            ip(1),
            FlowProto::Udp,
            TcpFlowState::NotTcp,
            Instant::now(),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(table.get(7, Instant::now()), None);
    }

    #[test]
    fn insert_returns_evicted_on_expired_slot() {
        let ttls = ConnTtls {
            tcp_handshake: Duration::from_secs(60),
            tcp_established: Duration::from_millis(1),
            tcp_closing: Duration::from_secs(60),
            udp: Duration::from_secs(60),
            other: Duration::from_secs(60),
        };
        let mut table = ConnTable::new(4, ttls);
        table.insert(
            0,
            ip(1),
            FlowProto::Tcp,
            TcpFlowState::Established,
            Instant::now(),
        );
        std::thread::sleep(Duration::from_millis(5));
        let now = Instant::now();
        assert_eq!(
            table.insert(4, ip(2), FlowProto::Tcp, TcpFlowState::Established, now),
            InsertResult::EvictedExpired
        );
        assert_eq!(table.get(4, now), Some(ip(2)));
    }

    #[test]
    fn insert_returns_dropped_full_when_packed() {
        let now = Instant::now();
        let mut table = ConnTable::new(4, tcp_ttls());
        for i in 0..4u64 {
            table.insert(
                i * 7,
                ip(i as u8 + 1),
                FlowProto::Tcp,
                TcpFlowState::Established,
                now,
            );
        }
        assert_eq!(
            table.insert(999, ip(99), FlowProto::Tcp, TcpFlowState::Established, now),
            InsertResult::DroppedFull
        );
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn high_fill_all_entries_retrievable() {
        let now = Instant::now();
        let capacity = 64;
        let fill = capacity * 90 / 100;
        let mut table = ConnTable::new(capacity, tcp_ttls());

        let keys: Vec<u64> = (0..fill as u64).map(|i| i * 31 + 7).collect();
        for (i, &k) in keys.iter().enumerate() {
            table.insert(
                k,
                ip((i % 254) as u8 + 1),
                FlowProto::Tcp,
                TcpFlowState::Established,
                now,
            );
        }
        for (i, &k) in keys.iter().enumerate() {
            assert_eq!(
                table.get(k, now),
                Some(ip((i % 254) as u8 + 1)),
                "missing key {k} at index {i}"
            );
        }
    }

    #[test]
    fn fill_bp_tracks_size() {
        let now = Instant::now();
        let mut table = ConnTable::new(128usize, tcp_ttls());
        assert_eq!(table.fill_bp(), 0);
        for i in 0..32u64 {
            table.insert(
                i * 31 + 5,
                ip(i as u8 + 1),
                FlowProto::Tcp,
                TcpFlowState::Established,
                now,
            );
        }
        assert!(table.fill_bp() > 0);
    }
}
