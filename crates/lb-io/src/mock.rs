use crate::{PacketBuf, PacketIo};
use crossbeam::queue::ArrayQueue;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Shared state between MockIo and MockIoHandle.
#[derive(Debug, Default)]
struct MockIoInner {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

/// The I/O side used by the forwarder (implements PacketIo).
pub struct MockIo {
    inner: Arc<Mutex<MockIoInner>>,
}

/// The test-side handle for injecting and reading packets.
pub struct MockIoHandle {
    inner: Arc<Mutex<MockIoInner>>,
}

/// Create a paired MockIo + MockIoHandle.
pub fn mock_io() -> (MockIo, MockIoHandle) {
    let inner = Arc::new(Mutex::new(MockIoInner::default()));
    (
        MockIo {
            inner: Arc::clone(&inner),
        },
        MockIoHandle { inner },
    )
}

impl MockIoHandle {
    /// Inject a packet into the RX queue (will be received by the forwarder).
    pub fn inject_packet(&self, data: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        inner.rx.push_back(data.to_vec());
    }

    /// Read a transmitted packet from the TX queue.
    pub fn read_transmitted(&self) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();
        inner.tx.pop_front()
    }

    /// Number of packets in the TX queue.
    pub fn tx_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.tx.len()
    }

    /// Number of packets in the RX queue.
    pub fn rx_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.rx.len()
    }
}

impl PacketIo for MockIo {
    fn recv_batch(&mut self, buf: &mut [PacketBuf]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        let mut count = 0;
        for slot in buf.iter_mut() {
            if let Some(data) = inner.rx.pop_front() {
                *slot = PacketBuf::from_slice(&data);
                count += 1;
            } else {
                break;
            }
        }
        Ok(count)
    }

    fn send_batch(&mut self, buf: &[PacketBuf]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        for pkt in buf {
            if pkt.len > 0 {
                inner.tx.push_back(pkt.as_slice().to_vec());
            }
        }
        Ok(buf.iter().filter(|p| p.len > 0).count())
    }
}

// ---------------------------------------------------------------------------
// Lock-free mock: uses atomic ring buffers instead of Mutex.
// Suitable for benchmarks where Mutex overhead would distort measurements.
// ---------------------------------------------------------------------------

const LOCKFREE_RING_SIZE: usize = 8192;

/// Lock-free I/O side used by the forwarder (implements PacketIo).
pub struct MockIoLockFree {
    rx: Arc<ArrayQueue<PacketBuf>>,
    tx: Arc<ArrayQueue<PacketBuf>>,
    tx_count: Arc<AtomicUsize>,
}

/// Lock-free test-side handle for injecting and reading packets.
pub struct MockIoLockFreeHandle {
    rx: Arc<ArrayQueue<PacketBuf>>,
    tx: Arc<ArrayQueue<PacketBuf>>,
    tx_count: Arc<AtomicUsize>,
}

/// Create a paired lock-free MockIo + handle.
///
/// Uses crossbeam `ArrayQueue` (lock-free bounded MPMC) instead of `Mutex<VecDeque>`,
/// eliminating artificial lock contention in benchmarks. This reflects production
/// topology where NIC rings are lockless.
pub fn mock_io_lockfree() -> (MockIoLockFree, MockIoLockFreeHandle) {
    let rx = Arc::new(ArrayQueue::new(LOCKFREE_RING_SIZE));
    let tx = Arc::new(ArrayQueue::new(LOCKFREE_RING_SIZE));
    let tx_count = Arc::new(AtomicUsize::new(0));
    (
        MockIoLockFree {
            rx: Arc::clone(&rx),
            tx: Arc::clone(&tx),
            tx_count: Arc::clone(&tx_count),
        },
        MockIoLockFreeHandle { rx, tx, tx_count },
    )
}

impl MockIoLockFreeHandle {
    /// Inject a packet into the RX ring (will be received by the forwarder).
    pub fn inject_packet(&self, data: &[u8]) {
        let _ = self.rx.push(PacketBuf::from_slice(data));
    }

    /// Read a transmitted packet from the TX ring.
    pub fn read_transmitted(&self) -> Option<PacketBuf> {
        self.tx.pop()
    }

    /// Number of packets transmitted (monotonically increasing).
    pub fn tx_count(&self) -> usize {
        self.tx_count.load(Ordering::Relaxed)
    }
}

impl PacketIo for MockIoLockFree {
    fn recv_batch(&mut self, buf: &mut [PacketBuf]) -> io::Result<usize> {
        let mut count = 0;
        for slot in buf.iter_mut() {
            match self.rx.pop() {
                Some(pkt) => {
                    *slot = pkt;
                    count += 1;
                }
                None => break,
            }
        }
        Ok(count)
    }

    fn send_batch(&mut self, buf: &[PacketBuf]) -> io::Result<usize> {
        let mut count = 0;
        for pkt in buf {
            if pkt.len > 0 {
                let _ = self.tx.push(pkt.clone());
                count += 1;
            }
        }
        self.tx_count.fetch_add(count, Ordering::Relaxed);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (mut io, handle) = mock_io();

        for i in 0..10 {
            handle.inject_packet(&[i; 64]);
        }

        let mut buf = vec![PacketBuf::new(); 16];
        let n = io.recv_batch(&mut buf).unwrap();
        assert_eq!(n, 10);

        for (i, entry) in buf.iter().enumerate().take(10) {
            assert_eq!(entry.as_slice(), &[i as u8; 64]);
        }
    }

    #[test]
    fn empty_recv_returns_zero() {
        let (mut io, _handle) = mock_io();
        let mut buf = vec![PacketBuf::new(); 8];
        let n = io.recv_batch(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn send_then_read() {
        let (mut io, handle) = mock_io();

        let pkts = vec![
            PacketBuf::from_slice(&[1, 2, 3]),
            PacketBuf::from_slice(&[4, 5, 6]),
        ];
        let sent = io.send_batch(&pkts).unwrap();
        assert_eq!(sent, 2);
        assert_eq!(handle.tx_count(), 2);

        let pkt1 = handle.read_transmitted().unwrap();
        assert_eq!(pkt1, vec![1, 2, 3]);
        let pkt2 = handle.read_transmitted().unwrap();
        assert_eq!(pkt2, vec![4, 5, 6]);
        assert!(handle.read_transmitted().is_none());
    }

    #[test]
    fn recv_limited_by_buffer_size() {
        let (mut io, handle) = mock_io();
        for _ in 0..10 {
            handle.inject_packet(&[0xAA; 32]);
        }

        let mut buf = vec![PacketBuf::new(); 3];
        let n = io.recv_batch(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(handle.rx_count(), 7); // 7 remaining
    }
}
