//! Pre-allocated packet frame arena.
//!
//! Packets are never copied between threads — only `FrameIndex` (u32) values
//! flow through the SPSC queues. Each frame is a fixed 2048-byte buffer that
//! steering, rewriters, and the muxer access by index into a shared `Arc<PacketPool>`.
//!
//! Frame lifecycle:
//! ```text
//!   free list → [Steering alloc] → rx_queue → [Rewriter mutate] → tx_queue → [Muxer send] → free list
//! ```
//!
//! The free list is a lock-free ring (crossbeam ArrayQueue) shared between
//! the muxer (producer: returns frames after TX) and steering (consumer:
//! allocates frames for RX). This mirrors AF_XDP's UMEM completion queue.

use crossbeam::queue::ArrayQueue;
use lb_io::PACKET_BUF_SIZE;

/// Index into the `PacketPool` frame array.
pub type FrameIndex = u32;

/// Sentinel value for an invalid/uninitialized frame index.
pub const INVALID_FRAME: FrameIndex = u32::MAX;

/// A single frame in the pool.
#[repr(C)]
pub struct Frame {
    pub data: [u8; PACKET_BUF_SIZE],
    pub len: usize,
}

impl Frame {
    fn new() -> Self {
        Self {
            data: [0u8; PACKET_BUF_SIZE],
            len: 0,
        }
    }

    /// Write packet data into this frame.
    #[inline]
    pub fn write_from(&mut self, src: &[u8]) {
        let copy_len = src.len().min(PACKET_BUF_SIZE);
        self.data[..copy_len].copy_from_slice(&src[..copy_len]);
        self.len = copy_len;
    }

    /// Get the valid packet data as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Pre-allocated arena of packet frames.
///
/// Thread safety: the pool itself is read-only (accessed via `Arc`). Each frame
/// is mutated by exactly one thread at a time — enforced by who holds the
/// `FrameIndex`. Interior mutability is provided via `UnsafeCell` since we
/// guarantee single-writer access through the index ownership protocol.
pub struct PacketPool {
    frames: Vec<std::cell::UnsafeCell<Frame>>,
    free_list: ArrayQueue<FrameIndex>,
    capacity: usize,
}

// Safety: frames are accessed by exactly one thread at a time, enforced by
// the FrameIndex ownership protocol (only one thread holds a given index).
unsafe impl Send for PacketPool {}
unsafe impl Sync for PacketPool {}

impl PacketPool {
    /// Create a new pool with `capacity` pre-allocated frames.
    /// All frames start on the free list.
    pub fn new(capacity: usize) -> Self {
        let mut frames = Vec::with_capacity(capacity);
        let free_list = ArrayQueue::new(capacity);

        for i in 0..capacity {
            frames.push(std::cell::UnsafeCell::new(Frame::new()));
            let _ = free_list.push(i as FrameIndex);
        }

        Self {
            frames,
            free_list,
            capacity,
        }
    }

    /// Allocate a frame from the free list. Returns `None` if exhausted.
    #[inline]
    pub fn alloc(&self) -> Option<FrameIndex> {
        self.free_list.pop()
    }

    /// Return a frame to the free list after the muxer has sent it.
    #[inline]
    pub fn free(&self, idx: FrameIndex) {
        debug_assert!((idx as usize) < self.capacity);
        let _ = self.free_list.push(idx);
    }

    /// Get a mutable reference to a frame by index.
    ///
    /// # Safety
    /// Caller must guarantee exclusive access to this frame index (i.e., no other
    /// thread holds the same index). This is enforced by the SPSC queue protocol.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    pub fn get_mut(&self, idx: FrameIndex) -> &mut Frame {
        debug_assert!((idx as usize) < self.capacity);
        unsafe { &mut *self.frames[idx as usize].get() }
    }

    /// Get a read-only reference to a frame by index.
    ///
    /// # Safety
    /// Caller must hold the index (single-owner protocol).
    #[inline]
    pub fn get(&self, idx: FrameIndex) -> &Frame {
        debug_assert!((idx as usize) < self.capacity);
        unsafe { &*self.frames[idx as usize].get() }
    }

    /// Number of frames currently on the free list.
    pub fn available(&self) -> usize {
        self.free_list.len()
    }

    /// Total capacity of the pool.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn alloc_and_free() {
        let pool = PacketPool::new(4);
        assert_eq!(pool.available(), 4);

        let idx = pool.alloc().unwrap();
        assert_eq!(pool.available(), 3);

        pool.free(idx);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn exhaust_pool() {
        let pool = PacketPool::new(2);
        let _a = pool.alloc().unwrap();
        let _b = pool.alloc().unwrap();
        assert!(pool.alloc().is_none());
    }

    #[test]
    fn write_and_read_frame() {
        let pool = PacketPool::new(1);
        let idx = pool.alloc().unwrap();

        let frame = pool.get_mut(idx);
        frame.write_from(&[0x45, 0x00, 0x00, 0x28]);
        assert_eq!(frame.len, 4);
        assert_eq!(&frame.as_slice()[..4], &[0x45, 0x00, 0x00, 0x28]);

        pool.free(idx);
    }

    #[test]
    fn frames_are_independent() {
        let pool = PacketPool::new(2);
        let a = pool.alloc().unwrap();
        let b = pool.alloc().unwrap();

        pool.get_mut(a).write_from(&[0xAA; 10]);
        pool.get_mut(b).write_from(&[0xBB; 10]);

        assert_eq!(pool.get(a).as_slice(), &[0xAA; 10]);
        assert_eq!(pool.get(b).as_slice(), &[0xBB; 10]);

        pool.free(a);
        pool.free(b);
    }

    #[test]
    fn cross_thread_access() {
        let pool = Arc::new(PacketPool::new(64));

        let pool_writer = Arc::clone(&pool);
        let idx = pool.alloc().unwrap();

        let handle = std::thread::spawn(move || {
            let frame = pool_writer.get_mut(idx);
            frame.write_from(&[0xDE, 0xAD]);
            idx
        });

        let returned_idx = handle.join().unwrap();
        assert_eq!(pool.get(returned_idx).as_slice(), &[0xDE, 0xAD]);
        pool.free(returned_idx);
    }
}
