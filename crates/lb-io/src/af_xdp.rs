//! AF_XDP packet I/O backend — **scaffold, not yet functional**.
//!
//! # Status
//!
//! This module is intentionally a scaffold. `AfXdpIo::new` returns
//! `Err(Unsupported)` with a pointer at the work that needs to happen.
//! Until that work lands, the only working backend is `mock`.
//!
//! # Why the scaffold exists
//!
//! The file used to contain ~200 lines of code that *created* an AF_XDP
//! socket via `socket(AF_XDP, SOCK_RAW, 0)` and then attempted to do I/O
//! with plain `recvfrom`/`sendto`. That does not work. An AF_XDP socket
//! requires the full XSK ring setup (UMEM + FILL + RX + TX + COMPLETION
//! rings, plus an attached XDP BPF program) before any traffic flows
//! through it — the kernel won't deliver packets via `recvfrom` on an
//! AF_XDP socket. The old code built in dev-mode but would have failed
//! silently in production (`recv_batch` returning 0 forever, with no
//! error surfaced).
//!
//! Keeping the old code around invited two kinds of lie: the feature flag
//! suggesting "AF_XDP is available", and the build succeeding so CI
//! agreed. Returning `Err(Unsupported)` early is more honest.
//!
//! # Planned implementation
//!
//! The strategic direction is to adopt the [`xdpilone`] crate (or the
//! more mature `libxdp-sys` + hand-written XSK ring helpers) rather
//! than rolling FFI against `libbpf-sys` by hand. The rough shape:
//!
//!   1. Allocate and register UMEM via `XDP_UMEM_REG` setsockopt.
//!   2. Set up FILL, RX, TX, COMPLETION rings via `XDP_MMAP_OFFSETS` /
//!      `XDP_FILL_RING` / `XDP_RX_RING` / `XDP_TX_RING` /
//!      `XDP_UMEM_COMPLETION_RING` setsockopt + mmap.
//!   3. Attach an XDP program to the target interface that redirects
//!      incoming packets into the XSK via `bpf_redirect_map`. The LB
//!      repo doesn't currently own an XDP program; `libxdp` ships a
//!      generic "receive everything" program that works for a first
//!      integration.
//!   4. On `recv_batch`: `xsk_ring_cons__peek` on RX, copy frames out
//!      of UMEM (or expose them zero-copy through `PacketBuf` if we
//!      teach the forwarder about UMEM lifetimes),
//!      `xsk_ring_cons__release`, then refill via `xsk_ring_prod` on
//!      FILL.
//!   5. On `send_batch`: reserve slots on TX via `xsk_ring_prod`,
//!      write frame data into UMEM, submit, then `sendto(socket_fd,
//!      NULL, 0, MSG_DONTWAIT, NULL, 0)` to wake the TX path. Reap
//!      COMPLETION to reclaim slots.
//!
//! Non-trivial decisions deferred until that PR:
//!
//!   * **Zero-copy vs copy through `PacketBuf`**: full zero-copy means
//!     the forwarder must operate on UMEM pointers, which changes the
//!     `PacketIo` trait signature. The initial integration likely copies
//!     at the boundary.
//!   * **Per-thread `AfXdpIo`**: each XSK binds to one queue ID. The
//!     forwarder's steering thread dispatches into per-rewriter queues
//!     today — the XSK topology should mirror that.
//!   * **XDP program loading**: ship our own `.o`, depend on `libxdp`'s
//!     default, or require the operator to load a program manually.
//!
//! [`xdpilone`]: https://docs.rs/xdpilone/

#[cfg(target_os = "linux")]
mod inner {
    use crate::{PacketBuf, PacketIo, PACKET_BUF_SIZE};
    use std::io;

    /// Configuration for the AF_XDP socket.
    ///
    /// The fields are carried over from the previous scaffold so the TOML
    /// schema and call sites don't need to churn when the real
    /// implementation lands.
    #[derive(Debug, Clone)]
    pub struct AfXdpConfig {
        /// Network interface name (e.g., "eth0").
        pub iface: String,
        /// Queue ID to bind to.
        pub queue_id: u32,
        /// Number of frames in the UMEM area.
        pub num_frames: u32,
        /// Size of each frame (must be >= `PACKET_BUF_SIZE`).
        pub frame_size: u32,
    }

    impl Default for AfXdpConfig {
        fn default() -> Self {
            Self {
                iface: "eth0".into(),
                queue_id: 0,
                num_frames: 4096,
                frame_size: PACKET_BUF_SIZE as u32,
            }
        }
    }

    /// AF_XDP socket I/O backend. **Scaffold only — see module docs.**
    pub struct AfXdpIo {
        _never: std::convert::Infallible,
    }

    impl AfXdpIo {
        /// Currently returns `Err(Unsupported)`. The full XSK-ring
        /// implementation is tracked as a follow-up (see module docs).
        pub fn new(_config: &AfXdpConfig) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "AF_XDP backend is not yet implemented — see crates/lb-io/src/af_xdp.rs \
                 for the roadmap. Use io_backend = \"mock\" for now.",
            ))
        }
    }

    impl PacketIo for AfXdpIo {
        fn recv_batch(&mut self, _buf: &mut [PacketBuf]) -> io::Result<usize> {
            match self._never {}
        }

        fn send_batch(&mut self, _buf: &[PacketBuf]) -> io::Result<usize> {
            match self._never {}
        }
    }
}

#[cfg(target_os = "linux")]
pub use inner::{AfXdpConfig, AfXdpIo};

#[cfg(not(target_os = "linux"))]
mod stub {
    use crate::{PacketBuf, PacketIo, PACKET_BUF_SIZE};
    use std::io;

    #[derive(Debug, Clone)]
    pub struct AfXdpConfig {
        pub iface: String,
        pub queue_id: u32,
        pub num_frames: u32,
        pub frame_size: u32,
    }

    impl Default for AfXdpConfig {
        fn default() -> Self {
            Self {
                iface: "eth0".into(),
                queue_id: 0,
                num_frames: 4096,
                frame_size: PACKET_BUF_SIZE as u32,
            }
        }
    }

    pub struct AfXdpIo {
        _never: std::convert::Infallible,
    }

    impl AfXdpIo {
        pub fn new(_config: &AfXdpConfig) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "AF_XDP is only supported on Linux",
            ))
        }
    }

    impl PacketIo for AfXdpIo {
        fn recv_batch(&mut self, _buf: &mut [PacketBuf]) -> io::Result<usize> {
            match self._never {}
        }

        fn send_batch(&mut self, _buf: &[PacketBuf]) -> io::Result<usize> {
            match self._never {}
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::{AfXdpConfig, AfXdpIo};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_xdp_new_returns_unsupported() {
        // Works on both Linux (scaffold) and non-Linux (platform stub).
        let err = AfXdpIo::new(&AfXdpConfig::default()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
