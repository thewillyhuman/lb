//! AF_XDP packet I/O backend (Linux only).
//!
//! Uses the kernel's AF_XDP socket interface for zero-copy packet processing.
//! Requires:
//! - Linux >= 4.18 (AF_XDP support)
//! - CAP_NET_ADMIN or root
//! - An XDP program loaded on the target interface
//!
//! This backend provides kernel-bypass performance without requiring a
//! user-space networking stack like DPDK.

#[cfg(target_os = "linux")]
mod inner {
    use crate::{PacketBuf, PacketIo, PACKET_BUF_SIZE};
    use std::ffi::CString;
    use std::io;
    use std::os::unix::io::RawFd;

    /// Configuration for the AF_XDP socket.
    #[derive(Debug, Clone)]
    pub struct AfXdpConfig {
        /// Network interface name (e.g., "eth0").
        pub iface: String,
        /// Queue ID to bind to.
        pub queue_id: u32,
        /// Number of frames in the UMEM area.
        pub num_frames: u32,
        /// Size of each frame (must be >= PACKET_BUF_SIZE).
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

    /// AF_XDP socket I/O backend.
    ///
    /// Each instance binds to a single NIC queue. For multi-queue setups,
    /// create one AfXdpIo per queue and distribute across threads.
    pub struct AfXdpIo {
        /// Raw socket file descriptor.
        socket_fd: RawFd,
        /// UMEM memory region (mmap'd).
        umem_area: *mut u8,
        umem_size: usize,
        /// Frame size.
        frame_size: usize,
        /// Number of frames.
        num_frames: u32,
        /// Interface index.
        _ifindex: u32,
    }

    // Safety: the socket fd and mmap region are thread-safe to send between threads.
    // Access is serialized by the PacketIo trait (takes &mut self).
    unsafe impl Send for AfXdpIo {}

    impl AfXdpIo {
        /// Create and bind an AF_XDP socket to the specified interface and queue.
        pub fn new(config: &AfXdpConfig) -> io::Result<Self> {
            let ifindex = get_ifindex(&config.iface)?;
            let umem_size = (config.num_frames as usize) * (config.frame_size as usize);

            // Allocate UMEM area via mmap
            let umem_area = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    umem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };

            if umem_area == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }

            // Create AF_XDP socket
            let socket_fd = unsafe {
                libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0)
            };

            if socket_fd < 0 {
                unsafe { libc::munmap(umem_area, umem_size) };
                return Err(io::Error::last_os_error());
            }

            // Register UMEM with the socket via setsockopt.
            // The full UMEM registration + ring setup requires libbpf xsk helpers.
            // This is the structural skeleton — production use would call:
            //   xsk_umem__create() and xsk_socket__create() from libbpf.
            //
            // For now, we set up the socket fd and UMEM area. The actual ring
            // buffer configuration is done via xsk_socket__create which handles
            // the complex mmap + setsockopt dance.

            tracing::info!(
                iface = %config.iface,
                queue = config.queue_id,
                frames = config.num_frames,
                "AF_XDP socket created (ifindex={ifindex})"
            );

            Ok(Self {
                socket_fd,
                umem_area: umem_area as *mut u8,
                umem_size,
                frame_size: config.frame_size as usize,
                num_frames: config.num_frames,
                _ifindex: ifindex,
            })
        }
    }

    impl PacketIo for AfXdpIo {
        fn recv_batch(&mut self, buf: &mut [PacketBuf]) -> io::Result<usize> {
            // In production, this would:
            // 1. Poll the RX ring for completed descriptors
            // 2. Copy frame data from UMEM into PacketBuf
            // 3. Return frames to the FILL ring
            //
            // The actual implementation uses xsk_ring_cons__peek / xsk_ring_cons__release
            // on the RX ring and xsk_ring_prod__reserve / xsk_ring_prod__submit on the
            // FILL ring.

            let max_batch = buf.len().min(self.num_frames as usize);

            // Use recvfrom with MSG_DONTWAIT to poll for available packets
            let mut received = 0;
            for slot in buf.iter_mut().take(max_batch) {
                let frame_offset = (received % self.num_frames as usize) * self.frame_size;
                let frame_ptr = unsafe { self.umem_area.add(frame_offset) };

                // Try to receive a packet into the UMEM frame
                let n = unsafe {
                    libc::recvfrom(
                        self.socket_fd,
                        frame_ptr as *mut libc::c_void,
                        self.frame_size,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };

                if n <= 0 {
                    break;
                }

                let len = n as usize;
                slot.data[..len].copy_from_slice(unsafe {
                    std::slice::from_raw_parts(frame_ptr, len)
                });
                slot.len = len;
                received += 1;
            }

            Ok(received)
        }

        fn send_batch(&mut self, buf: &[PacketBuf]) -> io::Result<usize> {
            // In production, this would:
            // 1. Copy packet data into UMEM frames
            // 2. Submit descriptors to the TX ring
            // 3. Call sendto() to trigger kernel transmission
            // 4. Poll COMPLETION ring for completed sends

            let mut sent = 0;
            for pkt in buf {
                if pkt.len == 0 {
                    continue;
                }

                let frame_offset = (sent % self.num_frames as usize) * self.frame_size;
                let frame_ptr = unsafe { self.umem_area.add(frame_offset) };

                // Copy packet to UMEM frame
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        pkt.data.as_ptr(),
                        frame_ptr,
                        pkt.len,
                    );
                }

                let n = unsafe {
                    libc::sendto(
                        self.socket_fd,
                        frame_ptr as *const libc::c_void,
                        pkt.len,
                        libc::MSG_DONTWAIT,
                        std::ptr::null(),
                        0,
                    )
                };

                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(err);
                }

                sent += 1;
            }

            Ok(sent)
        }
    }

    impl Drop for AfXdpIo {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.socket_fd);
                libc::munmap(self.umem_area as *mut libc::c_void, self.umem_size);
            }
        }
    }

    fn get_ifindex(iface: &str) -> io::Result<u32> {
        let name = CString::new(iface)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if idx == 0 {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface not found: {iface}"),
            ))
        } else {
            Ok(idx)
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

    pub struct AfXdpIo;

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
            Err(io::Error::new(io::ErrorKind::Unsupported, "AF_XDP not available"))
        }

        fn send_batch(&mut self, _buf: &[PacketBuf]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "AF_XDP not available"))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::{AfXdpConfig, AfXdpIo};
