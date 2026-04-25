//! AF_XDP packet I/O backend.
//!
//! Wires the kernel's AF_XDP socket interface via [`xdpilone`] (per ADR-002).
//! On Linux + the `af-xdp` feature, `AfXdpIo` is a working backend bound to
//! `(iface, queue_id)` driving real XSK rings. On non-Linux or without the
//! feature, `AfXdpIo::new` returns `Unsupported` so dev-mode builds keep
//! working unchanged.
//!
//! # Lifecycle (Linux + af-xdp)
//!
//! 1. Allocate a page-aligned UMEM buffer (default 8 MiB = 4096 frames ×
//!    2048 B).
//! 2. Register UMEM with the kernel via `Umem::new` and create the XSK
//!    socket via `Socket::with_shared`. Bind to (iface, queue_id).
//! 3. Map RX, TX, FILL, COMPLETION rings.
//! 4. **Pre-fill** the FILL ring with half the frames so the kernel has
//!    descriptors to write incoming packets into. The other half is held
//!    in `free_frames` for outbound TX.
//! 5. `recv_batch` drains RX, copies packet bytes into caller-provided
//!    `PacketBuf`s, and immediately recycles each consumed frame back to
//!    the FILL ring so the kernel can keep posting.
//! 6. `send_batch` drains COMPLETION first to reclaim TX frames, then
//!    pops a free frame for each outgoing packet, copies into UMEM, and
//!    posts the descriptor on the TX ring. `wake()` is called when the
//!    kernel reports `XDP_USE_NEED_WAKEUP`.
//!
//! # Why two pools?
//!
//! Splitting frames at init time into "RX-pool" (pre-filled into FILL)
//! and "TX-pool" (held in `free_frames`) means the two paths cannot
//! starve each other under load. Without that, a long FILL drain could
//! consume every frame and leave TX with nothing to send. The
//! kernel-recycled frames stay on their side: RX completions go back to
//! FILL, TX completions go back to `free_frames`.
//!
//! # XDP redirect program
//!
//! `AfXdpIo` does **not** load an XDP program itself in this commit. The
//! operator must load one separately (e.g. via `xdp-loader load --mode
//! native eth0 lb-redirect.o`) so packets actually reach the XSKMAP and
//! land on this socket. ADR-002 commit 2 adds program-bundling to
//! `lb-node` itself.
//!
//! [`xdpilone`]: https://docs.rs/xdpilone/

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
mod inner {
    use crate::{PacketBuf, PacketIo, PACKET_BUF_SIZE};
    use std::collections::VecDeque;
    use std::io;

    use xdpilone::xdp::XdpDesc;
    use xdpilone::{
        BufIdx, DeviceQueue, IfInfo, RingRx, RingTx, Socket, SocketConfig, Umem, UmemConfig,
    };

    /// Default UMEM frame size. Matches `PACKET_BUF_SIZE` so a packet
    /// fits in a single frame. Must be a power of two and ≥ 2048 for
    /// modern kernels.
    pub const DEFAULT_FRAME_SIZE: u32 = 2048;
    /// Default total UMEM frames (4096 × 2048 = 8 MiB). Half used for
    /// FILL pre-fill, half held for TX.
    pub const DEFAULT_NUM_FRAMES: u32 = 4096;
    /// Default size of the RX/TX rings. Must be a power of two.
    pub const DEFAULT_RING_SIZE: u32 = 2048;

    /// Configuration for the AF_XDP socket.
    #[derive(Debug, Clone)]
    pub struct AfXdpConfig {
        /// Network interface name (e.g., "eth0").
        pub iface: String,
        /// Queue ID to bind to. One AF_XDP socket per (iface, queue_id);
        /// multi-queue NICs should run one rewriter per queue.
        pub queue_id: u32,
        /// Number of frames in the UMEM area. Must be a power of two and
        /// at least `2 × ring_size` so RX and TX pools can each be sized
        /// to a full ring.
        pub num_frames: u32,
        /// Size of each frame. Must be ≥ `PACKET_BUF_SIZE`.
        pub frame_size: u32,
        /// Size of the RX and TX rings (slots per ring).
        pub ring_size: u32,
        /// Path to the pinned XSKMAP that the XDP redirect program is
        /// using to dispatch packets. `AfXdpIo::new` opens this map and
        /// inserts its own XSK fd at index `queue_id`, so packets the
        /// kernel-side program sends here actually arrive on this
        /// socket. `None` means "operator populated the map by hand
        /// (via bpftool); don't touch it" — useful for early bring-up
        /// or non-standard deployments.
        pub xskmap_pin: Option<String>,
    }

    impl Default for AfXdpConfig {
        fn default() -> Self {
            Self {
                iface: "eth0".into(),
                queue_id: 0,
                num_frames: DEFAULT_NUM_FRAMES,
                frame_size: DEFAULT_FRAME_SIZE,
                ring_size: DEFAULT_RING_SIZE,
                // Matches the path `deploy/xdp/load.sh` pins to.
                xskmap_pin: Some("/sys/fs/bpf/lb/xsks_map".into()),
            }
        }
    }

    /// AF_XDP socket I/O backend.
    pub struct AfXdpIo {
        // Field declaration order is significant — `rx`/`tx`/`device`
        // hold pointers into `umem`'s mapping; `umem` holds a pointer
        // into `_alloc`. Drop order is declaration order, so the rings
        // unmap before we drop the UMEM, which unmaps before we drop the
        // backing allocation. Reordering this is a use-after-free.
        rx: RingRx,
        tx: RingTx,
        device: DeviceQueue,
        umem: Umem,
        // Backing memory for UMEM. Held to keep the mapping alive — the
        // Umem stores a raw pointer into this, not a borrow.
        _alloc: Box<[std::mem::MaybeUninit<u8>]>,

        /// Frame indices currently free for TX. Replenished from
        /// COMPLETION inside `send_batch`.
        free_frames: VecDeque<u32>,
        frame_size: u32,
    }

    // Safety: `AfXdpIo` is intended to be moved between threads only at
    // construction time (the per-rewriter `MultiThreadedForwarder::start`
    // hand-off). Once on its owning thread, every field is touched through
    // the same `&mut self`. The `NonNull<[u8]>` inside `Umem` is the only
    // !Send field in xdpilone's API surface; it points at a heap region
    // we own (`_alloc`) and that region is alive for the lifetime of the
    // struct. There is no aliasing across threads — this is single-owner
    // hand-off, not shared access.
    unsafe impl Send for AfXdpIo {}

    impl AfXdpIo {
        /// Build, register, and bind the AF_XDP socket. Pre-fills the
        /// FILL ring with the RX-pool half of the UMEM frames.
        pub fn new(config: &AfXdpConfig) -> io::Result<Self> {
            if config.frame_size < PACKET_BUF_SIZE as u32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "frame_size ({}) must be >= PACKET_BUF_SIZE ({})",
                        config.frame_size, PACKET_BUF_SIZE
                    ),
                ));
            }
            if !config.num_frames.is_power_of_two() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "num_frames must be a power of two",
                ));
            }
            if config.num_frames < 2 * config.ring_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "num_frames must be >= 2 * ring_size to fit RX + TX pools",
                ));
            }

            // Allocate page-aligned UMEM. `Box::new_uninit_slice` allocates
            // on the heap; alignment of the resulting block is the natural
            // alignment of `MaybeUninit<u8>` (1), so we manually allocate
            // an aligned region instead.
            let total_bytes = (config.num_frames as usize) * (config.frame_size as usize);
            let alloc = aligned_uninit_slice(total_bytes, 4096)?;
            let mem_ptr = std::ptr::NonNull::new(alloc.as_ptr() as *mut u8)
                .expect("Box::new_uninit_slice never returns null");
            let mem = std::ptr::NonNull::slice_from_raw_parts(mem_ptr, total_bytes);

            // Register UMEM. Safety: `mem` is page-aligned, has the
            // `total_bytes` we computed, and `_alloc` outlives every
            // pointer derived from it (drop order in the struct).
            let umem_config = UmemConfig {
                frame_size: config.frame_size,
                fill_size: config.ring_size,
                complete_size: config.ring_size,
                headroom: 0,
                ..UmemConfig::default()
            };
            let umem = unsafe { Umem::new(umem_config, mem) }
                .map_err(|e| io::Error::other(format!("Umem::new: {e:?}")))?;

            // Resolve interface name → IfInfo (kernel-side struct
            // identifying the netdev + queue).
            let iface_c = std::ffi::CString::new(config.iface.as_str())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "iface contains NUL"))?;
            let mut ifinfo = IfInfo::invalid();
            ifinfo.from_name(&iface_c).map_err(|e| {
                io::Error::other(format!("IfInfo::from_name({:?}): {e:?}", config.iface))
            })?;
            ifinfo.set_queue(config.queue_id);

            // Create the XSK socket and ring wrappers.
            let sock = Socket::with_shared(&ifinfo, &umem)
                .map_err(|e| io::Error::other(format!("Socket::with_shared: {e:?}")))?;
            let device = umem
                .fq_cq(&sock)
                .map_err(|e| io::Error::other(format!("fq_cq: {e:?}")))?;

            let socket_config = SocketConfig {
                rx_size: std::num::NonZeroU32::new(config.ring_size),
                tx_size: std::num::NonZeroU32::new(config.ring_size),
                bind_flags: SocketConfig::XDP_BIND_NEED_WAKEUP,
            };
            let rxtx = umem
                .rx_tx(&sock, &socket_config)
                .map_err(|e| io::Error::other(format!("rx_tx: {e:?}")))?;
            let rx = rxtx
                .map_rx()
                .map_err(|e| io::Error::other(format!("map_rx: {e:?}")))?;
            let tx = rxtx
                .map_tx()
                .map_err(|e| io::Error::other(format!("map_tx: {e:?}")))?;

            // Bind activates the rings. Until this returns, no packets
            // flow.
            umem.bind(&rxtx)
                .map_err(|e| io::Error::other(format!("Umem::bind: {e:?}")))?;

            // Split frames: the first half (`num_rx_frames`) seeds the
            // FILL ring; the rest is held for TX in `free_frames`.
            let num_rx_frames = config.ring_size;
            let mut device = device;
            {
                let mut writer = device.fill(num_rx_frames);
                let frame_size = config.frame_size as u64;
                writer.insert((0..num_rx_frames).map(|i| i as u64 * frame_size));
                writer.commit();
            }
            let mut free_frames =
                VecDeque::with_capacity((config.num_frames - num_rx_frames) as usize);
            for i in num_rx_frames..config.num_frames {
                free_frames.push_back(i);
            }

            // Self-register in the pinned XSKMAP so the redirect program
            // can dispatch traffic to us. Without this step, the kernel-
            // side program runs but `bpf_redirect_map` returns map-miss
            // and packets fall through to XDP_PASS — i.e. the LB sees
            // nothing. `xskmap_pin = None` skips this for operators who
            // populate the map by hand (e.g. via bpftool).
            let xsk_fd = rx.as_raw_fd();
            if let Some(pin_path) = &config.xskmap_pin {
                xskmap::register_xsk(pin_path, config.queue_id, xsk_fd).map_err(|e| {
                    io::Error::other(format!(
                        "XSKMAP registration at {pin_path:?} for queue {} failed: {e}. \
                         Did you run deploy/xdp/load.sh on this host?",
                        config.queue_id
                    ))
                })?;
            }

            tracing::info!(
                iface = %config.iface,
                queue_id = config.queue_id,
                num_frames = config.num_frames,
                frame_size = config.frame_size,
                ring_size = config.ring_size,
                xskmap_pin = ?config.xskmap_pin,
                xsk_fd,
                "AF_XDP socket bound; FILL pre-filled with {num_rx_frames} frames"
            );

            Ok(AfXdpIo {
                rx,
                tx,
                device,
                umem,
                _alloc: alloc,
                free_frames,
                frame_size: config.frame_size,
            })
        }

        /// Convert a UMEM offset to the index of the frame containing it.
        /// XdpDesc `addr` may point into the middle of a frame (with
        /// headroom); we always recycle whole frames, so align down.
        #[inline]
        fn addr_to_frame_idx(&self, addr: u64) -> u32 {
            (addr / self.frame_size as u64) as u32
        }

        #[inline]
        fn frame_idx_to_addr(&self, idx: u32) -> u64 {
            idx as u64 * self.frame_size as u64
        }

        /// Copy `len` bytes from UMEM frame at `addr` into `dst`.
        ///
        /// # Safety
        /// `addr..addr+len` must lie within a single registered UMEM
        /// frame (kernel guarantees this for descriptors it produced),
        /// and the caller must hold exclusive access to that frame for
        /// the duration of the copy. Both invariants hold inside
        /// `recv_batch`: the descriptor came from the kernel via the RX
        /// ring, and we haven't yet recycled the frame.
        unsafe fn umem_read(&self, addr: u64, len: u32, dst: &mut [u8]) {
            // Recover the frame containing `addr`, then offset within it.
            let idx = self.addr_to_frame_idx(addr);
            let frame_offset = addr - self.frame_idx_to_addr(idx);
            let chunk = self
                .umem
                .frame(BufIdx(idx))
                .expect("kernel returned descriptor with out-of-range frame idx");
            let frame_start = chunk.addr.as_ptr() as *const u8;
            let src = frame_start.add(frame_offset as usize);
            let copy_len = (len as usize).min(dst.len());
            std::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), copy_len);
        }

        /// Copy `data` into UMEM frame `idx`, returning the descriptor
        /// to push onto TX.
        ///
        /// # Safety
        /// `idx` must come from `self.free_frames` (i.e. exclusively
        /// owned by this thread, not on any kernel ring).
        unsafe fn umem_write_for_tx(&mut self, idx: u32, data: &[u8]) -> XdpDesc {
            let chunk = self
                .umem
                .frame(BufIdx(idx))
                .expect("free_frames contained out-of-range frame idx");
            let dst = chunk.addr.as_ptr() as *mut u8;
            let copy_len = data.len().min(self.frame_size as usize);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, copy_len);
            XdpDesc {
                addr: self.frame_idx_to_addr(idx),
                len: copy_len as u32,
                options: 0,
            }
        }

        /// Drain the COMPLETION ring, returning each completed TX frame
        /// to `free_frames` for re-use. Cheap when nothing's pending.
        fn drain_completions(&mut self) {
            let max = self.free_frames.capacity() as u32 - self.free_frames.len() as u32;
            if max == 0 {
                return;
            }
            // Snapshot frame_size so the reader scope doesn't have to
            // borrow `self` again to call `addr_to_frame_idx`.
            let frame_size = self.frame_size as u64;
            let mut reader = self.device.complete(max);
            while let Some(addr) = reader.read() {
                self.free_frames.push_back((addr / frame_size) as u32);
            }
            reader.release();
        }
    }

    impl PacketIo for AfXdpIo {
        /// Drain up to `buf.len()` packets from the RX ring into the
        /// provided buffers. Returns the number of packets copied. Each
        /// consumed frame is immediately recycled to FILL so the kernel
        /// can keep delivering.
        fn recv_batch(&mut self, buf: &mut [PacketBuf]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            // Collect descriptors first, then refill FILL — we can't
            // hold the RX reader and FILL writer simultaneously (both
            // borrow `self.device` / `self.rx`).
            let mut consumed: smallvec::SmallVec<[(u64, u32); 64]> = smallvec::SmallVec::new();
            {
                let mut reader = self.rx.receive(buf.len() as u32);
                while let Some(desc) = reader.read() {
                    consumed.push((desc.addr, desc.len));
                    if consumed.len() == buf.len() {
                        break;
                    }
                }
                reader.release();
            }

            // Copy out + record frame indices to refill.
            for (i, (addr, len)) in consumed.iter().enumerate() {
                buf[i].len = (*len as usize).min(PACKET_BUF_SIZE);
                // Safety: descriptor came from the kernel; frame is
                // ours until we refill below.
                unsafe { self.umem_read(*addr, *len, &mut buf[i].data) };
            }

            // Recycle frames back to FILL so the kernel keeps delivering.
            // We recycle exactly the frames we just consumed. Pre-compute
            // frame-aligned addrs so the iterator into FILL doesn't need
            // to borrow `self` (which `device.fill(...)` is borrowing mut).
            if !consumed.is_empty() {
                let frame_size = self.frame_size as u64;
                let aligned: smallvec::SmallVec<[u64; 64]> = consumed
                    .iter()
                    .map(|(addr, _)| (addr / frame_size) * frame_size)
                    .collect();
                let mut writer = self.device.fill(aligned.len() as u32);
                writer.insert(aligned.iter().copied());
                writer.commit();
            }

            Ok(consumed.len())
        }

        /// Push up to `buf.len()` packets onto the TX ring. Drains the
        /// COMPLETION ring first to reclaim frames, then submits new
        /// descriptors and wakes the kernel if it reported
        /// `XDP_USE_NEED_WAKEUP`.
        fn send_batch(&mut self, buf: &[PacketBuf]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            // Reclaim TX frames the kernel has already transmitted.
            self.drain_completions();

            // We can only send as many as we have free frames AND the TX
            // ring has slots for. xdpilone's `transmit(n)` already caps
            // at the ring capacity.
            let max = buf.len().min(self.free_frames.len());
            if max == 0 {
                // No frames available — caller can retry after a future
                // send_batch drains COMPLETION further. Don't error;
                // returning 0 is the documented backpressure shape.
                return Ok(0);
            }

            // Build descriptors *before* taking the TX writer so the
            // umem_write_for_tx calls can borrow `self` mutably without
            // tangling with the writer's borrow on `self.tx`.
            let mut descs: smallvec::SmallVec<[XdpDesc; 64]> = smallvec::SmallVec::new();
            for pkt in &buf[..max] {
                let Some(idx) = self.free_frames.pop_front() else {
                    break;
                };
                // Safety: idx came from free_frames (exclusively owned).
                let desc = unsafe { self.umem_write_for_tx(idx, pkt.as_slice()) };
                descs.push(desc);
            }

            // Push descriptors onto TX in a tight scope so the writer
            // releases before we check `needs_wakeup`.
            let sent = {
                let mut writer = self.tx.transmit(descs.len() as u32);
                let n = writer.insert(descs.iter().copied()) as usize;
                writer.commit();
                n
            };

            // The kernel may have parked the TX path; nudge it.
            if self.tx.needs_wakeup() {
                self.tx.wake();
            }

            Ok(sent)
        }
    }

    /// Tiny helper module for talking to a pinned XSKMAP via the `bpf(2)`
    /// syscall. Pulled out so the `unsafe` is contained; the public
    /// surface is just `register_xsk(pin_path, queue_id, xsk_fd)`.
    mod xskmap {
        use std::ffi::CString;
        use std::io;
        use std::os::fd::{AsRawFd, OwnedFd, RawFd};

        // bpf(2) command numbers from `<linux/bpf.h>`. We hard-code rather
        // than pull libbpf-sys for two constants.
        const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
        const BPF_OBJ_GET: libc::c_uint = 7;

        /// `union bpf_attr` sub-shape used by `BPF_OBJ_GET`. Only the
        /// `pathname` field matters for us; the rest are zero.
        #[repr(C)]
        struct BpfAttrObjGet {
            pathname: u64, // user pointer to NUL-terminated path
            bpf_fd: u32,
            file_flags: u32,
            _pad: [u8; 100], // bpf_attr is large; zero-pad to be safe
        }

        /// `union bpf_attr` sub-shape used by `BPF_MAP_UPDATE_ELEM`.
        #[repr(C)]
        struct BpfAttrMapUpdate {
            map_fd: u32,
            _pad0: u32,
            key: u64,   // user pointer
            value: u64, // user pointer
            flags: u64,
            _pad1: [u8; 88],
        }

        unsafe fn sys_bpf<T>(cmd: libc::c_uint, attr: &T) -> io::Result<libc::c_long> {
            let ret = libc::syscall(
                libc::SYS_bpf,
                cmd,
                attr as *const T as *const libc::c_void,
                std::mem::size_of::<T>() as libc::c_uint,
            );
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ret)
            }
        }

        /// Open the pinned XSKMAP and insert `xsk_fd` at `queue_id`.
        ///
        /// On any error, the kernel-side state is left untouched —
        /// either the pin doesn't exist (operator forgot to run
        /// `load.sh`), the path isn't a map (something else is pinned
        /// there), or the user lacks `CAP_BPF` (or root).
        pub fn register_xsk(pin_path: &str, queue_id: u32, xsk_fd: RawFd) -> io::Result<()> {
            let cpath = CString::new(pin_path)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pin path has NUL"))?;

            let attr_get = BpfAttrObjGet {
                pathname: cpath.as_ptr() as u64,
                bpf_fd: 0,
                file_flags: 0,
                _pad: [0; 100],
            };
            // Safety: bpf(2) is a kernel ABI; our struct mirrors a
            // prefix of `union bpf_attr` and the kernel reads only the
            // fields it needs (which we set; the rest are zero).
            let map_fd = unsafe { sys_bpf(BPF_OBJ_GET, &attr_get) }?;
            // Wrap the returned fd in OwnedFd so it gets closed even on
            // error paths. `as RawFd` is sound because BPF_OBJ_GET
            // returns a non-negative fd on success.
            let map_fd = unsafe { OwnedFd::from_raw_fd(map_fd as RawFd) };

            let key: u32 = queue_id;
            let value: u32 = xsk_fd as u32;
            let attr_upd = BpfAttrMapUpdate {
                map_fd: map_fd.as_raw_fd() as u32,
                _pad0: 0,
                key: &key as *const u32 as u64,
                value: &value as *const u32 as u64,
                flags: 0, // BPF_ANY
                _pad1: [0; 88],
            };
            // Safety: same as above; map_fd is a valid kernel fd, key
            // and value are u32 stack locals alive until syscall return.
            unsafe { sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_upd) }?;

            // OwnedFd dropped here closes the map fd; the entry persists
            // because the map is also held by the pinned reference and
            // the live XSK fd.
            Ok(())
        }

        // Make OwnedFd::from_raw_fd available without adding an extra
        // import at the call site.
        use std::os::fd::FromRawFd;
    }

    /// Allocate a page-aligned uninitialized byte slice on the heap.
    /// `Umem::new` requires page alignment; `Box::new_uninit_slice` only
    /// guarantees the alignment of the element type (1 for `u8`).
    fn aligned_uninit_slice(
        size: usize,
        align: usize,
    ) -> io::Result<Box<[std::mem::MaybeUninit<u8>]>> {
        use std::alloc::{alloc, Layout};
        let layout = Layout::from_size_align(size, align)
            .map_err(|e| io::Error::other(format!("UMEM layout: {e}")))?;
        // Safety: layout is non-zero and the slice constructor below
        // takes ownership of the allocation.
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "UMEM allocation failed",
            ));
        }
        let slice_ptr =
            std::ptr::slice_from_raw_parts_mut(ptr as *mut std::mem::MaybeUninit<u8>, size);
        // Safety: ptr is non-null, allocated with the matching Layout,
        // and lives in a Box which will free with the same Layout on Drop.
        Ok(unsafe { Box::from_raw(slice_ptr) })
    }
}

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub use inner::{AfXdpConfig, AfXdpIo};

// Stub for non-Linux dev builds OR when the `af-xdp` feature is off.
// `AfXdpIo::new` errors with `Unsupported` so `lb-node`'s startup path
// surfaces a clear message and exits.
#[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
mod stub {
    use crate::{PacketBuf, PacketIo, PACKET_BUF_SIZE};
    use std::io;

    #[derive(Debug, Clone)]
    pub struct AfXdpConfig {
        pub iface: String,
        pub queue_id: u32,
        pub num_frames: u32,
        pub frame_size: u32,
        pub ring_size: u32,
        pub xskmap_pin: Option<String>,
    }

    impl Default for AfXdpConfig {
        fn default() -> Self {
            Self {
                iface: "eth0".into(),
                queue_id: 0,
                num_frames: 4096,
                frame_size: PACKET_BUF_SIZE as u32,
                ring_size: 2048,
                xskmap_pin: Some("/sys/fs/bpf/lb/xsks_map".into()),
            }
        }
    }

    pub struct AfXdpIo {
        _never: std::convert::Infallible,
    }

    impl AfXdpIo {
        pub fn new(_config: &AfXdpConfig) -> io::Result<Self> {
            #[cfg(not(target_os = "linux"))]
            let msg = "AF_XDP is only supported on Linux";
            #[cfg(target_os = "linux")]
            let msg = "AF_XDP support not compiled in — rebuild with --features af-xdp";
            Err(io::Error::new(io::ErrorKind::Unsupported, msg))
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

#[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
pub use stub::{AfXdpConfig, AfXdpIo};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_xdp_new_handles_unsupported_or_real() {
        // On non-Linux or without `af-xdp`, this returns Unsupported.
        // On Linux + af-xdp, this errors with whatever the kernel says
        // about binding to "eth0" queue 0 — usually `NoSuchDevice` in
        // CI sandboxes. Either way it's an `Err`, not a panic.
        match AfXdpIo::new(&AfXdpConfig::default()) {
            Ok(_) => {
                // Only reachable on a host with eth0 + queue 0 actually
                // present and an XDP program loaded. CI never hits this.
            }
            Err(e) => {
                let _ = e;
            }
        }
    }
}
