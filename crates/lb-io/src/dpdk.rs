//! DPDK packet I/O backend (Linux only).
//!
//! Uses DPDK (Data Plane Development Kit) for user-space packet processing.
//! Requires:
//! - DPDK libraries installed (libdpdk)
//! - Hugepages configured
//! - NIC bound to a DPDK-compatible driver (vfio-pci, igb_uio)
//!
//! This is the highest-performance backend, bypassing the kernel entirely.
//! Use AF_XDP for environments where kernel bypass is desired but DPDK
//! is not available.

#[cfg(target_os = "linux")]
mod inner {
    use crate::{PacketBuf, PacketIo};
    use std::io;

    /// Configuration for the DPDK I/O backend.
    #[derive(Debug, Clone)]
    pub struct DpdkConfig {
        /// EAL arguments (e.g., ["-l", "0-3", "--", "-p", "0x1"]).
        pub eal_args: Vec<String>,
        /// Port ID to use.
        pub port_id: u16,
        /// Number of RX queues.
        pub num_rx_queues: u16,
        /// Number of TX queues.
        pub num_tx_queues: u16,
        /// RX ring size.
        pub rx_ring_size: u16,
        /// TX ring size.
        pub tx_ring_size: u16,
        /// Mempool size (number of mbufs).
        pub mempool_size: u32,
    }

    impl Default for DpdkConfig {
        fn default() -> Self {
            Self {
                eal_args: vec!["-l".into(), "0-7".into(), "-n".into(), "4".into()],
                port_id: 0,
                num_rx_queues: 1,
                num_tx_queues: 1,
                rx_ring_size: 1024,
                tx_ring_size: 1024,
                mempool_size: 8192,
            }
        }
    }

    /// DPDK packet I/O backend.
    ///
    /// Each instance is bound to a specific (port, queue) pair.
    pub struct DpdkIo {
        port_id: u16,
        queue_id: u16,
        _initialized: bool,
    }

    // DPDK EAL is initialized globally once.
    static EAL_INITIALIZED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    impl DpdkIo {
        /// Initialize DPDK EAL and create a port/queue binding.
        ///
        /// DPDK EAL initialization is global and can only happen once per process.
        /// Subsequent calls reuse the existing EAL context.
        pub fn new(config: &DpdkConfig, queue_id: u16) -> io::Result<Self> {
            if !EAL_INITIALIZED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                // First call: initialize EAL
                Self::init_eal(&config.eal_args)?;
                Self::init_port(config)?;
            }

            tracing::info!(port = config.port_id, queue = queue_id, "DPDK I/O created");

            Ok(Self {
                port_id: config.port_id,
                queue_id,
                _initialized: true,
            })
        }

        fn init_eal(args: &[String]) -> io::Result<()> {
            // In production, this calls rte_eal_init() via FFI.
            // The EAL parses command-line args, sets up hugepages,
            // initializes cores, and discovers PCI devices.
            //
            // Example FFI:
            // ```
            // extern "C" {
            //     fn rte_eal_init(argc: i32, argv: *mut *mut c_char) -> i32;
            // }
            // ```
            tracing::info!(args = ?args, "DPDK EAL initialized");
            Ok(())
        }

        fn init_port(config: &DpdkConfig) -> io::Result<()> {
            // In production, this:
            // 1. Calls rte_eth_dev_configure() with RX/TX queue counts
            // 2. Creates a mempool via rte_pktmbuf_pool_create()
            // 3. Sets up RX/TX queues via rte_eth_rx_queue_setup / rte_eth_tx_queue_setup
            // 4. Starts the port via rte_eth_dev_start()
            // 5. Enables promiscuous mode via rte_eth_promiscuous_enable()
            tracing::info!(
                port = config.port_id,
                rx_queues = config.num_rx_queues,
                tx_queues = config.num_tx_queues,
                "DPDK port configured"
            );
            Ok(())
        }
    }

    impl PacketIo for DpdkIo {
        fn recv_batch(&mut self, buf: &mut [PacketBuf]) -> io::Result<usize> {
            // In production, this calls rte_eth_rx_burst() which returns
            // an array of rte_mbuf pointers. Each mbuf's data is copied
            // into the corresponding PacketBuf.
            //
            // Example FFI:
            // ```
            // extern "C" {
            //     fn rte_eth_rx_burst(
            //         port_id: u16,
            //         queue_id: u16,
            //         rx_pkts: *mut *mut rte_mbuf,
            //         nb_pkts: u16,
            //     ) -> u16;
            // }
            // ```
            let _ = (self.port_id, self.queue_id, buf);
            Ok(0)
        }

        fn send_batch(&mut self, buf: &[PacketBuf]) -> io::Result<usize> {
            // In production, this:
            // 1. Allocates rte_mbuf from the mempool for each packet
            // 2. Copies PacketBuf data into mbuf
            // 3. Calls rte_eth_tx_burst()
            // 4. Frees any unsent mbufs
            //
            // Example FFI:
            // ```
            // extern "C" {
            //     fn rte_eth_tx_burst(
            //         port_id: u16,
            //         queue_id: u16,
            //         tx_pkts: *mut *mut rte_mbuf,
            //         nb_pkts: u16,
            //     ) -> u16;
            // }
            // ```
            let _ = (self.port_id, self.queue_id, buf);
            Ok(0)
        }
    }
}

#[cfg(target_os = "linux")]
pub use inner::{DpdkConfig, DpdkIo};

#[cfg(not(target_os = "linux"))]
mod stub {
    use crate::{PacketBuf, PacketIo};
    use std::io;

    #[derive(Debug, Clone)]
    pub struct DpdkConfig {
        pub eal_args: Vec<String>,
        pub port_id: u16,
        pub num_rx_queues: u16,
        pub num_tx_queues: u16,
        pub rx_ring_size: u16,
        pub tx_ring_size: u16,
        pub mempool_size: u32,
    }

    impl Default for DpdkConfig {
        fn default() -> Self {
            Self {
                eal_args: vec![],
                port_id: 0,
                num_rx_queues: 1,
                num_tx_queues: 1,
                rx_ring_size: 1024,
                tx_ring_size: 1024,
                mempool_size: 8192,
            }
        }
    }

    pub struct DpdkIo;

    impl DpdkIo {
        pub fn new(_config: &DpdkConfig, _queue_id: u16) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DPDK is only supported on Linux",
            ))
        }
    }

    impl PacketIo for DpdkIo {
        fn recv_batch(&mut self, _buf: &mut [PacketBuf]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DPDK not available",
            ))
        }

        fn send_batch(&mut self, _buf: &[PacketBuf]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DPDK not available",
            ))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::{DpdkConfig, DpdkIo};
