use std::io;

#[cfg(feature = "mock")]
pub mod mock;

#[cfg(feature = "af-xdp")]
pub mod af_xdp;

#[cfg(feature = "dpdk")]
pub mod dpdk;

/// Maximum packet buffer size (accommodates jumbo frames + GRE overhead).
pub const PACKET_BUF_SIZE: usize = 2048;

/// Fixed-size packet buffer. No heap allocation on the hot path.
#[derive(Clone)]
pub struct PacketBuf {
    pub data: [u8; PACKET_BUF_SIZE],
    pub len: usize,
}

impl PacketBuf {
    pub fn new() -> Self {
        Self {
            data: [0u8; PACKET_BUF_SIZE],
            len: 0,
        }
    }

    /// Create a PacketBuf from a byte slice (copies data).
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut buf = Self::new();
        let copy_len = slice.len().min(PACKET_BUF_SIZE);
        buf.data[..copy_len].copy_from_slice(&slice[..copy_len]);
        buf.len = copy_len;
        buf
    }

    /// Get the valid packet data as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get the valid packet data as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl Default for PacketBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for packet I/O backends.
///
/// The forwarder is generic over this trait. Production uses AF_XDP,
/// tests use MockIo.
pub trait PacketIo: Send + 'static {
    /// Receive a batch of packets. Returns the number of packets received.
    fn recv_batch(&mut self, buf: &mut [PacketBuf]) -> io::Result<usize>;

    /// Send a batch of packets. Returns the number of packets sent.
    fn send_batch(&mut self, buf: &[PacketBuf]) -> io::Result<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_buf_from_slice() {
        let data = b"hello world";
        let buf = PacketBuf::from_slice(data);
        assert_eq!(buf.len, 11);
        assert_eq!(buf.as_slice(), data);
    }

    #[test]
    fn packet_buf_default_is_empty() {
        let buf = PacketBuf::new();
        assert_eq!(buf.len, 0);
        assert_eq!(buf.as_slice(), &[]);
    }

    #[test]
    fn packet_buf_oversized_slice_truncates() {
        let data = vec![0xAA; PACKET_BUF_SIZE + 100];
        let buf = PacketBuf::from_slice(&data);
        assert_eq!(buf.len, PACKET_BUF_SIZE);
    }
}
