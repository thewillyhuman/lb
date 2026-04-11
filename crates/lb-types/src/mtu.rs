use crate::error::LbError;

/// GRE encapsulation overhead: 20-byte outer IPv4 + 4-byte GRE header.
pub const GRE_OVERHEAD: u16 = 24;

/// Minimum IP + TCP header size (no options).
const IP_TCP_HEADER_SIZE: u16 = 40;

/// RFC 879 minimum MSS.
const MIN_MSS: u16 = 536;

/// Derived MTU parameters for GRE tunneling.
///
/// Constructed from a single `network_mtu` value; all other parameters are
/// derived automatically. See `.docs/mtu-handling-spec.md` §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuConfig {
    /// The link MTU configured by the operator.
    pub network_mtu: u16,
    /// Maximum inner packet size that fits after GRE encapsulation.
    pub effective_inner_mtu: u16,
    /// Maximum MSS value to allow in TCP SYN/SYN-ACK packets.
    pub tcp_mss_clamp: u16,
}

impl MtuConfig {
    /// Derive all tunnel parameters from `network_mtu`.
    ///
    /// Returns an error if:
    /// - `network_mtu` < 1280 (minimum for meaningful IP traffic)
    /// - `network_mtu` > 65535 (IP maximum)
    /// - Derived `tcp_mss_clamp` < 536 (RFC 879 minimum)
    pub fn new(network_mtu: u16) -> Result<Self, LbError> {
        if network_mtu < 1280 {
            return Err(LbError::Config(format!(
                "network_mtu {network_mtu} is below minimum 1280"
            )));
        }

        let effective_inner_mtu = network_mtu - GRE_OVERHEAD;
        let tcp_mss_clamp = effective_inner_mtu - IP_TCP_HEADER_SIZE;

        if tcp_mss_clamp < MIN_MSS {
            return Err(LbError::Config(format!(
                "derived tcp_mss_clamp {tcp_mss_clamp} is below RFC 879 minimum {MIN_MSS} \
                 (network_mtu must be >= 600)"
            )));
        }

        Ok(Self {
            network_mtu,
            effective_inner_mtu,
            tcp_mss_clamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_config_derives_correctly() {
        let c = MtuConfig::new(1500).unwrap();
        assert_eq!(c.effective_inner_mtu, 1476);
        assert_eq!(c.tcp_mss_clamp, 1436);
    }

    #[test]
    fn mtu_config_jumbo() {
        let c = MtuConfig::new(9000).unwrap();
        assert_eq!(c.effective_inner_mtu, 8976);
        assert_eq!(c.tcp_mss_clamp, 8936);
    }

    #[test]
    fn mtu_config_minimum() {
        let c = MtuConfig::new(1280).unwrap();
        assert_eq!(c.effective_inner_mtu, 1256);
        assert_eq!(c.tcp_mss_clamp, 1216);
    }

    #[test]
    fn mtu_config_rejects_too_small() {
        assert!(MtuConfig::new(500).is_err());
    }

    #[test]
    fn mtu_config_rejects_below_minimum() {
        assert!(MtuConfig::new(1279).is_err());
        assert!(MtuConfig::new(1280).is_ok());
    }
}
