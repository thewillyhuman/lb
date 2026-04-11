use crate::loader::LbConfig;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Save the current config to a local file for resilience.
pub fn save_cache(path: &Path, config: &LbConfig) -> Result<(), CacheError> {
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load config from the local cache file.
pub fn load_cache(path: &Path) -> Result<LbConfig, CacheError> {
    let contents = std::fs::read_to_string(path)?;
    let config: LbConfig = serde_json::from_str(&contents)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_types::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn cache_round_trip() {
        let config = LbConfig {
            vips: vec![Vip {
                id: VipId("test".into()),
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                services: vec![],
                owner: "test".into(),
                description: "".into(),
            }],
            pools: vec![BackendPool {
                id: BackendPoolId("pool".into()),
                backends: vec![Backend::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    443,
                )],
                health_check: None,
            }],
        };

        let dir = std::env::temp_dir();
        let path = dir.join("lb-test-cache.json");

        save_cache(&path, &config).unwrap();
        let loaded = load_cache(&path).unwrap();

        assert_eq!(loaded.vips.len(), 1);
        assert_eq!(loaded.pools.len(), 1);
        assert_eq!(loaded.vips[0].id, config.vips[0].id);

        std::fs::remove_file(&path).ok();
    }
}
