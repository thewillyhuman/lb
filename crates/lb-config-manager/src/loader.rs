use lb_types::{BackendPool, Vip};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// The full LB configuration as loaded from a local JSON file (ADR-001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbConfig {
    pub vips: Vec<Vip>,
    pub pools: Vec<BackendPool>,
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Load configuration from a local JSON file.
pub fn load_from_file(path: &Path) -> Result<LbConfig, LoadError> {
    let contents = std::fs::read_to_string(path)?;
    let config: LbConfig = serde_json::from_str(&contents)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_from_file_valid_json() {
        let json = r#"{
            "vips": [],
            "pools": []
        }"#;

        let dir = std::env::temp_dir();
        let path = dir.join("lb-test-config.json");
        std::fs::write(&path, json).unwrap();

        let config = load_from_file(&path).unwrap();
        assert!(config.vips.is_empty());
        assert!(config.pools.is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_from_file_not_found() {
        let result = load_from_file(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_from_file_invalid_json() {
        let dir = std::env::temp_dir();
        let path = dir.join("lb-test-invalid.json");
        std::fs::write(&path, "not json").unwrap();

        let result = load_from_file(&path);
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }
}
