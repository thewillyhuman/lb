//! File-based config watcher per ADR-001.
//!
//! Watches the LB config JSON file for changes using inotify (Linux) or
//! kqueue (macOS) via the `notify` crate. On each change, reloads and
//! validates the config, then sends it through a channel.

use crate::loader::{self, LbConfig, LoadError};
use crate::validator;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WatchError {
    #[error("failed to create file watcher: {0}")]
    WatcherInit(#[from] notify::Error),
    #[error("config load error: {0}")]
    Load(#[from] LoadError),
    #[error("config validation failed: {0:?}")]
    Validation(Vec<String>),
}

/// Watches a config file and sends validated LbConfig through a channel on each change.
pub struct ConfigWatcher {
    config_path: PathBuf,
    _watcher: RecommendedWatcher,
    rx: mpsc::Receiver<Result<Event, notify::Error>>,
}

impl ConfigWatcher {
    /// Create a new watcher for the given config file path.
    /// Performs an initial load and returns the watcher + initial config.
    pub fn new(config_path: &Path) -> Result<(Self, LbConfig), WatchError> {
        // Initial load
        let initial_config = loader::load_from_file(config_path)?;
        validate_config(&initial_config)?;

        let (tx, rx) = mpsc::channel();

        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })?;

        // Watch the parent directory to handle atomic renames (common with
        // tools like Puppet/Ansible that write to a temp file then mv).
        let watch_path = config_path.parent().unwrap_or(config_path);
        watcher.watch(watch_path, RecursiveMode::NonRecursive)?;

        Ok((
            Self {
                config_path: config_path.to_path_buf(),
                _watcher: watcher,
                rx,
            },
            initial_config,
        ))
    }

    /// Block until the config file changes. Returns the new validated config.
    /// Malformed files are logged and skipped (blocks again).
    pub fn wait_for_change(&self) -> LbConfig {
        loop {
            match self.rx.recv() {
                Ok(Ok(event)) => {
                    if !is_relevant_event(&event, &self.config_path) {
                        continue;
                    }

                    match self.try_reload() {
                        Ok(config) => return config,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                path = %self.config_path.display(),
                                "config reload failed, keeping previous config"
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "file watcher error");
                }
                Err(_) => {
                    // Channel closed — watcher dropped. This shouldn't happen in normal operation.
                    tracing::error!("config watcher channel closed");
                    // Park the thread to avoid a busy loop.
                    std::thread::park();
                }
            }
        }
    }

    fn try_reload(&self) -> Result<LbConfig, WatchError> {
        let config = loader::load_from_file(&self.config_path)?;
        validate_config(&config)?;
        tracing::info!(
            path = %self.config_path.display(),
            vips = config.vips.len(),
            pools = config.pools.len(),
            "config reloaded successfully"
        );
        Ok(config)
    }
}

fn validate_config(config: &LbConfig) -> Result<(), WatchError> {
    let pools: HashMap<String, _> = config
        .pools
        .iter()
        .map(|p| (p.id.0.clone(), p.clone()))
        .collect();

    if let Err(e) = validator::validate(&config.vips, &pools) {
        return Err(WatchError::Validation(e.errors));
    }
    Ok(())
}

fn is_relevant_event(event: &Event, config_path: &Path) -> bool {
    // Accept modify, create, and remove events.
    // On macOS (kqueue), atomic rename (mv) generates Create events for the
    // new path. We also accept events where the path matches the config file
    // name even without a full directory prefix (kqueue sometimes reports just
    // the filename).
    let is_relevant_kind = matches!(
        event.kind,
        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
    );

    if !is_relevant_kind {
        return false;
    }

    let config_name = config_path.file_name();
    event
        .paths
        .iter()
        .any(|p| p == config_path || (config_name.is_some() && p.file_name() == config_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_valid_config(path: &Path) {
        let json = r#"{
            "vips": [],
            "pools": []
        }"#;
        fs::write(path, json).unwrap();
    }

    #[test]
    fn initial_load_valid() {
        let dir = std::env::temp_dir().join("lb-watcher-test-init");
        fs::create_dir_all(&dir).ok();
        let path = dir.join("config.json");
        write_valid_config(&path);

        let (watcher, config) = ConfigWatcher::new(&path).unwrap();
        assert!(config.vips.is_empty());
        drop(watcher);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn initial_load_missing_file_fails() {
        let path = Path::new("/tmp/lb-watcher-test-nonexistent.json");
        assert!(ConfigWatcher::new(path).is_err());
    }

    #[test]
    fn detects_file_change() {
        let dir = std::env::temp_dir().join("lb-watcher-test-change");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        write_valid_config(&path);

        let (watcher, _) = ConfigWatcher::new(&path).unwrap();

        // Write a new config in a background thread after a short delay
        let path_clone = path.clone();
        std::thread::spawn(move || {
            // Give the watcher time to register with the OS
            std::thread::sleep(std::time::Duration::from_millis(500));
            let json = r#"{"vips": [], "pools": []}"#;
            fs::write(&path_clone, json).unwrap();
        });

        // wait_for_change blocks until the file is modified.
        // Wrap in a timeout thread to avoid hanging the test suite.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let config = watcher.wait_for_change();
            let _ = tx.send(config);
        });

        let config = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("timed out waiting for config change");
        assert!(config.vips.is_empty());

        fs::remove_dir_all(&dir).ok();
    }
}
