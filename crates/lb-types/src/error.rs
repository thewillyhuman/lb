use thiserror::Error;

#[derive(Debug, Error)]
pub enum LbError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no healthy backends for pool {0}")]
    NoHealthyBackends(String),

    #[error("VIP not found: {0}")]
    VipNotFound(String),

    #[error("pool not found: {0}")]
    PoolNotFound(String),
}
