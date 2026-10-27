// ─── Error Types ────────────────────────────────────────────────────────────

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FirewalldError {
    #[error("firewall-cmd not found. Is firewalld installed?")]
    FirewalldNotInstalled,

    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("firewall-cmd timed out after {0}s (firewalld may be unresponsive)")]
    Timeout(u64),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, FirewalldError>;
