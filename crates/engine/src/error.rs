use thiserror::Error;

pub type Result<T> = std::result::Result<T, EngineError>;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("template parse error: {0}")]
    Template(#[from] serde_yaml::Error),
    #[error("invalid template: {0}")]
    InvalidTemplate(String),
    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("rustscan not found on PATH")]
    RustScanMissing,
    #[error("rustscan failed: {0}")]
    RustScan(String),
    #[error("other: {0}")]
    Other(String),
}
