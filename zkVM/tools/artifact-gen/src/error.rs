use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("aiken export failed: {0}")]
    ExportFailed(String),
    #[error("failed to parse export output: {0}")]
    ParseFailed(String),
    #[error("no compiledCode found")]
    NoCompiledCode,
    #[error("invalid hex in compiledCode: {0}")]
    InvalidHex(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, Error>;
