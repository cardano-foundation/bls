use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid proof format: {0}")]
    InvalidProof(String),
    #[error("unsupported proof system: {0}")]
    UnsupportedProofSystem(String),
    #[error("wrapping failed: {0}")]
    WrappingFailed(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, Error>;
