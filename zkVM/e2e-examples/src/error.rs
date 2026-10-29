use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("runner error: {0}")]
    Runner(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
