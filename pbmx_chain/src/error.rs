//! Error type

/// Result specialization for PBMX crypto errors
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by PBMX
#[derive(Debug)]
pub enum Error {
    /// Occurs when serialization or deserialization fails
    Serde(pbmx_serde::Error),
    /// Occurs when a cryptography operation fails
    Crypto(pbmx_curve::Error),
}

impl From<pbmx_serde::Error> for Error {
    fn from(e: pbmx_serde::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<pbmx_curve::Error> for Error {
    fn from(e: pbmx_curve::Error) -> Self {
        Error::Crypto(e)
    }
}

impl From<Error> for std::fmt::Error {
    fn from(_: Error) -> Self {
        std::fmt::Error
    }
}
