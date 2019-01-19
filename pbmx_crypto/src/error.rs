//! Error type

/// Result specialization for PBMX crypto errors
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by PBMX
#[derive(Debug)]
pub enum Error {
    /// Occurs when serialization or deserialization fails
    Serde(pbmx_serde::Error),
    /// Occurs when VTMF decryption fails
    VtmfDecryption(crate::vtmf::DecryptionError),
    /// Occurs when building a fast modular exponentiation table fails
    FpowmPrecomputeFailure,
    /// Occurs when trying to combine a key of the wrong group
    GroupMismatch,
    /// Occurs when trying to create a permutation from a non-permutation vec
    NonPermutation,
}

impl From<pbmx_serde::Error> for Error {
    fn from(e: pbmx_serde::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<crate::vtmf::DecryptionError> for Error {
    fn from(e: crate::vtmf::DecryptionError) -> Self {
        Error::VtmfDecryption(e)
    }
}

impl From<Error> for std::fmt::Error {
    fn from(_: Error) -> Self {
        std::fmt::Error
    }
}
