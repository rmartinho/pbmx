//! Error type

/// Errors produced by PBMX
#[derive(Debug)]
pub enum Error {
    /// Occurs when serialization into or deserialization from bytes fails
    Bytes(bincode::Error),
    /// Occurs when deserialization from base64 fails
    Base64(base64::DecodeError),
    /// Occurs when deserialization from hex fails
    Hex(Option<std::num::ParseIntError>),
    /// Occurs when key exchange fails
    KeyExchange(crate::crypto::vtmf::KeyExchangeError),
    /// Occurs when decryption fails
    Decryption(crate::crypto::vtmf::DecryptionError),
}

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Error::Bytes(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::Hex(Some(e))
    }
}

impl From<Error> for std::fmt::Error {
    fn from(_: Error) -> Self {
        std::fmt::Error
    }
}
