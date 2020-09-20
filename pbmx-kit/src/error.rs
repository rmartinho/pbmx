use std::fmt::{self, Display, Formatter};

/// PBMX Result type
pub type Result<T> = std::result::Result<T, Error>;

/// Error type
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// An encoding error
    Encoding,
    /// A decoding error
    Decoding,
    /// A signature verification failure
    BadSignature,
    /// A proof verification failure
    BadProof,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Error::Encoding => write!(f, "encoding failure"),
            Error::Decoding => write!(f, "decoding failure"),
            Error::BadSignature => write!(f, "invalid signature"),
            Error::BadProof => write!(f, "invalid proof"),
        }
    }
}

impl std::error::Error for Error {}

/// An invalid permutation error
#[derive(Debug)]
pub struct InvalidPermutationError;

impl std::error::Error for InvalidPermutationError {}

impl Display for InvalidPermutationError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "invalid permutation")
    }
}
