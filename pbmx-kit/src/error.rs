use std::fmt::{self, Display, Formatter};

/// PBMX Result type
pub type Result<T> = std::result::Result<T, Error>;

/// Error type
#[derive(Debug)]
pub enum Error {
    /// An encoding error
    Encoding,
    /// A decoding error
    Decoding,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Error::Encoding => write!(f, "encoding failure"),
            Error::Decoding => write!(f, "decoding failure"),
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
