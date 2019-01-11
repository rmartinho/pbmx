pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Serde(pbmx_serde::Error),
    Crypto(pbmx_crypto::Error),
    Chain(pbmx_blocks::Error),
    Io(std::io::Error),
    BadCommand,
    BadGenesis,
    InvalidProof,
}

impl From<pbmx_serde::Error> for Error {
    fn from(e: pbmx_serde::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<pbmx_crypto::Error> for Error {
    fn from(e: pbmx_crypto::Error) -> Self {
        Error::Crypto(e)
    }
}

impl From<pbmx_blocks::Error> for Error {
    fn from(e: pbmx_blocks::Error) -> Self {
        Error::Chain(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for std::fmt::Error {
    fn from(_: Error) -> Self {
        std::fmt::Error
    }
}
