pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Clap(clap::Error),
    Crypto(pbmx_curve::Error),
    Chain(pbmx_chain::Error),
    Serde(pbmx_serde::Error),
    InvalidSubcommand,
}

impl Error {
    pub fn exit(&self) -> ! {
        match self {
            Error::Io(e) => clap::Error {
                message: e.to_string(),
                kind: clap::ErrorKind::Io,
                info: None,
            }
            .exit(),
            Error::Clap(e) => e.exit(),
            Error::Crypto(_) => clap::Error {
                message: "Key deserialization failure".into(),
                kind: clap::ErrorKind::Io,
                info: None,
            }
            .exit(),
            Error::Chain(_) => clap::Error {
                message: "Chain deserialization failure".into(),
                kind: clap::ErrorKind::Io,
                info: None,
            }
            .exit(),
            Error::Serde(_) => clap::Error {
                message: "Deserialization failure".into(),
                kind: clap::ErrorKind::Io,
                info: None,
            }
            .exit(),
            Error::InvalidSubcommand => clap::Error {
                message: "Invalid subcommand".into(),
                kind: clap::ErrorKind::InvalidSubcommand,
                info: None,
            }
            .exit(),
        }
    }
}

impl From<clap::Error> for Error {
    fn from(e: clap::Error) -> Self {
        Error::Clap(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<pbmx_curve::Error> for Error {
    fn from(e: pbmx_curve::Error) -> Self {
        Error::Crypto(e)
    }
}

impl From<pbmx_chain::Error> for Error {
    fn from(e: pbmx_chain::Error) -> Self {
        Error::Chain(e)
    }
}

impl From<pbmx_serde::Error> for Error {
    fn from(e: pbmx_serde::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<Error> for std::fmt::Error {
    fn from(_: Error) -> Self {
        std::fmt::Error
    }
}
