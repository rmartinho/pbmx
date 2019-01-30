pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Clap(clap::Error),
    Io(std::io::Error),
    Crypto(pbmx_curve::Error),
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
            Error::Crypto(e) => clap::Error {
                message: "Crypto failure".into(),
                kind: clap::ErrorKind::Io,
                info: None,
            }.exit(),
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

impl From<Error> for std::fmt::Error {
    fn from(_: Error) -> Self {
        std::fmt::Error
    }
}
