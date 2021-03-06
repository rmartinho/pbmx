pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Num(std::num::ParseIntError),
    Clap(clap::Error),
    Pbmx(pbmx_kit::Error),
    Toml(toml::de::Error),
    InvalidSubcommand,
    InvalidData,
    InvalidBlock,
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
            Error::Num(e) => clap::Error {
                message: e.to_string(),
                kind: clap::ErrorKind::Io,
                info: None,
            }
            .exit(),
            Error::Clap(e) => e.exit(),
            Error::Pbmx(e) => clap::Error {
                message: format!("{}", e),
                kind: clap::ErrorKind::InvalidValue,
                info: None,
            }
            .exit(),
            Error::Toml(e) => clap::Error {
                message: format!("{:?}", e),
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
            Error::InvalidData => clap::Error {
                message: "Invalid data".into(),
                kind: clap::ErrorKind::InvalidValue,
                info: None,
            }
            .exit(),
            Error::InvalidBlock => clap::Error {
                message: "Invalid block".into(),
                kind: clap::ErrorKind::InvalidValue,
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

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::Num(e)
    }
}

impl From<pbmx_kit::Error> for Error {
    fn from(e: pbmx_kit::Error) -> Self {
        Error::Pbmx(e)
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Toml(e)
    }
}

impl From<Error> for std::fmt::Error {
    fn from(_: Error) -> Self {
        std::fmt::Error
    }
}
