#[derive(Debug)]
pub enum SerializationError {
    Format(std::fmt::Error),
    Bincode(bincode::Error),
    Base64(base64::DecodeError),
}

impl From<bincode::Error> for SerializationError {
    fn from(e: bincode::Error) -> Self {
        SerializationError::Bincode(e)
    }
}

impl From<SerializationError> for std::fmt::Error {
    fn from(_: SerializationError) -> Self {
        std::fmt::Error
    }
}

impl From<base64::DecodeError> for SerializationError {
    fn from(e: base64::DecodeError) -> Self {
        SerializationError::Base64(e)
    }
}

macro_rules! derive_base64_conversions {
    ($t:ty) => {
        impl $t {
            /// Serializes to bytes
            pub fn to_bytes(
                &self,
            ) -> ::std::result::Result<::std::vec::Vec<u8>, crate::macros::SerializationError> {
                let bytes = ::bincode::config().big_endian().serialize(self)?;
                Ok(bytes)
            }

            /// Deserializes from bytes
            pub fn from_bytes(
                bytes: &[u8],
            ) -> ::std::result::Result<Self, crate::macros::SerializationError> {
                let x = ::bincode::config().big_endian().deserialize(bytes)?;
                Ok(x)
            }
        }

        impl ::std::fmt::Display for $t {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "{}", ::base64::encode(&self.to_bytes()?))
            }
        }

        impl ::std::str::FromStr for $t {
            type Err = crate::macros::SerializationError;

            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                let bytes = ::base64::decode(s)?;
                let x = Self::from_bytes(&bytes)?;
                Ok(x)
            }
        }
    };
}
