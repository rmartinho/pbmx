macro_rules! derive_base64_conversions {
    ($t:ty) => {
        impl $t {
            /// Serializes to bytes
            pub fn to_bytes(
                &self,
            ) -> ::std::result::Result<::std::vec::Vec<u8>, crate::error::Error> {
                let bytes = ::bincode::config().big_endian().serialize(self)?;
                Ok(bytes)
            }

            /// Deserializes from bytes
            pub fn from_bytes(bytes: &[u8]) -> ::std::result::Result<Self, crate::error::Error> {
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
            type Err = crate::error::Error;

            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                let bytes = ::base64::decode(s)?;
                let x = Self::from_bytes(&bytes)?;
                Ok(x)
            }
        }
    };
}
