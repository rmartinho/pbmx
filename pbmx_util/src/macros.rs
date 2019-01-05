/// Derives string conversions via serialization to/from base64
#[macro_export]
macro_rules! derive_base64_conversions {
    ($t:ty, $e:ty) => {
        impl $crate::serde::ToBytes for $t {
            type Error = $e;

            fn to_bytes(&self) -> ::std::result::Result<::std::vec::Vec<u8>, Self::Error> {
                let bytes = ::bincode::config().big_endian().serialize(self)?;
                Ok(bytes)
            }
        }

        impl $crate::serde::FromBytes for $t {
            type Error = $e;

            fn from_bytes(bytes: &[u8]) -> ::std::result::Result<Self, Self::Error> {
                let x = ::bincode::config().big_endian().deserialize(bytes)?;
                Ok(x)
            }
        }

        impl ::std::fmt::Display for $t {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                use $crate::serde::ToBytes;
                write!(
                    f,
                    "{}",
                    ::base64::encode_config(&self.to_bytes()?, ::base64::URL_SAFE_NO_PAD)
                )
            }
        }

        impl ::std::str::FromStr for $t {
            type Err = $e;

            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                use $crate::serde::FromBytes;
                let bytes = ::base64::decode_config(s, ::base64::URL_SAFE_NO_PAD)?;
                let x = Self::from_bytes(&bytes)?;
                Ok(x)
            }
        }
    };
}
