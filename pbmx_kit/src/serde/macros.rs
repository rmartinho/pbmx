/// Derives string conversions via serialization to/from base64
#[macro_export]
macro_rules! derive_base64_conversions {
    ($t:ty) => {
        impl $crate::serde::ToBytes for $t {
            fn to_bytes(&self) -> ::std::result::Result<::std::vec::Vec<u8>, $crate::Error> {
                let bytes = ::bincode::config()
                    .big_endian()
                    .serialize(self)
                    .map_err(|_| $crate::Error::Encoding)?;
                Ok(bytes)
            }
        }

        impl $crate::serde::FromBytes for $t {
            fn from_bytes(bytes: &[u8]) -> ::std::result::Result<Self, $crate::Error> {
                let x = ::bincode::config()
                    .big_endian()
                    .deserialize(bytes)
                    .map_err(|_| $crate::Error::Decoding)?;
                Ok(x)
            }
        }
    };
}
