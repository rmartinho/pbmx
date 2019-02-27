/// Derives string conversions via serialization to/from base64
#[macro_export]
macro_rules! derive_base64_conversions {
    ($t:ty, $e:ty) => {
        impl $crate::serde::ToBytes for $t {
            type Error = $e;

            fn to_bytes(&self) -> ::std::result::Result<::std::vec::Vec<u8>, Self::Error> {
                let bytes = ::bincode::config().big_endian().serialize(self).map_err($crate::serde::Error::from)?;
                Ok(bytes)
            }
        }

        impl $crate::serde::FromBytes for $t {
            type Error = $e;

            fn from_bytes(bytes: &[u8]) -> ::std::result::Result<Self, Self::Error> {
                let x = ::bincode::config().big_endian().deserialize(bytes).map_err($crate::serde::Error::from)?;
                Ok(x)
            }
        }
    };
}