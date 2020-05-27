/// Derives string conversions via serialization to/from base64
#[macro_export]
macro_rules! derive_base64_conversions {
    ($t:ty) => {
        impl $crate::serde::ToBytes for $t {
            fn to_bytes(&self) -> $crate::Result<::std::vec::Vec<u8>> {
                let bytes = ::bincode::config()
                    .big_endian()
                    .serialize(self)
                    .map_err(|_| $crate::Error::Encoding)?;
                Ok(bytes)
            }
        }

        impl $crate::serde::FromBytes for $t {
            fn from_bytes(bytes: &[u8]) -> $crate::Result<Self> {
                let x = ::bincode::config()
                    .big_endian()
                    .deserialize(bytes)
                    .map_err(|_| $crate::Error::Decoding)?;
                Ok(x)
            }
        }
    };
}

/// Derives Protocol Buffer conversions for opaque message types (i.e. they have
/// a single field `bytes raw`)
#[macro_export]
macro_rules! derive_opaque_proto_conversions {
    ($t:ty : $m:ty) => {
        impl $crate::serde::Proto for $t {
            type Message = $m;

            fn to_proto(&self) -> $crate::Result<$m> {
                use $crate::serde::ToBytes;
                let mut m = <$m>::default();
                m.raw = self.to_bytes()?;
                Ok(m)
            }

            fn from_proto(m: &$m) -> $crate::Result<Self> {
                use $crate::serde::FromBytes;
                <$t>::from_bytes(&m.raw)
            }
        }

        derive_base64_conversions!($t);
    };
}
