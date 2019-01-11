//! Serialization/deserialization

use serde::{de::Deserialize, ser::Serialize};

/// A trait for types that can be serialized to bytes
pub trait ToBytes {
    /// Error type
    type Error;

    /// Serializes to bytes
    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error>;
}

/// A trait for types that can be deserialized from bytes
pub trait FromBytes: Sized {
    /// Error type
    type Error;

    /// Deserializes from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}

impl<T> ToBytes for Vec<T>
where
    T: Serialize,
{
    type Error = crate::error::Error;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let bytes = bincode::config()
            .big_endian()
            .serialize(self)
            .map_err(crate::error::Error::from)?;
        Ok(bytes)
    }
}

impl<T, U> ToBytes for (T, U)
where
    T: Serialize,
    U: Serialize,
{
    type Error = crate::error::Error;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let bytes = bincode::config()
            .big_endian()
            .serialize(self)
            .map_err(crate::error::Error::from)?;
        Ok(bytes)
    }
}

impl<T> FromBytes for Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    type Error = crate::error::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let x = bincode::config()
            .big_endian()
            .deserialize(bytes)
            .map_err(crate::Error::from)?;
        Ok(x)
    }
}

impl<T, U> FromBytes for (T, U)
where
    T: for<'de> Deserialize<'de>,
    U: for<'de> Deserialize<'de>,
{
    type Error = crate::error::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let x = bincode::config()
            .big_endian()
            .deserialize(bytes)
            .map_err(crate::Error::from)?;
        Ok(x)
    }
}
