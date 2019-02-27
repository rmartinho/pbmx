//! Serialization/deserialization

use crate::serde::Error;
use serde::{de::Deserialize, ser::Serialize};
use std::{collections::HashMap, hash::Hash};

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

/// A trait for types that can be serialized to base64
pub trait ToBase64 {
    /// Error type
    type Error;

    /// Serializes to base64
    fn to_base64(&self) -> Result<String, Self::Error>;
}

/// A trait for types that can be deserialized from base64
pub trait FromBase64: Sized {
    /// Error type
    type Error;

    /// Deserializes from base64
    fn from_base64(string: &str) -> Result<Self, Self::Error>;
}

impl<T> ToBase64 for T
where
    T: ToBytes,
{
    type Error = T::Error;

    fn to_base64(&self) -> Result<String, Self::Error> {
        Ok(base64::encode_config(
            &self.to_bytes()?,
            base64::URL_SAFE_NO_PAD,
        ))
    }
}

impl<T> FromBase64 for T
where
    T: FromBytes,
    T::Error: From<Error>,
{
    type Error = T::Error;

    fn from_base64(string: &str) -> Result<Self, Self::Error> {
        let bytes = base64::decode_config(string, base64::URL_SAFE_NO_PAD).map_err(Error::from)?;
        let x = Self::from_bytes(&bytes)?;
        Ok(x)
    }
}

impl<T> ToBytes for Vec<T>
where
    T: Serialize,
{
    type Error = crate::serde::Error;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let bytes = bincode::config().big_endian().serialize(self)?;
        Ok(bytes)
    }
}

impl<T, U> ToBytes for (T, U)
where
    T: Serialize,
    U: Serialize,
{
    type Error = crate::serde::Error;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let bytes = bincode::config().big_endian().serialize(self)?;
        Ok(bytes)
    }
}

impl<T, U> ToBytes for HashMap<T, U>
where
    T: Serialize + Eq + Hash,
    U: Serialize,
{
    type Error = crate::serde::Error;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let bytes = bincode::config().big_endian().serialize(self)?;
        Ok(bytes)
    }
}

impl<T> FromBytes for Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    type Error = crate::serde::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let x = bincode::config().big_endian().deserialize(bytes)?;
        Ok(x)
    }
}

impl<T, U> FromBytes for (T, U)
where
    T: for<'de> Deserialize<'de>,
    U: for<'de> Deserialize<'de>,
{
    type Error = crate::serde::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let x = bincode::config()
            .big_endian()
            .deserialize(bytes)
            .map_err(crate::serde::Error::from)?;
        Ok(x)
    }
}

impl<T, U> FromBytes for HashMap<T, U>
where
    T: for<'de> Deserialize<'de> + Eq + Hash,
    U: for<'de> Deserialize<'de>,
{
    type Error = crate::serde::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let x = bincode::config().big_endian().deserialize(bytes)?;
        Ok(x)
    }
}
