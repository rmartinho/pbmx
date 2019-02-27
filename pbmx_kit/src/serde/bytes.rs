//! Serialization/deserialization

use crate::{Error, Result};
use serde::{de::Deserialize, ser::Serialize};
use std::{collections::HashMap, hash::Hash};

/// A trait for types that can be serialized to bytes
pub trait ToBytes {
    /// Serializes to bytes
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

/// A trait for types that can be deserialized from bytes
pub trait FromBytes: Sized {
    /// Deserializes from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// A trait for types that can be serialized to base64
pub trait ToBase64 {
    /// Serializes to base64
    fn to_base64(&self) -> Result<String>;
}

/// A trait for types that can be deserialized from base64
pub trait FromBase64: Sized {
    /// Deserializes from base64
    fn from_base64(string: &str) -> Result<Self>;
}

impl<T> ToBase64 for T
where
    T: ToBytes,
{
    fn to_base64(&self) -> Result<String> {
        Ok(base64::encode_config(
            &self.to_bytes()?,
            base64::URL_SAFE_NO_PAD,
        ))
    }
}

impl<T> FromBase64 for T
where
    T: FromBytes,
{
    fn from_base64(string: &str) -> Result<Self> {
        let bytes =
            base64::decode_config(string, base64::URL_SAFE_NO_PAD).map_err(|_| Error::Decoding)?;
        let x = Self::from_bytes(&bytes)?;
        Ok(x)
    }
}

impl<T> ToBytes for Vec<T>
where
    T: Serialize,
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = bincode::config()
            .big_endian()
            .serialize(self)
            .map_err(|_| Error::Encoding)?;
        Ok(bytes)
    }
}

impl<T, U> ToBytes for (T, U)
where
    T: Serialize,
    U: Serialize,
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = bincode::config()
            .big_endian()
            .serialize(self)
            .map_err(|_| Error::Encoding)?;
        Ok(bytes)
    }
}

impl<T, U> ToBytes for HashMap<T, U>
where
    T: Serialize + Eq + Hash,
    U: Serialize,
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = bincode::config()
            .big_endian()
            .serialize(self)
            .map_err(|_| Error::Encoding)?;
        Ok(bytes)
    }
}

impl<T> FromBytes for Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let x = bincode::config()
            .big_endian()
            .deserialize(bytes)
            .map_err(|_| Error::Decoding)?;
        Ok(x)
    }
}

impl<T, U> FromBytes for (T, U)
where
    T: for<'de> Deserialize<'de>,
    U: for<'de> Deserialize<'de>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let x = bincode::config()
            .big_endian()
            .deserialize(bytes)
            .map_err(|_| Error::Decoding)?;
        Ok(x)
    }
}

impl<T, U> FromBytes for HashMap<T, U>
where
    T: for<'de> Deserialize<'de> + Eq + Hash,
    U: for<'de> Deserialize<'de>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let x = bincode::config()
            .big_endian()
            .deserialize(bytes)
            .map_err(|_| Error::Decoding)?;
        Ok(x)
    }
}
