//! Serialization/deserialization

use super::Message;
use crate::{Error, Result};

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
    T: Message,
{
    fn to_base64(&self) -> Result<String> {
        Ok(base64::encode_config(
            &self.encode()?,
            base64::URL_SAFE_NO_PAD,
        ))
    }
}

impl<T> FromBase64 for T
where
    T: Message,
{
    fn from_base64(string: &str) -> Result<Self> {
        let bytes =
            base64::decode_config(string, base64::URL_SAFE_NO_PAD).map_err(|_| Error::Decoding)?;
        let x = Self::decode(&bytes)?;
        Ok(x)
    }
}
