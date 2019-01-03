//! Serialization/deserialization

use serde::{Serialize, Serializer};
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

/// Serializes a map as a flat vector
///
/// This implies that the keys can be reconstructed from the values alone.
pub fn serialize_flat_map<K, V, S>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    K: Eq + Hash,
    V: Serialize,
    S: Serializer,
{
    let v: Vec<_> = map.values().collect();
    v.serialize(serializer)
}
