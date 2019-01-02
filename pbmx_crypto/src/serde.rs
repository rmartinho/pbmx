//! Serialization/deserialization

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
