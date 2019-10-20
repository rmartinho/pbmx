//! PBMX toolbox utilities

#[macro_use]
mod macros;
mod bytes;
mod protobuf;
pub use self::{
    bytes::{FromBase64, FromBytes, ToBase64, ToBytes},
    protobuf::Proto,
};

use crate::Error;
use serde::ser::{Serialize, Serializer};
use std::{
    collections::{BTreeSet, HashMap},
    hash::{BuildHasher, Hash},
};

/// A PBMX protocol message
pub trait Message: Sized {
    /// Encodes a value as a PBMX message
    fn encode(&self) -> Result<Vec<u8>, Error>;
    /// Decodes a PBMX message into a value
    fn decode(buf: &[u8]) -> Result<Self, Error>;
}

impl<T> Message for T
where
    T: Proto,
{
    fn encode(&self) -> Result<Vec<u8>, Error> {
        use prost::Message;
        let msg = self.to_proto()?;
        let raw_len = self.to_proto()?.encoded_len();
        let delim_len = prost::length_delimiter_len(raw_len);
        let mut buf = Vec::with_capacity(raw_len + delim_len);
        msg.encode_length_delimited(&mut buf)
            .map_err(|_| Error::Encoding)?;
        Ok(buf)
    }

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        use prost::Message;
        let msg =
            <Self as Proto>::Message::decode_length_delimited(buf).map_err(|_| Error::Encoding)?;
        Self::from_proto(&msg)
    }
}

/// Serializes a map as a flat vector
///
/// This implies that the keys can be reconstructed from the values alone.
/// The flat vector is ordered by the keys, so that the serialized form is
/// deterministic.
pub(crate) fn serialize_flat_map<K, V, H, S>(
    map: &HashMap<K, V, H>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    K: Eq + Ord + Hash,
    V: Serialize,
    H: BuildHasher,
    S: Serializer,
{
    let keys: BTreeSet<_> = map.keys().collect();
    let v: Vec<_> = keys.iter().map(|k| map.get(k).unwrap()).collect();
    v.serialize(serializer)
}

/// Deserializes a series of Protocol Buffers messages
pub(crate) fn vec_from_proto<T: Proto>(v: &[T::Message]) -> Result<Vec<T>, Error> {
    v.iter().map(Proto::from_proto).collect()
}

/// Serializes a series of Protocol Buffers messages
pub(crate) fn vec_to_proto<T: Proto>(v: &[T]) -> Result<Vec<T::Message>, Error> {
    v.iter().map(Proto::to_proto).collect()
}
