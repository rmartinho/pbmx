//! Protocol Buffers support

use crate::Result;
use prost;

/// A trait for types that can be serialized with Protocol Buffers
pub trait Proto: Sized {
    /// The message type that corresponds to this type
    type Message: prost::Message + Default;

    /// Converts to a Protocol Buffers message
    fn to_proto(&self) -> Result<Self::Message>;

    /// Converts from a Protocol Buffers message
    fn from_proto(m: &Self::Message) -> Result<Self>;
}
