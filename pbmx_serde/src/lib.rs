#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX toolbox utilities

#[macro_use]
mod macros;
mod bytes;
pub use self::bytes::{FromBytes, ToBytes};
mod error;
pub use self::error::{Error, Result};

use serde::ser::{Serialize, Serializer};
use std::{collections::HashMap, hash::Hash};

/// Serializes a map as a flat vector
///
/// This implies that the keys can be reconstructed from the values alone.
pub fn serialize_flat_map<K, V, S>(
    map: &HashMap<K, V>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    K: Eq + Hash,
    V: Serialize,
    S: Serializer,
{
    let v: Vec<_> = map.values().collect();
    v.serialize(serializer)
}
