//! PBMX toolbox utilities

#[macro_use]
mod macros;
mod bytes;
pub use self::bytes::{FromBase64, FromBytes, ToBase64, ToBytes};

use serde::ser::{Serialize, Serializer};
use std::{
    collections::{BTreeSet, HashMap},
    hash::{BuildHasher, Hash},
};

/// Serializes a map as a flat vector
///
/// This implies that the keys can be reconstructed from the values alone.
/// The flat vector is ordered by the keys, so that the serialized form is
/// deterministic.
pub fn serialize_flat_map<K, V, H, S>(
    map: &HashMap<K, V, H>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
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
